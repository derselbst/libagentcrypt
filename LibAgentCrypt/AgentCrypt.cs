/*
 * Copyright (c) 2019-2022, Nicola Di Lieto <nicola.dilieto@gmail.com>
 * Copyright (c) 2025, Ported to C#/.NET by GitHub Copilot
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

using System.Security.Cryptography;
using HASH = System.Security.Cryptography.SHA256;

namespace LibAgentCrypt;

/// <summary>
/// Provides encryption and decryption functionality using SSH agent keys.
/// </summary>
public class AgentCrypt
{
    private const int NonceBytes = 12;
    private const int KeyBytes = HASH.HashSizeInBytes;
    private const int MacBytes = 16;
    private const int HashBytes = HASH.HashSizeInBytes;
    private const int MinPadSize = 16;
    private const int ChunkSize = 4 * 1024;


    private const byte FileVersion = 0;
    private static readonly byte[] FileHeader = [ (byte)'A', (byte)'C', (byte)'B', FileVersion ];

    /// <summary>
    /// Encrypts a block of data using an SSH agent key.
    /// </summary>
    /// <param name="cleartext">The data to encrypt.</param>
    /// <param name="keySha256">The SHA256 fingerprint of the SSH key (optional, uses first key if null).</param>
    /// <param name="padSize">Padding size (minimum 16 bytes).</param>
    /// <param name="agentPath">Path to SSH agent socket (uses SSH_AUTH_SOCK if null).</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] Encrypt(byte[] cleartext, string? keySha256 = null, int padSize = MinPadSize, string? agentPath = null)
    {
        if (cleartext == null)
            throw new ArgumentNullException(nameof(cleartext));
        if (padSize < 0)
            throw new ArgumentException("Pad size cannot be negative", nameof(padSize));

        if (padSize < MinPadSize)
            padSize = MinPadSize;

        using var agent = new SshAgent(agentPath);
        agent.Connect();

        var keyBlob = agent.FindKeyBySha256(keySha256);

        // Calculate padded size
        int padBufSize = cleartext.Length % padSize;
        if (cleartext.Length < padSize)
        {
            padBufSize = padSize;
        }
        else if (padBufSize == 0)
        {
            padBufSize = cleartext.Length;
        }
        else
        {
            padBufSize = cleartext.Length + (padSize - padBufSize);
        }
        padBufSize += 4; // Add 4 bytes for original length

        // Create padded buffer
        var padBuf = new byte[padBufSize];
        Array.Copy(cleartext, 0, padBuf, 0, cleartext.Length);

        // Fill padding with random data
        if (padBufSize - 4 > cleartext.Length)
        {
            var randomPadding = RandomNumberGenerator.GetBytes(padBufSize - 4 - cleartext.Length);
            Array.Copy(randomPadding, 0, padBuf, cleartext.Length, randomPadding.Length);
        }

        // Write original length at the end
        padBuf[padBufSize - 4] = (byte)(cleartext.Length >> 24);
        padBuf[padBufSize - 3] = (byte)(cleartext.Length >> 16);
        padBuf[padBufSize - 2] = (byte)(cleartext.Length >> 8);
        padBuf[padBufSize - 1] = (byte)cleartext.Length;

        // Generate nonce
        var randomKey = RandomNumberGenerator.GetBytes(KeyBytes);
        var nonce = new byte[NonceBytes];
        using (var hmac = new HMACSHA256(randomKey))
        {
            var nonceData = hmac.ComputeHash(padBuf);
            Array.Copy(nonceData, 0, nonce, 0, NonceBytes);
        }

        // Compute key hash
        byte[] keyHash;
        using (var sha = HASH.Create())
        {
            keyHash = SshAgent.ComputeKeyHash(keyBlob, nonce, HASH.Create());
        }

        // Create challenge (nonce + hash)
        var challenge = new byte[nonce.Length + keyHash.Length];
        Array.Copy(nonce, 0, challenge, 0, nonce.Length);
        Array.Copy(keyHash, 0, challenge, nonce.Length, keyHash.Length);

        // Sign with SSH agent
        var legacyEnv = Environment.GetEnvironmentVariable("AGENTCRYPT_LEGACY");
        bool useLegacy = !string.IsNullOrEmpty(legacyEnv) && legacyEnv != "0";
        var signature = agent.Sign(keyBlob, challenge, useLegacy);

        // Derive encryption key from signature
        byte[] encryptionKey;
        using (var sha = HASH.Create())
        {
            encryptionKey = sha.ComputeHash(signature);
        }

        // Encrypt using ChaCha20-Poly1305
        var ciphertext = new byte[nonce.Length + keyHash.Length + MacBytes + padBufSize];
        Array.Copy(nonce, 0, ciphertext, 0, nonce.Length);
        Array.Copy(keyHash, 0, ciphertext, nonce.Length, keyHash.Length);

        using var chacha = new ChaCha20Poly1305(encryptionKey);
        chacha.Encrypt(nonce, padBuf, ciphertext.AsSpan(nonce.Length + keyHash.Length + MacBytes), 
            ciphertext.AsSpan(nonce.Length + keyHash.Length, MacBytes));

        Array.Clear(encryptionKey, 0, encryptionKey.Length);
        Array.Clear(padBuf, 0, padBuf.Length);

        return ciphertext;
    }

    /// <summary>
    /// Decrypts a block of data using an SSH agent key.
    /// </summary>
    /// <param name="ciphertext">The encrypted data.</param>
    /// <param name="agentPath">Path to SSH agent socket (uses SSH_AUTH_SOCK if null).</param>
    /// <returns>The decrypted data.</returns>
    public static byte[] Decrypt(byte[] ciphertext, string? agentPath = null)
    {
        if (ciphertext == null)
        {
            throw new ArgumentNullException(nameof(ciphertext));
        }

        int minSize = NonceBytes + HashBytes + MacBytes;
        if (ciphertext.Length < minSize)
        {
            throw new InvalidDataException($"Ciphertext too short! Must be at least {minSize} but was only {ciphertext.Length}");
        }

        var nonce = new byte[NonceBytes];
        var keyHash = new byte[HashBytes];
        Array.Copy(ciphertext, 0, nonce, 0, NonceBytes);
        Array.Copy(ciphertext, NonceBytes, keyHash, 0, HashBytes);

        using var agent = new SshAgent(agentPath);
        agent.Connect();

        byte[] keyBlob;
        using (var sha = HASH.Create())
        {
            keyBlob = agent.FindKeyByHash(nonce, keyHash, sha);
        }

        // Try to decrypt with both legacy and modern signatures
        byte[] plaintext = null!;
        bool success = false;

        foreach (bool useLegacy in new[] { false, true })
        {
            try
            {
                var challenge = new byte[nonce.Length + keyHash.Length];
                Array.Copy(nonce, 0, challenge, 0, nonce.Length);
                Array.Copy(keyHash, 0, challenge, nonce.Length, keyHash.Length);

                var signature = agent.Sign(keyBlob, challenge, useLegacy);

                byte[] encryptionKey;
                using (var sha = HASH.Create())
                {
                    encryptionKey = sha.ComputeHash(signature);
                }

                var paddedSize = ciphertext.Length - NonceBytes - HashBytes - MacBytes;
                plaintext = new byte[paddedSize];

                using var chacha = new ChaCha20Poly1305(encryptionKey);
                chacha.Decrypt(nonce, 
                    ciphertext.AsSpan(NonceBytes + HashBytes + MacBytes),
                    ciphertext.AsSpan(NonceBytes + HashBytes, MacBytes),
                    plaintext);

                Array.Clear(encryptionKey, 0, encryptionKey.Length);
                success = true;
                break;
            }
            catch (CryptographicException)
            {
                if (useLegacy)
                    throw new InvalidDataException("Failed to decrypt: invalid key or corrupted data");
            }
        }

        if (!success || plaintext == null)
            throw new InvalidDataException("Failed to decrypt: invalid key or corrupted data");

        // Extract original length
        int originalLength = (plaintext[plaintext.Length - 4] << 24) |
                            (plaintext[plaintext.Length - 3] << 16) |
                            (plaintext[plaintext.Length - 2] << 8) |
                            plaintext[plaintext.Length - 1];

        if (originalLength >= plaintext.Length)
            throw new InvalidDataException("Invalid decrypted data");

        var result = new byte[originalLength];
        Array.Copy(plaintext, 0, result, 0, originalLength);
        Array.Clear(plaintext, 0, plaintext.Length);

        return result;
    }

    /// <summary>
    /// Encrypts a file using an SSH agent key.
    /// </summary>
    /// <param name="inputPath">Path to the input file.</param>
    /// <param name="outputPath">Path to the output file.</param>
    /// <param name="keySha256">The SHA256 fingerprint of the SSH key (optional).</param>
    /// <param name="agentPath">Path to SSH agent socket (uses SSH_AUTH_SOCK if null).</param>
    public static void EncryptFile(string inputPath, string outputPath, string? keySha256 = null, string? agentPath = null)
    {
        using var input = File.OpenRead(inputPath);
        using var output = File.Create(outputPath);
        EncryptStream(input, output, keySha256, agentPath);
    }

    /// <summary>
    /// Encrypts a stream using an SSH agent key.
    /// </summary>
    public static void EncryptStream(Stream input, Stream output, string? keySha256 = null, string? agentPath = null)
    {
        // Generate random key for stream encryption
        var streamKey = RandomNumberGenerator.GetBytes(KeyBytes);

        // Encrypt the stream key with agent
        var encryptedKey = Encrypt(streamKey, keySha256, 0, agentPath);

        var headerToBeWritten = new List<byte>();

        // Write file header: magic
        headerToBeWritten.AddRange(FileHeader);

        var keySizeBytes = BitConverter.GetBytes((ushort)encryptedKey.Length);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(keySizeBytes);
        }
        // Write file header: size of encrypted key
        headerToBeWritten.AddRange(keySizeBytes);

        // Compute header hash: SHA256(FileHeader | keySizeBytes);
        var headerHash = new byte[HashBytes];
        using (var sha = HASH.Create())
        {
            headerHash = sha.ComputeHash(headerToBeWritten.ToArray());
        }
        // Write file header: hash
        headerToBeWritten.AddRange(headerHash);
        // Write encrypted key
        headerToBeWritten.AddRange(encryptedKey);

        // Encrypt file content with ChaCha20-Poly1305 stream
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        headerToBeWritten.AddRange(nonce);

        // Write the header!
        output.Write(headerToBeWritten.ToArray());

        using var chacha = new ChaCha20Poly1305(streamKey);
        
        var buffer = new byte[ChunkSize];
        var cipherBuffer = new byte[buffer.Length + MacBytes];
        var tag = new byte[MacBytes];
        
        int bytesRead;
        long counter = 0;
        while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            var currentNonce = new byte[12];
            Array.Copy(nonce, currentNonce, 12);
            
            // Increment counter in nonce
            for (int i = 0; i < 8; i++)
            {
                currentNonce[4 + i] = (byte)(counter >> (i * 8));
            }
            
            chacha.Encrypt(currentNonce, buffer.AsSpan(0, bytesRead), 
                cipherBuffer.AsSpan(MacBytes, bytesRead), tag);
            
            output.Write(tag, 0, MacBytes);
            output.Write(cipherBuffer, MacBytes, bytesRead);
            counter++;
        }

        Array.Clear(streamKey, 0, streamKey.Length);
    }

    /// <summary>
    /// Decrypts a file using an SSH agent key.
    /// </summary>
    /// <param name="inputPath">Path to the encrypted file.</param>
    /// <param name="outputPath">Path to the output file.</param>
    /// <param name="agentPath">Path to SSH agent socket (uses SSH_AUTH_SOCK if null).</param>
    public static void DecryptFile(string inputPath, string outputPath, string? agentPath = null)
    {
        using var input = File.OpenRead(inputPath);
        using var output = File.Create(outputPath);
        DecryptStream(input, output, agentPath);
    }

    /// <summary>
    /// Decrypts a stream using an SSH agent key.
    /// </summary>
    public static void DecryptStream(Stream input, Stream output, string? agentPath = null)
    {
        // Read and verify header
        var header = new byte[6 + HashBytes];
        if (input.Read(header, 0, header.Length) != header.Length)
            throw new InvalidDataException("Invalid file format");

        if (header[0] != 0x41 || header[1] != 0x43 || header[2] != 0x42 || header[3] != 0x00)
            throw new InvalidDataException("Invalid file magic");

        var keySizeBytes = new byte[] { header[4], header[5] };
        if (BitConverter.IsLittleEndian)
            Array.Reverse(keySizeBytes);
        var keySize = BitConverter.ToUInt16(keySizeBytes, 0);

        // Verify header hash
        var expectedHash = new byte[HashBytes];
        Array.Copy(header, 6, expectedHash, 0, HashBytes);

        // Compute header hash: SHA256(FileHeader | keySizeBytes);
        using (var sha = HASH.Create())
        {
            var computedHash = sha.ComputeHash(header, 0, 6);
            if (!computedHash.SequenceEqual(expectedHash))
            {
                throw new InvalidDataException("Header hash mismatch");
            }
        }

        // Read and decrypt stream key
        var encryptedKey = new byte[keySize];
        if (input.Read(encryptedKey, 0, keySize) != keySize)
            throw new InvalidDataException("Failed to read encrypted key");

        var streamKey = Decrypt(encryptedKey, agentPath);
        if (streamKey.Length != KeyBytes)
            throw new InvalidDataException("Invalid stream key size");

        // Read nonce
        var nonce = new byte[12];
        if (input.Read(nonce, 0, 12) != 12)
            throw new InvalidDataException("Failed to read nonce");

        // Decrypt file content
        using var chacha = new ChaCha20Poly1305(streamKey);
        
        var buffer = new byte[ChunkSize + MacBytes];
        long counter = 0;
        
        while (true)
        {
            var tag = new byte[MacBytes];
            var tagBytesRead = input.Read(tag, 0, MacBytes);
            if (tagBytesRead == 0)
                break;
            if (tagBytesRead != MacBytes)
                throw new InvalidDataException("Incomplete tag");

            int bytesRead = input.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
                throw new InvalidDataException("Unexpected end of file");

            var currentNonce = new byte[12];
            Array.Copy(nonce, currentNonce, 12);
            
            for (int i = 0; i < 8; i++)
            {
                currentNonce[4 + i] = (byte)(counter >> (i * 8));
            }
            
            var plainBuffer = new byte[bytesRead];
            chacha.Decrypt(currentNonce, buffer.AsSpan(0, bytesRead), tag, plainBuffer);
            
            output.Write(plainBuffer, 0, bytesRead);
            counter++;
        }

        Array.Clear(streamKey, 0, streamKey.Length);
    }

    /// <summary>
    /// Encodes binary data to base64 without padding.
    /// </summary>
    public static string ToBase64(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=');
    }

    /// <summary>
    /// Decodes base64 data (with or without padding).
    /// </summary>
    public static byte[] FromBase64(string data)
    {
        // Add padding if needed
        int padding = (4 - (data.Length % 4)) % 4;
        if (padding > 0)
        {
            data = data + new string('=', padding);
        }
        return Convert.FromBase64String(data);
    }

    /// <summary>
    /// Returns the library version.
    /// </summary>
    public static string GetVersion()
    {
        return "2.0.0"; // C# port version
    }
}
