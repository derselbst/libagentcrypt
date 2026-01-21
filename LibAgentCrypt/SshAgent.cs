/*
 * Copyright (c) 2019-2022, Nicola Di Lieto <nicola.dilieto@gmail.com>
 * Copyright (c) 2025, Ported to C#/.NET by GitHub Copilot
 * Copyright (c) 2026, by y3tmo, fixing remaining bugs and nonsense caused by Copilot
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

using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace LibAgentCrypt;

internal enum AgentCommand : byte
{
    // SSH_AGENTC_REQUEST_IDENTITIES
    RequestIdentities = 11,
    // SSH_AGENTC_SIGN_REQUEST
    SignRequest = 13
}

internal enum AgentReply : byte
{
    Failure = 5,
    Success = 6,
    IdentitiesAnswer = 12,
    SignResponse = 14
}

internal enum AgentFlags : uint
{
    RsaSha2_256 = 2,
    RsaSha2_512 = 4
}

internal enum KeyType
{
    Unsupported = -1,
    Rsa = 0,
    Ed25519 = 1
}

internal enum SignatureType
{
    Unsupported = -1,
    RsaSha1 = 0,
    RsaSha2_256 = 1,
    RsaSha2_512 = 2,
    Ed25519 = 3
}

/// <summary>
/// Provides communication with the SSH agent for signing operations by implementing the "SSH Agent Protocol", see
/// https://www.ietf.org/archive/id/draft-miller-ssh-agent-11.html
/// </summary>
internal class SshAgent : IDisposable
{
    private Stream? _stream;
    private readonly string _agentPath;

    public SshAgent(string? agentPath = null)
    {
        _agentPath = agentPath ?? Environment.GetEnvironmentVariable("SSH_AUTH_SOCK")
            ?? throw new InvalidOperationException("SSH_AUTH_SOCK environment variable not set");
    }

    /// <summary>
    /// Connects to the SSH agent via the socket or pipe given by _agentPath.
    /// </summary>
    public void Connect()
    {
        // NamedPipeClientStream automatically handles both:
        // - Windows named pipes (e.g., \\.\pipe\openssh-ssh-agent)
        // - Unix domain sockets (e.g., /tmp/ssh-XXX/agent.123)
        if (OperatingSystem.IsWindows())
        {
            // On Windows, the path is typically \\.\pipe\openssh-ssh-agent
            // Extract the pipe name from the path
            string pipeName;
            if (_agentPath.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase))
            {
                pipeName = _agentPath.Substring(@"\\.\pipe\".Length);
            }
            else if (_agentPath.StartsWith(@"\\?\pipe\", StringComparison.OrdinalIgnoreCase))
            {
                pipeName = _agentPath.Substring(@"\\?\pipe\".Length);
            }
            else
            {
                // Assume it's just the pipe name
                pipeName = _agentPath;
            }

            var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
            pipe.Connect();
            _stream = pipe;
        }
        else
        {
            // On Unix systems, use the path directly as a Unix domain socket
            var endpoint = new UnixDomainSocketEndPoint(_agentPath);
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            socket.Connect(endpoint);
            _stream = new NetworkStream(socket, ownsSocket: true);
        }
    }

    /// <summary>
    /// Requests the agent to list all available SSH keys by sending a SSH_AGENTC_REQUEST_IDENTITIES command.
    /// </summary>
    /// <returns>Returns a list containing a tuple of public keys + an optional comment identifying the key (typically the name of the key).</returns>
    /// <exception cref="InvalidDataException"></exception>
    public List<(byte[] KeyBlob, string Comment)> ListKeys()
    {
        EnsureConnected();

        var command = new SshAgentMessage();
        command.WriteByte((byte)AgentCommand.RequestIdentities);

        var reply = SendCommand(command);
        var replyType = (AgentReply)reply.ReadByte();

        if (replyType != AgentReply.IdentitiesAnswer)
        {
            throw new InvalidDataException("Invalid reply from SSH agent");
        }

        var numKeys = reply.ReadUInt32();
        var keys = new List<(byte[], string)>();

        for (uint i = 0; i < numKeys; i++)
        {
            var keyBlob = reply.ReadBlob();
            var comment = reply.ReadString();
            keys.Add((keyBlob, comment));
        }

        return keys;
    }

    /// <summary>
    /// Requests a signing request to the agent, i.e. SSH_AGENTC_SIGN_REQUEST
    /// </summary>
    /// <param name="keyBlob">Public ssh key used to identify the key to sign with.</param>
    /// <param name="data">The data to be signed.</param>
    /// <param name="useLegacy">If false (the default) the agent will receive an extra flag if the key is an RSA key, asking it to use an SHA256 signature based algorithm.
    /// If true, this special flag is left unset, assuming the agent does not support it, in which case the agent might use a less secure SHA1- or DSA-based signature.</param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException"></exception>
    /// <exception cref="InvalidDataException"></exception>
    public byte[] Sign(byte[] keyBlob, byte[] data, bool useLegacy = false)
    {
        EnsureConnected();

        var keyType = GetKeyType(keyBlob);
        if (keyType == KeyType.Unsupported)
        {
            throw new NotSupportedException("Unsupported key type. Only RSA and ED25519 keys are supported.");
        }

        uint flags = 0;
        if (keyType == KeyType.Rsa && !useLegacy)
        {
            flags = (uint)AgentFlags.RsaSha2_256;
        }

        var command = new SshAgentMessage();
        command.WriteByte((byte)AgentCommand.SignRequest);
        command.WriteBlob(keyBlob);
        command.WriteBlob(data);
        command.WriteUInt32(flags);

        var reply = SendCommand(command);
        var replyType = (AgentReply)reply.ReadByte();

        if (replyType != AgentReply.SignResponse)
        {
            throw new InvalidDataException("Invalid reply from SSH agent");
        }

        return reply.ReadBlob();
    }

    /// <summary>
    /// Requests the agent to list available keys and tries to find one that matches the given fingerprint.
    /// </summary>
    /// <param name="keyFingerprint">A base64 encoded SHA256 fingerprint, like the ones you get from ssh-add -l</param>
    /// <returns>The public ssh key matching the fingerprint.</returns>
    /// <exception cref="KeyNotFoundException"></exception>
    public byte[] FindKeyBySha256(string? keyFingerprint)
    {
        var keys = ListKeys();

        if (string.IsNullOrEmpty(keyFingerprint))
        {
            // Return first supported key
            foreach (var (keyBlob, _) in keys)
            {
                if (GetKeyType(keyBlob) != KeyType.Unsupported)
                {
                    return keyBlob;
                }
            }
            throw new KeyNotFoundException("No supported SSH keys found in agent");
        }

        // Remove "SHA256:" prefix if present
        if (keyFingerprint.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
        {
            keyFingerprint = keyFingerprint.Substring(7);
        }

        foreach (var (keyBlob, _) in keys)
        {
            if (GetKeyType(keyBlob) != KeyType.Unsupported)
            {
                var hash = SHA256.HashData(keyBlob);
                var base64 = Convert.ToBase64String(hash).TrimEnd('=');

                if (base64.StartsWith(keyFingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    return keyBlob;
                }
            }
        }

        throw new KeyNotFoundException($"SSH key with fingerprint '{keyFingerprint}' not found in agent");
    }

    /// <summary>
    /// Requests the agent to list available keys and tries to find one that matches the expectedHash.
    /// </summary>
    /// <param name="nonce">The nonce read from the encrypted file.</param>
    /// <param name="expectedHash">The expected hash to look for. This hash was originally created by ComputeKeyHash().</param>
    /// <param name="hashEngine">The hash engine that was used when the encrypted file was written, typically SHA256.</param>
    /// <returns>A public key identifying the ssh key.</returns>
    /// <exception cref="KeyNotFoundException"></exception>
    public byte[] FindKeyByHash(byte[] nonce, byte[] expectedHash, HashAlgorithm hashEngine)
    {
        var keys = ListKeys();

        foreach (var (keyBlob, _) in keys)
        {
            if (GetKeyType(keyBlob) != KeyType.Unsupported)
            {
                var computedHash = ComputeKeyHash(keyBlob, nonce, hashEngine);
                if (expectedHash.SequenceEqual(computedHash))
                {
                    return keyBlob;
                }
            }
        }

        throw new KeyNotFoundException("SSH key matching the encrypted data not found in agent");
    }

    /// <summary>
    /// Computes a hash for a given ssh key and nonce.
    /// </summary>
    /// <param name="keyBlob">The public ssh key.</param>
    /// <param name="nonce">The random nonce</param>
    /// <param name="hash">The hash engine to use, typically SHA256.</param>
    /// <returns>The hash composed of SHA(keyblob + nonce)</returns>
    public static byte[] ComputeKeyHash(byte[] keyBlob, byte[] nonce, HashAlgorithm hash)
    {
        byte[] input = keyBlob.Concat(nonce).ToArray();
        return hash.ComputeHash(input);
    }

    /// <summary>
    /// Retrieves which cryptographic algorithm is use by a key.
    /// </summary>
    /// <param name="keyBlob">The public ssh key</param>
    /// <returns>An enum identifying the crypto algorithm of the key.</returns>
    private static KeyType GetKeyType(byte[] keyBlob)
    {
        try
        {
            var msg = new SshAgentMessage(keyBlob);
            var typeName = msg.ReadString();

            return typeName switch
            {
                "ssh-rsa" => KeyType.Rsa,
                "ssh-ed25519" => KeyType.Ed25519,
                _ => KeyType.Unsupported
            };
        }
        catch
        {
            return KeyType.Unsupported;
        }
    }

    /// <summary>
    /// Sends a command to the SSH agent.
    /// </summary>
    /// <param name="command"></param>
    /// <returns></returns>
    /// <exception cref="IOException"></exception>
    private SshAgentMessage SendCommand(SshAgentMessage command)
    {
        EnsureConnected();

        var data = command.ToArray();
        var lengthBytes = BitConverter.GetBytes((uint)data.Length);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(lengthBytes);
        }

        _stream!.Write(lengthBytes);
        _stream.Write(data);
        _stream.Flush();

        // Read response length
        var responseLengthBytes = new byte[4];
        var bytesRead = _stream.Read(responseLengthBytes);
        if (bytesRead != 4)
        {
            throw new IOException("Failed to read response length from SSH agent");
        }

        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(responseLengthBytes);
        }
        var responseLength = BitConverter.ToUInt32(responseLengthBytes, 0);

        // Read response data
        var responseData = new byte[responseLength];
        var totalBytesRead = 0;
        while (totalBytesRead < responseLength)
        {
            bytesRead = _stream.Read(responseData, totalBytesRead, (int)(responseLength - totalBytesRead));
            if (bytesRead == 0)
            {
                throw new IOException("SSH agent connection closed unexpectedly");
            }
            totalBytesRead += bytesRead;
        }

        return new SshAgentMessage(responseData);
    }

    private void EnsureConnected()
    {
        if (_stream == null)
        {
            Connect();
        }
    }

    public void Dispose()
    {
        _stream?.Dispose();
    }
}

/// <summary>
/// Helper class for building and parsing SSH agent protocol messages.
/// </summary>
internal class SshAgentMessage
{
    private readonly MemoryStream _stream;
    private readonly BinaryReader? _reader;
    private readonly BinaryWriter? _writer;

    public SshAgentMessage()
    {
        _stream = new MemoryStream();
        _writer = new BinaryWriter(_stream);
    }

    public SshAgentMessage(byte[] data)
    {
        _stream = new MemoryStream(data);
        _reader = new BinaryReader(_stream);
    }

    public void WriteByte(byte value)
    {
        _writer!.Write(value);
    }

    public void WriteUInt32(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }
        _writer!.Write(bytes);
    }

    public void WriteBlob(byte[] data)
    {
        WriteUInt32((uint)data.Length);
        _writer!.Write(data);
    }

    public void WriteString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteBlob(bytes);
    }

    public byte ReadByte()
    {
        return _reader!.ReadByte();
    }

    public uint ReadUInt32()
    {
        var bytes = _reader!.ReadBytes(4);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }
        return BitConverter.ToUInt32(bytes, 0);
    }

    public byte[] ReadBlob()
    {
        var length = ReadUInt32();
        if (length > 0x8000000)
        {
            throw new InvalidDataException("Blob size too large");
        }
        return _reader!.ReadBytes((int)length);
    }

    public string ReadString()
    {
        var bytes = ReadBlob();
        return Encoding.UTF8.GetString(bytes);
    }

    public byte[] ToArray()
    {
        return _stream.ToArray();
    }
}
