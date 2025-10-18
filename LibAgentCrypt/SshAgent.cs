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

using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace LibAgentCrypt;

internal enum AgentCommand : byte
{
    RequestIdentities = 11,
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
/// Provides communication with the SSH agent for signing operations.
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

    public byte[] FindKeyByHash(byte[] nonce, byte[] hash)
    {
        var keys = ListKeys();

        foreach (var (keyBlob, _) in keys)
        {
            if (GetKeyType(keyBlob) != KeyType.Unsupported)
            {
                var computedHash = ComputeKeyHash(keyBlob, nonce);
                if (hash.SequenceEqual(computedHash))
                {
                    return keyBlob;
                }
            }
        }

        throw new KeyNotFoundException("SSH key matching the encrypted data not found in agent");
    }

    public static byte[] ComputeKeyHash(byte[] keyBlob, byte[] nonce)
    {
        using var blake2 = new Blake2bHashAlgorithm(32);
        blake2.Update(nonce);
        blake2.Update(keyBlob);
        return blake2.Finalize();
    }

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
