/*
 * Blake2b hash algorithm implementation for .NET
 * Based on the BLAKE2 specification: https://www.blake2.net/
 */

using System.Security.Cryptography;

namespace LibAgentCrypt;

/// <summary>
/// BLAKE2b cryptographic hash algorithm implementation.
/// </summary>
internal class Blake2bHashAlgorithm : IDisposable
{
    private static readonly ulong[] IV =
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    private static readonly byte[,] Sigma =
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };

    private readonly ulong[] _h = new ulong[8];
    private readonly ulong[] _t = new ulong[2];
    private readonly ulong[] _f = new ulong[2];
    private readonly byte[] _buffer = new byte[128];
    private int _bufferLength;
    private readonly int _hashSize;
    private readonly byte[]? _key;

    public Blake2bHashAlgorithm(int hashSize = 32, byte[]? key = null)
    {
        if (hashSize <= 0 || hashSize > 64)
            throw new ArgumentException("Hash size must be between 1 and 64 bytes", nameof(hashSize));
        if (key != null && key.Length > 64)
            throw new ArgumentException("Key size must be between 0 and 64 bytes", nameof(key));

        _hashSize = hashSize;
        _key = key;
        Initialize();
    }

    private void Initialize()
    {
        Array.Copy(IV, _h, 8);
        _h[0] ^= 0x01010000UL ^ ((ulong)(_key?.Length ?? 0) << 8) ^ (ulong)_hashSize;
        _t[0] = _t[1] = 0;
        _f[0] = _f[1] = 0;
        _bufferLength = 0;
        
        // If a key is provided, process it as the first block
        if (_key != null && _key.Length > 0)
        {
            var keyBlock = new byte[128];
            Array.Copy(_key, keyBlock, _key.Length);
            Update(keyBlock, 0, 128);
            Array.Clear(keyBlock, 0, 128);
        }
    }

    public void Update(byte[] data)
    {
        Update(data, 0, data.Length);
    }

    public void Update(byte[] data, int offset, int count)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (offset < 0 || count < 0 || offset + count > data.Length)
            throw new ArgumentException("Invalid offset or count");

        int dataPos = offset;
        int remaining = count;

        while (remaining > 0)
        {
            int toCopy = Math.Min(remaining, 128 - _bufferLength);
            Array.Copy(data, dataPos, _buffer, _bufferLength, toCopy);
            _bufferLength += toCopy;
            dataPos += toCopy;
            remaining -= toCopy;

            if (_bufferLength == 128)
            {
                IncrementCounter(128);
                Compress(_buffer, 0);
                _bufferLength = 0;
            }
        }
    }

    public byte[] Finalize()
    {
        IncrementCounter((ulong)_bufferLength);
        _f[0] = 0xFFFFFFFFFFFFFFFFUL;

        // Pad remaining buffer with zeros
        for (int i = _bufferLength; i < 128; i++)
        {
            _buffer[i] = 0;
        }

        Compress(_buffer, 0);

        // Extract hash
        var hash = new byte[_hashSize];
        for (int i = 0; i < _hashSize; i++)
        {
            hash[i] = (byte)(_h[i >> 3] >> (8 * (i & 7)));
        }

        return hash;
    }

    private void IncrementCounter(ulong increment)
    {
        _t[0] += increment;
        if (_t[0] < increment)
        {
            _t[1]++;
        }
    }

    private void Compress(byte[] block, int offset)
    {
        ulong[] v = new ulong[16];
        ulong[] m = new ulong[16];

        // Initialize work vector
        for (int i = 0; i < 8; i++)
        {
            v[i] = _h[i];
            v[i + 8] = IV[i];
        }

        v[12] ^= _t[0];
        v[13] ^= _t[1];
        v[14] ^= _f[0];
        v[15] ^= _f[1];

        // Parse message block
        for (int i = 0; i < 16; i++)
        {
            m[i] = BitConverter.ToUInt64(block, offset + i * 8);
        }

        // 12 rounds of mixing
        for (int round = 0; round < 12; round++)
        {
            // Column mixing
            G(v, m, round, 0, 4, 8, 12, 0);
            G(v, m, round, 1, 5, 9, 13, 2);
            G(v, m, round, 2, 6, 10, 14, 4);
            G(v, m, round, 3, 7, 11, 15, 6);

            // Diagonal mixing
            G(v, m, round, 0, 5, 10, 15, 8);
            G(v, m, round, 1, 6, 11, 12, 10);
            G(v, m, round, 2, 7, 8, 13, 12);
            G(v, m, round, 3, 4, 9, 14, 14);
        }

        // Update hash state
        for (int i = 0; i < 8; i++)
        {
            _h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void G(ulong[] v, ulong[] m, int round, int a, int b, int c, int d, int msgIdx)
    {
        int x = Sigma[round, msgIdx];
        int y = Sigma[round, msgIdx + 1];

        v[a] = v[a] + v[b] + m[x];
        v[d] = RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + m[y];
        v[d] = RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 63);
    }

    private static ulong RotateRight(ulong value, int bits)
    {
        return (value >> bits) | (value << (64 - bits));
    }

    public void Dispose()
    {
        Array.Clear(_h, 0, _h.Length);
        Array.Clear(_buffer, 0, _buffer.Length);
    }
}
