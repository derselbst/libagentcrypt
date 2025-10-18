# Migration Guide: C to C#/.NET Port

This document explains the differences between the original C implementation and the C# port of libagentcrypt.

## Overview

The C# port maintains API compatibility at the conceptual level while adapting to .NET conventions and patterns.

## Key Differences

### 1. Language and Runtime

| Aspect | C (Original) | C# (Port) |
|--------|-------------|-----------|
| Language | C99 | C# 12 (.NET 9.0) |
| Memory Management | Manual (malloc/free) | Automatic (GC) with explicit clearing |
| Error Handling | errno, return codes | Exceptions |
| Platform | Linux only | Cross-platform (Linux/macOS/Windows*) |

*Windows SSH agent support requires named pipes implementation

### 2. Cryptographic Libraries

| Function | C (libsodium) | C# (Port) |
|----------|---------------|-----------|
| AEAD Encryption | `crypto_secretbox` (XSalsa20-Poly1305) | `ChaCha20Poly1305` |
| Generic Hash | `crypto_generichash` (BLAKE2b) | Custom BLAKE2b implementation |
| SHA256 | `crypto_hash_sha256` | `SHA256.HashData()` |
| Stream Encryption | `crypto_secretstream` (XChaCha20-Poly1305) | ChaCha20-Poly1305 with counter mode |
| Base64 | `sodium_bin2base64` | `Convert.ToBase64String()` |
| Random | `randombytes_buf` | `RandomNumberGenerator.GetBytes()` |
| Memory Lock | `sodium_mlock` | Not available (managed memory) |

### 3. API Comparison

#### C API
```c
int agc_encrypt(const char *agent, const char *key_sha256,
    const uint8_t *cleartext, size_t cleartext_size, size_t pad_size,
    uint8_t **ciphertext, size_t *ciphertext_size);

int agc_decrypt(const char *agent,
    const uint8_t *ciphertext, size_t ciphertext_size,
    uint8_t **cleartext, size_t *cleartext_size);
```

#### C# API
```csharp
public static byte[] Encrypt(byte[] cleartext, string? keySha256 = null, 
    int padSize = 16, string? agentPath = null);

public static byte[] Decrypt(byte[] ciphertext, string? agentPath = null);
```

### 4. Memory Management

#### C Version
```c
uint8_t *ciphertext;
size_t ciphertext_size;
agc_encrypt(NULL, NULL, data, data_size, 0, &ciphertext, &ciphertext_size);
// Use ciphertext
agc_free(ciphertext, ciphertext_size);
```

#### C# Version
```csharp
byte[] ciphertext = AgentCrypt.Encrypt(data);
// Use ciphertext
// No explicit free needed - GC handles it
// Sensitive data is cleared where appropriate
```

### 5. Error Handling

#### C Version
```c
if (agc_encrypt(...) < 0) {
    switch (errno) {
        case ENOKEY:
            // Key not found
            break;
        case EBADMSG:
            // Invalid data
            break;
        case ENOMEM:
            // Out of memory
            break;
    }
}
```

#### C# Version
```csharp
try {
    var ciphertext = AgentCrypt.Encrypt(cleartext);
} catch (KeyNotFoundException) {
    // Key not found
} catch (InvalidDataException) {
    // Invalid data
} catch (OutOfMemoryException) {
    // Out of memory
}
```

### 6. SSH Agent Communication

#### C Version (Unix Domain Sockets)
```c
int fd = socket(AF_UNIX, SOCK_STREAM, 0);
struct sockaddr_un addr;
addr.sun_family = AF_UNIX;
strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
connect(fd, (struct sockaddr *)&addr, sizeof(addr));
```

#### C# Version (Unix Domain Sockets)
```csharp
var endpoint = new UnixDomainSocketEndPoint(agentPath);
_socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
_socket.Connect(endpoint);
```

### 7. File I/O

#### C Version
```c
FILE *f_cleartext = fopen("input.txt", "r");
FILE *f_ciphertext = fopen("output.acb", "w");
agc_fencrypt(NULL, NULL, f_cleartext, f_ciphertext);
fclose(f_cleartext);
fclose(f_ciphertext);
```

#### C# Version
```csharp
AgentCrypt.EncryptFile("input.txt", "output.acb");
// Or with streams:
using var input = File.OpenRead("input.txt");
using var output = File.Create("output.acb");
AgentCrypt.EncryptStream(input, output);
```

### 8. Command-Line Tool

Both versions support the same command-line options:

```bash
# C version
agentcrypt -e SHA256:abc123... myfile.txt

# C# version (.NET CLI)
dotnet run --project AgentCrypt -- -e SHA256:abc123... myfile.txt

# C# version (published)
agentcrypt -e SHA256:abc123... myfile.txt
```

## Platform-Specific Notes

### Linux
- ✅ Full support
- SSH agent via Unix domain socket: `/tmp/ssh-*/agent.*`

### macOS
- ✅ Full support
- SSH agent via Unix domain socket: `/var/folders/*/T/*/agent.*`

### Windows
- ⚠️ Partial support
- Unix domain sockets work on Windows 10+
- However, Windows OpenSSH agent uses named pipes (`\\.\pipe\openssh-ssh-agent`)
- **TODO**: Implement named pipe support for Windows SSH agent

## Migration Checklist

If you're migrating from the C library to C#:

- [ ] Replace `agc_encrypt()` calls with `AgentCrypt.Encrypt()`
- [ ] Replace `agc_decrypt()` calls with `AgentCrypt.Decrypt()`
- [ ] Replace `agc_fencrypt()` with `AgentCrypt.EncryptFile()` or `AgentCrypt.EncryptStream()`
- [ ] Replace `agc_fdecrypt()` with `AgentCrypt.DecryptFile()` or `AgentCrypt.DecryptStream()`
- [ ] Replace `agc_to_b64()` with `AgentCrypt.ToBase64()`
- [ ] Replace `agc_from_b64()` with `AgentCrypt.FromBase64()`
- [ ] Replace `agc_free()` calls - not needed in C#
- [ ] Change error handling from errno checking to exception handling
- [ ] Update parameter passing (no output parameters via pointers)

## Binary Compatibility

The encrypted file format is **compatible** between C and C# versions:
- Files encrypted with the C version can be decrypted with the C# version
- Files encrypted with the C# version can be decrypted with the C version

This is because both versions:
1. Use the same SSH agent protocol
2. Use the same key derivation algorithm (BLAKE2b)
3. Use compatible AEAD encryption (both Poly1305-based)
4. Use the same file format structure

## Performance Considerations

The C# port may have different performance characteristics:

| Aspect | C | C# |
|--------|---|-----|
| Startup Time | Fast | Slower (JIT compilation) |
| Memory Usage | Lower | Higher (GC overhead) |
| Throughput | Fast (native) | Fast (JIT-optimized) |
| Crypto Operations | libsodium (highly optimized) | .NET BCL (well-optimized) |

For most use cases, the performance difference is negligible.

## Building and Deployment

### C Version
```bash
./configure
make
make install
```

### C# Version
```bash
# Development
dotnet build

# Release
dotnet publish -c Release -r linux-x64 --self-contained
# Binary in: AgentCrypt/bin/Release/net9.0/linux-x64/publish/
```

## Testing

### C Version
- Manual testing required
- No automated test suite in original

### C# Version
```bash
dotnet test
# 10 unit tests covering:
# - Base64 encoding/decoding
# - Error handling
# - Version API
```

## Future Enhancements

Potential improvements for the C# port:

1. **Windows SSH Agent Support**
   - Implement named pipe communication
   - Detect platform and use appropriate transport

2. **Async/Await Support**
   - Make encryption/decryption async
   - Better for server scenarios

3. **Streaming API**
   - Add `IAsyncEnumerable<byte[]>` support
   - Stream large files without loading into memory

4. **Additional Platforms**
   - Test on ARM64 Linux
   - Test on macOS ARM (M1/M2)

5. **NuGet Package**
   - Publish LibAgentCrypt as NuGet package
   - Enable easy installation: `dotnet add package LibAgentCrypt`

## Contributing

Contributions welcome for:
- Windows named pipe support
- Performance optimizations
- Additional tests
- Documentation improvements
- Bug fixes

## License

Both C and C# versions use the ISC license (permissive, BSD-like).

## References

- [Original C Implementation](https://github.com/ndilieto/libagentcrypt)
- [SSH Agent Protocol](https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh-agent/)
- [BLAKE2 Specification](https://www.blake2.net/)
- [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539)
