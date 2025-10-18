# LibAgentCrypt - C#/.NET Port

This is a cross-platform C#/.NET port of the libagentcrypt library. It provides symmetric encryption and decryption using SSH agent keys, eliminating the need to type passwords.

## Features

- ✅ **Cross-platform**: Full support on Linux, macOS, and Windows 10+ via Unix domain sockets and named pipes
- ✅ **Modern .NET**: Built on .NET 9.0
- ✅ **No external dependencies**: Uses built-in .NET cryptography APIs
- ✅ **SSH Agent Protocol**: Full implementation of SSH agent communication
- ✅ **RSA and ED25519 support**: Works with both key types
- ✅ **File and stream encryption**: Encrypt/decrypt files of any size
- ✅ **Text mode**: Line-by-line encryption for configuration files
- ✅ **Windows named pipe support**: Native integration with Windows OpenSSH agent

## Original C Implementation

This port is based on the original C implementation by Nicola Di Lieto:
- Original repository: https://github.com/ndilieto/libagentcrypt
- Documentation: https://ndilieto.github.io/libagentcrypt

## Cryptography Changes

The C# port replaces libsodium with .NET's built-in cryptography:

| Original (libsodium) | C# Port (.NET) |
|---------------------|----------------|
| `crypto_secretbox` (XSalsa20-Poly1305) | `ChaCha20Poly1305` |
| `crypto_generichash` (BLAKE2b) | Custom BLAKE2b implementation |
| `crypto_hash_sha256` | `SHA256` |
| `crypto_secretstream` (XChaCha20-Poly1305) | `ChaCha20Poly1305` with counter |

## Building

```bash
dotnet build
```

## Installation

```bash
dotnet publish -c Release
# Binary will be in AgentCrypt/bin/Release/net9.0/publish/
```

## Usage

### Command Line Tool

The `agentcrypt` command-line tool provides the same functionality as the original C version:

```bash
# Encrypt a file
dotnet run --project AgentCrypt -- myfile.txt

# Decrypt a file
dotnet run --project AgentCrypt -- -d myfile.txt.acb

# Text mode (line-by-line)
dotnet run --project AgentCrypt -- -t myfile.txt

# Use specific SSH key
dotnet run --project AgentCrypt -- -e SHA256:abc123... myfile.txt

# Show help
dotnet run --project AgentCrypt -- -h
```

### Library API

```csharp
using LibAgentCrypt;

// Encrypt data
byte[] cleartext = Encoding.UTF8.GetBytes("Secret message");
byte[] encrypted = AgentCrypt.Encrypt(cleartext);

// Decrypt data
byte[] decrypted = AgentCrypt.Decrypt(encrypted);

// Encrypt a file
AgentCrypt.EncryptFile("input.txt", "output.acb");

// Decrypt a file
AgentCrypt.DecryptFile("output.acb", "decrypted.txt");

// Base64 encoding (for text storage)
string base64 = AgentCrypt.ToBase64(encrypted);
byte[] decoded = AgentCrypt.FromBase64(base64);
```

## Platform Support

### Linux
Full support via Unix domain sockets. Requires SSH agent to be running:
```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_rsa
```

### macOS
Full support via Unix domain sockets. Uses the built-in SSH agent.

### Windows
✅ **Full support** (Windows 10 or later) via Windows named pipes. Works with the OpenSSH authentication agent service.

To use on Windows:
1. Ensure the OpenSSH Authentication Agent service is running:
   ```powershell
   # Start the service (run PowerShell as Administrator)
   Start-Service ssh-agent
   
   # Enable automatic start on boot
   Set-Service -Name ssh-agent -StartupType Automatic
   ```
2. Add your SSH key:
   ```powershell
   ssh-add ~\.ssh\id_rsa
   ```
3. Set the `SSH_AUTH_SOCK` environment variable to the Windows named pipe:
   ```powershell
   # Set for current session
   $env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
   
   # Set permanently for current user
   [System.Environment]::SetEnvironmentVariable('SSH_AUTH_SOCK', '\\.\pipe\openssh-ssh-agent', 'User')
   ```

Note: On Windows, the library uses named pipes which automatically provide the same functionality as Unix domain sockets on Linux/macOS.

## SSH Key Types

Only RSA and ED25519 keys are supported (DSA and ECDSA produce non-deterministic signatures and cannot be used for encryption).

- **RSA**: Use keys with at least 2048 bits
- **ED25519**: Recommended for best security

## Environment Variables

- `SSH_AUTH_SOCK`: Path to SSH agent socket (required)
- `AGENTCRYPT_LEGACY`: Set to non-zero to force RSA SHA1 signatures (not recommended)

## Security

- Encrypted data includes authentication (AEAD encryption)
- Keys are derived from SSH agent signatures
- Padding hides true message length
- Memory is cleared after use where possible

## Algorithms

### Block Encryption (Encrypt/Decrypt methods)
1. Generate random nonce using HMAC-SHA256
2. Compute key fingerprint hash using BLAKE2b
3. Create challenge = nonce + hash
4. Sign challenge with SSH agent
5. Derive encryption key from signature using BLAKE2b
6. Encrypt with ChaCha20-Poly1305

### File Encryption (EncryptFile/DecryptFile methods)
1. Generate random stream key
2. Encrypt stream key using block encryption
3. Write header with encrypted key
4. Encrypt file content using ChaCha20-Poly1305 streaming

## License

Copyright (c) 2019-2022, Nicola Di Lieto <nicola.dilieto@gmail.com>  
Copyright (c) 2025, C#/.NET port by GitHub Copilot

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

## Contributing

Contributions are welcome! Please feel free to submit pull requests for:
- Additional tests
- Performance improvements
- Bug fixes

## Differences from C Version

1. **Cryptography**: Uses .NET APIs instead of libsodium
2. **Language**: C# instead of C
3. **Platform**: Fully cross-platform with native Windows named pipe support
4. **Memory Management**: Managed by .NET GC with secure clearing where appropriate
5. **Error Handling**: Uses exceptions instead of errno

## Version

This is version 2.0.0 of libagentcrypt (C# port).
