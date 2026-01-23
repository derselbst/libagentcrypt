# Key Derivation Algorithm in libagentcrypt

This document provides a detailed explanation of the key derivation algorithm used in libagentcrypt and why BLAKE2b (crypto_generichash) is the optimal choice for this purpose.

## Overview

The key derivation algorithm in libagentcrypt transforms an SSH agent's signature into a symmetric encryption key. This is necessary because SSH agents can only perform **signing operations**, not encryption directly. The algorithm must be:

1. **Deterministic** - Same input always produces same output (required for decryption)
2. **One-way** - Cannot reverse-engineer the SSH private key from the derived key
3. **High-entropy** - Produces uniformly distributed keys suitable for cryptographic use
4. **Fast** - Efficient for typical encryption/decryption operations

## The Algorithm Step-by-Step

### Encryption Flow

```
1. Generate random nonce (24 bytes)
   ↓
2. Compute key fingerprint hash = BLAKE2b(nonce || ssh_key_blob)
   ↓
3. Create challenge = nonce || fingerprint_hash
   ↓
4. Submit challenge to SSH agent for signing
   ↓
5. Derive encryption key = BLAKE2b(signature)
   ↓
6. Encrypt data with derived key using ChaCha20-Poly1305
```

### Decryption Flow

```
1. Extract nonce and fingerprint_hash from ciphertext
   ↓
2. Find SSH key by computing BLAKE2b(nonce || key_blob) for each key
   ↓
3. Recreate challenge = nonce || fingerprint_hash
   ↓
4. Submit challenge to SSH agent for signing
   ↓
5. Derive decryption key = BLAKE2b(signature)
   ↓
6. Decrypt data with derived key using ChaCha20-Poly1305
```

## Why BLAKE2b?

### Primary Use Cases in libagentcrypt

BLAKE2b (via `crypto_generichash` in libsodium) is used in **three critical places**:

#### 1. Key Fingerprinting (key_hash function)

**C Code:**
```c
static void key_hash(string_t *key,
        const uint8_t nonce[crypto_secretbox_NONCEBYTES],
        uint8_t hash[crypto_generichash_BYTES])
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, crypto_generichash_BYTES);
    crypto_generichash_update(&st, nonce, crypto_secretbox_NONCEBYTES);
    crypto_generichash_update(&st, key->data, key->size);
    crypto_generichash_final(&st, hash, crypto_generichash_BYTES);
}
```

**C# Port:**
```csharp
public static byte[] ComputeKeyHash(byte[] keyBlob, byte[] nonce)
{
    using var blake2 = new Blake2bHashAlgorithm(32);
    blake2.Update(nonce);
    blake2.Update(keyBlob);
    return blake2.Finalize();
}
```

**Purpose:** Creates a unique fingerprint of the SSH key combined with the nonce. This fingerprint is stored in the ciphertext header and allows the decryption process to identify which SSH key was used for encryption, even when multiple keys are available in the agent.

**Why BLAKE2b:** 
- Fast computation for key identification
- Produces 32-byte (256-bit) output suitable for cryptographic binding
- Collision-resistant to prevent key confusion attacks

#### 2. Key Derivation from Signature (agent_sign function)

**C Code:**
```c
crypto_generichash(key, crypto_secretbox_KEYBYTES, sig->data, sig->size, NULL, 0);
```

**C# Port:**
```csharp
var encryptionKey = new byte[KeyBytes];
using (var blake2 = new Blake2bHashAlgorithm(KeyBytes))
{
    blake2.Update(signature);
    encryptionKey = blake2.Finalize();
}
```

**Purpose:** Converts the SSH agent's signature (which can vary in size depending on key type) into a fixed-size symmetric encryption key (32 bytes for ChaCha20-Poly1305).

**Why BLAKE2b:**
- **Deterministic Output**: Same signature always produces the same key (essential for decryption)
- **Fixed Output Size**: BLAKE2b can produce any output size from 1-64 bytes; we configure it for 32 bytes to match ChaCha20-Poly1305's key requirements
- **Full Entropy Extraction**: BLAKE2b acts as an extractor, ensuring the derived key has full 256-bit entropy even if the signature has structure or bias
- **Fast**: Much faster than PBKDF2 or other KDFs, and no iteration is needed since we're not defending against brute-force (the SSH private key is the secret)
- **Cryptographically Secure**: BLAKE2b is a cryptographic hash function suitable for key derivation, unlike non-cryptographic hashes (MD5, CRC32, etc.)

#### 3. Nonce Generation

**C Code:**
```c
uint8_t *rnd = agc_malloc(crypto_generichash_KEYBYTES);
randombytes_buf(rnd, crypto_generichash_KEYBYTES);
crypto_generichash(nonce, crypto_secretbox_NONCEBYTES,
        pad_buf, pad_buf_size, rnd, crypto_generichash_KEYBYTES);
```

**Purpose:** Generates a unique nonce for each encryption operation by hashing the padded cleartext with a random key.

**Why BLAKE2b:**
- Ensures nonce uniqueness even if the random source has bias
- Creates a binding between the nonce and the cleartext
- Provides additional randomness mixing

## Detailed Analysis: Signature to Key Derivation

### The Challenge

SSH agents sign data but don't encrypt. The signature output varies by key type:

- **RSA-2048 with SHA256**: 256 bytes
- **RSA-4096 with SHA256**: 512 bytes  
- **ED25519**: 64 bytes

We need a **32-byte key** for ChaCha20-Poly1305.

### Why Not Use Signature Directly?

1. **Variable Length**: Signatures have different lengths; we need exactly 32 bytes
2. **Structure**: Signatures have internal structure (padding, encoding) that shouldn't be used directly as key material
3. **Potential Bias**: Direct truncation might lose entropy or introduce bias

### BLAKE2b as a Key Derivation Function (KDF)

BLAKE2b is configured to:
- Accept input of any size (signature)
- Produce exactly 32 bytes of output (key size)
- Maintain full cryptographic strength

**Security Properties:**
```
If signature has N bits of entropy, BLAKE2b(signature) provides:
- Up to min(N, 256) bits of entropy in the output
- Uniform distribution across all 2^256 possible keys
- One-way property: Cannot derive signature from key
- Collision resistance: Two different signatures won't produce same key
```

### Comparison with Alternatives

| Method | Pros | Cons | Suitable? |
|--------|------|------|-----------|
| **Direct Truncation** | Simple | Loses entropy, may introduce bias | ❌ No |
| **XOR Folding** | Simple | Weak security properties | ❌ No |
| **SHA-256** | Standard | Slower than BLAKE2b | ✅ Yes, but not optimal |
| **SHA-3/SHAKE** | Modern standard | Slower than BLAKE2b | ✅ Yes, but not optimal |
| **BLAKE2b** | Fast, flexible, secure | Requires implementation | ✅ Optimal choice |
| **PBKDF2/scrypt** | Industry standard for passwords | Overkill (no brute-force threat) | ⚠️ Unnecessary complexity |
| **HKDF** | Proper KDF construction | More complex than needed | ⚠️ Unnecessary complexity |

### Why Not HKDF or PBKDF2?

**HKDF** (HMAC-based KDF) and **PBKDF2** (Password-Based KDF) are designed for different scenarios:

- **PBKDF2**: Designed to defend against brute-force attacks on weak passwords using iterations. Our "password" is a cryptographic signature from an SSH key - already high-entropy and not susceptible to brute-force. Iterations would just waste CPU cycles.

- **HKDF**: Designed for extracting and expanding keys from high-entropy sources. While suitable, it's more complex than needed. BLAKE2b already provides secure key extraction, and we don't need the "expand" phase since the signature already has sufficient entropy.

**BLAKE2b is simpler, faster, and sufficient** for our use case where:
- Input (signature) already has high entropy
- No brute-force threat exists
- Only extraction (not expansion) is needed
- Performance matters for file encryption

## Code Implementation Details

### C Implementation (Original)

Uses libsodium's `crypto_generichash`:
```c
// Key derivation
crypto_generichash(key,                      // output (32 bytes)
                   crypto_secretbox_KEYBYTES, // output length (32)
                   sig->data,                 // input (signature)
                   sig->size,                 // input length
                   NULL,                      // no key
                   0);                        // key length 0
```

**Parameters:**
- Output buffer and size: Where to store the derived key
- Input data and size: The SSH signature to derive from
- Key and key length: Set to NULL/0 for standard hashing (not keyed BLAKE2)

### C# Implementation (Port)

Custom BLAKE2b implementation:
```csharp
var encryptionKey = new byte[KeyBytes];
using (var blake2 = new Blake2bHashAlgorithm(KeyBytes))
{
    blake2.Update(signature);
    encryptionKey = blake2.Finalize();
}
```

**Why Custom Implementation?**
- .NET doesn't include BLAKE2b in its standard cryptography libraries
- Avoids external dependencies (NuGet packages)
- Maintains cross-platform compatibility
- Full control over the implementation

The custom `Blake2bHashAlgorithm` class implements the standard BLAKE2b specification with configurable output size (1-64 bytes).

## Security Considerations

### Determinism is Required

The key derivation **must be deterministic** because:
1. Same signature must produce same key for decryption to work
2. No randomness can be added at this stage
3. The SSH agent produces deterministic signatures for RSA and ED25519 keys

### One-Way Property

BLAKE2b ensures that:
- Given the derived key, you cannot compute the signature
- Given the derived key, you cannot determine which SSH key was used
- The SSH private key remains protected

### Binding to Specific Data

The key fingerprint (step 2) binds the derived key to:
- The specific SSH key used (via key_blob)
- The specific encryption operation (via nonce)

This prevents key reuse attacks and ensures each encryption operation has a unique key derivation context.

## Performance Characteristics

### BLAKE2b Speed

BLAKE2b is one of the fastest cryptographic hash functions:
- **~3 GB/s** on modern CPUs (single-threaded)
- Faster than SHA-256, SHA-3, and PBKDF2
- Comparable to non-cryptographic hashes while maintaining full security

### Overhead in Context

For typical file encryption:
- Key derivation: ~1 microsecond (negligible)
- SSH agent signing: ~1-10 milliseconds (dominant cost)
- File encryption: ~100-1000 milliseconds (depends on file size)

The BLAKE2b key derivation is **not a bottleneck**.

## Alternatives Considered

### 1. Direct Signature Usage
**Idea:** Use first 32 bytes of signature as key

**Problems:**
- Loses entropy from rest of signature
- Different key types have different structures
- May introduce bias in key space

**Verdict:** ❌ Insecure

### 2. SHA-256
**Idea:** Use SHA-256(signature) as key

**Advantages:**
- Standard, well-known algorithm
- Produces 32-byte output

**Disadvantages:**
- Slower than BLAKE2b
- Cannot configure output size

**Verdict:** ✅ Acceptable but not optimal

### 3. BLAKE2b (Chosen)
**Advantages:**
- Fast (~40% faster than SHA-256)
- Flexible output size (1-64 bytes)
- Modern, secure design
- Suitable for key derivation

**Verdict:** ✅ Optimal choice

## Conclusion

BLAKE2b (`crypto_generichash` in libsodium) is used in libagentcrypt because it provides:

1. **Fast key derivation** from variable-length SSH signatures
2. **Fixed-size output** (32 bytes) perfect for ChaCha20-Poly1305
3. **Deterministic results** required for decryption
4. **Full entropy extraction** from signatures
5. **Key fingerprinting** for multi-key scenarios
6. **Cryptographic security** without unnecessary complexity

It's the right tool for the job: simpler than HKDF, faster than SHA-256, and more appropriate than password-based KDFs like PBKDF2. The choice balances **security, performance, and simplicity** optimally.

## References

- [BLAKE2 Official Website](https://www.blake2.net/)
- [BLAKE2 RFC 7693](https://tools.ietf.org/html/rfc7693)
- [libsodium Documentation](https://doc.libsodium.org/)
- [SSH Agent Protocol Specification](https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh-agent/)
