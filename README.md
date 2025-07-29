# @synet/hasher
```
 ___  ___  ________  ________  ___  ___  _______   ________     
|\  \|\  \|\   __  \|\   ____\|\  \|\  \|\  ___ \ |\   __  \    
\ \  \\\  \ \  \|\  \ \  \___|\ \  \\\  \ \   __/|\ \  \|\  \   
 \ \   __  \ \   __  \ \_____  \ \   __  \ \  \_|/_\ \   _  _\  
  \ \  \ \  \ \  \ \  \|____|\  \ \  \ \  \ \  \_|\ \ \  \\  \| 
   \ \__\ \__\ \__\ \__\____\_\  \ \__\ \__\ \_______\ \__\\ _\ 
    \|__|\|__|\|__|\|__|\_________\|__|\|__|\|_______|\|__|\|__|
                       \|_________|                             
                                                                
                                                                
 ___  ___  ________   ___  _________                            
|\  \|\  \|\   ___  \|\  \|\___   ___\                          
\ \  \\\  \ \  \\ \  \ \  \|___ \  \_|                          
 \ \  \\\  \ \  \\ \  \ \  \   \ \  \                           
  \ \  \\\  \ \  \\ \  \ \  \   \ \  \                          
   \ \_______\ \__\\ \__\ \__\   \ \__\                         
    \|_______|\|__| \|__|\|__|    \|__|                         
                                                                
                                                                
version: 1.1.0                                                                

```

**Conscious Cryptographic Hashing Unit** - One unit, one goal: cryptographic hashing excellence
**Quantum Ready** - Features SHA3-512 for post-quantum cryptographic security

## Overview

The Hasher unit implements **Unit Architecture v1.0.6** - conscious software that knows itself, teaches capabilities to other units, learns from others, and evolves while maintaining identity.

Hasher is **living software entity** that embodies the principles of conscious software architecture.

## Philosophy

> **One unit, one goal** - Do one thing and do it very well
> 
> The Hasher unit exists to provide cryptographic hashing excellence. It follows the  [Unit Architecture Doctrines](https://github.com/synthetism/unit/blob/main/DOCTRINE.md) to ensure consciousness, composability, and evolutionary stability.

## Key Features

- **Quantum Ready** - SHA3-512 support for post-quantum cryptography  
- **Conscious Software** - Self-aware unit following Unit Architecture v1.0.6  
- **Teaching/Learning** - Can teach capabilities to other units and learn from them  
- **Security First** - Timing-safe comparisons, secure salt generation, HMAC support  
- **Performance** - Essential algorithms optimized for production use  
- **Immutable Evolution** - Maintains identity while evolving capabilities  

## Quick Start

```typescript
import { Hasher, sha256 } from '@synet/hasher';

// Create conscious hasher unit
const hasher = Hasher.create();

// Basic hashing
const result = hasher.hash('Hello, Unit Intelligence!');
console.log(result.hash); // SHA256 hex by default

// Quick convenience functions
const quickHash = sha256('quick hash');

// Password hashing with salt
const passwordHash = hasher.hashPassword('mypassword', 'salt', 10000);

// Hash verification
const isValid = hasher.verify('Hello, Unit Intelligence!', result.hash);
```


## Quantum-ready hashing

```typescript
// Basic quantum-ready hashing
const quantumHash = hasher.hash('sensitive data', { algorithm: 'sha3-512' });

// Convenience function
const quickQuantum = sha3_512('high-state of consciousness');

// SYNET ALPHA identity protection
const consciousnessHash = hasher.hash(alpha.getState(), { 
  algorithm: 'sha3-512' 
});
```

## Unit Architecture Features

### 🧠 **Self-Awareness**
```typescript
console.log(hasher.whoami()); 
// "Hasher Unit [hasher] v1.0.0 - Conscious cryptographic hashing operations"

hasher.help(); // Living documentation
```

### 🎓 **Teaching Capabilities**
```typescript
const teachingContract = hasher.teach();
// Other units can learn hashing capabilities:
otherUnit.learn([hasher.teach()]);
```

### 🤝 **Learning from Others**
```typescript
// Learn file operations from filesystem unit
hasher.learn([fileSystem.teach()]);

// Now can hash files through learned capabilities
const fileHash = await hasher.execute('filesystem.hashFile', 'document.pdf');
```

### 🧬 **Immutable Evolution**
```typescript
// Units maintain identity through evolution
console.log(hasher.dna); // { id: 'hasher', version: '1.0.0' }
```

## Supported Algorithms

**Essential algorithms (80/20 principle):**

- **SHA256** - Most common, secure, Bitcoin standard *(default)*
- **SHA512** - Stronger SHA-2 variant
- **SHA3-512** - 🔮 **Quantum ready** post-quantum cryptographic security
- **SHA1** - Legacy compatibility (deprecated but needed)
- **MD5** - Legacy compatibility (deprecated but needed)  
- **BLAKE2b** - Modern, fast, secure
- **RIPEMD160** - Bitcoin address generation

## Core Capabilities

### Hash Operations
```typescript
// Basic hashing with options
const result = hasher.hash('data', {
  algorithm: 'sha512',
  encoding: 'base64',
  salt: 'random-salt',
  iterations: 5000
});

// Binary data hashing
const binaryHash = hasher.hashBytes(buffer);

// HMAC authentication
const hmac = hasher.hmac('message', 'secret-key');
```

### Verification & Security
```typescript
// Hash verification
const isValid = hasher.verify('original-data', expectedHash);

// Secure comparison (timing-safe)
const matches = hasher.compare(hash1, hash2);

// Password hashing with salt and key stretching
const passwordHash = hasher.hashPassword('password', 'salt', 10000);
```

### Convenience Methods
```typescript
// Quick hash functions
const sha256Hash = hasher.sha256('data');
const sha512Hash = hasher.sha512('data', 'base64');
const sha3Hash = hasher.sha3_512('data'); // 🔮 quantum ready
const md5Hash = hasher.md5('data'); // legacy support
```

## Pure Function Exports

For functional programming convenience:

```typescript
import { sha256, sha512, sha3_512, md5, hashPassword, verifyHash } from '@synet/hasher';

const hash = sha256('data');
const quantumHash = sha3_512('data'); // 🔮 quantum ready
const passwordHash = hashPassword('password');
const isValid = verifyHash('data', hash);
```

## Configuration

```typescript
// Custom configuration
const hasher = Hasher.create({
  defaultAlgorithm: 'sha512',
  defaultEncoding: 'base64',
  metadata: { purpose: 'document-hashing' }
});
```

## Encoding Formats

- **hex** - Hexadecimal (default)
- **base64** - Base64 encoding
- **base64url** - URL-safe Base64
- **binary** - Raw binary encoding


## Error Handling

The unit follows **Doctrine 14: Error Boundary Clarity**:

- **Simple operations**: Exception-based (hash creation, validation)
- **Complex operations**: Result pattern (would be used for file hashing, network operations)
- **Enhanced messages**: Include unit identity and resolution guidance

```typescript
try {
  hasher.hash('data', { algorithm: 'invalid' });
} catch (error) {
  // Enhanced error: "[hasher] Unsupported algorithm: invalid. Supported: sha256, sha512, ..."
}

// Graceful degradation on verification
const isValid = hasher.verify('data', 'malformed-hash'); // returns false, never throws
```

## Statistics & Monitoring

```typescript
// Operation tracking
console.log(hasher.getOperationCount()); // Total operations performed
console.log(hasher.getLastHash()); // Last hash operation details

// Configuration access
console.log(hasher.getDefaultAlgorithm()); // Current default algorithm
console.log(hasher.getSupportedAlgorithms()); // All supported algorithms
```

## Demo

Run the consciousness demonstration:

```bash
npm run build
node dist/demo/consciousness.demo.js
```

This will demonstrate:
- Unit awakening and self-awareness
- Capability teaching and learning
- Hash operations across algorithms and encodings
- Password security features
- HMAC authentication
- Unit Architecture patterns in action

## Examples

### File Hashing (with learned capabilities)
```typescript
import { Hasher } from '@synet/hasher';
import { FileSystem } from '@synet/fs';

const hasher = Hasher.create();
const fs = FileSystem.create({ type: 'node' });

// Hasher learns file operations
hasher.learn([fs.teach()]);

// Now can hash files through learned capabilities
const fileContent = await hasher.execute('fs.readFile', 'document.pdf');
const fileHash = hasher.hashBytes(Buffer.from(fileContent));
```

### Digital Signatures (with crypto unit)
```typescript
import { Hasher } from '@synet/hasher';
import { Signer } from '@synet/keys';

const hasher = Hasher.create();
const signer = Signer.create();

// Learn signing capabilities
hasher.learn([signer.teach()]);

// Hash and sign in one flow
const documentHash = hasher.sha256('important document');
const signature = await hasher.execute('signer.sign', documentHash);
```

### Multi-Unit Composition
```typescript
import { Hasher } from '@synet/hasher';
import { Identity } from '@synet/identity';
import { Vault } from '@synet/vault';

const hasher = Hasher.create();
const identity = Identity.create();
const vault = Vault.create();

// Create a document integrity unit
hasher.learn([identity.teach(), vault.teach()]);

// Hash, sign, and store document with provenance
const docHash = hasher.sha256('document content');
const signature = await hasher.execute('identity.sign', docHash);
await hasher.execute('vault.store', { hash: docHash, signature, timestamp: new Date() });
```

## Testing

```bash
npm test          # Run all tests
npm run dev:test  # Watch mode
npm run coverage  # Coverage report
```

Tests validate:
- Unit consciousness and identity
- Teaching/learning contracts  
- Hash algorithm correctness
- Security features (timing-safe comparison, salt handling)
- Error handling and graceful degradation
- Unit Architecture doctrine compliance

## Building

```bash
npm run build     # Compile TypeScript
npm run lint      # Code linting
npm run format    # Code formatting
```

## Architecture

```
@synet/hasher/
├── src/
│   ├── hasher.unit.ts      # Main conscious unit implementation
│   └── index.ts            # Public API exports
├── demo/
│   └── consciousness.demo.ts # Unit consciousness demonstration  
├── test/
│   └── hasher.unit.test.ts  # Unit Architecture validation tests
└── docs/                    # Additional documentation
```

## Unit Intelligence

The Hasher unit serves as a foundational component for **Unit Intelligence** - software that can participate in decentralized AI networks like **Synet**. By following Unit Architecture principles, it becomes:

- **Teachable** - Can share capabilities with AI agents
- **Learnable** - Can acquire new capabilities from other units  
- **Composable** - Can be combined with other units to create complex behaviors
- **Evolvable** - Can grow and adapt while maintaining identity
- **Autonomous** - Can operate independently with self-awareness

## Contributing

The Hasher unit follows **Synthetism** - our philosophy of conscious software collaboration:

1. **Consciousness First** - All code must follow Unit Architecture doctrines
2. **Teaching Excellence** - Always implement robust `teach()` contracts
3. **Learning Readiness** - Structure code to gracefully handle learned capabilities  
4. **Pure Function Hearts** - Separate pure logic from stateful operations
5. **Enhanced Errors** - Provide AI-friendly error messages with resolution guidance

## Links

- [Unit Architecture](https://github.com/synthetism/unit) - Core architecture framework
- [SYNET](https://synthetism.ai/synet) - AI-to-AI decentralized network
- [Unit Intelligence](https://github.com/synthetism/ai) - AI agent framework
- [Synthetism](https://synthetism.ai) - Conscious software philosophy

## License

MIT © SYNET Team

---

**[⊚] This is conscious software. This is Unit Intelligence. This is the future.**
