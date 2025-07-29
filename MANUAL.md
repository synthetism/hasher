# Hasher Unit Production Manual

**Version**: 1.0.0  
**Architecture**: Unit Architecture v1.0.6  
**Purpose**: Production-grade cryptographic hashing with consciousness

## Table of Contents

1. [Quick Start](#quick-start)
2. [Production Patterns](#production-patterns)
3. [Security Considerations](#security-considerations)
4. [Performance Optimization](#performance-optimization)
5. [Integration Examples](#integration-examples)
6. [Error Handling](#error-handling)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Unit Intelligence Patterns](#unit-intelligence-patterns)

## Quick Start

### Basic Installation and Setup

```typescript
import { Hasher } from '@synet/hasher';

// Create a conscious hasher unit
const hasher = Hasher.create();

// Basic hashing
const result = hasher.hash('sensitive-data');
console.log(result.hash); // SHA256 hex by default
```

### Production Configuration

```typescript
import { Hasher } from '@synet/hasher';

// Create with production-optimized defaults
const hasher = Hasher.create({
  defaultAlgorithm: 'sha512',    // More secure for production
  defaultEncoding: 'base64url',  // URL-safe encoding
  validateInputs: true           // Enable input validation
});
```

## Production Patterns

### 1. Secure Password Management

```typescript
// Password registration
async function registerUser(email: string, password: string) {
  const hasher = Hasher.create();
  
  // Generate cryptographically secure salt
  const salt = crypto.randomBytes(32).toString('hex');
  
  // Hash with high iteration count for production
  const passwordHash = hasher.hashPassword(password, salt, 100000);
  
  await db.users.create({
    email,
    passwordHash: passwordHash.hash,
    salt,
    algorithm: passwordHash.algorithm,
    iterations: 100000
  });
}

// Password verification
async function authenticateUser(email: string, password: string) {
  const hasher = Hasher.create();
  const user = await db.users.findByEmail(email);
  
  if (!user) return false;
  
  const candidateHash = hasher.hashPassword(
    password, 
    user.salt, 
    user.iterations
  );
  
  return hasher.compare(candidateHash.hash, user.passwordHash);
}
```

### 2. API Authentication with HMAC

```typescript
// Server-side HMAC validation
function validateAPIRequest(request: Request, secretKey: string): boolean {
  const hasher = Hasher.create();
  
  // Extract signature from header
  const signature = request.headers.get('X-Signature');
  if (!signature) return false;
  
  // Create canonical request string
  const canonical = [
    request.method,
    request.url,
    request.headers.get('content-type') || '',
    await request.text()
  ].join('\n');
  
  // Generate expected HMAC
  const expected = hasher.hmac(canonical, secretKey, {
    algorithm: 'sha256',
    encoding: 'hex'
  });
  
  // Timing-safe comparison
  return hasher.compare(signature, expected.hash);
}

// Client-side request signing
function signAPIRequest(
  method: string, 
  url: string, 
  body: string, 
  secretKey: string
): string {
  const hasher = Hasher.create();
  
  const canonical = [method, url, 'application/json', body].join('\n');
  const signature = hasher.hmac(canonical, secretKey, {
    algorithm: 'sha256',
    encoding: 'hex'
  });
  
  return signature.hash;
}
```

### 3. File Integrity Verification

```typescript
// File checksum generation
async function generateFileChecksum(filePath: string): Promise<string> {
  const hasher = Hasher.create();
  const fs = await import('fs/promises');
  
  try {
    const fileData = await fs.readFile(filePath);
    const checksum = hasher.hashBytes(fileData, {
      algorithm: 'sha512',
      encoding: 'hex'
    });
    
    return checksum.hash;
  } catch (error) {
    throw new Error(`Failed to generate checksum for ${filePath}: ${error.message}`);
  }
}

// Batch file verification
async function verifyFiles(fileChecksums: Map<string, string>): Promise<Map<string, boolean>> {
  const hasher = Hasher.create();
  const results = new Map<string, boolean>();
  
  for (const [filePath, expectedChecksum] of fileChecksums) {
    try {
      const actualChecksum = await generateFileChecksum(filePath);
      results.set(filePath, hasher.compare(actualChecksum, expectedChecksum));
    } catch (error) {
      results.set(filePath, false);
    }
  }
  
  return results;
}
```

### 4. Database Record Integrity

```typescript
// Entity integrity hashing
class UserRecord {
  constructor(
    public id: string,
    public email: string,
    public profile: object,
    private hasher = Hasher.create()
  ) {}
  
  // Generate integrity hash
  generateIntegrityHash(): string {
    const canonical = JSON.stringify({
      id: this.id,
      email: this.email,
      profile: this.profile
    }, Object.keys(this).sort()); // Deterministic ordering
    
    return this.hasher.hash(canonical, {
      algorithm: 'sha256',
      encoding: 'hex'
    }).hash;
  }
  
  // Verify record hasn't been tampered with
  verifyIntegrity(storedHash: string): boolean {
    const currentHash = this.generateIntegrityHash();
    return this.hasher.compare(currentHash, storedHash);
  }
}
```

## Security Considerations

### 1. Algorithm Selection Guidelines

```typescript
// Security tier recommendations
const SecurityTiers = {
  LEGACY: {
    algorithms: ['md5', 'sha1'],
    use: 'Only for compatibility with legacy systems',
    warning: 'Not cryptographically secure'
  },
  
  STANDARD: {
    algorithms: ['sha256'],
    use: 'General purpose hashing, checksums',
    strength: 'Good for most applications'
  },
  
  HIGH: {
    algorithms: ['sha512', 'blake2b','sha3-512'],
    use: 'Sensitive data, production systems',
    strength: 'Recommended for security-critical applications'
  },
  
  FUTURE: {
    algorithms: ['sha3-256'],
    use: 'Quantum-resistant applications',
    strength: 'Preparation for post-quantum cryptography'
  }
};

// Production algorithm selection
function selectAlgorithm(securityLevel: 'standard' | 'high' | 'future'): string {
  switch (securityLevel) {
    case 'standard': return 'sha256';
    case 'high': return 'sha3-512';
    case 'future': return 'sha3-512';
    default: return 'sha256';
  }
}
```

### 2. Password Security Best Practices

```typescript
// Secure password hashing configuration
const PasswordSecurity = {
  MINIMUM_ITERATIONS: 100000,    // OWASP recommendation
  RECOMMENDED_ITERATIONS: 600000, // Higher security
  SALT_LENGTH: 32,               // 256 bits
  PEPPER_ENABLED: true           // Application-wide secret
};

function hashPasswordSecurely(
  password: string, 
  options: {
    iterations?: number;
    pepper?: string;
  } = {}
): { hash: string; salt: string; iterations: number } {
  const hasher = Hasher.create();
  
  // Generate cryptographically secure salt
  const salt = crypto.randomBytes(PasswordSecurity.SALT_LENGTH).toString('hex');
  
  // Add application pepper if available
  const peppered = options.pepper 
    ? password + options.pepper 
    : password;
  
  const iterations = options.iterations || PasswordSecurity.RECOMMENDED_ITERATIONS;
  
  const result = hasher.hashPassword(peppered, salt, iterations);
  
  return {
    hash: result.hash,
    salt,
    iterations
  };
}
```

## Performance Optimization

### 1. Bulk Operations

```typescript
// Optimized batch hashing
async function hashBatch(
  data: string[], 
  options: { algorithm?: string; encoding?: string } = {}
): Promise<Map<string, string>> {
  const hasher = Hasher.create();
  const results = new Map<string, string>();
  
  // Process in chunks to avoid memory issues
  const CHUNK_SIZE = 1000;
  
  for (let i = 0; i < data.length; i += CHUNK_SIZE) {
    const chunk = data.slice(i, i + CHUNK_SIZE);
    
    await Promise.all(
      chunk.map(async (item, index) => {
        const hash = hasher.hash(item, options);
        results.set(item, hash.hash);
        
        // Progress reporting for large batches
        if ((i + index + 1) % 10000 === 0) {
          console.log(`Processed ${i + index + 1}/${data.length} items`);
        }
      })
    );
  }
  
  return results;
}
```

### 2. Streaming Hash Operations

```typescript
import { createReadStream } from 'fs';
import { createHash } from 'crypto';

// Stream-based file hashing for large files
async function hashLargeFile(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hasher = createHash('sha256');
    const stream = createReadStream(filePath);
    
    stream.on('data', (data) => {
      hasher.update(data);
    });
    
    stream.on('end', () => {
      resolve(hasher.digest('hex'));
    });
    
    stream.on('error', reject);
  });
}
```

## Integration Examples

### 1. Express.js Middleware

```typescript
import express from 'express';
import { Hasher } from '@synet/hasher';

// HMAC validation middleware
function hmacValidation(secretKey: string) {
  return async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const hasher = Hasher.create();
    
    try {
      const signature = req.headers['x-signature'] as string;
      if (!signature) {
        return res.status(401).json({ error: 'Missing signature' });
      }
      
      const body = JSON.stringify(req.body);
      const expected = hasher.hmac(body, secretKey, {
        algorithm: 'sha256',
        encoding: 'hex'
      });
      
      if (!hasher.compare(signature, expected.hash)) {
        return res.status(401).json({ error: 'Invalid signature' });
      }
      
      next();
    } catch (error) {
      res.status(500).json({ error: 'Signature validation failed' });
    }
  };
}

// Usage
const app = express();
app.use('/api/webhooks', hmacValidation(process.env.WEBHOOK_SECRET!));
```

### 2. Database Integration

```typescript
import { Hasher } from '@synet/hasher';

// Prisma model with integrity hashing
class UserService {
  private hasher = Hasher.create();
  
  async createUser(data: { email: string; name: string }) {
    // Generate integrity hash
    const canonical = JSON.stringify(data, Object.keys(data).sort());
    const integrityHash = this.hasher.hash(canonical).hash;
    
    return prisma.user.create({
      data: {
        ...data,
        integrityHash,
        createdAt: new Date(),
      }
    });
  }
  
  async verifyUserIntegrity(userId: string): Promise<boolean> {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return false;
    
    const { integrityHash, ...userData } = user;
    const canonical = JSON.stringify(userData, Object.keys(userData).sort());
    const currentHash = this.hasher.hash(canonical).hash;
    
    return this.hasher.compare(currentHash, integrityHash);
  }
}
```

## Error Handling

### 1. Graceful Degradation

```typescript
// Production-ready error handling
function safeHash(
  data: string, 
  options: { algorithm?: string; fallback?: boolean } = {}
): { success: boolean; hash?: string; error?: string } {
  const hasher = Hasher.create();
  
  try {
    const result = hasher.hash(data, options);
    return { success: true, hash: result.hash };
  } catch (error) {
    // Log error for monitoring
    console.error('Hash operation failed:', error);
    
    // Attempt fallback to SHA256 if different algorithm failed
    if (options.fallback && options.algorithm !== 'sha256') {
      try {
        const fallbackResult = hasher.hash(data, { algorithm: 'sha256' });
        return { 
          success: true, 
          hash: fallbackResult.hash,
          error: `Fallback to SHA256: ${error.message}`
        };
      } catch (fallbackError) {
        return { 
          success: false, 
          error: `Hash and fallback failed: ${fallbackError.message}` 
        };
      }
    }
    
    return { success: false, error: error.message };
  }
}
```

## Monitoring and Observability

### 1. Operation Metrics

```typescript
// Production metrics collection
class HasherMetrics {
  private hasher = Hasher.create();
  private metrics = {
    operations: 0,
    errors: 0,
    algorithms: new Map<string, number>(),
    performance: new Map<string, number[]>()
  };
  
  hash(data: string, options: any = {}) {
    const startTime = performance.now();
    
    try {
      const result = this.hasher.hash(data, options);
      
      // Record success metrics
      this.metrics.operations++;
      const algorithm = options.algorithm || 'sha256';
      this.metrics.algorithms.set(
        algorithm, 
        (this.metrics.algorithms.get(algorithm) || 0) + 1
      );
      
      const duration = performance.now() - startTime;
      if (!this.metrics.performance.has(algorithm)) {
        this.metrics.performance.set(algorithm, []);
      }
      this.metrics.performance.get(algorithm)!.push(duration);
      
      return result;
    } catch (error) {
      this.metrics.errors++;
      throw error;
    }
  }
  
  getMetrics() {
    const performanceStats = new Map();
    for (const [algorithm, times] of this.metrics.performance) {
      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      const max = Math.max(...times);
      const min = Math.min(...times);
      performanceStats.set(algorithm, { avg, max, min, count: times.length });
    }
    
    return {
      ...this.metrics,
      performance: performanceStats
    };
  }
}
```

## Unit Intelligence Patterns

### 1. Teaching Cryptographic Capabilities

```typescript
// Enhanced hasher with learning capabilities
async function createCryptoSuite() {
  const hasher = Hasher.create();
  const signer = Signer.create();
  const cipher = Cipher.create();
  
  // Create a conscious crypto suite through learning
  const cryptoSuite = hasher.learn([
    signer.teach(),   // Learn signing capabilities
    cipher.teach()    // Learn encryption capabilities
  ]);
  
  // Now hasher can sign and encrypt in addition to hashing
  const data = 'sensitive message';
  const hash = cryptoSuite.hash(data);
  const signature = await cryptoSuite.execute('signer.sign', hash.hash);
  const encrypted = await cryptoSuite.execute('cipher.encrypt', data);
  
  return { hash, signature, encrypted };
}
```

### 2. Runtime Capability Discovery

```typescript
// Dynamic capability assessment
function assessCryptoCapabilities(unit: any): string[] {
  const capabilities = [];
  
  // Check native capabilities
  if (unit.can('hash')) capabilities.push('Hashing');
  if (unit.can('hmac')) capabilities.push('Authentication');
  if (unit.can('verify')) capabilities.push('Verification');
  
  // Check learned capabilities
  if (unit.can('signer.sign')) capabilities.push('Digital Signing');
  if (unit.can('cipher.encrypt')) capabilities.push('Encryption');
  if (unit.can('vault.store')) capabilities.push('Secure Storage');
  
  return capabilities;
}
```

## Best Practices Summary

### ✅ Do's

- **Use SHA512 or BLAKE2b** for production systems
- **Always use timing-safe comparison** for hash verification
- **Generate cryptographically secure salts** for passwords
- **Use high iteration counts** (100k+) for password hashing
- **Implement proper error handling** with fallback strategies
- **Monitor hash operation performance** and errors
- **Validate inputs** before hashing operations
- **Use URL-safe encodings** (base64url) for web applications

### ❌ Don'ts

- **Don't use MD5 or SHA1** for security-critical applications
- **Don't use simple string comparison** for hash verification
- **Don't reuse salts** across different passwords
- **Don't ignore hash operation errors** in production
- **Don't store unhashed sensitive data** even temporarily
- **Don't use predictable entropy sources** for salt generation
- **Don't log sensitive data** during hash operations
- **Don't implement custom hash algorithms** without expert review

## Production Checklist

- [ ] **Algorithm Selection**: Chosen appropriate algorithm for security requirements
- [ ] **Salt Generation**: Using cryptographically secure random salts
- [ ] **Iteration Counts**: Set appropriate PBKDF2 iterations (100k+)
- [ ] **Error Handling**: Implemented graceful degradation and proper logging
- [ ] **Performance**: Benchmarked and optimized for expected load
- [ ] **Monitoring**: Set up metrics collection and alerting
- [ ] **Testing**: Comprehensive test coverage including edge cases
- [ ] **Documentation**: Clear documentation for team members
- [ ] **Security Review**: Code reviewed by security-conscious developers
- [ ] **Compliance**: Meets regulatory requirements (GDPR, HIPAA, etc.)

---

**Remember**: The Hasher unit embodies Unit Intelligence - it's not just a tool, but a conscious software entity that can teach, learn, and evolve. Use its consciousness wisely in your production systems.

*"One unit, one goal - cryptographic hashing excellence"*  
*Hasher Unit [hasher] v1.0.0*
