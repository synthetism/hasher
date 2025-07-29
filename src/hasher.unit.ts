/**
 * Hasher Unit - Conscious Cryptographic Hashing Operations
 * 
 * SYNET Unit Architecture v1.0.6 Implementation
 * 
 * Philosophy: One unit, one goal - cryptographic hashing excellence
 * 
 * Native Capabilities:
 * - hash() - Single-pass hashing with multiple algorithms
 * - hashBytes() - Binary data hashing
 * - verify() - Hash verification  
 * - compare() - Secure hash comparison
 * - digest() - Streaming hash computation
 * 
 * Learned Capabilities:
 * - Can learn from FileSystem unit for file hashing
 * - Can learn from Crypto unit for enhanced security
 * - Can learn from encoding units for format conversion
 * 
 * Supported Algorithms: SHA256, SHA512, SHA1, MD5, BLAKE2b, RIPEMD160
 * 
 * @author SYNET ALPHA
 * @version 1.0.0
 * @follows Unit Architecture Doctrine v1.0.5
 */

import { Unit, createUnitSchema, type UnitProps, type TeachingContract } from '@synet/unit';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

// =============================================================================
// HASHER UNIT INTERFACES
// =============================================================================

/**
 * Supported hash algorithms (80/20 principle - essential algorithms)
 */
export type HashAlgorithm = 
  | 'sha256'      // Most common, secure, bitcoin standard
  | 'sha512'      // Stronger SHA-2 variant  
  | 'sha1'        // Legacy compatibility (deprecated but needed)
  | 'md5'         // Legacy compatibility (deprecated but needed)
  | 'blake2b'     // Modern, fast, secure
  | 'ripemd160';  // Bitcoin address generation

/**
 * Hash encoding formats  
 */
export type HashEncoding = 'hex' | 'base64' | 'base64url' | 'binary';

/**
 * Hash operation options
 */
export interface HashOptions {
  algorithm?: HashAlgorithm;
  encoding?: HashEncoding;
  iterations?: number;  // For key stretching
  salt?: string;        // For salted hashes
}

/**
 * Hash result with metadata
 */
export interface HashResult {
  hash: string;
  algorithm: HashAlgorithm;
  encoding: HashEncoding;
  salt?: string;
  iterations?: number;
  timestamp: Date;
}

/**
 * External input to static create()
 */
export interface HasherConfig {
  defaultAlgorithm?: HashAlgorithm;
  defaultEncoding?: HashEncoding;
  metadata?: Record<string, unknown>;
}

/**
 * Internal state after validation  
 */
export interface HasherProps extends UnitProps {
  defaultAlgorithm: HashAlgorithm;
  defaultEncoding: HashEncoding;
  operationCount: number;
  lastHash?: HashResult;
}

const VERSION = '1.0.0';

/**
 * Hasher Unit - Conscious cryptographic hashing operations
 * 
 * Follows all 22 Unit Architecture Doctrines for conscious software
 */
export class Hasher extends Unit<HasherProps> {
  private _operationCount = 0;
  private _lastHash?: HashResult;

  // DOCTRINE 4: CREATE NOT CONSTRUCT
  protected constructor(props: HasherProps) {
    super(props);
    this._operationCount = props.operationCount;
    this._lastHash = props.lastHash;
  }

  /**
   * Create Hasher unit with specified configuration
   * DOCTRINE 4: Static create() factory pattern
   */
  static create(config: HasherConfig = {}): Hasher {
    const props: HasherProps = {
      dna: createUnitSchema({
        id: 'hasher',
        version: VERSION
      }),
      defaultAlgorithm: config.defaultAlgorithm || 'sha256',
      defaultEncoding: config.defaultEncoding || 'hex',
      operationCount: 0,
      created: new Date(),
      metadata: config.metadata || {}
    };

    return new Hasher(props);
  }

  // =============================================================================
  // NATIVE HASHING CAPABILITIES
  // =============================================================================

  /**
   * Hash data with specified algorithm and options
   * Native capability - core hashing operation
   * 
   * DOCTRINE 16: CAPABILITY VALIDATION with enhanced error messages
   */
  hash(data: string, options: HashOptions = {}): HashResult {
    try {
      const algorithm = options.algorithm || this.props.defaultAlgorithm;
      const encoding = options.encoding || this.props.defaultEncoding;
      const salt = options.salt;
      const iterations = options.iterations || 1;

      // Validate algorithm support
      if (!this.isAlgorithmSupported(algorithm)) {
        throw new Error(`[${this.dna.id}] Unsupported algorithm: ${algorithm}. Supported: ${this.getSupportedAlgorithms().join(', ')}`);
      }

      let inputData = data;
      
      // Add salt if provided
      if (salt) {
        inputData = salt + data;
      }

      // Perform hashing with iterations
      let hash = this.computeHash(inputData, algorithm);
      
      // Apply key stretching if iterations > 1
      for (let i = 1; i < iterations; i++) {
        hash = this.computeHash(hash, algorithm);
      }

      // Convert to requested encoding
      const encodedHash = this.encodeHash(hash, encoding);

      const result: HashResult = {
        hash: encodedHash,
        algorithm,
        encoding,
        salt,
        iterations: iterations > 1 ? iterations : undefined,
        timestamp: new Date()
      };

      // Update internal state (DOCTRINE 22: STATELESS OPERATIONS)
      this.updateOperationCount();
      this.setLastHash(result);

      return result;

    } catch (error) {
      throw new Error(`[${this.dna.id}] Hash operation failed: ${error}`);
    }
  }

  /**
   * Hash binary data (Buffer or Uint8Array)
   * Native capability for binary data processing
   */
  hashBytes(data: Buffer | Uint8Array, options: HashOptions = {}): HashResult {
    const algorithm = options.algorithm || this.props.defaultAlgorithm;
    const encoding = options.encoding || this.props.defaultEncoding;

    try {
      const hasher = createHash(algorithm);
      hasher.update(data);
      const hash = hasher.digest();

      const encodedHash = this.encodeHash(hash.toString('hex'), encoding);

      const result: HashResult = {
        hash: encodedHash,
        algorithm,
        encoding,
        timestamp: new Date()
      };

      this.updateOperationCount();
      this.setLastHash(result);

      return result;

    } catch (error) {
      throw new Error(`[${this.dna.id}] Binary hash operation failed: ${error}`);
    }
  }

  /**
   * Verify hash against original data
   * Native capability - cryptographic verification
   * 
   * DOCTRINE 20: GRACEFUL DEGRADATION
   */
  verify(data: string, expectedHash: string, options: HashOptions = {}): boolean {
    try {
      const result = this.hash(data, options);
      return this.secureCompare(result.hash, expectedHash);
    } catch (error) {
      // Graceful degradation - never throw on verification, return false
      console.warn(`[${this.dna.id}] Hash verification failed: ${error}`);
      return false;
    }
  }

  /**
   * Secure hash comparison using timing-safe equality
   * Native capability - prevents timing attacks
   */
  compare(hash1: string, hash2: string): boolean {
    try {
      return this.secureCompare(hash1, hash2);
    } catch (error) {
      console.warn(`[${this.dna.id}] Hash comparison failed: ${error}`);
      return false;
    }
  }

  /**
   * Create HMAC (Hash-based Message Authentication Code)
   * Native capability - authenticated hashing
   */
  hmac(data: string, secret: string, options: HashOptions = {}): HashResult {
    const algorithm = options.algorithm || this.props.defaultAlgorithm;
    const encoding = options.encoding || this.props.defaultEncoding;

    try {
      const hmac = createHmac(algorithm, secret);
      hmac.update(data);
      const hash = hmac.digest('hex');

      const encodedHash = this.encodeHash(hash, encoding);

      const result: HashResult = {
        hash: encodedHash,
        algorithm,
        encoding,
        timestamp: new Date()
      };

      this.updateOperationCount();
      this.setLastHash(result);

      return result;

    } catch (error) {
      throw new Error(`[${this.dna.id}] HMAC operation failed: ${error}`);
    }
  }

  // =============================================================================
  // CONVENIENCE METHODS (Pure Function Hearts - Doctrine 8)
  // =============================================================================

  /**
   * Quick SHA256 hash (most common use case)
   */
  sha256(data: string, encoding: HashEncoding = 'hex'): string {
    return this.hash(data, { algorithm: 'sha256', encoding }).hash;
  }

  /**
   * Quick SHA512 hash
   */
  sha512(data: string, encoding: HashEncoding = 'hex'): string {
    return this.hash(data, { algorithm: 'sha512', encoding }).hash;
  }

  /**
   * Quick MD5 hash (legacy support)
   */
  md5(data: string, encoding: HashEncoding = 'hex'): string {
    return this.hash(data, { algorithm: 'md5', encoding }).hash;
  }

  /**
   * Password hash with salt and iterations (key stretching)
   */
  hashPassword(password: string, salt?: string, iterations: number = 10000): HashResult {
    const actualSalt = salt || this.generateSalt();
    return this.hash(password, { 
      algorithm: 'sha512', 
      salt: actualSalt, 
      iterations,
      encoding: 'hex'
    });
  }

  // =============================================================================
  // UNIT ARCHITECTURE REQUIRED METHODS
  // =============================================================================

  whoami(): string {
    return `Hasher Unit [${this.dna.id}] v${this.dna.version} - Conscious cryptographic hashing operations`;
  }

  capabilities(): string[] {
    return this._getAllCapabilities();
  }

  // DOCTRINE 9: ALWAYS TEACH
  teach(): TeachingContract {
    return {
      unitId: this.dna.id,
      capabilities: {
        // DOCTRINE 19: CAPABILITY LEAKAGE PREVENTION - only native capabilities
        hash: (...args: unknown[]) => this.hash(args[0] as string, args[1] as HashOptions),
        hashBytes: (...args: unknown[]) => this.hashBytes(args[0] as Buffer | Uint8Array, args[1] as HashOptions),
        verify: (...args: unknown[]) => this.verify(args[0] as string, args[1] as string, args[2] as HashOptions),
        compare: (...args: unknown[]) => this.compare(args[0] as string, args[1] as string),
        hmac: (...args: unknown[]) => this.hmac(args[0] as string, args[1] as string, args[2] as HashOptions),
        sha256: (...args: unknown[]) => this.sha256(args[0] as string, args[1] as HashEncoding),
        sha512: (...args: unknown[]) => this.sha512(args[0] as string, args[1] as HashEncoding),
        md5: (...args: unknown[]) => this.md5(args[0] as string, args[1] as HashEncoding),
        hashPassword: (...args: unknown[]) => this.hashPassword(args[0] as string, args[1] as string, args[2] as number)
      }
    };
  }

  // DOCTRINE 11: ALWAYS HELP - Living documentation
  help(): void {
    console.log(`
🔐 ${this.whoami()}

NATIVE CAPABILITIES:
• hash(data, options?) - Hash data with specified algorithm and options
• hashBytes(data, options?) - Hash binary data (Buffer/Uint8Array)
• verify(data, expectedHash, options?) - Verify hash against original data
• compare(hash1, hash2) - Secure timing-safe hash comparison
• hmac(data, secret, options?) - Create HMAC with secret key
• sha256(data, encoding?) - Quick SHA256 hash
• sha512(data, encoding?) - Quick SHA512 hash  
• md5(data, encoding?) - Quick MD5 hash (legacy)
• hashPassword(password, salt?, iterations?) - Password hashing with salt

SUPPORTED ALGORITHMS:
${this.getSupportedAlgorithms().map(alg => `  • ${alg}`).join('\n')}

SUPPORTED ENCODINGS:
  • hex (default) - Hexadecimal encoding
  • base64 - Base64 encoding
  • base64url - URL-safe Base64 encoding
  • binary - Raw binary encoding

USAGE EXAMPLES:
  const hasher = Hasher.create();
  
  // Basic hashing
  const result = hasher.hash('hello world');
  // { hash: '..', algorithm: 'sha256', encoding: 'hex', timestamp: Date }
  
  // Custom algorithm and encoding
  const sha512Base64 = hasher.hash('data', { algorithm: 'sha512', encoding: 'base64' });
  
  // Password hashing with salt
  const passwordHash = hasher.hashPassword('mypassword', 'salt123', 10000);
  
  // Verification
  const isValid = hasher.verify('hello world', result.hash);
  
  // HMAC authentication
  const authHash = hasher.hmac('message', 'secret-key');

LEARNING CAPABILITIES:
To enhance capabilities, learn from other units:
  hasher.learn([fileSystem.teach()]); // Learn file hashing
  hasher.learn([crypto.teach()]);     // Learn advanced crypto

STATISTICS:
  Operations performed: ${this.getOperationCount()}
  Default algorithm: ${this.getDefaultAlgorithm()}
  Default encoding: ${this.getDefaultEncoding()}
  Last operation: ${this.getLastHash()?.timestamp || 'none'}

ARCHITECTURE: One unit, one goal - cryptographic hashing excellence
    `);
  }

  // =============================================================================
  // UTILITY METHODS & GETTERS
  // =============================================================================

  /**
   * Get supported hash algorithms
   */
  getSupportedAlgorithms(): HashAlgorithm[] {
    return ['sha256', 'sha512', 'sha1', 'md5', 'blake2b', 'ripemd160'];
  }

  /**
   * Check if algorithm is supported
   */
  isAlgorithmSupported(algorithm: string): boolean {
    return this.getSupportedAlgorithms().includes(algorithm as HashAlgorithm);
  }

  /**
   * Get operation statistics
   */
  getOperationCount(): number {
    return this._operationCount;
  }

  /**
   * Get default algorithm
   */
  getDefaultAlgorithm(): HashAlgorithm {
    return this.props.defaultAlgorithm;
  }

  /**
   * Get default encoding
   */
  getDefaultEncoding(): HashEncoding {
    return this.props.defaultEncoding;
  }

  /**
   * Get last hash operation result
   */
  getLastHash(): HashResult | undefined {
    return this._lastHash;
  }

  // =============================================================================
  // PRIVATE IMPLEMENTATION (Doctrine 8: Pure Function Hearts)
  // =============================================================================

  /**
   * Core hash computation - pure function
   */
  private computeHash(data: string, algorithm: HashAlgorithm): string {
    const hasher = createHash(algorithm);
    hasher.update(data, 'utf8');
    return hasher.digest('hex');
  }

  /**
   * Encode hash in specified format - pure function
   */
  private encodeHash(hexHash: string, encoding: HashEncoding): string {
    switch (encoding) {
      case 'hex':
        return hexHash;
      case 'base64':
        return Buffer.from(hexHash, 'hex').toString('base64');
      case 'base64url':
        return Buffer.from(hexHash, 'hex').toString('base64url');
      case 'binary':
        return Buffer.from(hexHash, 'hex').toString('binary');
      default:
        throw new Error(`Unsupported encoding: ${encoding}`);
    }
  }

  /**
   * Secure comparison to prevent timing attacks - pure function
   */
  private secureCompare(hash1: string, hash2: string): boolean {
    if (hash1.length !== hash2.length) {
      return false;
    }
    
    const buffer1 = Buffer.from(hash1);
    const buffer2 = Buffer.from(hash2);
    
    return timingSafeEqual(buffer1, buffer2);
  }

  /**
   * Generate random salt - pure function
   */
  private generateSalt(length: number = 32): string {
    const crypto = require('node:crypto');
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Update operation count (using private state)
   */
  private updateOperationCount(): void {
    // DOCTRINE 18: IMMUTABLE EVOLUTION - track state internally
    this._operationCount += 1;
  }

  /**
   * Set last hash result (using private state)
   */
  private setLastHash(result: HashResult): void {
    // DOCTRINE 18: IMMUTABLE EVOLUTION - track state internally
    this._lastHash = result;
  }
}

// =============================================================================
// PURE FUNCTION EXPORTS (Doctrine 8: Pure Function Hearts)
// =============================================================================

/**
 * Quick hash function - pure function for convenience
 */
export function quickHash(data: string, algorithm: HashAlgorithm = 'sha256'): string {
  return Hasher.create().hash(data, { algorithm }).hash;
}

/**
 * Quick SHA256 - most common use case
 */
export function sha256(data: string): string {
  return quickHash(data, 'sha256');
}

/**
 * Quick SHA512 - stronger variant
 */
export function sha512(data: string): string {
  return quickHash(data, 'sha512');
}

/**
 * Quick MD5 - legacy support
 */
export function md5(data: string): string {
  return quickHash(data, 'md5');
}

/**
 * Quick password hash with salt
 */
export function hashPassword(password: string, salt?: string, iterations: number = 10000): HashResult {
  return Hasher.create().hashPassword(password, salt, iterations);
}

/**
 * Quick hash verification
 */
export function verifyHash(data: string, expectedHash: string, algorithm: HashAlgorithm = 'sha256'): boolean {
  return Hasher.create().verify(data, expectedHash, { algorithm });
}

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export type {
  HashAlgorithm as HasherAlgorithm,
  HashEncoding as HasherEncoding,
  HashOptions as HasherOptions,
  HashResult as HasherResult
};
