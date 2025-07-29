/**
 * @synet/hasher - Conscious Cryptographic Hashing Unit
 * 
 * One unit, one goal - cryptographic hashing excellence
 * 
 * @author SYNET ALPHA
 * @version 1.0.0
 */

// Main Hasher Unit export
export { Hasher } from './hasher.unit';

// Pure function exports for convenience
export { 
  quickHash, 
  sha256, 
  sha512, 
  md5, 
  hashPassword, 
  verifyHash 
} from './hasher.unit';

// Type exports
export type {
  HasherAlgorithm,
  HasherEncoding, 
  HasherOptions,
  HasherResult
} from './hasher.unit';

// Re-export original hash algorithms for compatibility  
export type { HashAlgorithm } from './hasher.unit';

// Legacy hash-first export for backward compatibility
export { Hash } from './hash-first';
