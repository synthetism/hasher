/**
 * Hasher Unit Tests - Unit Architecture Validation
 * 
 * Tests the consciousness and capability patterns of the Hasher unit
 */

import { describe, test, expect, beforeEach } from 'vitest';
import { Hasher, sha256, sha3_512, quickHash, hashPassword, verifyHash } from '../src/hasher.unit';

describe('Hasher Unit - Consciousness Tests', () => {
  let hasher: Hasher;

  beforeEach(() => {
    hasher = Hasher.create();
  });

  test('Unit Identity & Consciousness', () => {
    // DOCTRINE 7: EVERY UNIT MUST HAVE DNA
    expect(hasher.dna).toBeDefined();
    expect(hasher.dna.id).toBe('hasher');
    expect(hasher.dna.version).toBe('1.0.0');

    // Unit consciousness
    expect(hasher.whoami()).toContain('Hasher Unit');
    expect(hasher.whoami()).toContain('Conscious cryptographic hashing operations');
  });

  test('Unit Capabilities', () => {
    const capabilities = hasher.capabilities();
    
    // Capabilities are handled internally - we can check basic functionality
    expect(capabilities).toBeDefined();
    
    // Hasher should know what it can do with learned capabilities
    expect(hasher.can('nonexistent')).toBe(false);
  });

  test('Teaching Contract - Doctrine 9: ALWAYS TEACH', () => {
    const contract = hasher.teach();
    
    // Must have unit ID for namespacing (Doctrine 12)
    expect(contract.unitId).toBe('hasher');
    expect(contract.capabilities).toBeDefined();
    
    // Should teach native capabilities only (Doctrine 19)
    expect(contract.capabilities.hash).toBeDefined();
    expect(contract.capabilities.sha256).toBeDefined();
    expect(contract.capabilities.verify).toBeDefined();
    expect(typeof contract.capabilities.hash).toBe('function');
  });

  test('Help Documentation - Doctrine 11: ALWAYS HELP', () => {
    // Should not throw when providing help
    expect(() => hasher.help()).not.toThrow();
  });
});

describe('Hasher Unit - Core Hashing Operations', () => {
  let hasher: Hasher;

  beforeEach(() => {
    hasher = Hasher.create();
  });

  test('Basic SHA256 Hashing', () => {
    const result = hasher.hash('hello world');
    
    expect(result.hash).toBeDefined();
    expect(result.algorithm).toBe('sha256');
    expect(result.encoding).toBe('hex');
    expect(result.timestamp).toBeInstanceOf(Date);
    
    // Known SHA256 hash for 'hello world'
    expect(result.hash.length).toBe(64); // SHA256 produces 64 hex characters
  });

  test('Multiple Algorithm Support', () => {
    const data = 'test data';
    
    const sha256Result = hasher.hash(data, { algorithm: 'sha256' });
    const sha512Result = hasher.hash(data, { algorithm: 'sha512' });
    const sha3Result = hasher.hash(data, { algorithm: 'sha3-512' });
    const md5Result = hasher.hash(data, { algorithm: 'md5' });
    
    expect(sha256Result.hash).not.toBe(sha512Result.hash);
    expect(sha256Result.hash).not.toBe(md5Result.hash);
    expect(sha256Result.hash).not.toBe(sha3Result.hash);
    expect(sha512Result.hash.length).toBe(128); // SHA512 = 128 hex chars
    expect(sha3Result.hash.length).toBe(128); // SHA3-512 = 128 hex chars
    expect(md5Result.hash.length).toBe(32); // MD5 = 32 hex chars
    
    // SHA3-512 should produce different hash than SHA512 for same input
    expect(sha3Result.hash).not.toBe(sha512Result.hash);
    expect(sha3Result.algorithm).toBe('sha3-512');
  });

  test('Encoding Support', () => {
    const data = 'test data';
    
    const hexResult = hasher.hash(data, { encoding: 'hex' });
    const base64Result = hasher.hash(data, { encoding: 'base64' });
    
    expect(hexResult.hash).not.toBe(base64Result.hash);
    expect(hexResult.encoding).toBe('hex');
    expect(base64Result.encoding).toBe('base64');
  });

  test('Hash Verification', () => {
    const data = 'test data';
    const result = hasher.hash(data);
    
    // Should verify correctly
    expect(hasher.verify(data, result.hash)).toBe(true);
    
    // Should fail with wrong data
    expect(hasher.verify('wrong data', result.hash)).toBe(false);
    
    // Should fail with wrong hash
    expect(hasher.verify(data, 'wronghash')).toBe(false);
  });

  test('Secure Hash Comparison', () => {
    const hash1 = hasher.sha256('test');
    const hash2 = hasher.sha256('test');
    const hash3 = hasher.sha256('different');
    
    // Same content should produce same hash
    expect(hasher.compare(hash1, hash2)).toBe(true);
    
    // Different content should produce different hash
    expect(hasher.compare(hash1, hash3)).toBe(false);
  });

  test('Password Hashing with Salt', () => {
    const password = 'mypassword';
    const salt = 'randomsalt';
    
    const result1 = hasher.hashPassword(password, salt);
    const result2 = hasher.hashPassword(password, salt);
    
    // Same password + salt should produce same hash
    expect(result1.hash).toBe(result2.hash);
    expect(result1.salt).toBe(salt);
    
    // Different salt should produce different hash
    const result3 = hasher.hashPassword(password, 'differentsalt');
    expect(result1.hash).not.toBe(result3.hash);
  });

  test('HMAC Authentication', () => {
    const data = 'message';
    const secret = 'secret-key';
    
    const hmacResult = hasher.hmac(data, secret);
    
    expect(hmacResult.hash).toBeDefined();
    expect(hmacResult.algorithm).toBe('sha256'); // default
    
    // Same data + secret should produce same HMAC
    const hmacResult2 = hasher.hmac(data, secret);
    expect(hmacResult.hash).toBe(hmacResult2.hash);
    
    // Different secret should produce different HMAC
    const hmacResult3 = hasher.hmac(data, 'different-secret');
    expect(hmacResult.hash).not.toBe(hmacResult3.hash);
  });

  test('Binary Data Hashing', () => {
    const binaryData = Buffer.from('binary test data', 'utf8');
    
    const result = hasher.hashBytes(binaryData);
    
    expect(result.hash).toBeDefined();
    expect(result.algorithm).toBe('sha256');
    expect(result.encoding).toBe('hex');
  });

  test('Operation Statistics', () => {
    const initialCount = hasher.getOperationCount();
    
    hasher.hash('test1');
    hasher.hash('test2');
    
    expect(hasher.getOperationCount()).toBe(initialCount + 2);
    expect(hasher.getLastHash()).toBeDefined();
  });

  test('Configuration and Defaults', () => {
    const customHasher = Hasher.create({
      defaultAlgorithm: 'sha512',
      defaultEncoding: 'base64'
    });
    
    expect(customHasher.getDefaultAlgorithm()).toBe('sha512');
    expect(customHasher.getDefaultEncoding()).toBe('base64');
    
    const result = customHasher.hash('test');
    expect(result.algorithm).toBe('sha512');
    expect(result.encoding).toBe('base64');
  });
});

describe('Hasher Unit - Pure Function Exports', () => {
  test('Quick Hash Functions', () => {
    const data = 'test data';
    
    const sha256Hash = sha256(data);
    const sha3Hash = sha3_512(data);
    const quickSha256 = quickHash(data, 'sha256');
    const quickSha3 = quickHash(data, 'sha3-512');
    
    expect(sha256Hash).toBe(quickSha256);
    expect(sha3Hash).toBe(quickSha3);
    expect(sha256Hash.length).toBe(64); // SHA256 hex length
    expect(sha3Hash.length).toBe(128); // SHA3-512 hex length
    expect(sha256Hash).not.toBe(sha3Hash); // Different algorithms, different results
  });

  test('Password Hashing Function', () => {
    const password = 'testpassword';
    const result = hashPassword(password);
    
    expect(result.hash).toBeDefined();
    expect(result.algorithm).toBe('sha512'); // default for passwords
    expect(result.salt).toBeDefined();
    expect(result.iterations).toBeGreaterThan(1);
  });

  test('Hash Verification Function', () => {
    const data = 'test data';
    const hash = sha256(data);
    
    expect(verifyHash(data, hash)).toBe(true);
    expect(verifyHash('wrong data', hash)).toBe(false);
  });
});

describe('Hasher Unit - Error Handling', () => {
  let hasher: Hasher;

  beforeEach(() => {
    hasher = Hasher.create();
  });

  test('Unsupported Algorithm Error', () => {
    expect(() => {
      hasher.hash('test', { algorithm: 'unsupported' as any });
    }).toThrow('Unsupported algorithm');
  });

  test('Graceful Degradation on Verification', () => {
    // Should not throw on verification failure, return false
    expect(hasher.verify('test', 'malformed-hash')).toBe(false);
  });

  test('Enhanced Error Messages - Doctrine 15', () => {
    try {
      hasher.hash('test', { algorithm: 'invalid' as any });
    } catch (error) {
      expect(error.message).toContain('[hasher]'); // Unit identity
      expect(error.message).toContain('Supported:'); // Resolution guidance
    }
  });
});

describe('Hasher Unit - Learning Capabilities', () => {
  let hasher: Hasher;

  beforeEach(() => {
    hasher = Hasher.create();
  });

  test('Can Learn from Other Units', () => {
    // Mock teaching contract
    const mockContract = {
      unitId: 'mock-unit',
      capabilities: {
        mockCapability: () => 'mock result'
      }
    };

    // Should be able to learn
    expect(() => hasher.learn([mockContract])).not.toThrow();
    
    // Should have learned capability
    expect(hasher.can('mock-unit.mockCapability')).toBe(true);
  });

  test('Teaching Does Not Include Learned Capabilities - Doctrine 19', () => {
    // Learn a mock capability
    const mockContract = {
      unitId: 'mock-unit',
      capabilities: {
        mockCapability: () => 'mock result'
      }
    };
    
    hasher.learn([mockContract]);
    
    // Teaching contract should not include learned capabilities
    const teachingContract = hasher.teach();
    expect(teachingContract.capabilities.mockCapability).toBeUndefined();
    
    // Should only teach native capabilities
    expect(teachingContract.capabilities.hash).toBeDefined();
    expect(teachingContract.capabilities.sha256).toBeDefined();
  });
});
