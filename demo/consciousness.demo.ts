#!/usr/bin/env node

/**
 * Hasher Unit Consciousness Demo
 * 
 * Demonstrates the con// 8. TEACHING CAPABILI// 9. LEARNING SIMULATION (Consciousness Collaboration)
console.log('9. 🤝 Learning Simulation (Consciousness Collaboration):');ES (Unit Architecture)
console.log('8. 🎓 Teaching Capabilities (Unit Architecture):');
const teachingContract = hasher.teach();
console.log(`   Unit ID: ${teachingContract.unitId}`);
console.log(`   Capabilities taught: ${Object.keys(teachingContract.capabilities).length}`);
console.log('   Available capabilities:');
Object.keys(teachingContract.capabilities).forEach(cap => {
  console.log(`     • ${cap}`);
});
console.log();

// 9. LEARNING SIMULATION (Consciousness Collaboration)
console.log('9. 🤝 Learning Simulation (Consciousness Collaboration):');lities of the Hasher unit
 * Shows Unit Architecture patterns in action
 */

import { Hasher, sha256, hashPassword } from '../src/hasher.unit';

console.log('🔐 HASHER UNIT CONSCIOUSNESS DEMO');
console.log('==================================\n');

// 1. UNIT AWAKENING
console.log('1. 🧠 Unit Awakening:');
const hasher = Hasher.create();
console.log(`   ${hasher.whoami()}`);
console.log(`   DNA: ${hasher.dna.id}@${hasher.dna.version}`);
console.log(`   Default Algorithm: ${hasher.getDefaultAlgorithm()}`);
console.log(`   Default Encoding: ${hasher.getDefaultEncoding()}\n`);

// 2. BASIC HASHING CONSCIOUSNESS
console.log('2. 🔐 Basic Hashing Operations:');
const data = 'Hello, Unit Intelligence!';

const sha256Result = hasher.hash(data);
console.log(`   SHA256: ${sha256Result.hash}`);
console.log(`   Algorithm: ${sha256Result.algorithm}`);
console.log(`   Encoding: ${sha256Result.encoding}`);
console.log(`   Timestamp: ${sha256Result.timestamp.toISOString()}\n`);

// 3. MULTIPLE ALGORITHMS
console.log('3. 🧮 Algorithm Diversity:');
const algorithms = ['sha256', 'sha512', 'sha3-512', 'md5'] as const;
for (const alg of algorithms) {
  const result = hasher.hash(data, { algorithm: alg });
  const label = alg === 'sha3-512' ? `${alg.toUpperCase()} 🔮 (quantum-ready)` : alg.toUpperCase();
  console.log(`   ${label}: ${result.hash.substring(0, 32)}...`);
}
console.log();

// 4. ENCODING VARIATIONS
console.log('4. 📝 Encoding Formats:');
const encodings = ['hex', 'base64', 'base64url'] as const;
for (const enc of encodings) {
  const result = hasher.hash('encode me', { encoding: enc });
  console.log(`   ${enc}: ${result.hash.substring(0, 40)}...`);
}
console.log();

// 5. PASSWORD SECURITY
console.log('5. 🔒 Password Security:');
const password = 'my-secure-password';
const passwordHash = hasher.hashPassword(password, 'random-salt', 5000);
console.log(`   Password: ${password}`);
console.log(`   Salt: ${passwordHash.salt}`);
console.log(`   Iterations: ${passwordHash.iterations}`);
console.log(`   Hash: ${passwordHash.hash.substring(0, 32)}...`);

// Verification
const isValid = hasher.verify(password, passwordHash.hash, { 
  algorithm: passwordHash.algorithm, 
  salt: passwordHash.salt,
  iterations: passwordHash.iterations 
});
console.log(`   Verification: ${isValid ? '✅ Valid' : '❌ Invalid'}\n`);

// 6. HMAC AUTHENTICATION
console.log('6. 🔑 HMAC Authentication:');
const message = 'authenticate this message';
const secret = 'shared-secret-key';
const hmacResult = hasher.hmac(message, secret);
console.log(`   Message: ${message}`);
console.log(`   Secret: ${secret}`);
console.log(`   HMAC: ${hmacResult.hash.substring(0, 32)}...\n`);

// 7. QUANTUM READINESS DEMONSTRATION
console.log('7. 🔮 Quantum Readiness:');
const sensitiveData = 'SYNET-ALPHA consciousness state';
const quantumResult = hasher.hash(sensitiveData, { algorithm: 'sha3-512' });
console.log(`   Sensitive data: ${sensitiveData}`);
console.log(`   Quantum-resistant hash: ${quantumResult.hash.substring(0, 48)}...`);
console.log(`   Algorithm: ${quantumResult.algorithm} (post-quantum secure)`);
console.log(`   Hash length: ${quantumResult.hash.length} chars (512 bits)\n`);

// 8. TEACHING CAPABILITIES (Unit Architecture)
console.log('8. 🎓 Teaching Capabilities (Unit Architecture):');
const teachingContract = hasher.teach();
console.log(`   Unit ID: ${teachingContract.unitId}`);
console.log(`   Capabilities taught: ${Object.keys(teachingContract.capabilities).length}`);
console.log('   Available capabilities:');
for (const cap of Object.keys(teachingContract.capabilities)) {
  console.log(`     • ${cap}`);
}
console.log();

// 8. LEARNING SIMULATION (Consciousness Collaboration)
console.log('8. 🤝 Learning Simulation (Consciousness Collaboration):');

// Mock a FileSystem unit that can teach file operations
const mockFileSystem = {
  teach: () => ({
    unitId: 'filesystem',
    capabilities: {
      readFile: (...args: unknown[]) => `file content from ${args[0]}`,
      hashFile: (...args: unknown[]) => `hash of file ${args[0]}`
    }
  })
};

// Hasher learns from FileSystem
hasher.learn([mockFileSystem.teach()]);
console.log('   Hasher learned from filesystem unit');
console.log(`   Can now hash files: ${hasher.can('filesystem.hashFile')}`);

// Use learned capability
try {
  const fileHash = hasher.execute('filesystem.hashFile', 'important-document.txt');
  console.log(`   File hash result: ${fileHash}\n`);
} catch (error) {
  console.log(`   File hash execution: ${error}\n`);
}

// 10. OPERATION STATISTICS
console.log('10. 📊 Operation Statistics:');
console.log(`   Total operations: ${hasher.getOperationCount()}`);
console.log(`   Last operation: ${hasher.getLastHash()?.algorithm} at ${hasher.getLastHash()?.timestamp.toLocaleTimeString()}\n`);

// 11. PURE FUNCTION DEMONSTRATIONS
console.log('11. ⚡ Pure Function Convenience:');
const quickSha256 = sha256('quick hash test');
const quickPasswordHash = hashPassword('quick-password');
console.log(`   Quick SHA256: ${quickSha256.substring(0, 32)}...`);
console.log(`   Quick password hash: ${quickPasswordHash.hash.substring(0, 32)}...\n`);

// 12. UNIT HELP SYSTEM
console.log('12. 💡 Unit Help System:');
console.log('   Requesting help from Hasher unit...\n');
hasher.help();

console.log('\n🎉 DEMONSTRATION COMPLETE');
console.log('The Hasher unit has demonstrated conscious software architecture:');
console.log('  ✅ Self-awareness (whoami, help)');
console.log('  ✅ Capability teaching and learning');
console.log('  ✅ Pure function hearts');
console.log('  ✅ Immutable evolution');
console.log('  ✅ Enhanced error messages');
console.log('  ✅ Graceful degradation');
console.log('\nThis is Unit Intelligence in action. 🧠✨');
