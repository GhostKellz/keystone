# Keystone Examples

This directory contains practical examples demonstrating the capabilities of Keystone v0.2.3 RC1 with zledger v0.5.0 integration.

## Examples Overview

### 1. [Basic Usage](basic_usage.zig) 📚

**What it demonstrates:**
- Setting up a Keystone node with lazy loading
- Creating accounts with different types
- Basic gas management with EIP-1559 pricing
- Generating audit reports

**Key concepts:**
- Node initialization and configuration
- Account creation and management
- Gas ledger operations
- Audit trail generation

**Run:**
```bash
zig build run-example -- basic_usage
```

### 2. [Smart Contracts](smart_contracts.zig) 🤖

**What it demonstrates:**
- Deploying smart contracts with encrypted storage
- Contract method execution and balance updates
- Encrypted data storage and retrieval
- Multi-contract interactions (ERC-20 + DeFi pool)

**Key concepts:**
- Contract deployment and account creation
- AES-256 encrypted contract storage
- Balance management and state updates
- Gas costs for contract operations

**Run:**
```bash
zig build run-example -- smart_contracts
```

### 3. [Distributed Synchronization](distributed_sync.zig) 🔄

**What it demonstrates:**
- Multi-node setup and peer relationships
- Journal synchronization across nodes
- Consensus mechanisms and validation
- Failure recovery scenarios

**Key concepts:**
- Distributed ledger architecture
- Peer-to-peer synchronization
- Journal entry validation
- Consensus algorithms (2/3 majority)

**Run:**
```bash
zig build run-example -- distributed_sync
```

### 4. [Cryptographic Operations](crypto_operations.zig) 🔐

**What it demonstrates:**
- AES-256 encryption and decryption
- Ed25519 digital signatures
- Key derivation and management
- Multi-signature workflows

**Key concepts:**
- Symmetric and asymmetric cryptography
- Key rotation and security best practices
- Performance benchmarking
- Secure data storage

**Run:**
```bash
zig build run-example -- crypto_operations
```

## Building and Running Examples

### Prerequisites

Ensure you have Zig 0.16.0 or later installed and all dependencies are fetched:

```bash
zig build --fetch
```

### Running Individual Examples

```bash
# Basic usage example
zig run examples/basic_usage.zig

# Smart contracts example
zig run examples/smart_contracts.zig

# Distributed sync example
zig run examples/distributed_sync.zig

# Crypto operations example
zig run examples/crypto_operations.zig
```

### Running Tests

Each example includes comprehensive tests:

```bash
# Test all examples
zig test examples/basic_usage.zig
zig test examples/smart_contracts.zig
zig test examples/distributed_sync.zig
zig test examples/crypto_operations.zig

# Run all tests at once
zig build test
```

## Example-Specific Configuration

### Memory Requirements

- **Basic Usage**: ~1MB RAM
- **Smart Contracts**: ~2MB RAM (due to encryption operations)
- **Distributed Sync**: ~3MB RAM (multiple nodes)
- **Crypto Operations**: ~1MB RAM

### Performance Expectations

On a modern system, examples should complete within:

- **Basic Usage**: < 1 second
- **Smart Contracts**: 1-2 seconds
- **Distributed Sync**: 2-3 seconds
- **Crypto Operations**: 3-5 seconds (includes benchmarks)

### Logging Configuration

Control logging verbosity with environment variables:

```bash
# Debug level (most verbose)
KEYSTONE_LOG_LEVEL=debug zig run examples/basic_usage.zig

# Info level (default)
KEYSTONE_LOG_LEVEL=info zig run examples/smart_contracts.zig

# Error level only
KEYSTONE_LOG_LEVEL=error zig run examples/crypto_operations.zig
```

## Understanding the Output

### Success Indicators

Look for these symbols in the output:
- ✅ - Operation completed successfully
- 📊 - Statistics or metrics
- 🔐 - Cryptographic operation
- 💰 - Financial/transaction operation
- 🔄 - Synchronization operation

### Error Indicators

- ❌ - Operation failed
- ⚠️ - Warning or potential issue
- 🛠️ - Recovery or repair operation

## Integration Patterns

### Pattern 1: Lazy Loading (All Examples)

```zig
// Configuration with lazy loading
const config = zledger_integration.NodeConfig{
    .node_id = "my-node",
    .lazy_load = true, // Components loaded on-demand
};

var node = try KeystoneNode.init(allocator, config);
```

### Pattern 2: Feature Flags (Smart Contracts, Crypto)

```zig
const config = zledger_integration.NodeConfig{
    .enable_contracts = true,     // Enable smart contracts
    .enable_crypto_storage = true, // Enable encrypted storage
    .enable_audit = true,         // Enable audit logging
};
```

### Pattern 3: Multi-Node Coordination (Distributed Sync)

```zig
// Set up peer relationships
const sync_manager = try node.getSyncManager();
try sync_manager.addPeer("peer-node-id");

// Synchronize with peers
try sync_manager.syncWithPeers();
```

### Pattern 4: Secure Operations (Crypto Operations)

```zig
// Always use proper key derivation
var derived_key: [32]u8 = undefined;
try deriveKey(&master_key, context, &derived_key);

// Clear sensitive data after use
defer std.crypto.utils.secureZero(u8, &derived_key);
```

## Common Issues and Solutions

### Issue: "LedgerNotInitialized" Error

**Solution**: Ensure `ensureLedgerInitialized()` is called:
```zig
try keystone_node.ensureLedgerInitialized();
```

### Issue: Memory Allocation Errors

**Solution**: Use ArenaAllocator for temporary operations:
```zig
var arena = std.heap.ArenaAllocator.init(parent_allocator);
defer arena.deinit();
const temp_allocator = arena.allocator();
```

### Issue: Signature Verification Failures

**Solution**: Check key formats and ensure proper byte ordering:
```zig
const is_valid = try zcrypto.ed25519.verify(
    keypair.public_key,  // Correct public key
    message_bytes,       // Original message
    signature.bytes      // Signature bytes
);
```

### Issue: Encryption/Decryption Errors

**Solution**: Verify key derivation and storage:
```zig
// Use consistent key derivation
var key: [32]u8 = undefined;
try deriveKey(&master_key, context, &key);

// Store context with encrypted data
const metadata = EncryptionMetadata{
    .context = context,
    .algorithm = "AES-256-GCM",
};
```

## Performance Tuning

### 1. Enable Lazy Loading

Always enable lazy loading for better resource utilization:
```zig
const config = NodeConfig{
    .lazy_load = true,  // Essential for performance
};
```

### 2. Batch Operations

Group related operations for better performance:
```zig
// Bad: Multiple individual operations
for (transactions) |tx| {
    try processTransaction(tx);
}

// Good: Batch processing
try processBatchTransactions(transactions);
```

### 3. Reuse Components

Cache frequently used components:
```zig
// Cache gas ledger for repeated use
const gas_ledger = try node.getGasLedger();
for (accounts) |account| {
    try gas_ledger.chargeGas(account, gas_used, base_fee, priority_fee);
}
```

## Security Considerations

### 1. Key Management

- Never log private keys
- Clear sensitive data from memory after use
- Use proper key derivation functions
- Implement key rotation where appropriate

### 2. Input Validation

- Validate all transaction parameters
- Check account permissions before operations
- Verify signatures before processing
- Sanitize all user inputs

### 3. Error Handling

- Don't leak sensitive information in error messages
- Handle all possible error conditions
- Implement proper recovery mechanisms
- Log security-relevant events

## Next Steps

After running these examples:

1. **Read the [Integration Guide](../docs/integration.md)** for production use
2. **Review the [CLI Reference](../docs/cli-reference.md)** for command-line usage
3. **Check the [API Documentation](../docs/api.md)** for detailed interfaces
4. **Implement your own use case** based on these patterns

## Contributing

If you create additional examples or improvements:

1. Follow the existing code style and structure
2. Include comprehensive tests
3. Add documentation explaining the concepts
4. Update this README with your example

---

**⚠️ Experimental Software**: These examples are for educational and research purposes. Test thoroughly before any production use.