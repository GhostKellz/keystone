# Keystone v0.2.3 RC1 Documentation

![Keystone Logo](../logo.png)

Keystone is a modular execution layer for distributed systems and Web3 runtimes, enhanced with **zledger v0.5.0** and **zcrypto modular** integration.

## Quick Start

```bash
# Initialize Keystone ledger
zig build run -- init

# Create a DID identity
zig build run -- identity create alice "Alice's test account"

# Deploy a smart contract
zig build run -- contract deploy 0x1234567890abcdef

# Check gas statistics
zig build run -- gas stats

# Encrypt sensitive data
zig build run -- crypto encrypt "my secret data"
```

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Keystone      │    │   zledger v0.5  │    │   zcrypto       │
│ Execution Layer │◄──►│ Ledger Engine   │◄──►│ Crypto Library  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
    ┌────▼────┐              ┌───▼───┐               ┌───▼───┐
    │Identity │              │Journal│               │Ed25519│
    │ & Auth  │              │Replay │               │ Sigs  │
    └─────────┘              └───────┘               └───────┘
```

## Key Features

### 🔧 Core Features
- **Lazy-loaded Components**: Efficient resource usage with on-demand initialization
- **Identity-Aware Transactions**: Every transaction is cryptographically signed and verified
- **Double-Entry Bookkeeping**: Ensures financial integrity and auditability

### ⛽ Gas Management (EIP-1559)
- **Base Fee + Priority Fee Model**: Modern gas pricing similar to Ethereum
- **Burn Mechanism**: Base fees are burned, priority fees go to validators
- **Gas Estimation**: Predict costs for different transaction types

### 🤖 Smart Contracts
- **Encrypted Storage**: Contract data is encrypted using AES-256
- **Account Abstraction**: Flexible account types and permissions
- **Method Execution**: Call contract methods with balance updates

### 🔄 Distributed Synchronization
- **Journal Replay**: Sync state across distributed nodes
- **Peer Management**: Add and manage synchronization peers
- **Merkle Tree Validation**: Ensure data integrity across the network

### 🔐 Cryptography
- **AES-256 Encryption**: Secure data encryption for sensitive information
- **Ed25519 Signatures**: Fast and secure digital signatures
- **Key Generation**: Built-in keypair generation utilities

## Documentation Index

1. [Installation Guide](installation.md) - How to build and install Keystone
2. [CLI Reference](cli-reference.md) - Complete command reference
3. [Integration Guide](integration.md) - How to integrate with zledger and zcrypto
4. [Architecture Overview](architecture.md) - System design and components
5. [Security Model](security.md) - Cryptographic guarantees and threat model
6. [API Documentation](api.md) - Programming interface reference
7. [Examples](../examples/) - Practical usage examples
8. [Migration Guide](migration.md) - Upgrading from previous versions

## Version Information

- **Keystone**: v0.2.3 RC1
- **zledger**: v0.5.0 (with modular configuration)
- **zcrypto**: v0.9.2 (modular build system)
- **Shroud**: v1.2.4 (identity management)
- **zsync**: v0.5.4 (synchronization utilities)

## Dependencies

```zig
// build.zig.zon
.dependencies = .{
    .zledger = .{
        .url = "https://github.com/ghostkellz/zledger/archive/refs/tags/v0.5.0.tar.gz",
        .hash = "zledger-0.5.0-...",
    },
    .zcrypto = .{
        .url = "https://github.com/ghostkellz/zcrypto/archive/refs/heads/main.tar.gz",
        .hash = "zcrypto-0.9.2-...",
    },
    // ... other dependencies
},
```

## Build Configuration

Keystone supports modular builds with feature flags:

```bash
# Full build with all features
zig build

# Minimal build (ledger + identity only)
zig build -Dledger=true -Dzsig=true -Dcontracts=false

# Development build with debugging
zig build -Doptimize=Debug
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.

## License

Keystone is experimental software for educational and research purposes.

---

**⚠️ Experimental Software**: Keystone is designed for laboratory and personal use. Thoroughly test before any production deployment.