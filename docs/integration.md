# Integration Guide

This guide explains how to integrate Keystone v0.2.3 RC1 with zledger v0.5.0 and zcrypto for your own applications.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Setting up Dependencies](#setting-up-dependencies)
- [Basic Integration](#basic-integration)
- [Advanced Features](#advanced-features)
- [Performance Optimization](#performance-optimization)
- [Security Considerations](#security-considerations)
- [Migration from Previous Versions](#migration-from-previous-versions)

## Architecture Overview

Keystone v0.2.3 RC1 provides a layered integration approach:

```
Your Application
       │
       ▼
┌─────────────────┐
│ Keystone Module │  ◄─── Your integration point
├─────────────────┤
│ zledger_integration.zig │  ◄─── Lazy-loaded components
├─────────────────┤
│ zledger v0.5.0  │  ◄─── Core ledger functionality
├─────────────────┤
│ zcrypto v0.9.2  │  ◄─── Cryptographic primitives
└─────────────────┘
```

### Key Components

1. **KeystoneNode**: Main integration point with lazy loading
2. **GasLedger**: EIP-1559 gas management
3. **ContractState**: Smart contract storage with encryption
4. **SyncManager**: Distributed synchronization
5. **Cryptographic Utilities**: Ed25519 + AES-256 operations

## Setting up Dependencies

### 1. Add to `build.zig.zon`

```zig
.dependencies = .{
    .zledger = .{
        .url = "https://github.com/ghostkellz/zledger/archive/refs/tags/v0.5.0.tar.gz",
        .hash = "zledger-0.5.0-gtTGiG9OBAD3kXV9XUMy7Qc1O2nhj6CW_2QZi-5jV3XE",
    },
    .zcrypto = .{
        .url = "https://github.com/ghostkellz/zcrypto/archive/refs/heads/main.tar.gz",
        .hash = "zcrypto-0.9.2-rgQAI79uDQArK9xAs_3jE_fAhsLf46jUowo8aNguD1oy",
    },
    .shroud = .{
        .url = "https://github.com/ghostkellz/shroud/archive/main.tar.gz",
        .hash = "shroud-1.2.4-z7C8mXYWBQDnbScUT0wV5HI44ceuV9BYHelv9F-82sqJ",
    },
    .zsync = .{
        .url = "https://github.com/ghostkellz/zsync/archive/refs/heads/main.tar.gz",
        .hash = "zsync-0.5.4-KAuheZ4THQAlN32uBKm76ezT7dPT6rvj4ll56NiA9z9M",
    },
},
```

### 2. Configure `build.zig`

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Configure zledger with modular features
    const zledger_dep = b.dependency("zledger", .{
        .target = target,
        .optimize = optimize,
        .ledger = true,        // Core ledger functionality
        .zsig = true,          // Identity verification
        .contracts = true,     // Smart contract execution
        .crypto_storage = true, // Encrypted storage
        .wallet = true,        // Wallet integration
    });

    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });

    const shroud_dep = b.dependency("shroud", .{
        .target = target,
        .optimize = optimize,
    });

    const zsync_dep = b.dependency("zsync", .{
        .target = target,
        .optimize = optimize,
    });

    // Create your module
    const your_module = b.addModule("your_app", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zledger", .module = zledger_dep.module("zledger") },
            .{ .name = "zcrypto", .module = zcrypto_dep.module("zcrypto") },
            .{ .name = "shroud", .module = shroud_dep.module("shroud") },
            .{ .name = "zsync", .module = zsync_dep.module("zsync") },
        },
    });

    // Rest of build configuration...
}
```

## Basic Integration

### 1. Create Your Integration Module

Create `src/keystone_integration.zig`:

```zig
const std = @import("std");
const zledger = @import("zledger");
const zcrypto = @import("zcrypto");

pub const MyKeystoneApp = struct {
    allocator: std.mem.Allocator,
    keystone_node: ?KeystoneNode = null,

    pub fn init(allocator: std.mem.Allocator) MyKeystoneApp {
        return MyKeystoneApp{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MyKeystoneApp) void {
        if (self.keystone_node) |*node| {
            node.deinit();
        }
    }

    pub fn initializeKeystone(self: *MyKeystoneApp) !void {
        const config = KeystoneNode.Config{
            .node_id = "my-app-node-001",
            .enable_audit = true,
            .enable_crypto_storage = true,
            .enable_contracts = true,
            .lazy_load = true,
        };

        self.keystone_node = try KeystoneNode.init(self.allocator, config);
    }

    pub fn createAccount(self: *MyKeystoneApp, name: []const u8) !u32 {
        if (self.keystone_node) |*node| {
            return try node.createAccount(name, .Assets);
        }
        return error.KeystoneNotInitialized;
    }

    pub fn sendTransaction(self: *MyKeystoneApp, from: u32, to: u32, amount: u64) !void {
        if (self.keystone_node) |*node| {
            // Create transaction
            var tx = zledger.Transaction.init(self.allocator);
            defer tx.deinit();

            try tx.addEntry(.{
                .account_id = from,
                .amount = zledger.FixedPoint.fromInt(amount),
                .debit = false, // Credit (sending)
            });

            try tx.addEntry(.{
                .account_id = to,
                .amount = zledger.FixedPoint.fromInt(amount),
                .debit = true, // Debit (receiving)
            });

            // Sign and execute
            const tx_data = try tx.serialize(self.allocator);
            defer self.allocator.free(tx_data);

            if (node.identity) |identity| {
                const signature = try zledger.signMessage(identity, tx_data);
                try node.executeSignedTransaction(tx_data, signature, identity.public_key);
            }
        }
    }
};
```

### 2. Use in Your Application

```zig
const std = @import("std");
const MyKeystoneApp = @import("keystone_integration.zig").MyKeystoneApp;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = MyKeystoneApp.init(allocator);
    defer app.deinit();

    // Initialize Keystone
    try app.initializeKeystone();

    // Create accounts
    const alice_account = try app.createAccount("alice");
    const bob_account = try app.createAccount("bob");

    // Send transaction
    try app.sendTransaction(alice_account, bob_account, 100);

    std.log.info("Transaction completed successfully!");
}
```

## Advanced Features

### 1. Smart Contract Integration

```zig
pub const ContractManager = struct {
    keystone_node: *KeystoneNode,

    pub fn deployContract(self: *ContractManager, contract_code: []const u8) ![]const u8 {
        // Generate contract address
        var hasher = std.crypto.hash.blake3.Blake3.init(.{});
        hasher.update(contract_code);
        var hash_bytes: [32]u8 = undefined;
        hasher.final(&hash_bytes);

        const contract_address = try std.fmt.allocPrint(
            self.keystone_node.allocator,
            "0x{s}",
            .{std.fmt.fmtSliceHexLower(&hash_bytes)}
        );

        // Deploy using contract state
        const contract_state = try self.keystone_node.getContractState();
        _ = try contract_state.getOrCreateContractAccount(contract_address);

        // Store contract code
        try contract_state.storeContractData(contract_address, "code", contract_code);

        return contract_address;
    }

    pub fn callContract(self: *ContractManager, contract_address: []const u8, method: []const u8, params: []const u8) ![]u8 {
        const contract_state = try self.keystone_node.getContractState();

        // Execute method (simplified)
        if (std.mem.eql(u8, method, "transfer")) {
            const amount = std.fmt.parseInt(i64, params, 10) catch 0;
            try contract_state.updateContractBalance(contract_address, amount);
        }

        return try self.keystone_node.allocator.dupe(u8, "success");
    }
};
```

### 2. Gas Management Integration

```zig
pub const GasManager = struct {
    gas_ledger: *GasLedger,

    pub fn estimateGas(self: *GasManager, operation: []const u8) u64 {
        _ = self;
        return switch (std.hash_map.hash(operation)) {
            std.hash_map.hash("transfer") => 21000,
            std.hash_map.hash("contract_call") => 50000,
            std.hash_map.hash("contract_deploy") => 200000,
            else => 25000,
        };
    }

    pub fn chargeForExecution(self: *GasManager, account_id: u32, operation: []const u8) !void {
        const gas_needed = self.estimateGas(operation);
        const base_fee = 0.00000002; // 20 gwei
        const priority_fee = 0.000000001; // 1 gwei

        try self.gas_ledger.chargeGas(account_id, gas_needed, base_fee, priority_fee);
    }
};
```

### 3. Distributed Synchronization

```zig
pub const NetworkManager = struct {
    sync_manager: *SyncManager,

    pub fn setupNetwork(self: *NetworkManager, peer_nodes: []const []const u8) !void {
        for (peer_nodes) |peer| {
            try self.sync_manager.addPeer(peer);
        }
    }

    pub fn syncPeriodically(self: *NetworkManager) !void {
        // Run sync every 30 seconds
        while (true) {
            try self.sync_manager.syncWithPeers();
            std.time.sleep(30 * std.time.ns_per_s);
        }
    }
};
```

## Performance Optimization

### 1. Lazy Loading Best Practices

```zig
pub const OptimizedKeystoneApp = struct {
    node: KeystoneNode,

    // Cache frequently used components
    cached_gas_ledger: ?*GasLedger = null,
    cached_contract_state: ?*ContractState = null,

    pub fn getGasLedger(self: *OptimizedKeystoneApp) !*GasLedger {
        if (self.cached_gas_ledger == null) {
            self.cached_gas_ledger = try self.node.getGasLedger();
        }
        return self.cached_gas_ledger.?;
    }

    pub fn getContractState(self: *OptimizedKeystoneApp) !*ContractState {
        if (self.cached_contract_state == null) {
            self.cached_contract_state = try self.node.getContractState();
        }
        return self.cached_contract_state.?;
    }
};
```

### 2. Batched Operations

```zig
pub fn processBatchTransactions(app: *MyKeystoneApp, transactions: []const Transaction) !void {
    // Initialize ledger once for the batch
    if (app.keystone_node) |*node| {
        try node.ensureLedgerInitialized();

        for (transactions) |tx| {
            // Process without re-initializing
            try processTransaction(node, tx);
        }

        // Single audit entry for the batch
        const audit_report = try node.generateAuditReport();
        defer audit_report.deinit();
    }
}
```

### 3. Memory Management

```zig
pub const MemoryEfficientApp = struct {
    arena: std.heap.ArenaAllocator,
    keystone_node: KeystoneNode,

    pub fn init(parent_allocator: std.mem.Allocator) !MemoryEfficientApp {
        var arena = std.heap.ArenaAllocator.init(parent_allocator);
        const allocator = arena.allocator();

        const config = KeystoneNode.Config{
            .node_id = "memory-efficient-node",
            .lazy_load = true, // Essential for memory efficiency
        };

        return MemoryEfficientApp{
            .arena = arena,
            .keystone_node = try KeystoneNode.init(allocator, config),
        };
    }

    pub fn deinit(self: *MemoryEfficientApp) void {
        self.keystone_node.deinit();
        self.arena.deinit();
    }

    pub fn resetMemory(self: *MemoryEfficientApp) void {
        // Reset arena to free all temporary allocations
        _ = self.arena.reset(.retain_capacity);
    }
};
```

## Security Considerations

### 1. Key Management

```zig
pub const SecureKeyManager = struct {
    identity: zledger.Keypair,
    encrypted_storage: std.HashMap([]const u8, []u8),

    pub fn init(allocator: std.mem.Allocator) !SecureKeyManager {
        return SecureKeyManager{
            .identity = try zledger.generateKeypair(),
            .encrypted_storage = std.HashMap([]const u8, []u8).init(allocator),
        };
    }

    pub fn storeSecurely(self: *SecureKeyManager, key: []const u8, value: []const u8) !void {
        // Derive encryption key from identity
        var derived_key: [32]u8 = undefined;
        std.crypto.pwhash.scrypt(
            &derived_key,
            key,
            &self.identity.private_key,
            .{ .ln = 15, .r = 8, .p = 1 }
        ) catch return error.KeyDerivationFailed;

        // Encrypt and store
        const encrypted = try zcrypto.aes256.encrypt(self.allocator, value, derived_key);
        try self.encrypted_storage.put(key, encrypted);
    }
};
```

### 2. Transaction Validation

```zig
pub fn validateTransaction(tx: *const zledger.Transaction) !bool {
    // Check double-entry bookkeeping
    var debit_total: i64 = 0;
    var credit_total: i64 = 0;

    for (tx.entries.items) |entry| {
        if (entry.debit) {
            debit_total += @intCast(entry.amount.value);
        } else {
            credit_total += @intCast(entry.amount.value);
        }
    }

    if (debit_total != credit_total) {
        return error.ImbalancedTransaction;
    }

    // Verify signature if present
    if (tx.signature) |sig| {
        const tx_data = try tx.serialize(tx.allocator);
        defer tx.allocator.free(tx_data);

        const verification = try zcrypto.ed25519.verify(
            tx.identity.?,
            tx_data,
            sig.bytes
        );

        if (!verification) {
            return error.InvalidSignature;
        }
    }

    return true;
}
```

### 3. Access Control

```zig
pub const AccessController = struct {
    permissions: std.HashMap([]const u8, PermissionSet),

    pub fn checkPermission(self: *AccessController, user_did: []const u8, required: Permission) bool {
        if (self.permissions.get(user_did)) |perms| {
            return perms.has(required);
        }
        return false;
    }

    pub fn requirePermission(self: *AccessController, user_did: []const u8, required: Permission) !void {
        if (!self.checkPermission(user_did, required)) {
            return error.InsufficientPermissions;
        }
    }
};
```

## Migration from Previous Versions

### From Keystone v0.2.2

1. **Update Dependencies**: Use the new modular configuration
2. **Replace Global State**: Use KeystoneNode instances instead
3. **Update CLI Integration**: Use new command structure
4. **Add Lazy Loading**: Components are now lazy-loaded by default

```zig
// Old (v0.2.2)
var global_ledger: ?zledger.Ledger = null;

// New (v0.2.3 RC1)
var keystone_node = try KeystoneNode.init(allocator, config);
const ledger = try keystone_node.ensureLedgerInitialized();
```

### From zledger v0.4.x

1. **Enable New Features**: Use the modular build configuration
2. **Update API Calls**: Some method signatures have changed
3. **Add Gas Management**: Integrate EIP-1559 gas pricing
4. **Use Contract Storage**: Leverage encrypted storage features

## Troubleshooting

### Common Issues

1. **Lazy Loading Errors**: Ensure `ensureLedgerInitialized()` is called
2. **Memory Leaks**: Use ArenaAllocator for temporary operations
3. **Signature Verification Failures**: Check key formats and derivation
4. **Gas Estimation Issues**: Verify transaction types and parameters

### Debugging

```zig
// Enable debug logging
const log = std.log.scoped(.keystone_integration);

log.debug("Initializing Keystone node: {s}", .{config.node_id});
log.info("Transaction executed: {}", .{tx.id});
log.warn("Gas estimation may be inaccurate: {s}", .{tx_type});
log.err("Failed to sync with peer: {s}", .{peer_id});
```

### Performance Profiling

```bash
# Build with profiling
zig build -Doptimize=ReleaseSafe -Dtrace

# Run with allocation tracking
zig build run -- --log-level=debug --trace-allocations
```

## Best Practices

1. **Use Lazy Loading**: Don't initialize components until needed
2. **Batch Operations**: Group related transactions for better performance
3. **Validate Early**: Check permissions and signatures before processing
4. **Handle Errors Gracefully**: Provide meaningful error messages
5. **Log Security Events**: Audit all privilege escalations and key operations
6. **Test Thoroughly**: Use the provided test examples as starting points

## Support

For integration support:
- Check the [examples directory](../examples/)
- Review [API documentation](api.md)
- See [troubleshooting guide](troubleshooting.md)
- Submit issues at the project repository