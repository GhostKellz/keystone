//! Comprehensive Integration Tests for Keystone v0.2.3 RC1
//!
//! This file contains integration tests for all major features:
//! - zledger v0.5.0 integration
//! - Lazy loading mechanisms
//! - Gas management (EIP-1559)
//! - Smart contracts with encryption
//! - Distributed synchronization
//! - Error handling and recovery

const std = @import("std");
const testing = std.testing;
const zledger_integration = @import("../src/zledger_integration.zig");
const error_handling = @import("../src/error_handling.zig");
const zcrypto = @import("zcrypto");

// Test configuration
const test_config = zledger_integration.NodeConfig{
    .node_id = "test-integration-node",
    .enable_audit = true,
    .enable_crypto_storage = true,
    .enable_contracts = true,
    .lazy_load = true,
};

/// Test basic Keystone node initialization and lazy loading
test "keystone node initialization and lazy loading" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    // Initially, components should not be loaded
    try testing.expect(node.ledger == null);
    try testing.expect(node.gas_ledger == null);
    try testing.expect(node.contract_state == null);
    try testing.expect(node.sync_manager == null);

    // Test lazy loading of ledger
    try node.ensureLedgerInitialized();
    try testing.expect(node.ledger != null);
    try testing.expect(node.identity != null);
    try testing.expect(node.is_initialized);

    // Test lazy loading of gas ledger
    const gas_ledger = try node.getGasLedger();
    try testing.expect(gas_ledger != null);
    try testing.expect(node.gas_ledger != null);

    // Test lazy loading of contract state
    const contract_state = try node.getContractState();
    try testing.expect(contract_state != null);
    try testing.expect(node.contract_state != null);

    // Test lazy loading of sync manager
    const sync_manager = try node.getSyncManager();
    try testing.expect(sync_manager != null);
    try testing.expect(node.sync_manager != null);

    // Verify node configuration
    try testing.expectEqualStrings("test-integration-node", node.node_id);
    try testing.expect(node.config.enable_audit);
    try testing.expect(node.config.enable_crypto_storage);
    try testing.expect(node.config.enable_contracts);
    try testing.expect(node.config.lazy_load);
}

/// Test account creation and management
test "account creation and management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    // Create various account types
    const asset_account = try node.createAccount("TestAssets", .Assets);
    const liability_account = try node.createAccount("TestLiabilities", .Liabilities);
    const equity_account = try node.createAccount("TestEquity", .Equity);
    const revenue_account = try node.createAccount("TestRevenue", .Revenue);
    const expense_account = try node.createAccount("TestExpenses", .Expenses);

    // Accounts should have unique IDs
    try testing.expect(asset_account != liability_account);
    try testing.expect(liability_account != equity_account);
    try testing.expect(equity_account != revenue_account);
    try testing.expect(revenue_account != expense_account);

    // All accounts should be valid (non-zero)
    try testing.expect(asset_account > 0);
    try testing.expect(liability_account > 0);
    try testing.expect(equity_account > 0);
    try testing.expect(revenue_account > 0);
    try testing.expect(expense_account > 0);
}

/// Test gas management with EIP-1559 pricing
test "gas management with EIP-1559" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    const gas_ledger = try node.getGasLedger();

    // Create test account
    const test_account = try node.createAccount("GasTestAccount", .Assets);

    // Test basic gas charging
    try gas_ledger.chargeGas(test_account, 21000, 0.00000002, 0.000000001);

    // Test higher gas usage (contract interaction)
    try gas_ledger.chargeGas(test_account, 150000, 0.00000003, 0.000000002);

    // Test gas statistics
    const stats = try gas_ledger.getGasStats();
    try testing.expect(stats.total_burned > 0);
    try testing.expect(stats.total_distributed > 0);
    try testing.expect(stats.current_base_fee > 0);

    // Test multiple gas charges
    for (0..10) |i| {
        const gas_used = 21000 + (i * 1000);
        try gas_ledger.chargeGas(test_account, @intCast(gas_used), 0.00000002, 0.000000001);
    }

    const final_stats = try gas_ledger.getGasStats();
    try testing.expect(final_stats.total_burned > stats.total_burned);
    try testing.expect(final_stats.total_distributed > stats.total_distributed);
}

/// Test smart contract deployment and encrypted storage
test "smart contracts and encrypted storage" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    const contract_state = try node.getContractState();

    // Deploy multiple contracts
    const contract1 = "0x1111111111111111111111111111111111111111";
    const contract2 = "0x2222222222222222222222222222222222222222";
    const contract3 = "0x3333333333333333333333333333333333333333";

    const account1 = try contract_state.getOrCreateContractAccount(contract1);
    const account2 = try contract_state.getOrCreateContractAccount(contract2);
    const account3 = try contract_state.getOrCreateContractAccount(contract3);

    try testing.expect(account1 != account2);
    try testing.expect(account2 != account3);

    // Test encrypted storage
    try contract_state.storeContractData(contract1, "name", "TestToken");
    try contract_state.storeContractData(contract1, "symbol", "TEST");
    try contract_state.storeContractData(contract1, "totalSupply", "1000000");
    try contract_state.storeContractData(contract1, "owner", "0xdeadbeef");

    // Retrieve and verify data
    const name = try contract_state.getContractData(contract1, "name");
    defer if (name) |n| allocator.free(n);
    try testing.expectEqualStrings("TestToken", name.?);

    const symbol = try contract_state.getContractData(contract1, "symbol");
    defer if (symbol) |s| allocator.free(s);
    try testing.expectEqualStrings("TEST", symbol.?);

    const supply = try contract_state.getContractData(contract1, "totalSupply");
    defer if (supply) |s| allocator.free(s);
    try testing.expectEqualStrings("1000000", supply.?);

    // Test non-existent data
    const nonexistent = try contract_state.getContractData(contract1, "nonexistent");
    try testing.expect(nonexistent == null);

    // Test balance updates
    try contract_state.updateContractBalance(contract1, 1000);
    try contract_state.updateContractBalance(contract1, -500);
    try contract_state.updateContractBalance(contract2, 2000);

    // Test data isolation between contracts
    try contract_state.storeContractData(contract2, "name", "AnotherToken");
    const contract2_name = try contract_state.getContractData(contract2, "name");
    defer if (contract2_name) |n| allocator.free(n);
    try testing.expectEqualStrings("AnotherToken", contract2_name.?);

    // Verify contract1 data is unchanged
    const contract1_name = try contract_state.getContractData(contract1, "name");
    defer if (contract1_name) |n| allocator.free(n);
    try testing.expectEqualStrings("TestToken", contract1_name.?);
}

/// Test distributed synchronization
test "distributed synchronization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create two nodes for sync testing
    const config1 = zledger_integration.NodeConfig{
        .node_id = "sync-test-node-1",
        .enable_audit = true,
        .lazy_load = true,
    };

    const config2 = zledger_integration.NodeConfig{
        .node_id = "sync-test-node-2",
        .enable_audit = true,
        .lazy_load = true,
    };

    var node1 = try zledger_integration.KeystoneNode.init(allocator, config1);
    defer node1.deinit();

    var node2 = try zledger_integration.KeystoneNode.init(allocator, config2);
    defer node2.deinit();

    // Get sync managers
    const sync1 = try node1.getSyncManager();
    const sync2 = try node2.getSyncManager();

    // Add peers
    try sync1.addPeer("sync-test-node-2");
    try sync2.addPeer("sync-test-node-1");

    // Verify peer addition
    try testing.expect(sync1.peer_nodes.items.len == 1);
    try testing.expect(sync2.peer_nodes.items.len == 1);
    try testing.expectEqualStrings("sync-test-node-2", sync1.peer_nodes.items[0]);
    try testing.expectEqualStrings("sync-test-node-1", sync2.peer_nodes.items[0]);

    // Test journal synchronization
    const timestamp = std.time.timestamp() - 3600; // 1 hour ago
    const journal1 = try node1.getJournalForSync(timestamp);
    defer node1.allocator.free(journal1);

    const journal2 = try node2.getJournalForSync(timestamp);
    defer node2.allocator.free(journal2);

    // Sync journals
    try node1.syncFromJournal(journal2);
    try node2.syncFromJournal(journal1);

    // Test sync with peers
    try sync1.syncWithPeers();
    try sync2.syncWithPeers();

    // Verify last sync timestamps were updated
    const current_time = std.time.timestamp();
    try testing.expect(sync1.last_sync_timestamp > 0);
    try testing.expect(sync2.last_sync_timestamp > 0);
    try testing.expect(sync1.last_sync_timestamp <= current_time);
    try testing.expect(sync2.last_sync_timestamp <= current_time);
}

/// Test cryptographic operations
test "cryptographic operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test AES-256 encryption/decryption
    const plaintext = "This is sensitive test data that needs encryption";
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const ciphertext = try zcrypto.aes256.encrypt(allocator, plaintext, key);
    defer allocator.free(ciphertext);

    try testing.expect(ciphertext.len > plaintext.len); // Should be larger due to padding/IV

    const decrypted = try zcrypto.aes256.decrypt(allocator, ciphertext, key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);

    // Test with wrong key (should fail)
    var wrong_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrong_key);

    const wrong_decrypt = zcrypto.aes256.decrypt(allocator, ciphertext, wrong_key);
    try testing.expectError(error.InvalidCiphertext, wrong_decrypt);

    // Test multiple encryptions with same key produce different ciphertexts (due to IV)
    const ciphertext2 = try zcrypto.aes256.encrypt(allocator, plaintext, key);
    defer allocator.free(ciphertext2);

    try testing.expect(!std.mem.eql(u8, ciphertext, ciphertext2));

    const decrypted2 = try zcrypto.aes256.decrypt(allocator, ciphertext2, key);
    defer allocator.free(decrypted2);

    try testing.expectEqualStrings(plaintext, decrypted2);
}

/// Test error handling and recovery mechanisms
test "error handling and recovery" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test circuit breaker
    var circuit_breaker = error_handling.CircuitBreaker.init(allocator, 3, 1000);

    // Test successful operations
    var success_count: u32 = 0;
    const success_operation = struct {
        count: *u32,
        fn call(count: *u32) anyerror!u32 {
            count.* += 1;
            return count.*;
        }
    };

    const result1 = try circuit_breaker.execute(u32, struct {
        fn call() anyerror!u32 {
            return success_operation.call(&success_count);
        }
    }.call);
    try testing.expect(result1 == 1);
    try testing.expect(circuit_breaker.state == .Closed);

    // Test failing operations
    var failure_count: u32 = 0;
    const failing_operation = struct {
        count: *u32,
        fn call(count: *u32) anyerror!void {
            count.* += 1;
            return error.TestFailure;
        }
    };

    // Trigger failures to open circuit breaker
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        const result = circuit_breaker.execute(void, struct {
            fn call() anyerror!void {
                return failing_operation.call(&failure_count);
            }
        }.call);
        try testing.expectError(error.TestFailure, result);
    }

    try testing.expect(circuit_breaker.state == .Open);
    try testing.expect(failure_count == 3);

    // Circuit should reject requests when open
    const rejected_result = circuit_breaker.execute(void, struct {
        fn call() anyerror!void {
            return {};
        }
    }.call);
    try testing.expectError(error_handling.KeystoneError.OperationTimeout, rejected_result);

    // Test retry mechanism
    const retry_config = error_handling.RetryConfig{
        .max_attempts = 3,
        .base_delay_ms = 10, // Small delay for testing
        .max_delay_ms = 100,
        .backoff_multiplier = 2.0,
        .jitter_enabled = false, // Disable for predictable testing
    };

    var retry_attempt_count: u32 = 0;
    const retry_operation = struct {
        count: *u32,
        fn call(count: *u32) anyerror!void {
            count.* += 1;
            if (count.* < 3) {
                return error.TestRetryFailure;
            }
            return {};
        }
    };

    const retry_result = try error_handling.retryWithBackoff(void, struct {
        fn call() anyerror!void {
            return retry_operation.call(&retry_attempt_count);
        }
    }.call, retry_config);

    try testing.expect(retry_attempt_count == 3);

    // Test exponential backoff calculation
    const backoff1 = error_handling.exponentialBackoff(retry_config, 0);
    const backoff2 = error_handling.exponentialBackoff(retry_config, 1);
    const backoff3 = error_handling.exponentialBackoff(retry_config, 2);

    try testing.expect(backoff1 == 10);
    try testing.expect(backoff2 == 20);
    try testing.expect(backoff3 == 40);

    // Test error context
    var error_ctx = try error_handling.ErrorContext.init(
        allocator,
        "test_operation",
        "test_node",
        error_handling.KeystoneError.TestFailure,
        "This is a test error"
    );
    defer error_ctx.deinit(allocator);

    try testing.expectEqualStrings("test_operation", error_ctx.operation);
    try testing.expectEqualStrings("test_node", error_ctx.node_id);
    try testing.expect(error_ctx.error_code == error_handling.KeystoneError.TestFailure);
    try testing.expectEqualStrings("This is a test error", error_ctx.details);

    try error_ctx.withRecoveryHint(allocator, "Try restarting the operation");
    try testing.expectEqualStrings("Try restarting the operation", error_ctx.recovery_hint.?);

    // Test error reporter
    var error_reporter = error_handling.ErrorReporter.init(allocator);
    defer error_reporter.deinit();

    try error_reporter.reportError(
        "test_operation_1",
        "test_node",
        error_handling.KeystoneError.NetworkUnavailable,
        "Network connection failed"
    );

    try error_reporter.reportError(
        "test_operation_2",
        "test_node",
        error_handling.KeystoneError.GasExhausted,
        "Insufficient gas for operation"
    );

    const recent_errors = error_reporter.getRecentErrors(10);
    try testing.expect(recent_errors.len == 2);
    try testing.expect(recent_errors[0].error_code == error_handling.KeystoneError.NetworkUnavailable);
    try testing.expect(recent_errors[1].error_code == error_handling.KeystoneError.GasExhausted);
}

/// Test recovery manager and checkpoints
test "recovery manager and checkpoints" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    var recovery_manager = try error_handling.initializeErrorHandling(allocator, &node);
    defer recovery_manager.deinit();

    // Test circuit breakers were created
    try testing.expect(recovery_manager.getCircuitBreaker("ledger") != null);
    try testing.expect(recovery_manager.getCircuitBreaker("network") != null);
    try testing.expect(recovery_manager.getCircuitBreaker("crypto") != null);

    // Test checkpoint creation
    try recovery_manager.createCheckpoint(&node);
    try testing.expect(recovery_manager.checkpoints.items.len == 2); // Initial + created

    // Create additional checkpoints
    try recovery_manager.createCheckpoint(&node);
    try recovery_manager.createCheckpoint(&node);
    try testing.expect(recovery_manager.checkpoints.items.len == 4);

    // Test recovery from checkpoint
    try recovery_manager.recoverFromLatestCheckpoint(&node);

    // Test health checks
    const health_results = try recovery_manager.health_checker.checkAll();
    defer allocator.free(health_results);

    try testing.expect(health_results.len == 3); // ledger, network, crypto
    for (health_results) |result| {
        try testing.expect(result.healthy); // All should be healthy in test
        try testing.expect(result.check_duration_ms >= 0);
    }
}

/// Comprehensive end-to-end integration test
test "end-to-end keystone integration" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize complete Keystone setup
    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    var recovery_manager = try error_handling.initializeErrorHandling(allocator, &node);
    defer recovery_manager.deinit();

    // Create accounts
    const alice = try node.createAccount("Alice", .Assets);
    const bob = try node.createAccount("Bob", .Assets);
    const contract_deployer = try node.createAccount("ContractDeployer", .Assets);

    // Set up gas management
    const gas_ledger = try node.getGasLedger();
    try gas_ledger.chargeGas(contract_deployer, 200000, 0.00000003, 0.000000002); // Contract deployment

    // Deploy a smart contract
    const contract_state = try node.getContractState();
    const token_contract = "0xe2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";
    _ = try contract_state.getOrCreateContractAccount(token_contract);

    // Initialize token contract
    try contract_state.storeContractData(token_contract, "name", "IntegrationToken");
    try contract_state.storeContractData(token_contract, "symbol", "INT");
    try contract_state.storeContractData(token_contract, "decimals", "18");
    try contract_state.storeContractData(token_contract, "totalSupply", "1000000000000000000000000"); // 1M tokens

    // Distribute tokens
    try contract_state.storeContractData(token_contract, "balance_alice", "500000000000000000000000");
    try contract_state.storeContractData(token_contract, "balance_bob", "500000000000000000000000");

    // Simulate token transfer
    try gas_ledger.chargeGas(alice, 50000, 0.00000002, 0.000000001);

    // Update balances (simulate transfer of 100 tokens from Alice to Bob)
    const transfer_amount = "100000000000000000000"; // 100 tokens in wei
    try contract_state.storeContractData(token_contract, "balance_alice", "499900000000000000000000");
    try contract_state.storeContractData(token_contract, "balance_bob", "500100000000000000000000");

    // Verify balances
    const alice_balance = try contract_state.getContractData(token_contract, "balance_alice");
    defer if (alice_balance) |balance| allocator.free(balance);
    try testing.expectEqualStrings("499900000000000000000000", alice_balance.?);

    const bob_balance = try contract_state.getContractData(token_contract, "balance_bob");
    defer if (bob_balance) |balance| allocator.free(balance);
    try testing.expectEqualStrings("500100000000000000000000", bob_balance.?);

    // Test synchronization setup
    const sync_manager = try node.getSyncManager();
    try sync_manager.addPeer("integration-test-peer");
    try testing.expect(sync_manager.peer_nodes.items.len == 1);

    // Generate audit report
    const audit_report = try node.generateAuditReport();
    defer audit_report.deinit();

    try testing.expectEqualStrings("test-integration-node", audit_report.keystone_node_id);
    try testing.expect(audit_report.consensus_ready);

    // Test gas statistics
    const final_gas_stats = try gas_ledger.getGasStats();
    try testing.expect(final_gas_stats.total_burned > 0);
    try testing.expect(final_gas_stats.total_distributed > 0);

    // Create final checkpoint
    try recovery_manager.createCheckpoint(&node);
    try testing.expect(recovery_manager.checkpoints.items.len >= 2);

    // Test health checks
    const health_results = try recovery_manager.health_checker.checkAll();
    defer allocator.free(health_results);

    var healthy_count: u32 = 0;
    for (health_results) |result| {
        if (result.healthy) {
            healthy_count += 1;
        }
    }
    try testing.expect(healthy_count == health_results.len); // All components should be healthy
}

/// Performance and stress test
test "performance and stress testing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    const gas_ledger = try node.getGasLedger();
    const contract_state = try node.getContractState();

    // Create multiple accounts
    var accounts = std.ArrayList(u32).init(allocator);
    defer accounts.deinit();

    const account_count = 100;
    for (0..account_count) |i| {
        const account_name = try std.fmt.allocPrint(allocator, "Account_{d}", .{i});
        defer allocator.free(account_name);

        const account_id = try node.createAccount(account_name, .Assets);
        try accounts.append(account_id);
    }

    try testing.expect(accounts.items.len == account_count);

    // Perform many gas operations
    const start_time = std.time.nanoTimestamp();

    for (accounts.items) |account| {
        try gas_ledger.chargeGas(account, 21000, 0.00000002, 0.000000001);
    }

    const gas_end_time = std.time.nanoTimestamp();
    const gas_duration_ms = @as(f64, @floatFromInt(gas_end_time - start_time)) / 1_000_000.0;

    // Should complete within reasonable time (adjust threshold as needed)
    try testing.expect(gas_duration_ms < 1000.0); // Less than 1 second

    // Deploy many contracts
    const contract_start_time = std.time.nanoTimestamp();

    for (0..50) |i| {
        const contract_address = try std.fmt.allocPrint(allocator, "0x{d:0>40}", .{i});
        defer allocator.free(contract_address);

        _ = try contract_state.getOrCreateContractAccount(contract_address);

        // Store some data
        try contract_state.storeContractData(contract_address, "id", contract_address);

        // Retrieve data to test encryption/decryption performance
        const retrieved = try contract_state.getContractData(contract_address, "id");
        defer if (retrieved) |data| allocator.free(data);

        try testing.expectEqualStrings(contract_address, retrieved.?);
    }

    const contract_end_time = std.time.nanoTimestamp();
    const contract_duration_ms = @as(f64, @floatFromInt(contract_end_time - contract_start_time)) / 1_000_000.0;

    // Contract operations should also complete within reasonable time
    try testing.expect(contract_duration_ms < 2000.0); // Less than 2 seconds

    // Final gas statistics should show significant activity
    const final_stats = try gas_ledger.getGasStats();
    try testing.expect(final_stats.total_burned >= account_count * 21000);
    try testing.expect(final_stats.total_distributed > 0);
}

/// Test memory management and cleanup
test "memory management and cleanup" {
    // This test uses a tracking allocator to verify no memory leaks
    var tracking = std.testing.allocator;

    var node = try zledger_integration.KeystoneNode.init(tracking, test_config);
    defer node.deinit();

    // Perform various operations that allocate memory
    const gas_ledger = try node.getGasLedger();
    const contract_state = try node.getContractState();
    const sync_manager = try node.getSyncManager();

    // Create accounts
    _ = try node.createAccount("MemTestAccount1", .Assets);
    _ = try node.createAccount("MemTestAccount2", .Assets);

    // Gas operations
    try gas_ledger.chargeGas(1, 21000, 0.00000002, 0.000000001);

    // Contract operations
    const test_contract = "0xmemtest1234567890abcdef1234567890abcdef";
    _ = try contract_state.getOrCreateContractAccount(test_contract);
    try contract_state.storeContractData(test_contract, "test_key", "test_value");

    const retrieved = try contract_state.getContractData(test_contract, "test_key");
    defer if (retrieved) |data| tracking.free(data);

    // Sync operations
    try sync_manager.addPeer("memory-test-peer");

    // All memory should be properly cleaned up when node is deinitialized
    // The tracking allocator will catch any leaks
}