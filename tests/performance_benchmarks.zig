//! Performance Benchmarks for Keystone v0.2.3 RC1
//!
//! This file contains comprehensive performance benchmarks for:
//! - Lazy loading performance
//! - Gas management throughput
//! - Encryption/decryption performance
//! - Contract storage operations
//! - Synchronization overhead

const std = @import("std");
const testing = std.testing;
const zledger_integration = @import("../src/zledger_integration.zig");
const error_handling = @import("../src/error_handling.zig");
const zcrypto = @import("zcrypto");
const zledger = @import("zledger");

/// Benchmark configuration
const BenchmarkConfig = struct {
    iterations: u32 = 1000,
    warmup_iterations: u32 = 100,
    timeout_ms: u64 = 10000,
};

const default_config = BenchmarkConfig{};

/// Benchmark result
const BenchmarkResult = struct {
    operation_name: []const u8,
    total_time_ns: u64,
    iterations: u32,
    avg_time_ns: u64,
    ops_per_second: f64,
    min_time_ns: u64,
    max_time_ns: u64,

    pub fn calculate(operation_name: []const u8, total_time_ns: u64, iterations: u32, min_time_ns: u64, max_time_ns: u64) BenchmarkResult {
        const avg_time_ns = total_time_ns / iterations;
        const ops_per_second = 1_000_000_000.0 / @as(f64, @floatFromInt(avg_time_ns));

        return BenchmarkResult{
            .operation_name = operation_name,
            .total_time_ns = total_time_ns,
            .iterations = iterations,
            .avg_time_ns = avg_time_ns,
            .ops_per_second = ops_per_second,
            .min_time_ns = min_time_ns,
            .max_time_ns = max_time_ns,
        };
    }

    pub fn print(self: BenchmarkResult) void {
        std.debug.print("Benchmark: {s}\n", .{self.operation_name});
        std.debug.print("  Iterations: {d}\n", .{self.iterations});
        std.debug.print("  Total time: {d:.2}ms\n", .{@as(f64, @floatFromInt(self.total_time_ns)) / 1_000_000.0});
        std.debug.print("  Average: {d:.2}μs per operation\n", .{@as(f64, @floatFromInt(self.avg_time_ns)) / 1000.0});
        std.debug.print("  Throughput: {d:.0} ops/second\n", .{self.ops_per_second});
        std.debug.print("  Min: {d:.2}μs, Max: {d:.2}μs\n", .{
            @as(f64, @floatFromInt(self.min_time_ns)) / 1000.0,
            @as(f64, @floatFromInt(self.max_time_ns)) / 1000.0,
        });
        std.debug.print("\n");
    }
};

/// Benchmark runner
fn runBenchmark(
    allocator: std.mem.Allocator,
    operation_name: []const u8,
    operation: anytype,
    config: BenchmarkConfig,
) !BenchmarkResult {
    // Warmup
    var i: u32 = 0;
    while (i < config.warmup_iterations) : (i += 1) {
        _ = try operation();
    }

    // Actual benchmark
    var total_time: u64 = 0;
    var min_time: u64 = std.math.maxInt(u64);
    var max_time: u64 = 0;

    i = 0;
    while (i < config.iterations) : (i += 1) {
        const start = std.time.nanoTimestamp();
        _ = try operation();
        const end = std.time.nanoTimestamp();
        const duration = @as(u64, @intCast(end - start));

        total_time += duration;
        min_time = @min(min_time, duration);
        max_time = @max(max_time, duration);

        // Check timeout
        if (total_time > config.timeout_ms * 1_000_000) {
            std.debug.print("Benchmark timeout after {d} iterations\n", .{i + 1});
            return BenchmarkResult.calculate(operation_name, total_time, i + 1, min_time, max_time);
        }
    }

    _ = allocator;
    return BenchmarkResult.calculate(operation_name, total_time, config.iterations, min_time, max_time);
}

/// Test lazy loading performance
test "benchmark lazy loading" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = zledger_integration.NodeConfig{
        .node_id = "benchmark-lazy-node",
        .enable_audit = true,
        .enable_crypto_storage = true,
        .enable_contracts = true,
        .lazy_load = true,
    };

    // Benchmark node initialization
    const init_result = try runBenchmark(allocator, "Node Initialization", struct {
        fn operation() !void {
            var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
            defer node.deinit();
        }
    }.operation, BenchmarkConfig{ .iterations = 100 });

    init_result.print();

    // Benchmark component lazy loading
    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    const ledger_init_result = try runBenchmark(allocator, "Ledger Lazy Loading", struct {
        node_ptr: *zledger_integration.KeystoneNode,

        fn init(n: *zledger_integration.KeystoneNode) @This() {
            return .{ .node_ptr = n };
        }

        fn operation(self: @This()) !void {
            try self.node_ptr.ensureLedgerInitialized();
        }
    }.init(&node).operation, BenchmarkConfig{ .iterations = 1000 });

    ledger_init_result.print();

    const gas_ledger_result = try runBenchmark(allocator, "Gas Ledger Access", struct {
        node_ptr: *zledger_integration.KeystoneNode,

        fn init(n: *zledger_integration.KeystoneNode) @This() {
            return .{ .node_ptr = n };
        }

        fn operation(self: @This()) !void {
            _ = try self.node_ptr.getGasLedger();
        }
    }.init(&node).operation, default_config);

    gas_ledger_result.print();
}

/// Test gas management performance
test "benchmark gas management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = zledger_integration.NodeConfig{
        .node_id = "benchmark-gas-node",
        .enable_audit = true,
        .lazy_load = true,
    };

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    const gas_ledger = try node.getGasLedger();
    const test_account = try node.createAccount("BenchmarkAccount", .Assets);

    // Benchmark basic gas charging
    const gas_charge_result = try runBenchmark(allocator, "Gas Charge Operations", struct {
        gas_ledger_ptr: *zledger_integration.GasLedger,
        account_id: u32,

        fn init(gl: *zledger_integration.GasLedger, account: u32) @This() {
            return .{ .gas_ledger_ptr = gl, .account_id = account };
        }

        fn operation(self: @This()) !void {
            try self.gas_ledger_ptr.chargeGas(self.account_id, 21000, 0.00000002, 0.000000001);
        }
    }.init(gas_ledger, test_account).operation, default_config);

    gas_charge_result.print();

    // Benchmark gas statistics retrieval
    const gas_stats_result = try runBenchmark(allocator, "Gas Statistics Retrieval", struct {
        gas_ledger_ptr: *zledger_integration.GasLedger,

        fn init(gl: *zledger_integration.GasLedger) @This() {
            return .{ .gas_ledger_ptr = gl };
        }

        fn operation(self: @This()) !zledger_integration.GasStatistics {
            return try self.gas_ledger_ptr.getGasStats();
        }
    }.init(gas_ledger).operation, default_config);

    gas_stats_result.print();

    // Benchmark higher gas operations (contract calls)
    const contract_gas_result = try runBenchmark(allocator, "Contract Gas Operations", struct {
        gas_ledger_ptr: *zledger_integration.GasLedger,
        account_id: u32,

        fn init(gl: *zledger_integration.GasLedger, account: u32) @This() {
            return .{ .gas_ledger_ptr = gl, .account_id = account };
        }

        fn operation(self: @This()) !void {
            try self.gas_ledger_ptr.chargeGas(self.account_id, 150000, 0.00000003, 0.000000002);
        }
    }.init(gas_ledger, test_account).operation, BenchmarkConfig{ .iterations = 500 });

    contract_gas_result.print();
}

/// Test cryptographic operations performance
test "benchmark cryptographic operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test data
    const test_data_small = "Small test data for encryption";
    const test_data_medium = "This is a medium-sized test data string that represents typical data that might be encrypted in a real-world scenario. It contains enough text to give a realistic performance measurement for AES-256 encryption operations.";
    const test_data_large = test_data_medium ** 10; // 10x repetition for larger data

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Benchmark AES-256 encryption (small data)
    const encrypt_small_result = try runBenchmark(allocator, "AES-256 Encrypt (Small)", struct {
        data: []const u8,
        encryption_key: [32]u8,

        fn init(d: []const u8, k: [32]u8) @This() {
            return .{ .data = d, .encryption_key = k };
        }

        fn operation(self: @This()) ![]u8 {
            return try zcrypto.aes256.encrypt(allocator, self.data, self.encryption_key);
        }
    }.init(test_data_small, key).operation, default_config);

    encrypt_small_result.print();

    // Benchmark AES-256 encryption (medium data)
    const encrypt_medium_result = try runBenchmark(allocator, "AES-256 Encrypt (Medium)", struct {
        data: []const u8,
        encryption_key: [32]u8,

        fn init(d: []const u8, k: [32]u8) @This() {
            return .{ .data = d, .encryption_key = k };
        }

        fn operation(self: @This()) ![]u8 {
            return try zcrypto.aes256.encrypt(allocator, self.data, self.encryption_key);
        }
    }.init(test_data_medium, key).operation, BenchmarkConfig{ .iterations = 500 });

    encrypt_medium_result.print();

    // Benchmark AES-256 encryption (large data)
    const encrypt_large_result = try runBenchmark(allocator, "AES-256 Encrypt (Large)", struct {
        data: []const u8,
        encryption_key: [32]u8,

        fn init(d: []const u8, k: [32]u8) @This() {
            return .{ .data = d, .encryption_key = k };
        }

        fn operation(self: @This()) ![]u8 {
            return try zcrypto.aes256.encrypt(allocator, self.data, self.encryption_key);
        }
    }.init(test_data_large, key).operation, BenchmarkConfig{ .iterations = 100 });

    encrypt_large_result.print();

    // Benchmark Ed25519 key generation
    const keygen_result = try runBenchmark(allocator, "Ed25519 Key Generation", struct {
        fn operation() !zledger.Keypair {
            return try zledger.generateKeypair();
        }
    }.operation, default_config);

    keygen_result.print();

    // Benchmark Ed25519 signing
    const keypair = try zledger.generateKeypair();
    const sign_result = try runBenchmark(allocator, "Ed25519 Signing", struct {
        signing_key: zledger.Keypair,
        message: []const u8,

        fn init(k: zledger.Keypair, m: []const u8) @This() {
            return .{ .signing_key = k, .message = m };
        }

        fn operation(self: @This()) !zledger.Signature {
            return try zledger.signMessage(self.signing_key, self.message);
        }
    }.init(keypair, test_data_medium).operation, default_config);

    sign_result.print();

    // Benchmark Ed25519 verification
    const signature = try zledger.signMessage(keypair, test_data_medium);
    const verify_result = try runBenchmark(allocator, "Ed25519 Verification", struct {
        public_key: [32]u8,
        message: []const u8,
        sig: zledger.Signature,

        fn init(pk: [32]u8, m: []const u8, s: zledger.Signature) @This() {
            return .{ .public_key = pk, .message = m, .sig = s };
        }

        fn operation(self: @This()) !bool {
            return try zcrypto.ed25519.verify(self.public_key, self.message, self.sig.bytes);
        }
    }.init(keypair.public_key, test_data_medium, signature).operation, default_config);

    verify_result.print();
}

/// Test contract storage performance
test "benchmark contract storage" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = zledger_integration.NodeConfig{
        .node_id = "benchmark-contract-node",
        .enable_crypto_storage = true,
        .enable_contracts = true,
        .lazy_load = true,
    };

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    const contract_state = try node.getContractState();
    const test_contract = "0xbenchmarkcontract1234567890abcdef123456";

    // Create contract account once
    _ = try contract_state.getOrCreateContractAccount(test_contract);

    // Benchmark contract account creation
    const account_creation_result = try runBenchmark(allocator, "Contract Account Creation", struct {
        contract_state_ptr: *zledger_integration.ContractState,
        counter: u32 = 0,

        fn init(cs: *zledger_integration.ContractState) @This() {
            return .{ .contract_state_ptr = cs };
        }

        fn operation(self: *@This()) !u32 {
            const address = try std.fmt.allocPrint(allocator, "0xbench{d:0>35}", .{self.counter});
            defer allocator.free(address);
            self.counter += 1;
            return try self.contract_state_ptr.getOrCreateContractAccount(address);
        }
    }.init(contract_state).operation, BenchmarkConfig{ .iterations = 500 });

    account_creation_result.print();

    // Benchmark encrypted storage write operations
    const storage_write_result = try runBenchmark(allocator, "Contract Storage Write", struct {
        contract_state_ptr: *zledger_integration.ContractState,
        contract_addr: []const u8,
        counter: u32 = 0,

        fn init(cs: *zledger_integration.ContractState, addr: []const u8) @This() {
            return .{ .contract_state_ptr = cs, .contract_addr = addr };
        }

        fn operation(self: *@This()) !void {
            const key = try std.fmt.allocPrint(allocator, "key_{d}", .{self.counter});
            defer allocator.free(key);
            const value = try std.fmt.allocPrint(allocator, "value_for_key_{d}", .{self.counter});
            defer allocator.free(value);
            self.counter += 1;

            try self.contract_state_ptr.storeContractData(self.contract_addr, key, value);
        }
    }.init(contract_state, test_contract).operation, default_config);

    storage_write_result.print();

    // Pre-populate some data for read benchmark
    for (0..100) |i| {
        const key = try std.fmt.allocPrint(allocator, "read_key_{d}", .{i});
        defer allocator.free(key);
        const value = try std.fmt.allocPrint(allocator, "read_value_{d}", .{i});
        defer allocator.free(value);
        try contract_state.storeContractData(test_contract, key, value);
    }

    // Benchmark encrypted storage read operations
    const storage_read_result = try runBenchmark(allocator, "Contract Storage Read", struct {
        contract_state_ptr: *zledger_integration.ContractState,
        contract_addr: []const u8,
        counter: u32 = 0,

        fn init(cs: *zledger_integration.ContractState, addr: []const u8) @This() {
            return .{ .contract_state_ptr = cs, .contract_addr = addr };
        }

        fn operation(self: *@This()) !?[]u8 {
            const key = try std.fmt.allocPrint(allocator, "read_key_{d}", .{self.counter % 100});
            defer allocator.free(key);
            self.counter += 1;

            return try self.contract_state_ptr.getContractData(self.contract_addr, key);
        }
    }.init(contract_state, test_contract).operation, default_config);

    storage_read_result.print();

    // Benchmark contract balance updates
    const balance_update_result = try runBenchmark(allocator, "Contract Balance Update", struct {
        contract_state_ptr: *zledger_integration.ContractState,
        contract_addr: []const u8,

        fn init(cs: *zledger_integration.ContractState, addr: []const u8) @This() {
            return .{ .contract_state_ptr = cs, .contract_addr = addr };
        }

        fn operation(self: @This()) !void {
            try self.contract_state_ptr.updateContractBalance(self.contract_addr, 100);
        }
    }.init(contract_state, test_contract).operation, default_config);

    balance_update_result.print();
}

/// Test synchronization performance
test "benchmark synchronization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = zledger_integration.NodeConfig{
        .node_id = "benchmark-sync-node",
        .enable_audit = true,
        .lazy_load = true,
    };

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    const sync_manager = try node.getSyncManager();

    // Benchmark peer addition
    const peer_add_result = try runBenchmark(allocator, "Peer Addition", struct {
        sync_manager_ptr: *zledger_integration.SyncManager,
        counter: u32 = 0,

        fn init(sm: *zledger_integration.SyncManager) @This() {
            return .{ .sync_manager_ptr = sm };
        }

        fn operation(self: *@This()) !void {
            const peer_id = try std.fmt.allocPrint(allocator, "benchmark-peer-{d}", .{self.counter});
            defer allocator.free(peer_id);
            self.counter += 1;

            try self.sync_manager_ptr.addPeer(peer_id);
        }
    }.init(sync_manager).operation, BenchmarkConfig{ .iterations = 500 });

    peer_add_result.print();

    // Benchmark journal retrieval
    const journal_result = try runBenchmark(allocator, "Journal Retrieval", struct {
        node_ptr: *zledger_integration.KeystoneNode,

        fn init(n: *zledger_integration.KeystoneNode) @This() {
            return .{ .node_ptr = n };
        }

        fn operation(self: @This()) ![]zledger.JournalEntry {
            const timestamp = std.time.timestamp() - 3600; // 1 hour ago
            return try self.node_ptr.getJournalForSync(timestamp);
        }
    }.init(&node).operation, BenchmarkConfig{ .iterations = 100 });

    journal_result.print();

    // Benchmark sync cycle
    const sync_cycle_result = try runBenchmark(allocator, "Sync Cycle", struct {
        sync_manager_ptr: *zledger_integration.SyncManager,

        fn init(sm: *zledger_integration.SyncManager) @This() {
            return .{ .sync_manager_ptr = sm };
        }

        fn operation(self: @This()) !void {
            try self.sync_manager_ptr.syncWithPeers();
        }
    }.init(sync_manager).operation, BenchmarkConfig{ .iterations = 100 });

    sync_cycle_result.print();

    // Benchmark audit report generation
    const audit_result = try runBenchmark(allocator, "Audit Report Generation", struct {
        node_ptr: *zledger_integration.KeystoneNode,

        fn init(n: *zledger_integration.KeystoneNode) @This() {
            return .{ .node_ptr = n };
        }

        fn operation(self: @This()) !zledger.DistributedAuditReport {
            return try self.node_ptr.generateAuditReport();
        }
    }.init(&node).operation, BenchmarkConfig{ .iterations = 100 });

    audit_result.print();
}

/// Test error handling performance
test "benchmark error handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Benchmark circuit breaker operations
    var circuit_breaker = error_handling.CircuitBreaker.init(allocator, 5, 1000);

    const circuit_breaker_result = try runBenchmark(allocator, "Circuit Breaker (Success)", struct {
        cb: *error_handling.CircuitBreaker,

        fn init(circuit_breaker_ptr: *error_handling.CircuitBreaker) @This() {
            return .{ .cb = circuit_breaker_ptr };
        }

        fn operation(self: @This()) !u32 {
            return try self.cb.execute(u32, struct {
                fn call() anyerror!u32 {
                    return 42;
                }
            }.call);
        }
    }.init(&circuit_breaker).operation, default_config);

    circuit_breaker_result.print();

    // Benchmark retry mechanism
    const retry_config = error_handling.RetryConfig{
        .max_attempts = 1, // Single attempt for performance testing
        .base_delay_ms = 0, // No delay for performance testing
    };

    const retry_result = try runBenchmark(allocator, "Retry Mechanism", struct {
        config: error_handling.RetryConfig,

        fn init(cfg: error_handling.RetryConfig) @This() {
            return .{ .config = cfg };
        }

        fn operation(self: @This()) !u32 {
            return try error_handling.retryWithBackoff(u32, struct {
                fn call() anyerror!u32 {
                    return 42;
                }
            }.call, self.config);
        }
    }.init(retry_config).operation, default_config);

    retry_result.print();

    // Benchmark error context creation
    const error_context_result = try runBenchmark(allocator, "Error Context Creation", struct {
        fn operation() !error_handling.ErrorContext {
            return try error_handling.ErrorContext.init(
                allocator,
                "benchmark_operation",
                "benchmark_node",
                error_handling.KeystoneError.NetworkUnavailable,
                "Benchmark error details"
            );
        }
    }.operation, default_config);

    error_context_result.print();

    // Benchmark error reporter
    var error_reporter = error_handling.ErrorReporter.init(allocator);
    defer error_reporter.deinit();

    const error_reporter_result = try runBenchmark(allocator, "Error Reporting", struct {
        reporter: *error_handling.ErrorReporter,

        fn init(r: *error_handling.ErrorReporter) @This() {
            return .{ .reporter = r };
        }

        fn operation(self: @This()) !void {
            try self.reporter.reportError(
                "benchmark_operation",
                "benchmark_node",
                error_handling.KeystoneError.TestFailure,
                "Benchmark error report"
            );
        }
    }.init(&error_reporter).operation, BenchmarkConfig{ .iterations = 500 });

    error_reporter_result.print();
}

/// Comprehensive performance test
test "comprehensive performance benchmark" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== Keystone v0.2.3 RC1 Performance Benchmark ===\n\n");

    const test_config = zledger_integration.NodeConfig{
        .node_id = "comprehensive-benchmark-node",
        .enable_audit = true,
        .enable_crypto_storage = true,
        .enable_contracts = true,
        .lazy_load = true,
    };

    var node = try zledger_integration.KeystoneNode.init(allocator, test_config);
    defer node.deinit();

    var recovery_manager = try error_handling.initializeErrorHandling(allocator, &node);
    defer recovery_manager.deinit();

    // End-to-end operation benchmark
    const e2e_result = try runBenchmark(allocator, "End-to-End Operation", struct {
        node_ptr: *zledger_integration.KeystoneNode,
        counter: u32 = 0,

        fn init(n: *zledger_integration.KeystoneNode) @This() {
            return .{ .node_ptr = n };
        }

        fn operation(self: *@This()) !void {
            // Create account
            const account_name = try std.fmt.allocPrint(allocator, "Account_{d}", .{self.counter});
            defer allocator.free(account_name);
            const account_id = try self.node_ptr.createAccount(account_name, .Assets);

            // Charge gas
            const gas_ledger = try self.node_ptr.getGasLedger();
            try gas_ledger.chargeGas(account_id, 21000, 0.00000002, 0.000000001);

            // Deploy contract
            const contract_address = try std.fmt.allocPrint(allocator, "0xe2e{d:0>36}", .{self.counter});
            defer allocator.free(contract_address);
            const contract_state = try self.node_ptr.getContractState();
            _ = try contract_state.getOrCreateContractAccount(contract_address);

            // Store encrypted data
            try contract_state.storeContractData(contract_address, "balance", "1000");

            self.counter += 1;
        }
    }.init(&node).operation, BenchmarkConfig{ .iterations = 100 });

    e2e_result.print();

    std.debug.print("=== Benchmark Summary ===\n");
    std.debug.print("All benchmarks completed successfully!\n");
    std.debug.print("End-to-end operations: {d:.0} ops/second\n", .{e2e_result.ops_per_second});
    std.debug.print("\nSystem is ready for RC1 release.\n\n");
}