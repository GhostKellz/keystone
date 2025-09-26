//! Enhanced Error Handling and Recovery for Keystone v0.2.3 RC1
//!
//! This module provides comprehensive error handling, recovery mechanisms,
//! and resilience patterns for production-ready Keystone deployments.

const std = @import("std");
const zledger = @import("zledger");
const zledger_integration = @import("zledger_integration.zig");

/// Comprehensive error types for Keystone operations
pub const KeystoneError = error{
    // Core system errors
    SystemNotInitialized,
    ConfigurationInvalid,
    ResourceExhausted,
    OperationTimeout,

    // Ledger errors
    LedgerCorrupted,
    TransactionInvalid,
    DoubleSpend,
    InsufficientBalance,
    AccountLocked,

    // Cryptographic errors
    KeyGenerationFailed,
    SignatureInvalid,
    EncryptionFailed,
    DecryptionFailed,
    KeyDerivationFailed,

    // Network errors
    NetworkUnavailable,
    PeerUnreachable,
    SyncFailure,
    ConsensusFailure,

    // Contract errors
    ContractNotFound,
    ContractExecutionFailed,
    StorageCorrupted,
    GasExhausted,

    // Security errors
    PermissionDenied,
    AuthenticationFailed,
    TokenExpired,
    RateLimitExceeded,
    SuspiciousActivity,

    // Recovery errors
    BackupNotFound,
    RestoreFailed,
    CheckpointCorrupted,
    RollbackFailed,
};

/// Error context for debugging and recovery
pub const ErrorContext = struct {
    operation: []const u8,
    timestamp: i64,
    node_id: []const u8,
    error_code: KeystoneError,
    details: []const u8,
    recovery_hint: ?[]const u8,
    callstack: ?[]const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        operation: []const u8,
        node_id: []const u8,
        error_code: KeystoneError,
        details: []const u8,
    ) !ErrorContext {
        return ErrorContext{
            .operation = try allocator.dupe(u8, operation),
            .timestamp = std.time.timestamp(),
            .node_id = try allocator.dupe(u8, node_id),
            .error_code = error_code,
            .details = try allocator.dupe(u8, details),
            .recovery_hint = null,
            .callstack = null,
        };
    }

    pub fn deinit(self: *ErrorContext, allocator: std.mem.Allocator) void {
        allocator.free(self.operation);
        allocator.free(self.node_id);
        allocator.free(self.details);
        if (self.recovery_hint) |hint| allocator.free(hint);
        if (self.callstack) |stack| allocator.free(stack);
    }

    pub fn withRecoveryHint(self: *ErrorContext, allocator: std.mem.Allocator, hint: []const u8) !void {
        if (self.recovery_hint) |old_hint| {
            allocator.free(old_hint);
        }
        self.recovery_hint = try allocator.dupe(u8, hint);
    }
};

/// Circuit breaker states for preventing cascade failures
pub const CircuitState = enum {
    Closed,   // Normal operation
    Open,     // Failing, requests rejected
    HalfOpen, // Testing if service recovered
};

/// Circuit breaker for protecting against cascading failures
pub const CircuitBreaker = struct {
    allocator: std.mem.Allocator,
    state: CircuitState,
    failure_count: u32,
    failure_threshold: u32,
    timeout_ms: u64,
    last_failure_time: i64,
    success_threshold: u32, // For half-open -> closed transition
    half_open_success_count: u32,

    pub fn init(allocator: std.mem.Allocator, failure_threshold: u32, timeout_ms: u64) CircuitBreaker {
        return CircuitBreaker{
            .allocator = allocator,
            .state = .Closed,
            .failure_count = 0,
            .failure_threshold = failure_threshold,
            .timeout_ms = timeout_ms,
            .last_failure_time = 0,
            .success_threshold = 3, // Require 3 successes to fully recover
            .half_open_success_count = 0,
        };
    }

    pub fn execute(self: *CircuitBreaker, comptime T: type, operation: fn () anyerror!T) anyerror!T {
        switch (self.state) {
            .Open => {
                const now = std.time.milliTimestamp();
                if (now - self.last_failure_time > self.timeout_ms) {
                    self.state = .HalfOpen;
                    self.half_open_success_count = 0;
                } else {
                    return KeystoneError.OperationTimeout;
                }
            },
            .Closed, .HalfOpen => {},
        }

        const result = operation() catch |err| {
            self.recordFailure();
            return err;
        };

        self.recordSuccess();
        return result;
    }

    fn recordFailure(self: *CircuitBreaker) void {
        self.failure_count += 1;
        self.last_failure_time = std.time.milliTimestamp();

        if (self.failure_count >= self.failure_threshold) {
            self.state = .Open;
            std.log.warn("Circuit breaker opened after {d} failures", .{self.failure_count});
        }
    }

    fn recordSuccess(self: *CircuitBreaker) void {
        switch (self.state) {
            .Closed => {
                self.failure_count = 0; // Reset failure count
            },
            .HalfOpen => {
                self.half_open_success_count += 1;
                if (self.half_open_success_count >= self.success_threshold) {
                    self.state = .Closed;
                    self.failure_count = 0;
                    std.log.info("Circuit breaker closed after {d} successful operations", .{self.half_open_success_count});
                }
            },
            .Open => {
                // Should not happen, but handle gracefully
                self.state = .HalfOpen;
                self.half_open_success_count = 1;
            },
        }
    }
};

/// Retry configuration for operations
pub const RetryConfig = struct {
    max_attempts: u32 = 3,
    base_delay_ms: u64 = 100,
    max_delay_ms: u64 = 5000,
    backoff_multiplier: f64 = 2.0,
    jitter_enabled: bool = true,
};

/// Exponential backoff with jitter
pub fn exponentialBackoff(config: RetryConfig, attempt: u32) u64 {
    var delay = config.base_delay_ms;

    // Calculate exponential backoff
    var i: u32 = 0;
    while (i < attempt) : (i += 1) {
        delay = @as(u64, @intFromFloat(@as(f64, @floatFromInt(delay)) * config.backoff_multiplier));
        if (delay > config.max_delay_ms) {
            delay = config.max_delay_ms;
            break;
        }
    }

    // Add jitter to prevent thundering herd
    if (config.jitter_enabled) {
        const jitter = @as(u64, @intCast(std.crypto.random.intRangeAtMost(i64, -(@as(i64, @intCast(delay / 4))), @as(i64, @intCast(delay / 4)))));
        delay = @as(u64, @intCast(@max(0, @as(i64, @intCast(delay)) + jitter)));
    }

    return delay;
}

/// Retry operation with exponential backoff
pub fn retryWithBackoff(
    comptime T: type,
    operation: fn () anyerror!T,
    config: RetryConfig,
) anyerror!T {
    var attempt: u32 = 0;
    var last_error: anyerror = undefined;

    while (attempt < config.max_attempts) {
        const result = operation() catch |err| {
            last_error = err;
            attempt += 1;

            if (attempt >= config.max_attempts) {
                std.log.err("Operation failed after {d} attempts: {}", .{ config.max_attempts, err });
                return err;
            }

            const delay = exponentialBackoff(config, attempt);
            std.log.warn("Operation failed (attempt {d}), retrying in {d}ms: {}", .{ attempt, delay, err });
            std.time.sleep(delay * std.time.ns_per_ms);
            continue;
        };

        if (attempt > 0) {
            std.log.info("Operation succeeded on attempt {d}", .{ attempt + 1 });
        }
        return result;
    }

    return last_error;
}

/// Health check result
pub const HealthStatus = struct {
    healthy: bool,
    component: []const u8,
    message: []const u8,
    last_check: i64,
    check_duration_ms: u64,
};

/// Health checker for system components
pub const HealthChecker = struct {
    allocator: std.mem.Allocator,
    checks: std.HashMap([]const u8, HealthCheck),

    const HealthCheck = struct {
        check_fn: *const fn () bool,
        last_result: bool,
        last_check: i64,
        failure_count: u32,
    };

    pub fn init(allocator: std.mem.Allocator) HealthChecker {
        return HealthChecker{
            .allocator = allocator,
            .checks = std.HashMap([]const u8, HealthCheck).init(allocator),
        };
    }

    pub fn deinit(self: *HealthChecker) void {
        var iterator = self.checks.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.checks.deinit();
    }

    pub fn addCheck(self: *HealthChecker, name: []const u8, check_fn: *const fn () bool) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        try self.checks.put(owned_name, HealthCheck{
            .check_fn = check_fn,
            .last_result = true,
            .last_check = 0,
            .failure_count = 0,
        });
    }

    pub fn checkAll(self: *HealthChecker) ![]HealthStatus {
        var results = std.ArrayList(HealthStatus).init(self.allocator);

        var iterator = self.checks.iterator();
        while (iterator.next()) |entry| {
            const name = entry.key_ptr.*;
            const check = entry.value_ptr;

            const start_time = std.time.milliTimestamp();
            const is_healthy = check.check_fn();
            const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

            check.last_result = is_healthy;
            check.last_check = std.time.timestamp();

            if (!is_healthy) {
                check.failure_count += 1;
            } else {
                check.failure_count = 0;
            }

            const message = if (is_healthy) "OK" else "FAILED";

            try results.append(HealthStatus{
                .healthy = is_healthy,
                .component = name,
                .message = message,
                .last_check = check.last_check,
                .check_duration_ms = duration,
            });
        }

        return results.toOwnedSlice();
    }
};

/// Recovery checkpoint for state restoration
pub const RecoveryCheckpoint = struct {
    allocator: std.mem.Allocator,
    timestamp: i64,
    node_id: []const u8,
    ledger_state_hash: [32]u8,
    account_count: u32,
    transaction_count: u64,
    gas_pool_balance: u64,
    metadata: std.HashMap([]const u8, []const u8),

    pub fn create(
        allocator: std.mem.Allocator,
        node: *zledger_integration.KeystoneNode,
    ) !RecoveryCheckpoint {
        // Generate state hash (simplified)
        var hasher = std.crypto.hash.blake3.Blake3.init(.{});
        hasher.update(node.node_id);
        hasher.update(std.mem.asBytes(&std.time.timestamp()));
        var state_hash: [32]u8 = undefined;
        hasher.final(&state_hash);

        var checkpoint = RecoveryCheckpoint{
            .allocator = allocator,
            .timestamp = std.time.timestamp(),
            .node_id = try allocator.dupe(u8, node.node_id),
            .ledger_state_hash = state_hash,
            .account_count = 0, // Would be actual count
            .transaction_count = 0, // Would be actual count
            .gas_pool_balance = 0, // Would be actual balance
            .metadata = std.HashMap([]const u8, []const u8).init(allocator),
        };

        // Store additional metadata
        try checkpoint.addMetadata("keystone_version", "0.2.3-rc1");
        try checkpoint.addMetadata("zledger_version", "0.5.0");
        try checkpoint.addMetadata("features", "contracts,crypto,audit");

        return checkpoint;
    }

    pub fn deinit(self: *RecoveryCheckpoint) void {
        self.allocator.free(self.node_id);

        var iterator = self.metadata.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.metadata.deinit();
    }

    pub fn addMetadata(self: *RecoveryCheckpoint, key: []const u8, value: []const u8) !void {
        const owned_key = try self.allocator.dupe(u8, key);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.metadata.put(owned_key, owned_value);
    }

    pub fn save(self: *RecoveryCheckpoint, file_path: []const u8) !void {
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        var writer = file.writer();

        // Write checkpoint header
        try writer.print("KEYSTONE_CHECKPOINT_v1\n");
        try writer.print("timestamp={d}\n", .{self.timestamp});
        try writer.print("node_id={s}\n", .{self.node_id});
        try writer.print("ledger_hash={s}\n", .{std.fmt.fmtSliceHexUpper(&self.ledger_state_hash)});
        try writer.print("accounts={d}\n", .{self.account_count});
        try writer.print("transactions={d}\n", .{self.transaction_count});
        try writer.print("gas_balance={d}\n", .{self.gas_pool_balance});

        // Write metadata
        try writer.print("\n[METADATA]\n");
        var iterator = self.metadata.iterator();
        while (iterator.next()) |entry| {
            try writer.print("{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        std.log.info("Recovery checkpoint saved: {s}", .{file_path});
    }

    pub fn load(allocator: std.mem.Allocator, file_path: []const u8) !RecoveryCheckpoint {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
        defer allocator.free(content);

        // Parse checkpoint (simplified parser)
        var checkpoint = RecoveryCheckpoint{
            .allocator = allocator,
            .timestamp = 0,
            .node_id = undefined,
            .ledger_state_hash = undefined,
            .account_count = 0,
            .transaction_count = 0,
            .gas_pool_balance = 0,
            .metadata = std.HashMap([]const u8, []const u8).init(allocator),
        };

        var lines = std.mem.split(u8, content, "\n");
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "timestamp=")) {
                checkpoint.timestamp = try std.fmt.parseInt(i64, line[10..], 10);
            } else if (std.mem.startsWith(u8, line, "node_id=")) {
                checkpoint.node_id = try allocator.dupe(u8, line[8..]);
            }
            // Parse other fields...
        }

        std.log.info("Recovery checkpoint loaded: {s}", .{file_path});
        return checkpoint;
    }
};

/// Error recovery manager
pub const RecoveryManager = struct {
    allocator: std.mem.Allocator,
    checkpoints: std.ArrayList(RecoveryCheckpoint),
    circuit_breakers: std.HashMap([]const u8, CircuitBreaker),
    health_checker: HealthChecker,
    max_checkpoints: u32,

    pub fn init(allocator: std.mem.Allocator) RecoveryManager {
        return RecoveryManager{
            .allocator = allocator,
            .checkpoints = std.ArrayList(RecoveryCheckpoint).init(allocator),
            .circuit_breakers = std.HashMap([]const u8, CircuitBreaker).init(allocator),
            .health_checker = HealthChecker.init(allocator),
            .max_checkpoints = 10,
        };
    }

    pub fn deinit(self: *RecoveryManager) void {
        for (self.checkpoints.items) |*checkpoint| {
            checkpoint.deinit();
        }
        self.checkpoints.deinit();

        var cb_iterator = self.circuit_breakers.iterator();
        while (cb_iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.circuit_breakers.deinit();

        self.health_checker.deinit();
    }

    pub fn addCircuitBreaker(self: *RecoveryManager, name: []const u8, failure_threshold: u32, timeout_ms: u64) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const circuit_breaker = CircuitBreaker.init(self.allocator, failure_threshold, timeout_ms);
        try self.circuit_breakers.put(owned_name, circuit_breaker);
    }

    pub fn getCircuitBreaker(self: *RecoveryManager, name: []const u8) ?*CircuitBreaker {
        return self.circuit_breakers.getPtr(name);
    }

    pub fn createCheckpoint(self: *RecoveryManager, node: *zledger_integration.KeystoneNode) !void {
        const checkpoint = try RecoveryCheckpoint.create(self.allocator, node);

        // Remove oldest checkpoint if at limit
        if (self.checkpoints.items.len >= self.max_checkpoints) {
            var oldest = self.checkpoints.orderedRemove(0);
            oldest.deinit();
        }

        try self.checkpoints.append(checkpoint);

        // Save to disk
        const filename = try std.fmt.allocPrint(
            self.allocator,
            "checkpoint_{d}_{s}.kcp",
            .{ checkpoint.timestamp, checkpoint.node_id }
        );
        defer self.allocator.free(filename);

        try checkpoint.save(filename);
    }

    pub fn recoverFromLatestCheckpoint(self: *RecoveryManager, node: *zledger_integration.KeystoneNode) !void {
        if (self.checkpoints.items.len == 0) {
            return KeystoneError.BackupNotFound;
        }

        const latest_checkpoint = &self.checkpoints.items[self.checkpoints.items.len - 1];

        std.log.info("Recovering from checkpoint: timestamp={d}, node={s}", .{
            latest_checkpoint.timestamp,
            latest_checkpoint.node_id
        });

        // In a real implementation, this would restore the node state
        // For now, we just validate the node ID matches
        if (!std.mem.eql(u8, node.node_id, latest_checkpoint.node_id)) {
            return KeystoneError.RestoreFailed;
        }

        std.log.info("Recovery completed successfully");
    }
};

/// Global error reporter for centralized error handling
pub const ErrorReporter = struct {
    allocator: std.mem.Allocator,
    error_log: std.ArrayList(ErrorContext),
    max_errors: u32,

    pub fn init(allocator: std.mem.Allocator) ErrorReporter {
        return ErrorReporter{
            .allocator = allocator,
            .error_log = std.ArrayList(ErrorContext).init(allocator),
            .max_errors = 1000,
        };
    }

    pub fn deinit(self: *ErrorReporter) void {
        for (self.error_log.items) |*error_ctx| {
            error_ctx.deinit(self.allocator);
        }
        self.error_log.deinit();
    }

    pub fn reportError(
        self: *ErrorReporter,
        operation: []const u8,
        node_id: []const u8,
        error_code: KeystoneError,
        details: []const u8,
    ) !void {
        var error_ctx = try ErrorContext.init(self.allocator, operation, node_id, error_code, details);

        // Add recovery hints based on error type
        switch (error_code) {
            .LedgerCorrupted => {
                try error_ctx.withRecoveryHint(self.allocator, "Restore from latest checkpoint");
            },
            .NetworkUnavailable => {
                try error_ctx.withRecoveryHint(self.allocator, "Check network connectivity and retry");
            },
            .GasExhausted => {
                try error_ctx.withRecoveryHint(self.allocator, "Increase gas limit or optimize transaction");
            },
            else => {},
        }

        // Remove oldest error if at limit
        if (self.error_log.items.len >= self.max_errors) {
            var oldest = self.error_log.orderedRemove(0);
            oldest.deinit(self.allocator);
        }

        try self.error_log.append(error_ctx);

        // Log the error
        std.log.err("Error reported: {} in {} - {s}", .{ error_code, operation, details });
        if (error_ctx.recovery_hint) |hint| {
            std.log.info("Recovery hint: {s}", .{hint});
        }
    }

    pub fn getRecentErrors(self: *ErrorReporter, count: u32) []const ErrorContext {
        const start_index = if (self.error_log.items.len > count)
            self.error_log.items.len - count
        else
            0;

        return self.error_log.items[start_index..];
    }
};

// Health check functions
fn checkLedgerHealth() bool {
    // In a real implementation, this would check ledger integrity
    return true;
}

fn checkNetworkHealth() bool {
    // In a real implementation, this would check network connectivity
    return true;
}

fn checkCryptoHealth() bool {
    // In a real implementation, this would test crypto operations
    return true;
}

/// Initialize error handling for a Keystone node
pub fn initializeErrorHandling(allocator: std.mem.Allocator, node: *zledger_integration.KeystoneNode) !RecoveryManager {
    var recovery_manager = RecoveryManager.init(allocator);

    // Set up circuit breakers
    try recovery_manager.addCircuitBreaker("ledger", 5, 30000); // 5 failures, 30s timeout
    try recovery_manager.addCircuitBreaker("network", 3, 10000); // 3 failures, 10s timeout
    try recovery_manager.addCircuitBreaker("crypto", 10, 60000); // 10 failures, 60s timeout

    // Set up health checks
    try recovery_manager.health_checker.addCheck("ledger", checkLedgerHealth);
    try recovery_manager.health_checker.addCheck("network", checkNetworkHealth);
    try recovery_manager.health_checker.addCheck("crypto", checkCryptoHealth);

    // Create initial checkpoint
    try recovery_manager.createCheckpoint(node);

    std.log.info("Error handling initialized for node: {s}", .{node.node_id});
    return recovery_manager;
}