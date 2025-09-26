//! Smart Contracts Example for Keystone v0.2.3 RC1
//!
//! This example demonstrates:
//! - Deploying smart contracts
//! - Encrypted contract storage
//! - Contract method execution
//! - Balance management

const std = @import("std");
const zledger_integration = @import("../src/zledger_integration.zig");
const zledger = @import("zledger");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("🚀 Starting Smart Contracts Example");

    // Initialize Keystone Node with contracts enabled
    const config = zledger_integration.NodeConfig{
        .node_id = "contract-example-node",
        .enable_audit = true,
        .enable_crypto_storage = true,
        .enable_contracts = true, // Essential for contract features
        .lazy_load = true,
    };

    var keystone_node = try zledger_integration.KeystoneNode.init(allocator, config);
    defer keystone_node.deinit();

    std.log.info("✅ Keystone node initialized with contracts enabled");

    // Step 1: Deploy a simple ERC-20 style token contract
    std.log.info("📦 Deploying token contract...");

    const contract_address = "0x1234567890abcdef1234567890abcdef12345678";
    const contract_state = try keystone_node.getContractState();

    // Create contract account
    const contract_account_id = try contract_state.getOrCreateContractAccount(contract_address);
    std.log.info("✅ Contract deployed at: {s} (Account ID: {d})", .{ contract_address, contract_account_id });

    // Step 2: Initialize contract storage with encrypted data
    std.log.info("💾 Setting up contract storage...");

    // Store token metadata
    try contract_state.storeContractData(contract_address, "name", "KeystoneToken");
    try contract_state.storeContractData(contract_address, "symbol", "KST");
    try contract_state.storeContractData(contract_address, "decimals", "18");
    try contract_state.storeContractData(contract_address, "totalSupply", "1000000");

    // Store user balances (encrypted)
    try contract_state.storeContractData(contract_address, "balance_alice", "500000");
    try contract_state.storeContractData(contract_address, "balance_bob", "300000");
    try contract_state.storeContractData(contract_address, "balance_charlie", "200000");

    std.log.info("✅ Contract storage initialized with encrypted data");

    // Step 3: Simulate contract method calls
    std.log.info("📞 Executing contract methods...");

    // Transfer from Alice to Bob (simulate transfer method)
    const transfer_amount: i64 = 10000;
    try simulateTransfer(contract_state, contract_address, "alice", "bob", transfer_amount);

    // Approve spending allowance
    try contract_state.storeContractData(contract_address, "allowance_alice_bob", "50000");
    std.log.info("✅ Alice approved Bob to spend 50,000 tokens");

    // Step 4: Query contract state
    std.log.info("🔍 Querying contract state...");

    const token_name = try contract_state.getContractData(contract_address, "name");
    defer if (token_name) |name| allocator.free(name);

    const alice_balance = try contract_state.getContractData(contract_address, "balance_alice");
    defer if (alice_balance) |balance| allocator.free(balance);

    const bob_balance = try contract_state.getContractData(contract_address, "balance_bob");
    defer if (bob_balance) |balance| allocator.free(balance);

    if (token_name) |name| {
        std.log.info("📋 Contract state:");
        std.log.info("  Token Name: {s}", .{name});
    }

    if (alice_balance) |balance| {
        std.log.info("  Alice Balance: {s} KST", .{balance});
    }

    if (bob_balance) |balance| {
        std.log.info("  Bob Balance: {s} KST", .{balance});
    }

    // Step 5: Contract balance management
    std.log.info("💰 Managing contract balances...");

    // Update contract balance in ledger (for gas payments, etc.)
    try contract_state.updateContractBalance(contract_address, 1000); // Add funds
    try contract_state.updateContractBalance(contract_address, -500); // Deduct gas costs

    // Step 6: Deploy a second contract (DeFi pool example)
    std.log.info("🏦 Deploying DeFi pool contract...");

    const pool_address = "0xabcdef1234567890abcdef1234567890abcdef12";
    _ = try contract_state.getOrCreateContractAccount(pool_address);

    // Initialize pool with liquidity
    try contract_state.storeContractData(pool_address, "token0", contract_address);
    try contract_state.storeContractData(pool_address, "token1", "0x0000000000000000000000000000000000000001"); // ETH
    try contract_state.storeContractData(pool_address, "reserve0", "100000");
    try contract_state.storeContractData(pool_address, "reserve1", "50");

    std.log.info("✅ DeFi pool deployed with initial liquidity");

    // Step 7: Gas management for contract operations
    std.log.info("⛽ Managing gas for contract operations...");

    const gas_ledger = try keystone_node.getGasLedger();

    // Charge gas for contract deployment (higher cost)
    try gas_ledger.chargeGas(1, 200000, 0.00000003, 0.000000002);

    // Charge gas for contract calls
    try gas_ledger.chargeGas(1, 50000, 0.00000002, 0.000000001);
    try gas_ledger.chargeGas(1, 75000, 0.00000002, 0.000000001);

    const gas_stats = try gas_ledger.getGasStats();
    std.log.info("📊 Gas usage for contract operations:");
    std.log.info("  Total burned: {d} units", .{gas_stats.total_burned});
    std.log.info("  Total distributed: {d} units", .{gas_stats.total_distributed});

    // Step 8: Generate comprehensive audit report
    std.log.info("📋 Generating audit report for contract operations...");

    const audit_report = try keystone_node.generateAuditReport();
    defer audit_report.deinit();

    std.log.info("✅ Audit report:");
    std.log.info("  Node ID: {s}", .{audit_report.keystone_node_id});
    std.log.info("  Features: {s}", .{audit_report.features_enabled});
    std.log.info("  Consensus ready: {}", .{audit_report.consensus_ready});

    std.log.info("🎉 Smart contracts example completed successfully!");
}

/// Simulate a token transfer by updating encrypted balances
fn simulateTransfer(
    contract_state: *zledger_integration.ContractState,
    contract_address: []const u8,
    from: []const u8,
    to: []const u8,
    amount: i64,
) !void {
    const allocator = contract_state.allocator;

    // Get current balances
    const from_key = try std.fmt.allocPrint(allocator, "balance_{s}", .{from});
    defer allocator.free(from_key);

    const to_key = try std.fmt.allocPrint(allocator, "balance_{s}", .{to});
    defer allocator.free(to_key);

    const from_balance_str = try contract_state.getContractData(contract_address, from_key);
    defer if (from_balance_str) |balance| allocator.free(balance);

    const to_balance_str = try contract_state.getContractData(contract_address, to_key);
    defer if (to_balance_str) |balance| allocator.free(balance);

    if (from_balance_str == null or to_balance_str == null) {
        return error.AccountNotFound;
    }

    // Parse balances
    const from_balance = std.fmt.parseInt(i64, from_balance_str.?, 10) catch return error.InvalidBalance;
    const to_balance = std.fmt.parseInt(i64, to_balance_str.?, 10) catch return error.InvalidBalance;

    if (from_balance < amount) {
        return error.InsufficientBalance;
    }

    // Update balances
    const new_from_balance = from_balance - amount;
    const new_to_balance = to_balance + amount;

    const new_from_str = try std.fmt.allocPrint(allocator, "{d}", .{new_from_balance});
    defer allocator.free(new_from_str);

    const new_to_str = try std.fmt.allocPrint(allocator, "{d}", .{new_to_balance});
    defer allocator.free(new_to_str);

    // Store updated balances (encrypted)
    try contract_state.storeContractData(contract_address, from_key, new_from_str);
    try contract_state.storeContractData(contract_address, to_key, new_to_str);

    // Update contract balance in ledger
    try contract_state.updateContractBalance(contract_address, -10); // Small fee for transfer

    std.log.info("💸 Transfer executed: {s} -> {s}: {d} tokens", .{ from, to, amount });
}

/// Advanced contract example with state machine
const ContractState = enum {
    Inactive,
    Active,
    Paused,
    Terminated,
};

fn simulateStateMachine(
    contract_state: *zledger_integration.ContractState,
    contract_address: []const u8,
    new_state: ContractState,
) !void {
    const state_str = switch (new_state) {
        .Inactive => "inactive",
        .Active => "active",
        .Paused => "paused",
        .Terminated => "terminated",
    };

    try contract_state.storeContractData(contract_address, "state", state_str);
    std.log.info("🔄 Contract state changed to: {s}", .{state_str});
}

test "smart contract operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = zledger_integration.NodeConfig{
        .node_id = "test-contract-node",
        .enable_audit = true,
        .enable_crypto_storage = true,
        .enable_contracts = true,
        .lazy_load = true,
    };

    var keystone_node = try zledger_integration.KeystoneNode.init(allocator, config);
    defer keystone_node.deinit();

    // Test contract deployment
    const contract_state = try keystone_node.getContractState();
    const test_contract = "0xtest1234567890abcdef";

    const account_id = try contract_state.getOrCreateContractAccount(test_contract);
    try std.testing.expect(account_id > 0);

    // Test encrypted storage
    try contract_state.storeContractData(test_contract, "test_key", "test_value");

    const retrieved_value = try contract_state.getContractData(test_contract, "test_key");
    defer if (retrieved_value) |value| allocator.free(value);

    try std.testing.expect(retrieved_value != null);
    try std.testing.expectEqualStrings("test_value", retrieved_value.?);

    // Test balance updates
    try contract_state.updateContractBalance(test_contract, 1000);
    try contract_state.updateContractBalance(test_contract, -500);

    // Should not throw errors
}

test "transfer simulation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = zledger_integration.NodeConfig{
        .node_id = "test-transfer-node",
        .enable_contracts = true,
        .enable_crypto_storage = true,
        .lazy_load = true,
    };

    var keystone_node = try zledger_integration.KeystoneNode.init(allocator, config);
    defer keystone_node.deinit();

    const contract_state = try keystone_node.getContractState();
    const test_contract = "0xtest_transfer_contract";

    // Set up initial balances
    try contract_state.storeContractData(test_contract, "balance_alice", "1000");
    try contract_state.storeContractData(test_contract, "balance_bob", "500");

    // Execute transfer
    try simulateTransfer(contract_state, test_contract, "alice", "bob", 100);

    // Verify balances
    const alice_balance = try contract_state.getContractData(test_contract, "balance_alice");
    defer if (alice_balance) |balance| allocator.free(balance);

    const bob_balance = try contract_state.getContractData(test_contract, "balance_bob");
    defer if (bob_balance) |balance| allocator.free(balance);

    try std.testing.expectEqualStrings("900", alice_balance.?);
    try std.testing.expectEqualStrings("600", bob_balance.?);
}