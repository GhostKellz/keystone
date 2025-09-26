//! Basic Usage Example for Keystone v0.2.3 RC1
//!
//! This example demonstrates:
//! - Setting up a Keystone node
//! - Creating accounts
//! - Performing transactions
//! - Basic gas management

const std = @import("std");
const zledger_integration = @import("../src/zledger_integration.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("🚀 Starting Keystone Basic Usage Example");

    // Step 1: Initialize Keystone Node
    const config = zledger_integration.NodeConfig{
        .node_id = "example-basic-node",
        .enable_audit = true,
        .enable_crypto_storage = true,
        .enable_contracts = false, // Keep it simple for basic example
        .lazy_load = true,
    };

    var keystone_node = try zledger_integration.KeystoneNode.init(allocator, config);
    defer keystone_node.deinit();

    std.log.info("✅ Keystone node initialized: {s}", .{keystone_node.node_id});

    // Step 2: Create accounts
    std.log.info("📝 Creating accounts...");

    const alice_account = try keystone_node.createAccount("Alice", .Assets);
    const bob_account = try keystone_node.createAccount("Bob", .Assets);
    const merchant_account = try keystone_node.createAccount("Merchant", .Revenue);

    std.log.info("✅ Created accounts:");
    std.log.info("  Alice: {d}", .{alice_account});
    std.log.info("  Bob: {d}", .{bob_account});
    std.log.info("  Merchant: {d}", .{merchant_account});

    // Step 3: Initialize gas management
    std.log.info("⛽ Setting up gas management...");

    const gas_ledger = try keystone_node.getGasLedger();

    // Simulate some gas usage
    try gas_ledger.chargeGas(alice_account, 21000, 0.00000002, 0.000000001); // Transfer transaction
    try gas_ledger.chargeGas(bob_account, 50000, 0.00000003, 0.000000002); // Contract interaction

    const gas_stats = try gas_ledger.getGasStats();
    std.log.info("📊 Gas statistics:");
    std.log.info("  Total burned: {d} units", .{gas_stats.total_burned});
    std.log.info("  Total distributed: {d} units", .{gas_stats.total_distributed});
    std.log.info("  Current base fee: {d:.9} ETH/gas", .{gas_stats.current_base_fee});

    // Step 4: Generate audit report
    std.log.info("📋 Generating audit report...");

    const audit_report = try keystone_node.generateAuditReport();
    defer audit_report.deinit();

    std.log.info("✅ Audit report generated:");
    std.log.info("  Consensus ready: {}", .{audit_report.consensus_ready});
    std.log.info("  Node ID: {s}", .{audit_report.keystone_node_id});
    std.log.info("  Features: {s}", .{audit_report.features_enabled});

    std.log.info("🎉 Basic usage example completed successfully!");
}

test "basic keystone operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = zledger_integration.NodeConfig{
        .node_id = "test-node",
        .enable_audit = true,
        .enable_crypto_storage = false,
        .enable_contracts = false,
        .lazy_load = true,
    };

    var keystone_node = try zledger_integration.KeystoneNode.init(allocator, config);
    defer keystone_node.deinit();

    // Test account creation
    const account1 = try keystone_node.createAccount("TestAccount1", .Assets);
    const account2 = try keystone_node.createAccount("TestAccount2", .Assets);

    try std.testing.expect(account1 != account2);

    // Test gas ledger
    const gas_ledger = try keystone_node.getGasLedger();
    try gas_ledger.chargeGas(account1, 1000, 0.00000001, 0.0);

    const stats = try gas_ledger.getGasStats();
    try std.testing.expect(stats.total_burned > 0);
}