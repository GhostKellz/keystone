//! Distributed Synchronization Example for Keystone v0.2.3 RC1
//!
//! This example demonstrates:
//! - Setting up multiple nodes
//! - Peer-to-peer synchronization
//! - Journal replay mechanisms
//! - Consensus and validation

const std = @import("std");
const zledger_integration = @import("../src/zledger_integration.zig");
const zledger = @import("zledger");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("🚀 Starting Distributed Synchronization Example");

    // Step 1: Set up multiple Keystone nodes
    std.log.info("🌐 Setting up distributed nodes...");

    var nodes = std.ArrayList(zledger_integration.KeystoneNode).init(allocator);
    defer {
        for (nodes.items) |*node| {
            node.deinit();
        }
        nodes.deinit();
    }

    // Create three nodes representing different participants
    const node_configs = [_]zledger_integration.NodeConfig{
        .{
            .node_id = "keystone-validator-001",
            .enable_audit = true,
            .enable_crypto_storage = true,
            .enable_contracts = true,
            .lazy_load = true,
        },
        .{
            .node_id = "keystone-validator-002",
            .enable_audit = true,
            .enable_crypto_storage = true,
            .enable_contracts = true,
            .lazy_load = true,
        },
        .{
            .node_id = "keystone-archive-node",
            .enable_audit = true,
            .enable_crypto_storage = false, // Archive node doesn't need encrypted storage
            .enable_contracts = false, // Archive node focuses on consensus
            .lazy_load = true,
        },
    };

    for (node_configs) |config| {
        const node = try zledger_integration.KeystoneNode.init(allocator, config);
        try nodes.append(node);
        std.log.info("✅ Node initialized: {s}", .{config.node_id});
    }

    // Step 2: Configure peer relationships
    std.log.info("🤝 Configuring peer relationships...");

    // Node 0 knows about Node 1 and Node 2
    const sync_manager_0 = try nodes.items[0].getSyncManager();
    try sync_manager_0.addPeer("keystone-validator-002");
    try sync_manager_0.addPeer("keystone-archive-node");

    // Node 1 knows about Node 0 and Node 2
    const sync_manager_1 = try nodes.items[1].getSyncManager();
    try sync_manager_1.addPeer("keystone-validator-001");
    try sync_manager_1.addPeer("keystone-archive-node");

    // Node 2 (archive) knows about both validators
    const sync_manager_2 = try nodes.items[2].getSyncManager();
    try sync_manager_2.addPeer("keystone-validator-001");
    try sync_manager_2.addPeer("keystone-validator-002");

    std.log.info("✅ Peer relationships configured");

    // Step 3: Create accounts on different nodes
    std.log.info("👥 Creating accounts across nodes...");

    // Create accounts on Node 0 (Validator 001)
    const alice_account = try nodes.items[0].createAccount("Alice", .Assets);
    const bob_account = try nodes.items[0].createAccount("Bob", .Assets);

    // Create accounts on Node 1 (Validator 002)
    const charlie_account = try nodes.items[1].createAccount("Charlie", .Assets);
    const diana_account = try nodes.items[1].createAccount("Diana", .Assets);

    std.log.info("✅ Accounts created:");
    std.log.info("  Node 0: Alice({d}), Bob({d})", .{ alice_account, bob_account });
    std.log.info("  Node 1: Charlie({d}), Diana({d})", .{ charlie_account, diana_account });

    // Step 4: Simulate transactions on different nodes
    std.log.info("💰 Simulating distributed transactions...");

    // Transaction on Node 0
    try simulateTransaction(&nodes.items[0], alice_account, bob_account, 1000, "Initial funding");

    // Transaction on Node 1
    try simulateTransaction(&nodes.items[1], charlie_account, diana_account, 500, "Cross-node transfer");

    // More transactions to create divergent state
    try simulateTransaction(&nodes.items[0], bob_account, alice_account, 200, "Refund transaction");
    try simulateTransaction(&nodes.items[1], diana_account, charlie_account, 100, "Service payment");

    std.log.info("✅ Transactions completed on different nodes");

    // Step 5: Demonstrate journal synchronization
    std.log.info("🔄 Starting synchronization process...");

    // Get journal entries from each node for sync demonstration
    const timestamp_24h_ago = std.time.timestamp() - (24 * 3600);

    for (nodes.items, 0..) |*node, i| {
        std.log.info("📋 Node {d} ({s}) synchronizing...", .{ i, node.node_id });

        const journal_entries = try node.getJournalForSync(timestamp_24h_ago);
        defer node.allocator.free(journal_entries);

        std.log.info("  📄 Node {d} has {d} journal entries to share", .{ i, journal_entries.len });

        // In a real implementation, these entries would be sent to peer nodes
        // For this example, we'll simulate the validation process
        const sync_manager = try node.getSyncManager();

        for (journal_entries) |entry| {
            const is_valid = try sync_manager.validateJournalEntry(entry);
            std.log.info("  ✓ Entry seq={d} validation: {}", .{ entry.sequence, is_valid });
        }
    }

    // Step 6: Simulate consensus mechanism
    std.log.info("🎯 Demonstrating consensus validation...");

    // Generate audit reports from all nodes
    var audit_reports = std.ArrayList(zledger.DistributedAuditReport).init(allocator);
    defer {
        for (audit_reports.items) |*report| {
            report.deinit();
        }
        audit_reports.deinit();
    }

    for (nodes.items, 0..) |*node, i| {
        const report = try node.generateAuditReport();
        try audit_reports.append(report);
        std.log.info("📊 Node {d} audit report generated", .{i});
    }

    // Compare Merkle roots for consensus (simplified)
    std.log.info("🌳 Comparing Merkle roots for consensus...");

    var consensus_count: u32 = 0;
    for (audit_reports.items, 0..) |report, i| {
        std.log.info("  Node {d}: Consensus ready = {}, Merkle root = {}", .{ i, report.consensus_ready, std.fmt.fmtSliceHexUpper(&report.merkle_root) });
        if (report.consensus_ready) {
            consensus_count += 1;
        }
    }

    const consensus_percentage = (@as(f64, @floatFromInt(consensus_count)) / @as(f64, @floatFromInt(audit_reports.items.len))) * 100.0;
    std.log.info("📈 Consensus status: {d}/{d} nodes ready ({d:.1}%)", .{ consensus_count, audit_reports.items.len, consensus_percentage });

    // Step 7: Demonstrate failure recovery
    std.log.info("🛠️  Simulating failure recovery scenario...");

    // Simulate Node 1 going offline and coming back
    std.log.info("⚠️  Simulating Node 1 temporary failure...");

    // When node comes back online, it would sync from peers
    const failed_node_sync = try nodes.items[1].getSyncManager();

    // Simulate receiving journal entries from peer nodes
    const sync_entries = try nodes.items[0].getJournalForSync(timestamp_24h_ago);
    defer nodes.items[0].allocator.free(sync_entries);

    // Apply sync entries to the "recovered" node
    try nodes.items[1].syncFromJournal(sync_entries);
    std.log.info("✅ Node 1 recovered and synchronized");

    // Step 8: Performance metrics
    std.log.info("📊 Synchronization performance metrics...");

    for (nodes.items, 0..) |*node, i| {
        const sync_manager = try node.getSyncManager();
        std.log.info("Node {d} ({s}):", .{ i, node.node_id });
        std.log.info("  Peers configured: {d}", .{sync_manager.peer_nodes.items.len});
        std.log.info("  Last sync timestamp: {d}", .{sync_manager.last_sync_timestamp});
        std.log.info("  Node online: {}", .{true}); // All nodes are online in this example
    }

    std.log.info("🎉 Distributed synchronization example completed!");
}

/// Simulate a transaction between accounts on a given node
fn simulateTransaction(
    node: *zledger_integration.KeystoneNode,
    from_account: u32,
    to_account: u32,
    amount: u64,
    description: []const u8,
) !void {
    // Ensure the ledger is initialized
    try node.ensureLedgerInitialized();

    // Create a mock transaction (in a real implementation, this would use proper zledger Transaction)
    std.log.info("💸 Transaction: Account {d} -> Account {d}: {d} units ({s})", .{ from_account, to_account, amount, description });

    // Simulate gas cost
    if (node.gas_ledger) |gas_ledger| {
        try gas_ledger.chargeGas(from_account, 21000, 0.00000002, 0.000000001);
    } else {
        // If gas ledger not yet initialized, get it
        const gas_ledger = try node.getGasLedger();
        try gas_ledger.chargeGas(from_account, 21000, 0.00000002, 0.000000001);
    }
}

/// Simulate a multi-node transaction that requires coordination
fn simulateCrossNodeTransaction(
    source_node: *zledger_integration.KeystoneNode,
    target_node: *zledger_integration.KeystoneNode,
    from_account: u32,
    to_account: u32,
    amount: u64,
) !void {
    std.log.info("🌉 Cross-node transaction initiated...");

    // Step 1: Prepare transaction on source node
    try source_node.ensureLedgerInitialized();

    // In a real implementation, this would:
    // 1. Create a cross-node transaction proposal
    // 2. Get approval from both nodes
    // 3. Execute atomically

    std.log.info("📤 Source node ({s}) preparing transfer of {d} units", .{ source_node.node_id, amount });

    // Step 2: Validate on target node
    try target_node.ensureLedgerInitialized();

    std.log.info("📥 Target node ({s}) validating incoming transfer", .{ target_node.node_id });

    // Step 3: Execute on both nodes (simplified)
    const source_gas = try source_node.getGasLedger();
    const target_gas = try target_node.getGasLedger();

    try source_gas.chargeGas(from_account, 50000, 0.00000003, 0.000000002); // Higher gas for cross-node
    try target_gas.chargeGas(to_account, 25000, 0.00000002, 0.000000001); // Processing fee on target

    std.log.info("✅ Cross-node transaction completed");
}

/// Demonstrate consensus algorithm (simplified)
fn checkConsensus(audit_reports: []const zledger.DistributedAuditReport) bool {
    if (audit_reports.len == 0) return false;

    const threshold = (audit_reports.len * 2) / 3; // 2/3 majority
    var ready_count: usize = 0;

    for (audit_reports) |report| {
        if (report.consensus_ready) {
            ready_count += 1;
        }
    }

    return ready_count >= threshold;
}

test "distributed synchronization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create two test nodes
    const config1 = zledger_integration.NodeConfig{
        .node_id = "test-node-1",
        .enable_audit = true,
        .lazy_load = true,
    };

    const config2 = zledger_integration.NodeConfig{
        .node_id = "test-node-2",
        .enable_audit = true,
        .lazy_load = true,
    };

    var node1 = try zledger_integration.KeystoneNode.init(allocator, config1);
    defer node1.deinit();

    var node2 = try zledger_integration.KeystoneNode.init(allocator, config2);
    defer node2.deinit();

    // Test peer addition
    const sync1 = try node1.getSyncManager();
    const sync2 = try node2.getSyncManager();

    try sync1.addPeer("test-node-2");
    try sync2.addPeer("test-node-1");

    try std.testing.expect(sync1.peer_nodes.items.len == 1);
    try std.testing.expect(sync2.peer_nodes.items.len == 1);

    // Test journal synchronization
    const timestamp = std.time.timestamp() - 3600; // 1 hour ago
    const journal_entries = try node1.getJournalForSync(timestamp);
    defer node1.allocator.free(journal_entries);

    // Should not fail
    try node2.syncFromJournal(journal_entries);
}

test "consensus validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create mock audit reports
    var reports = [_]zledger.DistributedAuditReport{
        .{
            .consensus_ready = true,
            .keystone_node_id = "node1",
            .features_enabled = "test",
            .merkle_root = [_]u8{0x01} ** 32,
        },
        .{
            .consensus_ready = true,
            .keystone_node_id = "node2",
            .features_enabled = "test",
            .merkle_root = [_]u8{0x01} ** 32,
        },
        .{
            .consensus_ready = false,
            .keystone_node_id = "node3",
            .features_enabled = "test",
            .merkle_root = [_]u8{0x02} ** 32,
        },
    };

    // 2 out of 3 nodes ready should reach consensus (≥ 2/3 majority)
    try std.testing.expect(checkConsensus(&reports));

    // If only 1 node is ready, should not reach consensus
    reports[1].consensus_ready = false;
    try std.testing.expect(!checkConsensus(&reports));
}