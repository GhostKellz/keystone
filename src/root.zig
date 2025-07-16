//! Keystone v0.1.0 - Ledger and Transaction Coordinator
//! 
//! Keystone is the foundation layer for the GhostKellz ecosystem, providing:
//! - Deterministic ledger state management
//! - Transaction coordination and validation  
//! - Audit journaling and integrity verification
//! - CLI interface for devnet and local validation
//!
//! Design principles:
//! - Opinionated: Clear transaction model and validation rules
//! - Identity-aware: Integration with Shroud DID system (future)
//! - Transparent: All logic is auditable and verifiable

const std = @import("std");

// Export main modules
pub const Transaction = @import("transaction.zig").Transaction;
pub const TxInput = @import("transaction.zig").TxInput;
pub const TxOutput = @import("transaction.zig").TxOutput;
pub const LedgerState = @import("ledger.zig").LedgerState;
pub const Account = @import("ledger.zig").Account;
pub const Journal = @import("journal.zig").Journal;
pub const JournalEntry = @import("journal.zig").JournalEntry;
pub const Cli = @import("cli.zig").Cli;

/// Keystone version
pub const VERSION = "0.1.0";

/// Create a simple transaction for testing
pub fn createSimpleTransaction(allocator: std.mem.Allocator, recipient: []const u8, amount: u64, memo: ?[]const u8) !Transaction {
    var tx = try Transaction.init(allocator, 1, memo);
    const output = try TxOutput.init(allocator, amount, recipient, null);
    try tx.addOutput(output);
    return tx;
}

/// Initialize a basic ledger with genesis account
pub fn initializeLedger(allocator: std.mem.Allocator) !LedgerState {
    var ledger = LedgerState.init(allocator);
    try ledger.createAccount("genesis", "Genesis account");
    return ledger;
}

pub fn bufferedPrint() !void {
    // Stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.fs.File.stdout().deprecatedWriter();
    // Buffering can improve performance significantly in print-heavy programs.
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Keystone v{s} - Ledger and Transaction Coordinator\n", .{VERSION});
    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // Don't forget to flush!
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}

test "simple transaction creation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var tx = try createSimpleTransaction(allocator, "alice", 1000, "Test payment");
    defer tx.deinit(allocator);
    
    try std.testing.expect(tx.outputs.items.len == 1);
    try std.testing.expect(tx.getTotalOutputValue() == 1000);
}

test "ledger initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var ledger = try initializeLedger(allocator);
    defer ledger.deinit();
    
    try std.testing.expect(ledger.getBalance("genesis").? == 0);
    try std.testing.expect(ledger.accounts.count() == 1);
}
