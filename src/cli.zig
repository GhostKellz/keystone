const std = @import("std");
const Transaction = @import("transaction.zig").Transaction;
const TxOutput = @import("transaction.zig").TxOutput;
const LedgerState = @import("ledger.zig").LedgerState;
const Journal = @import("journal.zig").Journal;

pub const CliError = error{
    InvalidCommand,
    InvalidArguments,
    FileError,
    LedgerError,
    InsufficientArguments,
};

/// CLI command types
pub const Command = enum {
    init,
    tx_new,
    tx_verify,
    state_view,
    help,
    
    pub fn fromString(str: []const u8) ?Command {
        if (std.mem.eql(u8, str, "init")) return .init;
        if (std.mem.eql(u8, str, "tx") or std.mem.eql(u8, str, "transaction")) return .tx_new;
        if (std.mem.eql(u8, str, "verify")) return .tx_verify;
        if (std.mem.eql(u8, str, "state")) return .state_view;
        if (std.mem.eql(u8, str, "help")) return .help;
        return null;
    }
};

/// Main CLI interface for Keystone
pub const Cli = struct {
    allocator: std.mem.Allocator,
    ledger: LedgerState,
    journal: Journal,
    data_dir: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, data_dir: ?[]const u8) !Cli {
        const actual_data_dir = data_dir orelse ".keystone";
        
        // Create data directory if it doesn't exist
        std.fs.cwd().makeDir(actual_data_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        
        const owned_data_dir = try allocator.dupe(u8, actual_data_dir);
        
        // Initialize components
        var ledger = LedgerState.init(allocator);
        
        const journal_path = try std.fmt.allocPrint(allocator, "{s}/journal.jsonl", .{actual_data_dir});
        defer allocator.free(journal_path);
        
        var journal = try Journal.init(allocator, journal_path);
        
        // Try to load existing state
        journal.loadFromFile() catch |err| {
            std.debug.print("Warning: Could not load journal from file: {}\n", .{err});
        };
        
        // Replay journal to restore ledger state
        journal.replayToLedger(&ledger) catch |err| {
            std.debug.print("Warning: Could not replay journal: {}\n", .{err});
        };
        
        return Cli{
            .allocator = allocator,
            .ledger = ledger,
            .journal = journal,
            .data_dir = owned_data_dir,
        };
    }
    
    pub fn deinit(self: *Cli) void {
        self.ledger.deinit();
        self.journal.deinit();
        self.allocator.free(self.data_dir);
    }
    
    /// Run CLI with provided arguments
    pub fn run(self: *Cli, args: [][:0]u8) !void {
        if (args.len < 2) {
            try self.printHelp();
            return;
        }
        
        const command = Command.fromString(args[1]) orelse {
            std.debug.print("Error: Unknown command '{s}'\n", .{args[1]});
            try self.printHelp();
            return CliError.InvalidCommand;
        };
        
        switch (command) {
            .init => try self.cmdInit(),
            .tx_new => try self.cmdTxNew(args[2..]),
            .tx_verify => try self.cmdTxVerify(args[2..]),
            .state_view => try self.cmdStateView(),
            .help => try self.printHelp(),
        }
    }
    
    /// Initialize keystone workspace
    fn cmdInit(self: *Cli) !void {
        std.debug.print("Initializing Keystone workspace in '{s}'\n", .{self.data_dir});
        
        // Create genesis account if ledger is empty
        if (self.ledger.accounts.count() == 0) {
            try self.ledger.createAccount("genesis", "Genesis account");
            std.debug.print("Created genesis account\n", .{});
        }
        
        // Save initial state
        try self.journal.saveToFile();
        
        std.debug.print("Keystone workspace initialized successfully\n", .{});
    }
    
    /// Create new transaction
    fn cmdTxNew(self: *Cli, args: [][:0]u8) !void {
        if (args.len < 2) {
            std.debug.print("Usage: keystone tx <recipient> <amount> [memo]\n", .{});
            return CliError.InsufficientArguments;
        }
        
        const recipient = args[0];
        const amount = std.fmt.parseInt(u64, args[1], 10) catch |err| {
            std.debug.print("Error: Invalid amount '{s}': {}\n", .{ args[1], err });
            return CliError.InvalidArguments;
        };
        
        const memo = if (args.len > 2) args[2] else null;
        
        // Create transaction
        var tx = try Transaction.init(self.allocator, self.journal.current_sequence + 1, memo);
        
        // Add output
        const output = try TxOutput.init(self.allocator, amount, recipient, null);
        try tx.addOutput(output);
        
        std.debug.print("Created transaction:\n", .{});
        std.debug.print("  ID: {s}\n", .{tx.id});
        std.debug.print("  To: {s}\n", .{recipient});
        std.debug.print("  Amount: {}\n", .{amount});
        if (memo) |m| {
            std.debug.print("  Memo: {s}\n", .{m});
        }
        
        // Apply to ledger and journal
        try self.ledger.applyTransaction(&tx);
        try self.journal.appendTransaction(tx);
        
        std.debug.print("Transaction applied successfully\n", .{});
        
        // Show updated balance
        if (self.ledger.getBalance(recipient)) |balance| {
            std.debug.print("New balance for {s}: {}\n", .{ recipient, balance });
        }
    }
    
    /// Verify transaction
    fn cmdTxVerify(self: *Cli, args: [][:0]u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: keystone verify <sequence_number>\n", .{});
            return CliError.InsufficientArguments;
        }
        
        const sequence = std.fmt.parseInt(u64, args[0], 10) catch |err| {
            std.debug.print("Error: Invalid sequence number '{s}': {}\n", .{ args[0], err });
            return CliError.InvalidArguments;
        };
        
        if (self.journal.getEntry(sequence)) |entry| {
            const is_valid = try entry.verify(self.allocator);
            std.debug.print("Transaction {} verification: {s}\n", .{ sequence, if (is_valid) "VALID" else "INVALID" });
            
            if (is_valid) {
                std.debug.print("  ID: {s}\n", .{entry.transaction.id});
                std.debug.print("  Timestamp: {}\n", .{entry.timestamp});
                std.debug.print("  Hash: {x}\n", .{entry.hash});
            }
        } else {
            std.debug.print("Error: Transaction {} not found\n", .{sequence});
        }
    }
    
    /// View current ledger state
    fn cmdStateView(self: *Cli) !void {
        std.debug.print("=== Keystone Ledger State ===\n", .{});
        
        // Ledger info
        std.debug.print("Sequence: {}\n", .{self.ledger.sequence});
        std.debug.print("Last Updated: {}\n", .{self.ledger.last_updated});
        std.debug.print("Total Accounts: {}\n", .{self.ledger.accounts.count()});
        
        // Journal info
        const journal_stats = self.journal.getStats();
        std.debug.print("Journal Entries: {}\n", .{journal_stats.total_entries});
        
        // Verify journal integrity
        const integrity_ok = try self.journal.verifyIntegrity();
        std.debug.print("Journal Integrity: {s}\n", .{if (integrity_ok) "OK" else "CORRUPTED"});
        
        // Account balances
        std.debug.print("\n=== Account Balances ===\n", .{});
        var iterator = self.ledger.accounts.iterator();
        while (iterator.next()) |entry| {
            std.debug.print("{s}: {}\n", .{ entry.key_ptr.*, entry.value_ptr.balance });
        }
        
        // Recent transactions
        std.debug.print("\n=== Recent Transactions ===\n", .{});
        const start_idx = if (journal_stats.total_entries > 5) journal_stats.total_entries - 5 else 0;
        
        for (start_idx..journal_stats.total_entries) |i| {
            if (self.journal.getEntry(i)) |entry| {
                std.debug.print("[{}] {} -> {} outputs, memo: {s}\n", .{
                    i,
                    entry.transaction.inputs.items.len,
                    entry.transaction.outputs.items.len,
                    entry.transaction.memo orelse "none",
                });
            }
        }
    }
    
    /// Print help information
    fn printHelp(self: *Cli) !void {
        std.debug.print("Keystone v0.1.0 - Ledger and Transaction Coordinator\n\n", .{});
        std.debug.print("Usage: keystone <command> [options]\n\n", .{});
        std.debug.print("Commands:\n", .{});
        std.debug.print("  init                    Initialize keystone workspace\n", .{});
        std.debug.print("  tx <recipient> <amount> Create new transaction\n", .{});
        std.debug.print("  verify <sequence>       Verify transaction by sequence number\n", .{});
        std.debug.print("  state                   View current ledger state\n", .{});
        std.debug.print("  help                    Show this help message\n\n", .{});
        std.debug.print("Examples:\n", .{});
        std.debug.print("  keystone init\n", .{});
        std.debug.print("  keystone tx alice 1000\n", .{});
        std.debug.print("  keystone tx bob 500 \"Payment for services\"\n", .{});
        std.debug.print("  keystone verify 0\n", .{});
        std.debug.print("  keystone state\n\n", .{});
        std.debug.print("Data directory: {s}\n", .{self.data_dir});
    }
};

// Tests
test "CLI command parsing" {
    try std.testing.expect(Command.fromString("init") == .init);
    try std.testing.expect(Command.fromString("tx") == .tx_new);
    try std.testing.expect(Command.fromString("help") == .help);
    try std.testing.expect(Command.fromString("invalid") == null);
}

test "CLI initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var cli = try Cli.init(allocator, ".test_keystone");
    defer cli.deinit();
    
    try std.testing.expect(cli.ledger.sequence == 0);
    try std.testing.expect(cli.journal.current_sequence == 0);
}
