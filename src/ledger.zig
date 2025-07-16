const std = @import("std");
const Transaction = @import("transaction.zig").Transaction;

/// Account represents a ledger account with balance tracking
pub const Account = struct {
    /// Account identifier (public key, address, or name)
    id: []const u8,
    /// Current balance
    balance: u64,
    /// Account creation timestamp
    created_at: i64,
    /// Optional metadata
    metadata: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, id: []const u8, metadata: ?[]const u8) !Account {
        return Account{
            .id = try allocator.dupe(u8, id),
            .balance = 0,
            .created_at = std.time.timestamp(),
            .metadata = if (metadata) |m| try allocator.dupe(u8, m) else null,
        };
    }
    
    pub fn deinit(self: *Account, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        if (self.metadata) |meta| {
            allocator.free(meta);
        }
    }
    
    /// Add value to the account balance
    pub fn credit(self: *Account, amount: u64) void {
        self.balance += amount;
    }
    
    /// Subtract value from the account balance
    pub fn debit(self: *Account, amount: u64) !void {
        if (amount > self.balance) {
            return error.InsufficientFunds;
        }
        self.balance -= amount;
    }
};

/// Ledger state maintains accounts and processes transactions
pub const LedgerState = struct {
    /// Map of account ID to Account
    accounts: std.HashMap([]const u8, Account, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    /// Transaction sequence number for ordering
    sequence: u64,
    /// Last state update timestamp
    last_updated: i64,
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) LedgerState {
        return LedgerState{
            .accounts = std.HashMap([]const u8, Account, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .sequence = 0,
            .last_updated = std.time.timestamp(),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *LedgerState) void {
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            var account = entry.value_ptr;
            account.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.accounts.deinit();
    }
    
    /// Create a new account
    pub fn createAccount(self: *LedgerState, id: []const u8, metadata: ?[]const u8) !void {
        if (self.accounts.contains(id)) {
            return error.AccountAlreadyExists;
        }
        
        const account = try Account.init(self.allocator, id, metadata);
        const owned_id = try self.allocator.dupe(u8, id);
        try self.accounts.put(owned_id, account);
        self.updateTimestamp();
    }
    
    /// Get account by ID
    pub fn getAccount(self: *LedgerState, id: []const u8) ?*Account {
        return self.accounts.getPtr(id);
    }
    
    /// Get account balance
    pub fn getBalance(self: *LedgerState, id: []const u8) ?u64 {
        if (self.getAccount(id)) |account| {
            return account.balance;
        }
        return null;
    }
    
    /// Apply a transaction to the ledger state
    pub fn applyTransaction(self: *LedgerState, transaction: *const Transaction) !void {
        // Validate transaction first
        if (!transaction.validate()) {
            return error.InvalidTransaction;
        }
        
        // For simplified v0.1.0: just process outputs as credits
        // In a full UTXO model, we'd process inputs and outputs separately
        for (transaction.outputs.items) |output| {
            // Ensure recipient account exists
            if (self.getAccount(output.recipient) == null) {
                try self.createAccount(output.recipient, null);
            }
            
            // Credit the recipient
            if (self.getAccount(output.recipient)) |account| {
                account.credit(output.value);
            }
        }
        
        // TODO: For full implementation:
        // 1. Validate and consume inputs (debit from source accounts)
        // 2. Verify signatures via zsig integration
        // 3. Check delegation tokens via Shroud integration
        // 4. Ensure input value >= output value (with fees)
        
        self.sequence += 1;
        self.updateTimestamp();
    }
    
    /// Create a simple snapshot of current state
    pub fn createSnapshot(self: LedgerState, allocator: std.mem.Allocator) !LedgerSnapshot {
        var snapshot = LedgerSnapshot{
            .sequence = self.sequence,
            .timestamp = self.last_updated,
            .account_balances = std.HashMap([]const u8, u64, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
        
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            const id_copy = try allocator.dupe(u8, entry.key_ptr.*);
            try snapshot.account_balances.put(id_copy, entry.value_ptr.balance);
        }
        
        return snapshot;
    }
    
    /// Validate internal consistency
    pub fn validate(self: LedgerState) bool {
        _ = self; // Placeholder for future validation logic
        // Basic consistency checks - accounts can exist without transactions (manually created)
        // if (self.sequence == 0 and self.accounts.count() > 0) {
        //     return false; // Accounts exist but no transactions processed
        // }
        
        // TODO: Add more validation:
        // - Total supply consistency
        // - Account balance non-negativity
        // - Transaction history consistency
        
        return true;
    }
    
    /// Export state to JSON
    pub fn toJson(self: LedgerState, allocator: std.mem.Allocator) ![]u8 {
        var json_obj = std.json.ObjectMap.init(allocator);
        defer json_obj.deinit();
        
        try json_obj.put("sequence", std.json.Value{ .integer = @intCast(self.sequence) });
        try json_obj.put("last_updated", std.json.Value{ .integer = self.last_updated });
        
        // Serialize accounts
        var accounts_obj = std.json.ObjectMap.init(allocator);
        defer accounts_obj.deinit();
        
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            var account_obj = std.json.ObjectMap.init(allocator);
            defer account_obj.deinit();
            
            try account_obj.put("balance", std.json.Value{ .integer = @intCast(entry.value_ptr.balance) });
            try account_obj.put("created_at", std.json.Value{ .integer = entry.value_ptr.created_at });
            
            if (entry.value_ptr.metadata) |meta| {
                try account_obj.put("metadata", std.json.Value{ .string = meta });
            }
            
            try accounts_obj.put(entry.key_ptr.*, std.json.Value{ .object = account_obj });
        }
        
        try json_obj.put("accounts", std.json.Value{ .object = accounts_obj });
        
        const json_value = std.json.Value{ .object = json_obj };
        return try std.json.stringifyAlloc(allocator, json_value, .{});
    }
    
    fn updateTimestamp(self: *LedgerState) void {
        self.last_updated = std.time.timestamp();
    }
};

/// Snapshot of ledger state at a point in time
pub const LedgerSnapshot = struct {
    sequence: u64,
    timestamp: i64,
    account_balances: std.HashMap([]const u8, u64, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    
    pub fn deinit(self: *LedgerSnapshot, allocator: std.mem.Allocator) void {
        var iterator = self.account_balances.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        self.account_balances.deinit();
    }
};

// Tests
test "ledger state basic operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var ledger = LedgerState.init(allocator);
    defer ledger.deinit();
    
    // Create accounts
    try ledger.createAccount("alice", null);
    try ledger.createAccount("bob", "Test account");
    
    // Check initial balances
    try std.testing.expect(ledger.getBalance("alice").? == 0);
    try std.testing.expect(ledger.getBalance("bob").? == 0);
    
    // Credit alice
    if (ledger.getAccount("alice")) |alice| {
        alice.credit(1000);
    }
    
    try std.testing.expect(ledger.getBalance("alice").? == 1000);
    try std.testing.expect(ledger.validate());
}

test "ledger state transaction processing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var ledger = LedgerState.init(allocator);
    defer ledger.deinit();
    
    // Create a transaction
    const TxOutput = @import("transaction.zig").TxOutput;
    
    var tx = try Transaction.init(allocator, 1, "Test payment");
    defer tx.deinit(allocator);
    
    const output = try TxOutput.init(allocator, 500, "alice", null);
    try tx.addOutput(output);
    
    // Apply transaction
    try ledger.applyTransaction(&tx);
    
    // Check that alice's account was created and credited
    try std.testing.expect(ledger.getBalance("alice").? == 500);
    try std.testing.expect(ledger.sequence == 1);
}
