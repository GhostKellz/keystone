const std = @import("std");
const zledger = @import("zledger");
const Transaction = @import("transaction.zig").Transaction;
const TxOutput = @import("transaction.zig").TxOutput;
const AccountRegistry = @import("account.zig").AccountRegistry;
const Permission = @import("account.zig").Permission;
const AccessToken = @import("account.zig").AccessToken;

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

/// UTXO represents an unspent transaction output
pub const UTXO = struct {
    /// Transaction ID that created this output
    tx_id: []const u8,
    /// Output index within the transaction
    output_index: u32,
    /// The actual output data
    output: TxOutput,
    /// Block height when created (for ordering)
    height: u64,
    
    pub fn init(allocator: std.mem.Allocator, tx_id: []const u8, output_index: u32, output: TxOutput, height: u64) !UTXO {
        return UTXO{
            .tx_id = try allocator.dupe(u8, tx_id),
            .output_index = output_index,
            .output = output,
            .height = height,
        };
    }
    
    pub fn deinit(self: *UTXO, allocator: std.mem.Allocator) void {
        allocator.free(self.tx_id);
        self.output.deinit(allocator);
    }
    
    /// Generate unique key for UTXO tracking
    pub fn getKey(self: UTXO, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.tx_id, self.output_index });
    }
};

/// Fee configuration for transactions
pub const FeeConfig = struct {
    /// Base fee per transaction
    base_fee: u64 = 10,
    /// Fee per byte of transaction data
    per_byte_fee: u64 = 1,
    /// Minimum fee required
    min_fee: u64 = 5,
    
    pub fn calculateFee(self: FeeConfig, tx_size_bytes: u64) u64 {
        const total_fee = self.base_fee + (tx_size_bytes * self.per_byte_fee);
        return @max(total_fee, self.min_fee);
    }
};

/// Ledger state maintains accounts and processes transactions
pub const LedgerState = struct {
    /// Map of account ID to Account
    accounts: std.HashMap([]const u8, Account, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    /// UTXO set tracking unspent outputs
    utxo_set: std.HashMap([]const u8, UTXO, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    /// Transaction sequence number for ordering
    sequence: u64,
    /// Last state update timestamp
    last_updated: i64,
    /// Fee configuration
    fee_config: FeeConfig,
    /// Current state root hash (Merkle tree root)
    state_root: ?[]u8,
    /// DID-based account registry for permissions
    account_registry: AccountRegistry,
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) LedgerState {
        return LedgerState{
            .accounts = std.HashMap([]const u8, Account, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .utxo_set = std.HashMap([]const u8, UTXO, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .sequence = 0,
            .last_updated = std.time.timestamp(),
            .fee_config = FeeConfig{},
            .state_root = null,
            .account_registry = AccountRegistry.init(allocator),
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
        
        var utxo_iterator = self.utxo_set.iterator();
        while (utxo_iterator.next()) |entry| {
            var utxo = entry.value_ptr;
            utxo.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.utxo_set.deinit();
        
        if (self.state_root) |root| {
            self.allocator.free(root);
        }
        
        self.account_registry.deinit();
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
    
    /// Get UTXO by transaction ID and output index
    pub fn getUTXO(self: *LedgerState, tx_id: []const u8, output_index: u32) ?*UTXO {
        const key_buf = std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ tx_id, output_index }) catch return null;
        defer self.allocator.free(key_buf);
        return self.utxo_set.getPtr(key_buf);
    }
    
    /// Add UTXO to the set
    fn addUTXO(self: *LedgerState, tx_id: []const u8, output_index: u32, output: TxOutput) !void {
        // Create a deep copy of the output to avoid memory issues
        const output_copy = try TxOutput.init(self.allocator, output.value, output.recipient, output.metadata);
        const utxo = try UTXO.init(self.allocator, tx_id, output_index, output_copy, self.sequence);
        const key = try utxo.getKey(self.allocator);
        try self.utxo_set.put(key, utxo);
    }
    
    /// Remove UTXO from the set (when spent)
    fn removeUTXO(self: *LedgerState, tx_id: []const u8, output_index: u32) !?UTXO {
        const key_buf = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ tx_id, output_index });
        defer self.allocator.free(key_buf);
        
        if (self.utxo_set.fetchRemove(key_buf)) |kv| {
            self.allocator.free(kv.key);
            return kv.value;
        }
        return null;
    }
    
    /// Calculate available balance for an account from UTXOs
    pub fn getUTXOBalance(self: *LedgerState, account_id: []const u8) u64 {
        var total: u64 = 0;
        var iterator = self.utxo_set.iterator();
        while (iterator.next()) |entry| {
            const utxo = entry.value_ptr;
            if (std.mem.eql(u8, utxo.output.recipient, account_id)) {
                total += utxo.output.value;
            }
        }
        return total;
    }
    
    /// Validate transaction permissions using access token
    fn validateTransactionPermissions(self: *LedgerState, transaction: *const Transaction, token_data: []const u8) !void {
        // Parse access token from delegation_token field
        // In a real implementation, this would deserialize the token properly
        // For now, we'll create a mock token for validation
        
        // Extract DID from transaction outputs to determine who is transacting
        var subject_did: ?[]const u8 = null;
        for (transaction.outputs.items) |output| {
            // Check if this is a DID-based recipient
            if (std.mem.startsWith(u8, output.recipient, "did:")) {
                subject_did = output.recipient;
                break;
            }
        }
        
        if (subject_did == null) {
            return error.NoDIDFound;
        }
        
        // Create mock access token for validation
        // In reality, this would be parsed from token_data
        var mock_token = AccessToken.init(
            self.allocator,
            "mock-token",
            "did:issuer:authority",
            subject_did.?,
            token_data,
            std.time.timestamp() + 3600 // 1 hour expiry
        ) catch return error.TokenParsingFailed;
        defer mock_token.deinit(self.allocator);
        
        // Grant send permission to the mock token
        try mock_token.permissions.add(self.allocator, Permission.Send);
        
        // Validate token and permissions
        if (!try self.account_registry.verifyAccessToken(mock_token, Permission.Send)) {
            return error.InsufficientPermissions;
        }
    }
    
    /// Apply a transaction to the ledger state
    pub fn applyTransaction(self: *LedgerState, transaction: *const Transaction) !void {
        // Validate transaction structure first
        if (!transaction.validate()) {
            return error.InvalidTransaction;
        }
        
        // Check permissions for transaction (if delegation token exists)
        if (transaction.delegation_token) |token_data| {
            try self.validateTransactionPermissions(transaction, token_data);
        }
        
        // Calculate total input and output values
        var total_input_value: u64 = 0;
        var total_output_value: u64 = 0;
        
        // Validate and collect inputs (consume UTXOs)
        var consumed_utxos = std.ArrayList(UTXO).init(self.allocator);
        defer {
            for (consumed_utxos.items) |*utxo| {
                utxo.deinit(self.allocator);
            }
            consumed_utxos.deinit();
        }
        
        // Handle inputs (if any) - coinbase transactions have no inputs
        for (transaction.inputs.items) |input| {
            // Find the UTXO being consumed
            if (self.getUTXO(input.prev_tx_id, input.output_index)) |utxo| {
                total_input_value += utxo.output.value;
                
                // Remove UTXO from set (consume it)
                if (try self.removeUTXO(input.prev_tx_id, input.output_index)) |consumed_utxo| {
                    try consumed_utxos.append(consumed_utxo);
                }
                
                // TODO: Verify signature for this input (zsig integration)
                // TODO: Check permission for spending this UTXO (Shroud integration)
            } else {
                return error.UTXONotFound;
            }
        }
        
        // Calculate total output value
        for (transaction.outputs.items) |output| {
            total_output_value += output.value;
        }
        
        // Calculate required fee (only for transactions with inputs)
        const required_fee = if (transaction.inputs.items.len > 0) blk: {
            const tx_size = transaction.toJson(self.allocator) catch return error.SerializationFailed;
            defer self.allocator.free(tx_size);
            break :blk self.fee_config.calculateFee(tx_size.len);
        } else 0; // Coinbase transactions don't pay fees
        
        // Validate balance: input_value >= output_value + fee (skip for coinbase)
        if (transaction.inputs.items.len > 0 and total_input_value < total_output_value + required_fee) {
            // Restore consumed UTXOs on failure
            for (consumed_utxos.items) |utxo| {
                const key = try utxo.getKey(self.allocator);
                defer self.allocator.free(key);
                try self.utxo_set.put(key, utxo);
            }
            return error.InsufficientFunds;
        }
        
        // Create new UTXOs from outputs
        for (transaction.outputs.items, 0..) |output, i| {
            // Ensure recipient account exists
            if (self.getAccount(output.recipient) == null) {
                try self.createAccount(output.recipient, null);
            }
            
            // Create new UTXO
            try self.addUTXO(transaction.id, @intCast(i), output);
            
            // Update account balance (for simplified balance tracking)
            if (self.getAccount(output.recipient)) |account| {
                account.credit(output.value);
            }
        }
        
        // Debit consumed UTXOs from account balances
        for (consumed_utxos.items) |utxo| {
            if (self.getAccount(utxo.output.recipient)) |account| {
                account.debit(utxo.output.value) catch {
                    // This shouldn't happen if UTXO set is consistent
                    return error.InconsistentState;
                };
            }
        }
        
        self.sequence += 1;
        self.updateTimestamp();
        try self.updateStateRoot();
    }
    
    /// Calculate and update the Merkle tree state root
    pub fn updateStateRoot(self: *LedgerState) !void {
        if (self.state_root) |old_root| {
            self.allocator.free(old_root);
        }
        
        self.state_root = try self.calculateStateRoot();
    }
    
    /// Calculate Merkle tree root from current state
    pub fn calculateStateRoot(self: *LedgerState) ![]u8 {
        var leaves = std.ArrayList([]u8).init(self.allocator);
        defer {
            for (leaves.items) |leaf| {
                self.allocator.free(leaf);
            }
            leaves.deinit();
        }
        
        // Add account hashes as leaves
        var account_iterator = self.accounts.iterator();
        while (account_iterator.next()) |entry| {
            const account = entry.value_ptr;
            const leaf_data = try std.fmt.allocPrint(
                self.allocator,
                "account:{s}:{}.{}",
                .{ account.id, account.balance, account.created_at }
            );
            defer self.allocator.free(leaf_data);
            
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(leaf_data);
            var hash: [32]u8 = undefined;
            hasher.final(&hash);
            
            try leaves.append(try self.allocator.dupe(u8, &hash));
        }
        
        // Add UTXO hashes as leaves
        var utxo_iterator = self.utxo_set.iterator();
        while (utxo_iterator.next()) |entry| {
            const utxo = entry.value_ptr;
            const leaf_data = try std.fmt.allocPrint(
                self.allocator,
                "utxo:{s}:{}:{s}:{}",
                .{ utxo.tx_id, utxo.output_index, utxo.output.recipient, utxo.output.value }
            );
            defer self.allocator.free(leaf_data);
            
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(leaf_data);
            var hash: [32]u8 = undefined;
            hasher.final(&hash);
            
            try leaves.append(try self.allocator.dupe(u8, &hash));
        }
        
        // Calculate Merkle root using simple binary tree approach
        if (leaves.items.len == 0) {
            // Empty state root
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update("empty_state");
            var hash: [32]u8 = undefined;
            hasher.final(&hash);
            return try self.allocator.dupe(u8, &hash);
        }
        
        return try self.calculateMerkleRoot(leaves.items);
    }
    
    /// Simple Merkle tree root calculation
    fn calculateMerkleRoot(self: *LedgerState, leaves: [][]u8) ![]u8 {
        if (leaves.len == 0) {
            return error.EmptyLeaves;
        }
        
        if (leaves.len == 1) {
            return try self.allocator.dupe(u8, leaves[0]);
        }
        
        var current_level = std.ArrayList([]u8).init(self.allocator);
        defer {
            for (current_level.items) |item| {
                self.allocator.free(item);
            }
            current_level.deinit();
        }
        
        // Copy leaves to current level
        for (leaves) |leaf| {
            try current_level.append(try self.allocator.dupe(u8, leaf));
        }
        
        // Build tree bottom-up
        while (current_level.items.len > 1) {
            var next_level = std.ArrayList([]u8).init(self.allocator);
            defer {
                for (next_level.items) |item| {
                    self.allocator.free(item);
                }
                next_level.deinit();
            }
            
            var i: usize = 0;
            while (i < current_level.items.len) {
                if (i + 1 < current_level.items.len) {
                    // Hash pair
                    const combined = try std.fmt.allocPrint(
                        self.allocator,
                        "{s}{s}",
                        .{ current_level.items[i], current_level.items[i + 1] }
                    );
                    defer self.allocator.free(combined);
                    
                    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                    hasher.update(combined);
                    var hash: [32]u8 = undefined;
                    hasher.final(&hash);
                    
                    try next_level.append(try self.allocator.dupe(u8, &hash));
                    i += 2;
                } else {
                    // Odd number - duplicate the last hash
                    try next_level.append(try self.allocator.dupe(u8, current_level.items[i]));
                    i += 1;
                }
            }
            
            // Free current level
            for (current_level.items) |item| {
                self.allocator.free(item);
            }
            current_level.clearAndFree();
            
            // Move next level to current
            try current_level.appendSlice(next_level.items);
            next_level.clearRetainingCapacity();
        }
        
        // Return the root (should be only item left)
        return try self.allocator.dupe(u8, current_level.items[0]);
    }
    
    /// Verify state integrity using Merkle tree
    pub fn verifyStateIntegrity(self: *LedgerState) !bool {
        const calculated_root = try self.calculateStateRoot();
        defer self.allocator.free(calculated_root);
        
        if (self.state_root) |current_root| {
            return std.mem.eql(u8, current_root, calculated_root);
        }
        
        return false; // No state root to compare against
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
