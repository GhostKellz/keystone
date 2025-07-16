const std = @import("std");
const Transaction = @import("transaction.zig").Transaction;
const LedgerState = @import("ledger.zig").LedgerState;

/// Journal entry represents a committed transaction with integrity chain
pub const JournalEntry = struct {
    /// The committed transaction
    transaction: Transaction,
    /// Hash of the previous entry (blockchain-style)
    prev_hash: ?[32]u8,
    /// Hash of this entry
    hash: [32]u8,
    /// Sequence number in the journal
    sequence: u64,
    /// Entry timestamp
    timestamp: i64,
    
    pub fn init(allocator: std.mem.Allocator, transaction: Transaction, prev_hash: ?[32]u8, sequence: u64) !JournalEntry {
        const timestamp = std.time.timestamp();
        const hash = try calculateEntryHash(allocator, &transaction, prev_hash, sequence, timestamp);
        
        return JournalEntry{
            .transaction = transaction,
            .prev_hash = prev_hash,
            .hash = hash,
            .sequence = sequence,
            .timestamp = timestamp,
        };
    }
    
    /// Verify the integrity of this journal entry
    pub fn verify(self: *const JournalEntry, allocator: std.mem.Allocator) !bool {
        const expected_hash = try calculateEntryHash(allocator, &self.transaction, self.prev_hash, self.sequence, self.timestamp);
        return std.crypto.utils.timingSafeEql([32]u8, self.hash, expected_hash);
    }
    
    /// Serialize journal entry to JSON
    pub fn toJson(self: *const JournalEntry, allocator: std.mem.Allocator) ![]u8 {
        var json_obj = std.json.ObjectMap.init(allocator);
        defer json_obj.deinit();
        
        // Add entry metadata
        try json_obj.put("sequence", std.json.Value{ .integer = @intCast(self.sequence) });
        try json_obj.put("timestamp", std.json.Value{ .integer = self.timestamp });
        const hash_hex = try std.fmt.allocPrint(allocator, "{x}", .{self.hash});
        defer allocator.free(hash_hex);
        try json_obj.put("hash", std.json.Value{ .string = hash_hex });
        
        if (self.prev_hash) |prev| {
            const prev_hex = try std.fmt.allocPrint(allocator, "{x}", .{prev});
            defer allocator.free(prev_hex);
            try json_obj.put("prev_hash", std.json.Value{ .string = prev_hex });
        }
        
        // Add transaction data
        const tx_json = try self.transaction.toJson(allocator);
        defer allocator.free(tx_json);
        const tx_parsed = try std.json.parseFromSlice(std.json.Value, allocator, tx_json, .{});
        defer tx_parsed.deinit();
        try json_obj.put("transaction", tx_parsed.value);
        
        const json_value = std.json.Value{ .object = json_obj };
        return try std.json.stringifyAlloc(allocator, json_value, .{});
    }
};

/// Journal maintains an ordered, integrity-checked log of all transactions
pub const Journal = struct {
    /// List of all journal entries
    entries: std.ArrayList(JournalEntry),
    /// Current sequence number
    current_sequence: u64,
    /// Optional file path for persistence
    file_path: ?[]const u8,
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, file_path: ?[]const u8) !Journal {
        return Journal{
            .entries = std.ArrayList(JournalEntry).init(allocator),
            .current_sequence = 0,
            .file_path = if (file_path) |path| try allocator.dupe(u8, path) else null,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Journal) void {
        for (self.entries.items) |*entry| {
            entry.transaction.deinit(self.allocator);
        }
        self.entries.deinit();
        
        if (self.file_path) |path| {
            self.allocator.free(path);
        }
    }
    
    /// Add a transaction to the journal
    pub fn appendTransaction(self: *Journal, transaction: Transaction) !void {
        const prev_hash = if (self.entries.items.len > 0) 
            self.entries.items[self.entries.items.len - 1].hash 
        else 
            null;
        
        const entry = try JournalEntry.init(self.allocator, transaction, prev_hash, self.current_sequence);
        try self.entries.append(entry);
        self.current_sequence += 1;
        
        // Optionally persist to file
        if (self.file_path) |_| {
            try self.saveToFile();
        }
    }
    
    /// Get journal entry by sequence number
    pub fn getEntry(self: *const Journal, sequence: u64) ?*const JournalEntry {
        if (sequence >= self.entries.items.len) {
            return null;
        }
        return &self.entries.items[sequence];
    }
    
    /// Get the latest journal entry
    pub fn getLatestEntry(self: *const Journal) ?*const JournalEntry {
        if (self.entries.items.len == 0) {
            return null;
        }
        return &self.entries.items[self.entries.items.len - 1];
    }
    
    /// Verify the integrity of the entire journal chain
    pub fn verifyIntegrity(self: *const Journal) !bool {
        if (self.entries.items.len == 0) {
            return true; // Empty journal is valid
        }
        
        // Check first entry
        if (self.entries.items[0].prev_hash != null) {
            return false; // First entry should have null prev_hash
        }
        
        // Verify each entry and chain integrity
        for (self.entries.items, 0..) |*entry, i| {
            // Verify entry hash
            if (!try entry.verify(self.allocator)) {
                return false;
            }
            
            // Verify chain linkage
            if (i > 0) {
                const prev_entry = &self.entries.items[i - 1];
                if (entry.prev_hash == null or !std.crypto.utils.timingSafeEql([32]u8, entry.prev_hash.?, prev_entry.hash)) {
                    return false;
                }
            }
            
            // Verify sequence ordering
            if (entry.sequence != i) {
                return false;
            }
        }
        
        return true;
    }
    
    /// Replay all transactions to rebuild ledger state
    pub fn replayToLedger(self: *const Journal, ledger: *LedgerState) !void {
        for (self.entries.items) |*entry| {
            try ledger.applyTransaction(&entry.transaction);
        }
    }
    
    /// Save journal to file (JSON format)
    pub fn saveToFile(self: *const Journal) !void {
        if (self.file_path == null) {
            return error.NoFilePath;
        }
        
        const file = try std.fs.cwd().createFile(self.file_path.?, .{});
        defer file.close();
        
        // Write each entry as a JSON line
        for (self.entries.items) |*entry| {
            const json = try entry.toJson(self.allocator);
            defer self.allocator.free(json);
            
            try file.writeAll(json);
            try file.writeAll("\n");
        }
    }
    
    /// Load journal from file
    pub fn loadFromFile(self: *Journal) !void {
        if (self.file_path == null) {
            return error.NoFilePath;
        }
        
        const file = std.fs.cwd().openFile(self.file_path.?, .{}) catch |err| switch (err) {
            error.FileNotFound => return, // No file to load, start fresh
            else => return err,
        };
        defer file.close();
        
        // Clear existing entries
        for (self.entries.items) |*entry| {
            entry.transaction.deinit(self.allocator);
        }
        self.entries.clearAndFree();
        self.current_sequence = 0;
        
        // Read and parse each line
        const file_size = try file.getEndPos();
        if (file_size == 0) return; // Empty file
        
        const content = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(content);
        _ = try file.readAll(content);
        
        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            
            // Parse JSON line and reconstruct JournalEntry
            const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch |err| {
                std.debug.print("Warning: Failed to parse journal entry: {}\n", .{err});
                continue;
            };
            defer parsed.deinit();
            
            const json_obj = parsed.value.object;
            
            // Extract basic fields
            const sequence = @as(u64, @intCast(json_obj.get("sequence").?.integer));
            const timestamp = json_obj.get("timestamp").?.integer;
            
            // Parse transaction
            const tx_obj = json_obj.get("transaction").?.object;
            const tx_id = tx_obj.get("id").?.string;
            const tx_timestamp = tx_obj.get("timestamp").?.integer;
            const tx_nonce = @as(u64, @intCast(tx_obj.get("nonce").?.integer));
            const tx_memo = if (tx_obj.get("memo")) |memo| memo.string else null;
            
            // Create transaction
            var transaction = Transaction{
                .id = try self.allocator.dupe(u8, tx_id),
                .timestamp = tx_timestamp,
                .nonce = tx_nonce,
                .inputs = std.ArrayList(@import("transaction.zig").TxInput).init(self.allocator),
                .outputs = std.ArrayList(@import("transaction.zig").TxOutput).init(self.allocator),
                .memo = if (tx_memo) |m| try self.allocator.dupe(u8, m) else null,
                .signatures = std.ArrayList([]const u8).init(self.allocator),
                .delegation_token = null,
            };
            
            // Parse outputs
            if (tx_obj.get("outputs")) |outputs_json| {
                for (outputs_json.array.items) |output_json| {
                    const output_obj = output_json.object;
                    const value = @as(u64, @intCast(output_obj.get("value").?.integer));
                    const recipient = output_obj.get("recipient").?.string;
                    const metadata = if (output_obj.get("metadata")) |meta| meta.string else null;
                    
                    const output = @import("transaction.zig").TxOutput{
                        .value = value,
                        .recipient = try self.allocator.dupe(u8, recipient),
                        .metadata = if (metadata) |m| try self.allocator.dupe(u8, m) else null,
                    };
                    try transaction.outputs.append(output);
                }
            }
            
            // Parse hash
            const hash_str = json_obj.get("hash").?.string;
            var hash: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&hash, hash_str);
            
            // Parse prev_hash if present
            var prev_hash: ?[32]u8 = null;
            if (json_obj.get("prev_hash")) |prev_hash_json| {
                var prev: [32]u8 = undefined;
                if (prev_hash_json == .string) {
                    _ = try std.fmt.hexToBytes(&prev, prev_hash_json.string);
                } else {
                    // Handle array format (legacy) - only take first 32 bytes
                    const len = @min(prev_hash_json.array.items.len, 32);
                    for (prev_hash_json.array.items[0..len], 0..) |item, i| {
                        prev[i] = @intCast(item.integer);
                    }
                }
                prev_hash = prev;
            }
            
            // Create journal entry
            const entry = JournalEntry{
                .transaction = transaction,
                .prev_hash = prev_hash,
                .hash = hash,
                .sequence = sequence,
                .timestamp = timestamp,
            };
            
            try self.entries.append(entry);
            self.current_sequence = sequence + 1;
        }
    }
    
    /// Export journal to JSON array
    pub fn toJson(self: *const Journal, allocator: std.mem.Allocator) ![]u8 {
        var json_array = std.json.Array.init(allocator);
        defer json_array.deinit();
        
        for (self.entries.items) |*entry| {
            const entry_json = try entry.toJson(allocator);
            defer allocator.free(entry_json);
            
            const entry_parsed = try std.json.parseFromSlice(std.json.Value, allocator, entry_json, .{});
            defer entry_parsed.deinit();
            
            try json_array.append(entry_parsed.value);
        }
        
        const json_value = std.json.Value{ .array = json_array };
        return try std.json.stringifyAlloc(allocator, json_value, .{});
    }
    
    /// Get journal statistics
    pub fn getStats(self: *const Journal) JournalStats {
        return JournalStats{
            .total_entries = self.entries.items.len,
            .current_sequence = self.current_sequence,
            .first_timestamp = if (self.entries.items.len > 0) self.entries.items[0].timestamp else 0,
            .last_timestamp = if (self.entries.items.len > 0) self.entries.items[self.entries.items.len - 1].timestamp else 0,
        };
    }
};

/// Journal statistics
pub const JournalStats = struct {
    total_entries: usize,
    current_sequence: u64,
    first_timestamp: i64,
    last_timestamp: i64,
};

/// Calculate hash for a journal entry
fn calculateEntryHash(
    allocator: std.mem.Allocator, 
    transaction: *const Transaction, 
    prev_hash: ?[32]u8, 
    sequence: u64, 
    timestamp: i64
) !([32]u8) {
    // Create input data for hashing
    const tx_json = try transaction.toJson(allocator);
    defer allocator.free(tx_json);
    
    const sequence_str = try std.fmt.allocPrint(allocator, "{d}", .{sequence});
    defer allocator.free(sequence_str);
    
    const timestamp_str = try std.fmt.allocPrint(allocator, "{d}", .{timestamp});
    defer allocator.free(timestamp_str);
    
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    
    // Add transaction data
    hasher.update(tx_json);
    hasher.update(sequence_str);
    hasher.update(timestamp_str);
    
    // Add previous hash if exists
    if (prev_hash) |prev| {
        hasher.update(&prev);
    }
    
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hash;
}

// Tests
test "journal entry creation and verification" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Create a transaction
    var tx = try Transaction.init(allocator, 1, "Test transaction");
    defer tx.deinit(allocator);
    
    // Create journal entry
    const entry = try JournalEntry.init(allocator, tx, null, 0);
    
    // Verify entry
    try std.testing.expect(try entry.verify(allocator));
    try std.testing.expect(entry.sequence == 0);
    try std.testing.expect(entry.prev_hash == null);
}

test "journal operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var journal = try Journal.init(allocator, null);
    defer journal.deinit();
    
    // Create and add transactions
    const tx1 = try Transaction.init(allocator, 1, "First transaction");
    const tx2 = try Transaction.init(allocator, 2, "Second transaction");
    
    try journal.appendTransaction(tx1);
    try journal.appendTransaction(tx2);
    
    // Verify journal integrity
    try std.testing.expect(try journal.verifyIntegrity());
    try std.testing.expect(journal.entries.items.len == 2);
    try std.testing.expect(journal.current_sequence == 2);
    
    // Check chain linkage
    const first_entry = journal.getEntry(0).?;
    const second_entry = journal.getEntry(1).?;
    
    try std.testing.expect(first_entry.prev_hash == null);
    try std.testing.expect(second_entry.prev_hash != null);
    try std.testing.expect(std.crypto.utils.timingSafeEql([32]u8, second_entry.prev_hash.?, first_entry.hash));
}
