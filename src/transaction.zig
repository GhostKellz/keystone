const std = @import("std");

/// Transaction inputs represent value being consumed
pub const TxInput = struct {
    /// Reference to previous transaction output
    prev_tx_id: []const u8,
    /// Index of the output being consumed
    output_index: u32,
    /// Digital signature proving ownership
    signature: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, prev_tx_id: []const u8, output_index: u32) !TxInput {
        return TxInput{
            .prev_tx_id = try allocator.dupe(u8, prev_tx_id),
            .output_index = output_index,
            .signature = null,
        };
    }
    
    pub fn deinit(self: *TxInput, allocator: std.mem.Allocator) void {
        allocator.free(self.prev_tx_id);
        if (self.signature) |sig| {
            allocator.free(sig);
        }
    }
};

/// Transaction outputs represent value being created
pub const TxOutput = struct {
    /// Amount being transferred
    value: u64,
    /// Recipient account identifier 
    recipient: []const u8,
    /// Optional metadata or conditions
    metadata: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, value: u64, recipient: []const u8, metadata: ?[]const u8) !TxOutput {
        return TxOutput{
            .value = value,
            .recipient = try allocator.dupe(u8, recipient),
            .metadata = if (metadata) |m| try allocator.dupe(u8, m) else null,
        };
    }
    
    pub fn deinit(self: *TxOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.recipient);
        if (self.metadata) |meta| {
            allocator.free(meta);
        }
    }
};

/// Core transaction structure
pub const Transaction = struct {
    /// Unique transaction identifier
    id: []const u8,
    /// Transaction timestamp
    timestamp: i64,
    /// Transaction nonce for uniqueness
    nonce: u64,
    /// List of inputs (value being consumed)
    inputs: std.ArrayList(TxInput),
    /// List of outputs (value being created)
    outputs: std.ArrayList(TxOutput),
    /// Optional memo/description
    memo: ?[]const u8,
    /// Digital signature(s) for the transaction
    signatures: std.ArrayList([]const u8),
    /// Optional delegation token from Shroud (for future integration)
    delegation_token: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, nonce: u64, memo: ?[]const u8) !Transaction {
        const timestamp = std.time.timestamp();
        const id = try generateTxId(allocator, timestamp, nonce);
        
        return Transaction{
            .id = id,
            .timestamp = timestamp,
            .nonce = nonce,
            .inputs = std.ArrayList(TxInput).init(allocator),
            .outputs = std.ArrayList(TxOutput).init(allocator),
            .memo = if (memo) |m| try allocator.dupe(u8, m) else null,
            .signatures = std.ArrayList([]const u8).init(allocator),
            .delegation_token = null,
        };
    }
    
    pub fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        
        for (self.inputs.items) |*input| {
            input.deinit(allocator);
        }
        self.inputs.deinit();
        
        for (self.outputs.items) |*output| {
            output.deinit(allocator);
        }
        self.outputs.deinit();
        
        if (self.memo) |memo| {
            allocator.free(memo);
        }
        
        for (self.signatures.items) |sig| {
            allocator.free(sig);
        }
        self.signatures.deinit();
        
        if (self.delegation_token) |token| {
            allocator.free(token);
        }
    }
    
    /// Add an input to the transaction
    pub fn addInput(self: *Transaction, input: TxInput) !void {
        try self.inputs.append(input);
    }
    
    /// Add an output to the transaction
    pub fn addOutput(self: *Transaction, output: TxOutput) !void {
        try self.outputs.append(output);
    }
    
    /// Add a signature to the transaction
    pub fn addSignature(self: *Transaction, allocator: std.mem.Allocator, signature: []const u8) !void {
        try self.signatures.append(try allocator.dupe(u8, signature));
    }
    
    /// Calculate total input value
    pub fn getTotalInputValue(self: Transaction) u64 {
        // Note: In a real implementation, this would look up the referenced outputs
        // For now, we'll implement a simplified version
        var total: u64 = 0;
        for (self.inputs.items) |_| {
            // TODO: Look up actual values from UTXO set
            total += 0; // Placeholder
        }
        return total;
    }
    
    /// Calculate total output value
    pub fn getTotalOutputValue(self: Transaction) u64 {
        var total: u64 = 0;
        for (self.outputs.items) |output| {
            total += output.value;
        }
        return total;
    }
    
    /// Validate transaction structure and basic rules
    pub fn validate(self: Transaction) bool {
        // Basic validation rules
        if (self.inputs.items.len == 0 and self.outputs.items.len == 0) {
            return false; // Empty transaction
        }
        
        // TODO: Add more validation:
        // - Signature verification (via zsig integration)
        // - Input/output value balance
        // - Nonce uniqueness
        // - Delegation token verification (via Shroud)
        
        return true;
    }
    
    /// Serialize transaction to JSON
    pub fn toJson(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
        // Use a simple string builder approach to avoid complex JSON object issues
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        const writer = buffer.writer();
        
        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"timestamp\":{},", .{self.timestamp});
        try writer.print("\"nonce\":{},", .{self.nonce});
        
        // Serialize inputs
        try writer.writeAll("\"inputs\":[");
        for (self.inputs.items, 0..) |input, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"prev_tx_id\":\"{s}\",", .{input.prev_tx_id});
            try writer.print("\"output_index\":{}", .{input.output_index});
            if (input.signature) |sig| {
                try writer.print(",\"signature\":\"{s}\"", .{sig});
            }
            try writer.writeAll("}");
        }
        try writer.writeAll("],");
        
        // Serialize outputs
        try writer.writeAll("\"outputs\":[");
        for (self.outputs.items, 0..) |output, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"value\":{},", .{output.value});
            try writer.print("\"recipient\":\"{s}\"", .{output.recipient});
            if (output.metadata) |meta| {
                try writer.print(",\"metadata\":\"{s}\"", .{meta});
            }
            try writer.writeAll("}");
        }
        try writer.writeAll("]");
        
        if (self.memo) |memo| {
            try writer.print(",\"memo\":\"{s}\"", .{memo});
        }
        
        try writer.writeAll("}");
        
        return buffer.toOwnedSlice();
    }
};

/// Generate a unique transaction ID
fn generateTxId(allocator: std.mem.Allocator, timestamp: i64, nonce: u64) ![]u8 {
    const timestamp_str = try std.fmt.allocPrint(allocator, "{}", .{timestamp});
    defer allocator.free(timestamp_str);
    
    const nonce_str = try std.fmt.allocPrint(allocator, "{}", .{nonce});
    defer allocator.free(nonce_str);
    
    const combined = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ timestamp_str, nonce_str });
    defer allocator.free(combined);
    
    // Use SHA256 for transaction ID
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(combined);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    
    return try std.fmt.allocPrint(allocator, "{x}", .{hash});
}

// Tests
test "transaction creation and basic operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var tx = try Transaction.init(allocator, 12345, "Test transaction");
    defer tx.deinit(allocator);
    
    // Add a test output
    const output = try TxOutput.init(allocator, 1000, "alice", "payment");
    try tx.addOutput(output);
    
    try std.testing.expect(tx.validate());
    try std.testing.expect(tx.getTotalOutputValue() == 1000);
    try std.testing.expect(tx.outputs.items.len == 1);
}
