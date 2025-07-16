const std = @import("std");
const zsig = @import("zsig");

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
    
    /// Generate transaction hash for signing
    pub fn getHash(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
        // Create a canonical representation for signing
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        const writer = buffer.writer();
        
        // Include core transaction data (excluding signatures)
        try writer.print("{}:{}", .{ self.timestamp, self.nonce });
        
        // Include inputs
        for (self.inputs.items) |input| {
            try writer.print(":{s}:{}", .{ input.prev_tx_id, input.output_index });
        }
        
        // Include outputs
        for (self.outputs.items) |output| {
            try writer.print(":{s}:{}", .{ output.recipient, output.value });
        }
        
        if (self.memo) |memo| {
            try writer.print(":{s}", .{memo});
        }
        
        // Hash the canonical representation
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(buffer.items);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        return try allocator.dupe(u8, &hash);
    }
    
    /// Sign transaction with a private key
    pub fn sign(self: *Transaction, allocator: std.mem.Allocator, private_key: []const u8) !void {
        const hash = try self.getHash(allocator);
        defer allocator.free(hash);
        
        // Use zsig to create signature
        const signature = try zsig.sign(allocator, private_key, hash);
        try self.addSignature(allocator, signature);
    }
    
    /// Verify all signatures in the transaction
    pub fn verifySignatures(self: Transaction, allocator: std.mem.Allocator, public_keys: []const []const u8) !bool {
        if (self.signatures.items.len != public_keys.len) {
            return false; // Signature count mismatch
        }
        
        const hash = try self.getHash(allocator);
        defer allocator.free(hash);
        
        // Verify each signature
        for (self.signatures.items, 0..) |signature, i| {
            const is_valid = try zsig.verify(allocator, public_keys[i], signature, hash);
            if (!is_valid) {
                return false;
            }
        }
        
        return true;
    }
    
    /// Multi-signature validation with M-of-N threshold
    pub fn verifyMultiSignature(self: Transaction, allocator: std.mem.Allocator, authorized_keys: []const []const u8, required_signatures: u32) !bool {
        if (required_signatures == 0 or required_signatures > authorized_keys.len) {
            return false; // Invalid threshold
        }
        
        const hash = try self.getHash(allocator);
        defer allocator.free(hash);
        
        var valid_signatures: u32 = 0;
        
        // For each signature, check if it's from an authorized key
        for (self.signatures.items) |signature| {
            for (authorized_keys) |pub_key| {
                if (try zsig.verify(allocator, pub_key, signature, hash)) {
                    valid_signatures += 1;
                    break; // Found a match, move to next signature
                }
            }
        }
        
        return valid_signatures >= required_signatures;
    }
    
    /// Add multiple signatures to transaction
    pub fn addMultipleSignatures(self: *Transaction, allocator: std.mem.Allocator, signatures: []const []const u8) !void {
        for (signatures) |sig| {
            try self.addSignature(allocator, sig);
        }
    }
    
    /// Validate transaction structure (basic validation)
    pub fn validate(self: Transaction) bool {
        // Basic validation rules
        if (self.inputs.items.len == 0 and self.outputs.items.len == 0) {
            return false; // Empty transaction
        }
        
        // Additional structural validations
        for (self.outputs.items) |output| {
            if (output.value == 0) {
                return false; // Zero-value output
            }
        }
        
        // TODO: Add more validation:
        // - Nonce uniqueness (checked by ledger)
        // - Delegation token verification (via Shroud)
        // - Input reference validation (checked by ledger)
        
        return true;
    }
    
    /// Validate transaction with required signatures
    pub fn validateSigned(self: Transaction) bool {
        if (!self.validate()) {
            return false;
        }
        
        // Check that we have at least one signature
        if (self.signatures.items.len == 0) {
            return false; // Unsigned transaction
        }
        
        return true;
    }
    
    /// Validate transaction with signature verification
    pub fn validateWithSignatures(self: Transaction, allocator: std.mem.Allocator, public_keys: []const []const u8) !bool {
        if (!self.validate()) {
            return false;
        }
        
        return try self.verifySignatures(allocator, public_keys);
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
    const timestamp_str = try std.fmt.allocPrint(allocator, "{d}", .{timestamp});
    defer allocator.free(timestamp_str);
    
    const nonce_str = try std.fmt.allocPrint(allocator, "{d}", .{nonce});
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

test "multi-signature transaction validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var tx = try Transaction.init(allocator, 12345, "Multi-sig test");
    defer tx.deinit(allocator);
    
    const output = try TxOutput.init(allocator, 1000, "alice", null);
    try tx.addOutput(output);
    
    // Add mock signatures (in real use, these would be actual signatures)
    try tx.addSignature(allocator, "sig1");
    try tx.addSignature(allocator, "sig2");
    
    try std.testing.expect(tx.validateSigned());
    try std.testing.expect(tx.signatures.items.len == 2);
}
