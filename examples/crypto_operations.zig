//! Cryptographic Operations Example for Keystone v0.2.3 RC1
//!
//! This example demonstrates:
//! - AES-256 encryption and decryption
//! - Ed25519 digital signatures
//! - Key derivation and management
//! - Secure data storage

const std = @import("std");
const zledger_integration = @import("../src/zledger_integration.zig");
const zledger = @import("zledger");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("🚀 Starting Cryptographic Operations Example");

    // Step 1: Initialize Keystone with crypto features
    const config = zledger_integration.NodeConfig{
        .node_id = "crypto-example-node",
        .enable_audit = true,
        .enable_crypto_storage = true,
        .enable_contracts = true,
        .lazy_load = true,
    };

    var keystone_node = try zledger_integration.KeystoneNode.init(allocator, config);
    defer keystone_node.deinit();

    std.log.info("✅ Keystone node initialized with crypto features");

    // Step 2: Key Generation and Management
    std.log.info("🔑 Demonstrating key generation...");

    // Generate multiple keypairs for different purposes
    const identity_keypair = try zledger.generateKeypair();
    const signing_keypair = try zledger.generateKeypair();
    const backup_keypair = try zledger.generateKeypair();

    std.log.info("✅ Generated keypairs:");
    std.log.info("  Identity: {s}", .{std.fmt.fmtSliceHexUpper(&identity_keypair.public_key)});
    std.log.info("  Signing: {s}", .{std.fmt.fmtSliceHexUpper(&signing_keypair.public_key)});
    std.log.info("  Backup: {s}", .{std.fmt.fmtSliceHexUpper(&backup_keypair.public_key)});

    // Step 3: AES-256 Encryption Examples
    std.log.info("🔐 Demonstrating AES-256 encryption...");

    const sensitive_data = [_][]const u8{
        "User's private API key: sk_live_abc123def456",
        "Database password: super_secret_password_2024",
        "Credit card number: 4532-1234-5678-9012",
        "Personal notes: This is confidential information",
    };

    var encrypted_data = std.ArrayList([]u8).init(allocator);
    defer {
        for (encrypted_data.items) |data| {
            allocator.free(data);
        }
        encrypted_data.deinit();
    }

    // Generate a master encryption key
    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);

    for (sensitive_data, 0..) |data, i| {
        // Derive unique key for each piece of data
        var derived_key: [32]u8 = undefined;
        try deriveKey(&master_key, i, &derived_key);

        // Encrypt the data
        const ciphertext = try zcrypto.aes256.encrypt(allocator, data, derived_key);
        try encrypted_data.append(ciphertext);

        std.log.info("🔒 Encrypted data {d}: {d} bytes -> {d} bytes", .{ i + 1, data.len, ciphertext.len });
    }

    // Step 4: Demonstrate decryption
    std.log.info("🔓 Demonstrating decryption...");

    for (encrypted_data.items, 0..) |ciphertext, i| {
        // Re-derive the same key
        var derived_key: [32]u8 = undefined;
        try deriveKey(&master_key, i, &derived_key);

        // Decrypt the data
        const plaintext = try zcrypto.aes256.decrypt(allocator, ciphertext, derived_key);
        defer allocator.free(plaintext);

        std.log.info("🔓 Decrypted data {d}: {s}", .{ i + 1, plaintext });
    }

    // Step 5: Digital Signatures
    std.log.info("✍️ Demonstrating digital signatures...");

    const messages_to_sign = [_][]const u8{
        "Transaction: Alice sends 100 tokens to Bob",
        "Contract deployment: TokenContract v1.0",
        "Governance proposal: Increase block size limit",
        "Audit report: All systems operational",
    };

    var signatures = std.ArrayList(zledger.Signature).init(allocator);
    defer signatures.deinit();

    for (messages_to_sign, 0..) |message, i| {
        const signature = try zledger.signMessage(signing_keypair, message);
        try signatures.append(signature);

        std.log.info("✍️ Signed message {d}:", .{ i + 1 });
        std.log.info("  Message: {s}", .{message});
        std.log.info("  Signature: {s}", .{std.fmt.fmtSliceHexUpper(&signature.bytes)});
    }

    // Step 6: Signature Verification
    std.log.info("✅ Demonstrating signature verification...");

    for (messages_to_sign, 0..) |message, i| {
        const signature = signatures.items[i];

        // Verify with correct key
        const is_valid = try zcrypto.ed25519.verify(signing_keypair.public_key, message, signature.bytes);
        std.log.info("✓ Message {d} verification with correct key: {}", .{ i + 1, is_valid });

        // Verify with wrong key (should fail)
        const is_invalid = try zcrypto.ed25519.verify(identity_keypair.public_key, message, signature.bytes);
        std.log.info("✗ Message {d} verification with wrong key: {}", .{ i + 1, is_invalid });
    }

    // Step 7: Encrypted Contract Storage
    std.log.info("💾 Demonstrating encrypted contract storage...");

    const contract_state = try keystone_node.getContractState();
    const contract_address = "0xcrypto_example_contract_12345678";

    // Create contract account
    _ = try contract_state.getOrCreateContractAccount(contract_address);

    // Store various types of encrypted data
    const contract_data = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "owner", .value = "did:keystone:crypto-example-owner" },
        .{ .key = "api_endpoint", .value = "https://api.example.com/v1/secure" },
        .{ .key = "encryption_key", .value = std.fmt.fmtSliceHexUpper(&master_key) },
        .{ .key = "backup_seeds", .value = "word1 word2 word3 word4 word5 word6" },
    };

    for (contract_data) |item| {
        try contract_state.storeContractData(contract_address, item.key, item.value);
        std.log.info("💾 Stored encrypted: {s}", .{item.key});
    }

    // Step 8: Retrieve and verify encrypted storage
    std.log.info("🔍 Retrieving encrypted contract data...");

    for (contract_data) |item| {
        const retrieved = try contract_state.getContractData(contract_address, item.key);
        defer if (retrieved) |data| allocator.free(data);

        if (retrieved) |data| {
            std.log.info("📖 Retrieved {s}: {s}", .{ item.key, data });
            // Verify data integrity
            try std.testing.expectEqualStrings(item.value, data);
        } else {
            std.log.err("❌ Failed to retrieve: {s}", .{item.key});
        }
    }

    // Step 9: Key Rotation Example
    std.log.info("🔄 Demonstrating key rotation...");

    // Generate new master key
    var new_master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&new_master_key);

    // Re-encrypt data with new key
    const test_data = "This is data that needs re-encryption";

    // Encrypt with old key
    var old_derived_key: [32]u8 = undefined;
    try deriveKey(&master_key, 0, &old_derived_key);
    const old_ciphertext = try zcrypto.aes256.encrypt(allocator, test_data, old_derived_key);
    defer allocator.free(old_ciphertext);

    // Decrypt with old key
    const decrypted = try zcrypto.aes256.decrypt(allocator, old_ciphertext, old_derived_key);
    defer allocator.free(decrypted);

    // Re-encrypt with new key
    var new_derived_key: [32]u8 = undefined;
    try deriveKey(&new_master_key, 0, &new_derived_key);
    const new_ciphertext = try zcrypto.aes256.encrypt(allocator, decrypted, new_derived_key);
    defer allocator.free(new_ciphertext);

    std.log.info("🔄 Key rotation completed:");
    std.log.info("  Old ciphertext length: {d} bytes", .{old_ciphertext.len});
    std.log.info("  New ciphertext length: {d} bytes", .{new_ciphertext.len});

    // Step 10: Multi-signature example
    std.log.info("📝 Demonstrating multi-signature workflow...");

    const multi_sig_message = "Multi-signature transaction: Transfer 1000 tokens from treasury";

    // Multiple parties sign the same message
    const signers = [_]zledger.Keypair{
        identity_keypair,
        signing_keypair,
        backup_keypair,
    };

    var multi_signatures = std.ArrayList(zledger.Signature).init(allocator);
    defer multi_signatures.deinit();

    for (signers, 0..) |signer, i| {
        const sig = try zledger.signMessage(signer, multi_sig_message);
        try multi_signatures.append(sig);
        std.log.info("✍️ Signer {d} signed: {s}", .{ i + 1, std.fmt.fmtSliceHexUpper(&sig.bytes[0..8]) });
    }

    // Verify all signatures
    var valid_signatures: u32 = 0;
    for (signers, 0..) |signer, i| {
        const sig = multi_signatures.items[i];
        const is_valid = try zcrypto.ed25519.verify(signer.public_key, multi_sig_message, sig.bytes);
        if (is_valid) {
            valid_signatures += 1;
        }
        std.log.info("✓ Signature {d} valid: {}", .{ i + 1, is_valid });
    }

    const required_signatures: u32 = 2; // 2-of-3 multisig
    const multisig_valid = valid_signatures >= required_signatures;
    std.log.info("🎯 Multi-signature result: {d}/{d} valid (required: {d}) -> {}", .{
        valid_signatures, signers.len, required_signatures, multisig_valid
    });

    // Step 11: Performance benchmarks
    std.log.info("⏱️  Running performance benchmarks...");

    const benchmark_data = "This is test data for performance benchmarking of encryption operations";
    const iterations: u32 = 1000;

    // Benchmark encryption
    const start_encrypt = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var bench_key: [32]u8 = undefined;
        std.crypto.random.bytes(&bench_key);

        const encrypted = try zcrypto.aes256.encrypt(allocator, benchmark_data, bench_key);
        allocator.free(encrypted);
    }
    const end_encrypt = std.time.nanoTimestamp();
    const encrypt_time_ms = @as(f64, @floatFromInt(end_encrypt - start_encrypt)) / 1_000_000.0;

    // Benchmark signing
    const start_sign = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        _ = try zledger.signMessage(signing_keypair, benchmark_data);
    }
    const end_sign = std.time.nanoTimestamp();
    const sign_time_ms = @as(f64, @floatFromInt(end_sign - start_sign)) / 1_000_000.0;

    std.log.info("📊 Performance results ({d} iterations):", .{iterations});
    std.log.info("  AES-256 encryption: {d:.2}ms total, {d:.4}ms per operation", .{ encrypt_time_ms, encrypt_time_ms / @as(f64, @floatFromInt(iterations)) });
    std.log.info("  Ed25519 signing: {d:.2}ms total, {d:.4}ms per operation", .{ sign_time_ms, sign_time_ms / @as(f64, @floatFromInt(iterations)) });

    std.log.info("🎉 Cryptographic operations example completed successfully!");
}

/// Derive a key using HKDF-like mechanism
fn deriveKey(master_key: *const [32]u8, context: usize, output_key: *[32]u8) !void {
    var hasher = std.crypto.hash.blake3.Blake3.init(.{});
    hasher.update(master_key);
    hasher.update(std.mem.asBytes(&context));
    hasher.final(output_key);
}

/// Secure key comparison (constant time)
fn secureCompare(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }

    return result == 0;
}

/// Generate a cryptographically secure random salt
fn generateSalt(salt: *[16]u8) void {
    std.crypto.random.bytes(salt);
}

/// Demonstrate password-based key derivation
fn deriveKeyFromPassword(password: []const u8, salt: *const [16]u8, output_key: *[32]u8) !void {
    try std.crypto.pwhash.scrypt(
        output_key,
        password,
        salt,
        .{ .ln = 15, .r = 8, .p = 1 } // Standard scrypt parameters
    );
}

test "cryptographic operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test key generation
    const keypair1 = try zledger.generateKeypair();
    const keypair2 = try zledger.generateKeypair();

    try std.testing.expect(!std.mem.eql(u8, &keypair1.public_key, &keypair2.public_key));
    try std.testing.expect(!std.mem.eql(u8, &keypair1.private_key, &keypair2.private_key));

    // Test encryption/decryption
    const test_data = "Hello, World!";
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const encrypted = try zcrypto.aes256.encrypt(allocator, test_data, key);
    defer allocator.free(encrypted);

    const decrypted = try zcrypto.aes256.decrypt(allocator, encrypted, key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(test_data, decrypted);

    // Test signing/verification
    const message = "Test message for signing";
    const signature = try zledger.signMessage(keypair1, message);

    const is_valid = try zcrypto.ed25519.verify(keypair1.public_key, message, signature.bytes);
    try std.testing.expect(is_valid);

    const is_invalid = try zcrypto.ed25519.verify(keypair2.public_key, message, signature.bytes);
    try std.testing.expect(!is_invalid);
}

test "key derivation" {
    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    var key3: [32]u8 = undefined;

    try deriveKey(&master_key, 0, &key1);
    try deriveKey(&master_key, 1, &key2);
    try deriveKey(&master_key, 0, &key3); // Same context as key1

    // Keys derived with different contexts should be different
    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));

    // Keys derived with same context should be identical
    try std.testing.expectEqualSlices(u8, &key1, &key3);
}

test "secure comparison" {
    const data1 = "secret123";
    const data2 = "secret123";
    const data3 = "secret124";

    try std.testing.expect(secureCompare(data1, data2));
    try std.testing.expect(!secureCompare(data1, data3));
    try std.testing.expect(!secureCompare(data1, "short"));
}

test "password-based key derivation" {
    const password = "my_secure_password";
    var salt: [16]u8 = undefined;
    generateSalt(&salt);

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;

    try deriveKeyFromPassword(password, &salt, &key1);
    try deriveKeyFromPassword(password, &salt, &key2);

    // Same password and salt should produce same key
    try std.testing.expectEqualSlices(u8, &key1, &key2);

    // Different salt should produce different key
    var different_salt: [16]u8 = undefined;
    generateSalt(&different_salt);

    var key3: [32]u8 = undefined;
    try deriveKeyFromPassword(password, &different_salt, &key3);

    try std.testing.expect(!std.mem.eql(u8, &key1, &key3));
}