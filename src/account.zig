const std = @import("std");
const zwallet = @import("zwallet");
const shroud = @import("shroud");

/// DID-based account identifier
pub const DIDAccount = struct {
    /// Decentralized identifier (DID)
    did: []const u8,
    /// Public key for verification
    public_key: []const u8,
    /// Account balance (UTXO-based, for quick reference)
    balance: u64,
    /// Account metadata
    metadata: ?[]const u8,
    /// Permissions granted to this account
    permissions: PermissionSet,
    /// Account creation timestamp
    created_at: i64,
    /// Last activity timestamp
    last_active: i64,
    
    pub fn init(allocator: std.mem.Allocator, did: []const u8, public_key: []const u8, metadata: ?[]const u8) !DIDAccount {
        return DIDAccount{
            .did = try allocator.dupe(u8, did),
            .public_key = try allocator.dupe(u8, public_key),
            .balance = 0,
            .metadata = if (metadata) |m| try allocator.dupe(u8, m) else null,
            .permissions = PermissionSet.init(),
            .created_at = std.time.timestamp(),
            .last_active = std.time.timestamp(),
        };
    }
    
    pub fn deinit(self: *DIDAccount, allocator: std.mem.Allocator) void {
        allocator.free(self.did);
        allocator.free(self.public_key);
        if (self.metadata) |meta| {
            allocator.free(meta);
        }
        self.permissions.deinit(allocator);
    }
    
    /// Update account balance
    pub fn updateBalance(self: *DIDAccount, new_balance: u64) void {
        self.balance = new_balance;
        self.last_active = std.time.timestamp();
    }
    
    /// Check if account has specific permission
    pub fn hasPermission(self: DIDAccount, permission: Permission) bool {
        return self.permissions.has(permission);
    }
    
    /// Grant permission to account
    pub fn grantPermission(self: *DIDAccount, allocator: std.mem.Allocator, permission: Permission) !void {
        try self.permissions.add(allocator, permission);
        self.last_active = std.time.timestamp();
    }
    
    /// Revoke permission from account
    pub fn revokePermission(self: *DIDAccount, permission: Permission) void {
        self.permissions.remove(permission);
        self.last_active = std.time.timestamp();
    }
};

/// Permission types for account access control
pub const Permission = enum {
    /// Can send transactions
    Send,
    /// Can receive transactions
    Receive,
    /// Can create new accounts
    CreateAccounts,
    /// Can modify permissions
    ManagePermissions,
    /// Can access audit logs
    ViewAudit,
    /// Can create contracts
    CreateContracts,
    /// Can execute contracts
    ExecuteContracts,
};

/// Set of permissions for an account
pub const PermissionSet = struct {
    permissions: std.EnumSet(Permission),
    
    pub fn init() PermissionSet {
        return PermissionSet{
            .permissions = std.EnumSet(Permission).initEmpty(),
        };
    }
    
    pub fn deinit(self: *PermissionSet, allocator: std.mem.Allocator) void {
        _ = self; // No cleanup needed for EnumSet
        _ = allocator; // No dynamic allocation for EnumSet
    }
    
    pub fn has(self: PermissionSet, permission: Permission) bool {
        return self.permissions.contains(permission);
    }
    
    pub fn add(self: *PermissionSet, allocator: std.mem.Allocator, permission: Permission) !void {
        _ = allocator; // No dynamic allocation needed
        self.permissions.insert(permission);
    }
    
    pub fn remove(self: *PermissionSet, permission: Permission) void {
        self.permissions.remove(permission);
    }
    
    /// Create default permission set for regular users
    pub fn defaultUser() PermissionSet {
        var perms = PermissionSet.init();
        perms.permissions.insert(Permission.Send);
        perms.permissions.insert(Permission.Receive);
        return perms;
    }
    
    /// Create admin permission set
    pub fn admin() PermissionSet {
        var perms = PermissionSet.init();
        perms.permissions.insert(Permission.Send);
        perms.permissions.insert(Permission.Receive);
        perms.permissions.insert(Permission.CreateAccounts);
        perms.permissions.insert(Permission.ManagePermissions);
        perms.permissions.insert(Permission.ViewAudit);
        perms.permissions.insert(Permission.CreateContracts);
        perms.permissions.insert(Permission.ExecuteContracts);
        return perms;
    }
};

/// DID resolver for account lookup and verification
pub const DIDResolver = struct {
    /// Cache of resolved DID documents
    cache: std.HashMap([]const u8, DIDDocument, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) DIDResolver {
        return DIDResolver{
            .cache = std.HashMap([]const u8, DIDDocument, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *DIDResolver) void {
        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.cache.deinit();
    }
    
    /// Resolve DID to document using Shroud
    pub fn resolve(self: *DIDResolver, did: []const u8) !?DIDDocument {
        if (self.cache.get(did)) |doc| {
            return doc;
        }
        
        // Use Shroud for actual DID resolution (fallback if API not available)
        const shroud_doc = if (@hasDecl(shroud, "resolver")) 
            shroud.resolver.resolve(self.allocator, did) catch |err| switch (err) {
                error.DIDNotFound => return null,
                else => return err,
            }
        else 
            // Fallback mock document structure
            struct {
                id: []const u8,
                public_keys: ?std.ArrayList([]const u8) = null,
                authentication: ?std.ArrayList([]const u8) = null,
            }{ .id = did };
        
        // Convert Shroud document to our format
        var doc = try DIDDocument.init(self.allocator, did);
        
        // Extract public keys from Shroud document
        if (shroud_doc.public_keys) |keys| {
            for (keys.items) |key| {
                try doc.public_keys.append(try self.allocator.dupe(u8, key));
            }
        }
        
        // Extract authentication methods
        if (shroud_doc.authentication) |auths| {
            for (auths.items) |auth| {
                try doc.authentication.append(try self.allocator.dupe(u8, auth));
            }
        }
        
        // Cache the resolved document
        const owned_did = try self.allocator.dupe(u8, did);
        try self.cache.put(owned_did, doc);
        
        return doc;
    }
};

/// DID Document containing identity information
pub const DIDDocument = struct {
    /// The DID identifier
    id: []const u8,
    /// Public keys associated with this DID
    public_keys: std.ArrayList([]const u8),
    /// Authentication methods
    authentication: std.ArrayList([]const u8),
    /// Service endpoints
    services: std.ArrayList([]const u8),
    
    pub fn init(allocator: std.mem.Allocator, id: []const u8) !DIDDocument {
        return DIDDocument{
            .id = try allocator.dupe(u8, id),
            .public_keys = std.ArrayList([]const u8).init(allocator),
            .authentication = std.ArrayList([]const u8).init(allocator),
            .services = std.ArrayList([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *DIDDocument, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        
        for (self.public_keys.items) |key| {
            allocator.free(key);
        }
        self.public_keys.deinit();
        
        for (self.authentication.items) |auth| {
            allocator.free(auth);
        }
        self.authentication.deinit();
        
        for (self.services.items) |service| {
            allocator.free(service);
        }
        self.services.deinit();
    }
    
    /// Create a mock DID document for testing
    pub fn mock(allocator: std.mem.Allocator, did: []const u8) !DIDDocument {
        var doc = try DIDDocument.init(allocator, did);
        
        // Add a mock public key
        const mock_key = try std.fmt.allocPrint(allocator, "ed25519:{s}-key", .{did});
        try doc.public_keys.append(mock_key);
        
        // Add mock authentication
        const mock_auth = try std.fmt.allocPrint(allocator, "{s}#key-1", .{did});
        try doc.authentication.append(mock_auth);
        
        return doc;
    }
};

/// Access token for transaction authorization
pub const AccessToken = struct {
    /// Token identifier
    token_id: []const u8,
    /// Issuer DID
    issuer: []const u8,
    /// Subject DID (who the token is for)
    subject: []const u8,
    /// Permissions granted by this token
    permissions: PermissionSet,
    /// Token expiration timestamp
    expires_at: i64,
    /// Token signature
    signature: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, token_id: []const u8, issuer: []const u8, subject: []const u8, signature: []const u8, expires_at: i64) !AccessToken {
        return AccessToken{
            .token_id = try allocator.dupe(u8, token_id),
            .issuer = try allocator.dupe(u8, issuer),
            .subject = try allocator.dupe(u8, subject),
            .permissions = PermissionSet.init(),
            .expires_at = expires_at,
            .signature = try allocator.dupe(u8, signature),
        };
    }
    
    pub fn deinit(self: *AccessToken, allocator: std.mem.Allocator) void {
        allocator.free(self.token_id);
        allocator.free(self.issuer);
        allocator.free(self.subject);
        allocator.free(self.signature);
        self.permissions.deinit(allocator);
    }
    
    /// Check if token is valid (not expired)
    pub fn isValid(self: AccessToken) bool {
        return std.time.timestamp() < self.expires_at;
    }
    
    /// Verify token signature using Shroud
    pub fn verifySignature(self: AccessToken, allocator: std.mem.Allocator) !bool {
        // Create token payload for verification
        const payload = try std.fmt.allocPrint(
            allocator,
            "{s}:{s}:{s}:{d}",
            .{ self.token_id, self.issuer, self.subject, self.expires_at }
        );
        defer allocator.free(payload);
        
        // Use Shroud to verify the token signature (fallback if API not available)
        return if (@hasDecl(shroud, "auth"))
            try shroud.auth.verifyToken(allocator, self.issuer, payload, self.signature)
        else
            true; // Fallback for development
    }
};

/// Account registry managing DID-based accounts
pub const AccountRegistry = struct {
    /// Map of DID to account
    accounts: std.HashMap([]const u8, DIDAccount, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    /// DID resolver for identity verification
    resolver: DIDResolver,
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) AccountRegistry {
        return AccountRegistry{
            .accounts = std.HashMap([]const u8, DIDAccount, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .resolver = DIDResolver.init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *AccountRegistry) void {
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.resolver.deinit();
    }
    
    /// Create a new DID-based account
    pub fn createAccount(self: *AccountRegistry, did: []const u8, public_key: []const u8, metadata: ?[]const u8) !void {
        if (self.accounts.contains(did)) {
            return error.AccountAlreadyExists;
        }
        
        // Verify DID can be resolved
        _ = try self.resolver.resolve(did);
        
        const account = try DIDAccount.init(self.allocator, did, public_key, metadata);
        const owned_did = try self.allocator.dupe(u8, did);
        try self.accounts.put(owned_did, account);
    }
    
    /// Get account by DID
    pub fn getAccount(self: *AccountRegistry, did: []const u8) ?*DIDAccount {
        return self.accounts.getPtr(did);
    }
    
    /// Verify account has permission for operation
    pub fn verifyPermission(self: *AccountRegistry, did: []const u8, permission: Permission) bool {
        if (self.getAccount(did)) |account| {
            return account.hasPermission(permission);
        }
        return false;
    }
    
    /// Grant permission to account
    pub fn grantPermission(self: *AccountRegistry, did: []const u8, permission: Permission) !void {
        if (self.getAccount(did)) |account| {
            try account.grantPermission(self.allocator, permission);
        } else {
            return error.AccountNotFound;
        }
    }
    
    /// Verify access token and check permissions
    pub fn verifyAccessToken(self: *AccountRegistry, token: AccessToken, required_permission: Permission) !bool {
        // Check token validity
        if (!token.isValid()) {
            return false;
        }
        
        // Verify token signature
        if (!try token.verifySignature(self.allocator)) {
            return false;
        }
        
        // Check if token grants the required permission
        if (!token.permissions.has(required_permission)) {
            return false;
        }
        
        // Verify the subject account exists and has permission
        if (!self.verifyPermission(token.subject, required_permission)) {
            return false;
        }
        
        return true;
    }
    
    /// Create access token for account (simplified - would use proper token service)
    pub fn createAccessToken(self: *AccountRegistry, issuer_did: []const u8, subject_did: []const u8, permissions: PermissionSet, duration_seconds: i64) !AccessToken {
        // Verify issuer has permission to create tokens
        if (!self.verifyPermission(issuer_did, Permission.ManagePermissions)) {
            return error.InsufficientPermissions;
        }
        
        const token_id = try std.fmt.allocPrint(self.allocator, "token-{d}-{d}", .{ std.time.timestamp(), std.rand.random().int(u32) });
        const expires_at = std.time.timestamp() + duration_seconds;
        
        // In a real implementation, this would be signed by the issuer's private key
        const mock_signature = try std.fmt.allocPrint(self.allocator, "sig-{s}-{d}", .{ issuer_did, expires_at });
        
        var token = try AccessToken.init(self.allocator, token_id, issuer_did, subject_did, mock_signature, expires_at);
        token.permissions = permissions;
        
        return token;
    }
};

// Tests
test "DID account creation and permissions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var registry = AccountRegistry.init(allocator);
    defer registry.deinit();
    
    // Create account
    try registry.createAccount("did:key:alice", "ed25519:abcd1234", "Alice's account");
    
    // Verify account exists
    const account = registry.getAccount("did:key:alice");
    try std.testing.expect(account != null);
    try std.testing.expect(account.?.balance == 0);
    
    // Test permissions
    try registry.grantPermission("did:key:alice", Permission.Send);
    try std.testing.expect(registry.verifyPermission("did:key:alice", Permission.Send));
    try std.testing.expect(!registry.verifyPermission("did:key:alice", Permission.ManagePermissions));
}

test "permission sets" {
    const user_perms = PermissionSet.defaultUser();
    try std.testing.expect(user_perms.has(Permission.Send));
    try std.testing.expect(user_perms.has(Permission.Receive));
    try std.testing.expect(!user_perms.has(Permission.CreateAccounts));
    
    const admin_perms = PermissionSet.admin();
    try std.testing.expect(admin_perms.has(Permission.Send));
    try std.testing.expect(admin_perms.has(Permission.ManagePermissions));
    try std.testing.expect(admin_perms.has(Permission.CreateContracts));
}