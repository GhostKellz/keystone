# Keystone v0.2.2 CLI Commands

Keystone is a DID-enabled ledger with advanced identity management, providing a comprehensive command-line interface for transaction processing, identity management, and audit operations.

## Table of Contents

- [Core Commands](#core-commands)
- [Identity Management](#identity-management)
- [Access Control](#access-control)
- [Audit & Transparency](#audit--transparency)
- [Wallet Integration](#wallet-integration)
- [Examples](#examples)

## Core Commands

### `keystone init`
Initialize a new Keystone ledger with DID support.

```bash
keystone init
```

**Features:**
- Creates genesis DID account
- Initializes ledger state
- Sets up audit journal
- Configures DID registry

**Output:**
```
🚀 Initializing Keystone v0.2.2 Ledger with DID Support...
✅ Genesis DID account created: did:keystone:genesis
✅ Keystone v0.2.2 initialized successfully
  📒 Ledger state: Ready
  🆔 DID registry: Active
  📝 Audit journal: Enabled
```

---

### `keystone tx <from_did> <to_did> <amount>`
Create a DID-based transaction between two accounts.

```bash
keystone tx <from_did> <to_did> <amount> [--token <access_token>]
```

**Parameters:**
- `from_did` - Source DID (e.g., `did:keystone:alice`)
- `to_did` - Destination DID (e.g., `did:keystone:bob`)
- `amount` - Transaction amount (numeric)
- `--token` - Optional access token for delegation

**Example:**
```bash
keystone tx did:keystone:alice did:keystone:bob 100
keystone tx did:keystone:alice did:keystone:bob 50 --token abc123...def456
```

**Features:**
- Permission verification
- Access token validation
- Cryptographic signing (zSig)
- Audit logging

---

### `keystone verify <transaction_hash>`
Verify transaction integrity and authenticity.

```bash
keystone verify <transaction_hash>
```

**Parameters:**
- `transaction_hash` - Hash of the transaction to verify

**Example:**
```bash
keystone verify abc123def456...
```

**Features:**
- Signature verification
- Audit trail validation
- Timestamp verification

---

### `keystone state [did]`
View ledger state or specific DID account information.

```bash
keystone state              # Overall ledger state
keystone state <did>        # Specific DID account
```

**Examples:**
```bash
keystone state                           # Overall state
keystone state did:keystone:alice        # Alice's account
```

**Output (Overall):**
```
📊 Overall Keystone v0.2.2 State:
  📈 Total accounts: 5
  💎 Current sequence: 42
  🆔 DID accounts: 3
  📝 Journal entries: 15
```

**Output (Specific DID):**
```
📊 Account state for DID: did:keystone:alice
  💰 Balance: 250
  🔑 Public key: ed25519:abc123...
  📅 Created: 1652772400
  ⏰ Last active: 1652772430
  🔐 Permissions:
    ✅ Send
    ✅ Receive
```

---

### `keystone help`
Display comprehensive help information.

```bash
keystone help
```

Shows all available commands with descriptions and examples.

---

## Identity Management

### `keystone identity create <name> [metadata]`
Create a new DID-based identity.

```bash
keystone identity create <name> [metadata]
```

**Parameters:**
- `name` - Human-readable name for the identity
- `metadata` - Optional metadata description

**Examples:**
```bash
keystone identity create alice
keystone identity create bob "Bob's trading account"
```

**Features:**
- Generates unique DID
- Creates Ed25519 keypair
- Sets default permissions
- Registers in DID registry

---

### `keystone identity list`
List all registered DID identities.

```bash
keystone identity list
```

**Output:**
```
📋 DID Identities in Keystone Registry:
  1. did:keystone:alice-1652772400
     Balance: 100
     Created: 1652772400
     Permissions: Send, Receive
  
  2. did:keystone:bob-1652772450
     Balance: 50
     Created: 1652772450
     Permissions: Send, Receive
```

---

### `keystone identity resolve <did>`
Resolve a DID to its document.

```bash
keystone identity resolve <did>
```

**Example:**
```bash
keystone identity resolve did:keystone:alice-1652772400
```

**Output:**
```
✅ DID Document resolved:
  ID: did:keystone:alice-1652772400
  Public Keys:
    - ed25519:abc123...def456
  Authentication Methods:
    - did:keystone:alice-1652772400#key-1
```

---

### `keystone whoami`
Show current identity context and session information.

```bash
keystone whoami
```

**Output:**
```
👤 Current Keystone v0.2.2 Identity Context
  🆔 Active DID: did:keystone:user-demo
  🔑 Key type: Ed25519
  🌐 Resolver: Shroud v1.2.3
  📱 Agent: Keystone CLI v0.2.2
  🔐 Current session permissions:
    ✅ transaction.create
    ✅ identity.view
    ✅ audit.view
```

---

### `keystone permit <did> <permission>`
Grant permissions to a DID account.

```bash
keystone permit <did> <permission>
```

**Available Permissions:**
- `send` - Can send transactions
- `receive` - Can receive transactions
- `create_accounts` - Can create new accounts
- `manage_permissions` - Can grant/revoke permissions
- `view_audit` - Can access audit logs

**Examples:**
```bash
keystone permit did:keystone:alice send
keystone permit did:keystone:bob manage_permissions
keystone permit did:keystone:admin view_audit
```

---

## Access Control

### `keystone token create <issuer_did> <subject_did> [duration_minutes]`
Create an access token for delegation.

```bash
keystone token create <issuer_did> <subject_did> [duration_minutes]
```

**Parameters:**
- `issuer_did` - DID creating the token (must have manage_permissions)
- `subject_did` - DID the token is for
- `duration_minutes` - Token validity period (default: 60 minutes)

**Examples:**
```bash
keystone token create did:keystone:admin did:keystone:alice
keystone token create did:keystone:admin did:keystone:bob 120
```

**Output:**
```
✅ Access token created successfully
  Token ID: token-1652772430-42
  Expires: 1652776030
  Signature: sig-did:keystone:admin-1652776030
```

---

### `keystone token verify <token>`
Verify an access token's validity.

```bash
keystone token verify <token>
```

**Example:**
```bash
keystone token verify token-1652772430-42
```

**Output:**
```
✅ Token is valid
  ⏰ Not expired
  🔐 Signature verified
  🎫 Permissions confirmed
```

---

## Audit & Transparency

### `keystone audit list [limit]`
Show recent audit entries.

```bash
keystone audit list [limit]
```

**Parameters:**
- `limit` - Maximum number of entries to show (default: 10)

**Examples:**
```bash
keystone audit list           # Last 10 entries
keystone audit list 25        # Last 25 entries
```

**Output:**
```
📝 Recent audit entries (limit: 10):
  1. [1652772430] seq=5 tx_id=tx-abc123...
      Hash: deadbeef...
  2. [1652772400] seq=4 tx_id=tx-def456...
      Hash: cafebabe...
```

---

### `keystone audit search <query>`
Search audit entries for specific content.

```bash
keystone audit search <query>
```

**Examples:**
```bash
keystone audit search alice               # Search for "alice"
keystone audit search "transaction"       # Search for "transaction"
keystone audit search did:keystone:bob    # Search for specific DID
```

**Output:**
```
🔍 Searching audit entries for: alice
  1. [1652772430] seq=5 tx_id=tx-alice-bob-100
      Index: 5
  2. [1652772400] seq=3 tx_id=tx-genesis-alice-50
      Index: 3

Found 2 matching entries
```

---

## Wallet Integration

### `keystone wallet balance <did>`
Show wallet balance for a DID.

```bash
keystone wallet balance <did>
```

**Example:**
```bash
keystone wallet balance did:keystone:alice
```

**Output:**
```
💰 Wallet balance for DID: did:keystone:alice
  💎 Balance: 150 units
  📊 Account type: DID-based
  🔗 Ledger integration: Active
```

---

### `keystone wallet utxos <did>`
Show unspent transaction outputs (UTXOs) for a DID.

```bash
keystone wallet utxos <did>
```

**Example:**
```bash
keystone wallet utxos did:keystone:alice
```

**Output:**
```
📦 UTXOs for DID: did:keystone:alice
  1. UTXO: 50 units (txid: abc123...def456)
  2. UTXO: 25 units (txid: fed654...321cba)
  3. UTXO: 75 units (txid: 789xyz...uvw012)

  Total UTXOs: 3
  Total Value: 150 units
```

---

### `keystone wallet send <from_did> <to_did> <amount>`
Send funds using wallet integration.

```bash
keystone wallet send <from_did> <to_did> <amount>
```

**Example:**
```bash
keystone wallet send did:keystone:alice did:keystone:bob 50
```

This command delegates to the transaction system with wallet-specific UTXO management.

---

## Examples

### Complete Workflow Example

```bash
# 1. Initialize Keystone
keystone init

# 2. Create identities
keystone identity create alice "Alice's account"
keystone identity create bob "Bob's account"

# 3. List identities
keystone identity list

# 4. Grant permissions
keystone permit did:keystone:alice-1652772400 send
keystone permit did:keystone:bob-1652772450 receive

# 5. Create transaction
keystone tx did:keystone:alice-1652772400 did:keystone:bob-1652772450 100

# 6. Check state
keystone state did:keystone:alice-1652772400
keystone state did:keystone:bob-1652772450

# 7. Create access token
keystone token create did:keystone:genesis did:keystone:alice-1652772400 120

# 8. View audit trail
keystone audit list 5
keystone audit search alice

# 9. Check wallet balances
keystone wallet balance did:keystone:alice-1652772400
keystone wallet utxos did:keystone:alice-1652772400
```

### Advanced Permission Management

```bash
# Create admin identity
keystone identity create admin "System administrator"

# Grant admin permissions
keystone permit did:keystone:admin-1652772500 create_accounts
keystone permit did:keystone:admin-1652772500 manage_permissions
keystone permit did:keystone:admin-1652772500 view_audit

# Use admin to create tokens for others
keystone token create did:keystone:admin-1652772500 did:keystone:alice-1652772400 240
```

### Transaction with Delegation

```bash
# Create token for Alice
keystone token create did:keystone:admin-1652772500 did:keystone:alice-1652772400

# Use token in transaction
keystone tx did:keystone:alice-1652772400 did:keystone:bob-1652772450 25 --token token-1652772500-123

# Verify the token
keystone token verify token-1652772500-123
```

---

## Enhanced Features in v0.2.2

- ✅ **Decentralized Identity (DID)** support via Shroud v1.2.3
- ✅ **Permission-based access control** with granular permissions
- ✅ **Access token delegation** for secure operation delegation
- ✅ **Comprehensive audit logging** with searchable trails
- ✅ **Cryptographic signature verification** using zSig
- ✅ **UTXO wallet integration** via zWallet
- ✅ **Enhanced ledger coordination** through zLedger

## Dependencies

- **Shroud v1.2.3** - Identity and DID management
- **zLedger v0.3.2** - Ledger state coordination
- **zSig v0.5.0** - Cryptographic signatures
- **zWallet v0.3.2** - UTXO wallet management

## Error Handling

All commands include comprehensive error handling:
- Permission validation
- Token expiration checks
- Signature verification
- Input validation
- Resource availability

Run `keystone help` for interactive assistance or refer to specific command help using `keystone <command> --help`.
