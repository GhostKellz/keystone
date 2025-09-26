# Keystone CLI Reference

Complete reference for all Keystone v0.2.3 RC1 commands.

## Table of Contents

- [Core Commands](#core-commands)
- [Identity Management](#identity-management)
- [Access Control](#access-control)
- [Audit & Transparency](#audit--transparency)
- [Wallet Integration](#wallet-integration)
- [Gas Management](#gas-management)
- [Smart Contracts](#smart-contracts)
- [Distributed Synchronization](#distributed-synchronization)
- [Cryptography](#cryptography)

## Core Commands

### `keystone init`

Initialize a new Keystone ledger with DID support and zledger v0.5.0 integration.

```bash
keystone init
```

**Output:**
```
🚀 Initializing Keystone v0.2.3 Ledger with DID Support...
✅ Enhanced Keystone Node (lazy-loaded)
✅ Zledger v0.5.0 Integration
✅ Modular zcrypto Support
✅ Genesis DID account created: did:keystone:genesis
📒 Ledger state: Ready
🆔 DID registry: Active
📝 Audit journal: Enabled
```

### `keystone tx <from_did> <to_did> <amount> [--token <token>]`

Create an identity-aware transaction between DID accounts.

```bash
keystone tx did:keystone:alice did:keystone:bob 100
keystone tx did:keystone:alice did:keystone:bob 50 --token eyJ0eXAiOiJKV1Q...
```

**Parameters:**
- `from_did`: Sender's DID identifier
- `to_did`: Recipient's DID identifier
- `amount`: Transaction amount (integer)
- `--token`: Optional access token for authorization

### `keystone verify <transaction_hash>`

Verify the cryptographic integrity of a transaction.

```bash
keystone verify 0x1234567890abcdef
```

### `keystone state [did]`

View ledger state or specific account information.

```bash
# View overall state
keystone state

# View specific DID account
keystone state did:keystone:alice
```

## Identity Management

### `keystone identity create <name> [metadata]`

Create a new DID identity with Ed25519 keypair.

```bash
keystone identity create alice "Alice's trading account"
keystone identity create bob
```

**Features:**
- Generates Ed25519 keypair using Shroud v1.2.4
- Creates DID with format `did:keystone:<name>-<timestamp>`
- Grants default permissions (Send, Receive)
- Logs creation to audit journal

### `keystone identity list`

List all registered DID identities.

```bash
keystone identity list
```

### `keystone identity resolve <did>`

Resolve a DID to its full document with keys and services.

```bash
keystone identity resolve did:keystone:alice-1234567890
```

### `keystone whoami`

Show current identity context and active session.

```bash
keystone whoami
```

### `keystone permit <did> <permission>`

Grant permissions to a DID account.

```bash
keystone permit did:keystone:alice send
keystone permit did:keystone:bob create_accounts
```

**Available permissions:**
- `send` - Create outgoing transactions
- `receive` - Accept incoming transactions
- `create_accounts` - Create new accounts
- `manage_permissions` - Grant/revoke permissions
- `view_audit` - Access audit logs

## Access Control

### `keystone token create <issuer_did> <subject_did> [duration_minutes]`

Create a time-limited access token for delegated operations.

```bash
keystone token create did:keystone:admin did:keystone:alice 60
keystone token create did:keystone:admin did:keystone:bob 1440  # 24 hours
```

### `keystone token verify <token>`

Verify the validity and signature of an access token.

```bash
keystone token verify eyJ0eXAiOiJKV1Q...
```

## Audit & Transparency

### `keystone audit list [limit]`

Show recent audit journal entries.

```bash
keystone audit list
keystone audit list 50  # Show last 50 entries
```

### `keystone audit search <query>`

Search audit log for specific transactions or actors.

```bash
keystone audit search alice
keystone audit search "contract_call"
keystone audit search tx_abc123
```

## Wallet Integration

### `keystone wallet balance <did>`

Show wallet balance for a DID account.

```bash
keystone wallet balance did:keystone:alice
```

### `keystone wallet utxos <did>`

Display unspent transaction outputs for a DID.

```bash
keystone wallet utxos did:keystone:alice
```

### `keystone wallet send <from_did> <to_did> <amount>`

Send funds using the wallet subsystem.

```bash
keystone wallet send did:keystone:alice did:keystone:bob 25
```

## Gas Management

### `keystone gas stats`

Display gas usage statistics with EIP-1559 metrics.

```bash
keystone gas stats
```

**Output:**
```
⛽ Gas Statistics (EIP-1559 Model):
  🔥 Total Gas Burned: 1,250,000 units
  💰 Total Fees Distributed: 450,000 units
  📊 Current Base Fee: 0.000000020 ETH/gas
  📈 Gas Utilization: 67.3%
```

### `keystone gas charge <account_id> <gas_used> <base_fee> [priority_fee]`

Manually charge gas fees using EIP-1559 pricing model.

```bash
keystone gas charge 1 21000 0.00000002
keystone gas charge 2 50000 0.00000003 0.000000001
```

**Parameters:**
- `account_id`: Numeric account ID
- `gas_used`: Amount of gas consumed
- `base_fee`: Base fee per gas unit (ETH/gas)
- `priority_fee`: Optional priority fee for faster processing

### `keystone gas estimate <transaction_type>`

Estimate gas requirements for different transaction types.

```bash
keystone gas estimate transfer
keystone gas estimate contract_call
keystone gas estimate contract_deploy
```

**Supported types:**
- `transfer`: Basic token transfer (21,000 gas)
- `contract_call`: Smart contract method call (50,000 gas)
- `contract_deploy`: Deploy new contract (200,000 gas)
- `complex_defi`: Complex DeFi interaction (350,000 gas)

## Smart Contracts

### `keystone contract deploy <contract_address>`

Deploy a smart contract with encrypted storage capabilities.

```bash
keystone contract deploy 0x1234567890abcdef
```

**Features:**
- Creates dedicated ledger account for contract
- Enables AES-256 encrypted storage
- Registers contract in state manager

### `keystone contract call <contract_address> <method> <amount>`

Execute a contract method with balance changes.

```bash
keystone contract call 0x1234567890abcdef transfer 100
keystone contract call 0x1234567890abcdef approve -50
```

### `keystone contract storage <contract_address> get <key>`

Read encrypted data from contract storage.

```bash
keystone contract storage 0x1234567890abcdef get balance
keystone contract storage 0x1234567890abcdef get owner
```

### `keystone contract storage <contract_address> set <key> <value>`

Write encrypted data to contract storage.

```bash
keystone contract storage 0x1234567890abcdef set balance 1000
keystone contract storage 0x1234567890abcdef set metadata "important data"
```

**Security:**
- All contract data is encrypted using AES-256
- Encryption keys are derived from contract address
- Storage operations are logged to audit journal

## Distributed Synchronization

### `keystone sync status`

Show the current synchronization status of this node.

```bash
keystone sync status
```

**Output:**
```
🔄 Distributed Synchronization Status:
  📡 Node ID: keystone-cli-node
  🌐 Peer Count: 3
  ⏰ Last Sync: 42 seconds ago
  📊 Sync Status: ✅ Up to date
  🔗 Journal Entries: 1,234
```

### `keystone sync peers`

List all configured peer nodes.

```bash
keystone sync peers
```

### `keystone sync peers add <peer_node_id>`

Add a new peer node for synchronization.

```bash
keystone sync peers add keystone-node-002
keystone sync peers add remote-validator-alpha
```

### `keystone sync run`

Manually trigger a synchronization cycle with all peers.

```bash
keystone sync run
```

**Process:**
1. Connects to all configured peer nodes
2. Requests journal entries since last sync
3. Validates entries using double-entry bookkeeping rules
4. Applies validated entries to local ledger
5. Sends local entries to peers

## Cryptography

### `keystone crypto encrypt <plaintext>`

Encrypt data using AES-256 with randomly generated key.

```bash
keystone crypto encrypt "sensitive information"
keystone crypto encrypt "API key: sk_test_..."
```

**Output:**
```
🔐 Encrypting data with zcrypto...
✅ Data encrypted successfully
  🔑 Key: 1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B
  📦 Ciphertext: 9F8E7D6C5B4A3928374656...
```

### `keystone crypto decrypt <ciphertext_hex>`

Decrypt AES-256 encrypted data (requires original key).

```bash
keystone crypto decrypt 9F8E7D6C5B4A3928374656...
```

### `keystone crypto sign <message>`

Sign a message using Ed25519 with node's identity key.

```bash
keystone crypto sign "Hello, World!"
keystone crypto sign "Transaction: Alice -> Bob: 100"
```

**Output:**
```
✍️ Signing message with Ed25519...
✅ Message signed successfully
  🔑 Public Key: A1B2C3D4E5F6789A0B1C2D3E4F567890ABCDEF...
  ✍️ Signature: 1234567890ABCDEF1234567890ABCDEF...
```

### `keystone crypto verify <message> <signature_hex>`

Verify an Ed25519 signature (requires public key).

```bash
keystone crypto verify "Hello, World!" 1234567890ABCDEF...
```

### `keystone crypto keygen`

Generate a new Ed25519 keypair for identity purposes.

```bash
keystone crypto keygen
```

**Output:**
```
🔑 Generating new Ed25519 keypair...
✅ Keypair generated successfully
  🔑 Public Key: A1B2C3D4E5F6789A0B1C2D3E4F567890ABCDEF...
  🔐 Private Key: 1234567890ABCDEF1234567890ABCDEF...
  ⚠️ Keep the private key secure!
```

## Error Handling

Common error codes and their meanings:

- `InvalidCommand` - Unknown or malformed command
- `InvalidArguments` - Incorrect number or format of arguments
- `PermissionDenied` - Insufficient permissions for operation
- `TokenExpired` - Access token has expired
- `InvalidSignature` - Cryptographic signature verification failed
- `LedgerNotInitialized` - Attempted operation before `keystone init`
- `AccountNotFound` - Referenced account does not exist

## Environment Variables

- `KEYSTONE_LOG_LEVEL` - Set logging verbosity (debug, info, warn, error)
- `KEYSTONE_DATA_DIR` - Override default data directory
- `KEYSTONE_NODE_ID` - Set custom node identifier

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Invalid command or arguments
- `3` - Permission denied
- `4` - Cryptographic error
- `5` - Network/synchronization error