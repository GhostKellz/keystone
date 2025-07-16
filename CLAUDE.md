# 🏛️ TODO: Keystone v0.1.0 Planning

> Keystone is the foundation layer for the GhostKellz ecosystem — providing ledger state, transaction coordination, and execution logic for identity-aware systems.

---

## 🧱 Core Responsibilities

- [x] Ledger: deterministic state + transaction commits
- [ ] Account abstraction (via `account.zig`)
- [ ] Transaction model (inputs/outputs, signatures, nonce, tags)
- [ ] Audit journaling (from `audit.zig` / `journal.zig`)
- [ ] CLI interface for devnet + local validation (`cli.zig`)
- [ ] State coordination layer (async execution, ZVM compatibility)

---

## 📂 Archive Files Audit

| File                     | Purpose                       | Keep?     | Notes                            |
|--------------------------|-------------------------------|-----------|----------------------------------|
| `account.zig`            | Account model abstraction     | ✅ Refactor | Align w/ `zwallet` + Shroud DID  |
| `tx.zig`                 | TX structure, signature layer | ✅ Refactor | Make compatible with `zsig`     |
| `crypto_storage.zig`     | On-disk or in-mem key logic   | ❌ Drop     | Move to `zsig` or `shroud` core |
| `fixed_point.zig`        | Decimal math                  | ✅ Maybe   | If Keystone handles balances     |
| `audit.zig`, `journal.zig` | Ledger journal/audit trail   | ✅ Refactor | Use for ledger replays/checks   |
| `async_wallet.zig`       | Parallel wallet logic         | ❌ Archive | Migrate core logic to `zwallet` |
| `zwallet_integration.zig`| Custom zwallet wrapper        | ❌ Archive | Not needed if zwallet is lib     |
| `main.zig` + `root.zig`  | Entrypoint + build bindings   | ✅ Keep    | Refactor later                   |

---

## 🔗 Integration Targets

- [ ] **Shroud**: import identity & token permissions from DID layer
- [ ] **zsig**: delegate signature validation to `zsig` interfaces
- [ ] **zwallet**: interface with wallet/account logic externally
- [ ] **ZVM**: ensure execution path is forward-compatible

---

## 🚧 Design Tasks

- [ ] Define `Transaction` struct
  - Inputs, outputs, signature(s), metadata
  - Optional delegation token from Shroud
- [ ] Build initial state model
  - Simple in-memory ledger w/ snapshot + journal
- [ ] Implement role-based access validation via Shroud
- [ ] CLI commands:
  - `keystone init`
  - `keystone tx new`
  - `keystone tx verify`
  - `keystone state view`

---

## 📦 External Projects to Pull

- [x] `github.com/ghostkellz/zsig`
  - Signature abstraction: verify(), sign(), keygen()
- [x] `github.com/ghostkellz/zwallet`
  - Account abstraction: wallet, balance, key management
- [ ] Use as dependencies in `build.zig.zon` via zig fetch --save https:///etc/ghost/zsig etc only if needed
- [ ] 
---

## 🧪 Testing

- [ ] Ledger state consistency (write -> read -> journal replay)
- [ ] TX signature validation via `zsig`
- [ ] Shroud integration: accept access tokens
- [ ] CLI E2E (sign → submit → state check)

---

## 🚀 Milestone v0.1.0 Goals

- [ ] In-memory ledger w/ working transaction model
- [ ] Shroud access validation on TX submission
- [ ] CLI operational (tx create, sign, verify)
- [ ] zsig + zwallet fully integrated as libraries
- [ ] Core unit tests + journal snapshot logic

---

## 🔐 Design Rule

> Keystone is **opinionated**, **identity-aware**, and **transparent**.
> It does not hide logic — it validates execution by trust, not magic.


