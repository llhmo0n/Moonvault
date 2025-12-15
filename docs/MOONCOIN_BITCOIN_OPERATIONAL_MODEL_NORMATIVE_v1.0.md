# MOONCOIN–BITCOIN OPERATIONAL MODEL
## Normative Specification v1.0

```
Document Status:    NORMATIVE
Version:            1.0
Date:               2025-12-15
Scope:              Defines the operational relationship between Mooncoin and Bitcoin
Authority:          This document is binding for all Mooncoin implementations
```

---

## 0. FOUNDATIONAL STATEMENT

> **Mooncoin is a human operational system around Bitcoin, without touching its sovereignty.**

All specifications in this document derive from this statement. Any implementation, proposal, or interpretation that contradicts this statement is invalid.

---

## 1. MODEL DEFINITION: LOCK–OPERATE–SETTLE

### 1.1 Model Overview

```
BITCOIN (sovereign reserve)
   ↑           ↓
 LOCK       SETTLE
   ↓           ↑
MOONCOIN (human operation)
```

### 1.2 Layer Responsibilities

| Layer | Domain | Function | Risk Absorbed |
|-------|--------|----------|---------------|
| Bitcoin | Settlement | Final reserve, value storage | Base value risk |
| Mooncoin | Operation | Daily use, human protection | Usage risk, operational error |

### 1.3 Invariants

The following conditions MUST hold at all times:

1. **INV-1**: Bitcoin NEVER trusts Mooncoin
2. **INV-2**: Mooncoin NEVER custodies BTC
3. **INV-3**: LOCK occurs ONLY on Bitcoin
4. **INV-4**: OPERATE occurs ONLY on Mooncoin
5. **INV-5**: SETTLE occurs ONLY on Bitcoin
6. **INV-6**: User can ALWAYS exit to Bitcoin unilaterally

---

## 2. LOCK SPECIFICATION

### 2.1 Definition

LOCK is the act of committing BTC to a time-locked script on Bitcoin, observable but not controllable by Mooncoin.

### 2.2 LOCK STANDARD Scripts (Normative)

The following scripts are STANDARD and MUST be supported by any conforming implementation:

#### 2.2.1 P2WSH Multisig with CLTV (DEFAULT)

```
OP_IF
    <2> <user_pubkey_hot> <user_pubkey_cold> <2> OP_CHECKMULTISIG
OP_ELSE
    <absolute_locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <user_pubkey_recovery> OP_CHECKSIG
OP_ENDIF
```

**Properties:**
- Immediate spending: requires both user keys (hot + cold)
- Unilateral exit: single recovery key after locktime
- No third party involvement

#### 2.2.2 HTLC Simple (for atomicity only)

```
OP_IF
    OP_SHA256 <hash> OP_EQUALVERIFY <user_pubkey> OP_CHECKSIG
OP_ELSE
    <relative_locktime> OP_CHECKSEQUENCEVERIFY OP_DROP
    <user_pubkey> OP_CHECKSIG
OP_ENDIF
```

**Properties:**
- Conditional release via preimage
- Automatic refund after timeout
- User controls both paths

### 2.3 LOCK ADVANCED Scripts (Optional)

The following scripts are OPTIONAL and MAY be supported:

| Script Type | Use Case | Status |
|-------------|----------|--------|
| CSV-only timelocks | Relative delays | OPTIONAL |
| Multi-path scripts | Complex conditions | OPTIONAL |
| Taproot constructions | Privacy optimization | OPTIONAL |

Advanced scripts MUST still satisfy all invariants in Section 1.3.

### 2.4 LOCK STANDARD Freeze

```
┌─────────────────────────────────────────────────────────────────┐
│ NORMATIVE STATEMENT: LOCK STANDARD FREEZE                        │
├─────────────────────────────────────────────────────────────────┤
│ The LOCK STANDARD templates defined in Section 2.2 are FROZEN   │
│ as of v1.0.                                                     │
│                                                                 │
│ NO new LOCK STANDARD templates may be added after v1.0.         │
│                                                                 │
│ LOCK ADVANCED templates (Section 2.3) may be added, but:        │
│   - They remain OPTIONAL, never STANDARD                        │
│   - They MUST satisfy all invariants (Section 1.3)              │
│   - They MUST NOT be required for protocol conformance          │
│                                                                 │
│ This freeze ensures that the minimal trusted script set         │
│ remains constant and auditable in perpetuity.                   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.5 LOCK Requirements

All LOCK scripts MUST satisfy:

| Requirement | Description |
|-------------|-------------|
| **REQ-L1** | User MUST be able to recover funds unilaterally after timelock |
| **REQ-L2** | Script MUST NOT reference Mooncoin state |
| **REQ-L3** | Script MUST NOT require third-party cooperation for exit |
| **REQ-L4** | Script MUST be valid under current Bitcoin consensus rules |
| **REQ-L5** | Script MUST use only widely-deployed opcodes |

### 2.6 Mooncoin's Role in LOCK

Mooncoin's involvement in LOCK is LIMITED to:

1. Observing the existence of a UTXO
2. Verifying script format matches STANDARD or ADVANCED templates
3. Recording the commitment for operational accounting

### 2.7 CRITICAL WARNING

```
┌─────────────────────────────────────────────────────────────────┐
│ WARNING: SCRIPT RESPONSIBILITY                                   │
├─────────────────────────────────────────────────────────────────┤
│ Mooncoin does NOT validate the semantic correctness of BTC      │
│ scripts. Mooncoin verifies ONLY existence and form.             │
│                                                                 │
│ The responsibility for script correctness is 100% on the user.  │
│                                                                 │
│ A malformed script may result in permanent loss of BTC.         │
│ Mooncoin provides NO protection against script errors.          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. OPERATE SPECIFICATION

### 3.1 Definition

OPERATE is the phase during which the user conducts activity on Mooncoin while their BTC remains locked on Bitcoin.

### 3.2 Guarantees (Positive)

Mooncoin GUARANTEES the following during OPERATE:

| Guarantee | Mechanism | Description |
|-----------|-----------|-------------|
| **G-1** | Vaults | Transactions can be reversed within a delay period |
| **G-2** | Social Recovery | Access can be restored via trusted contacts without custody transfer |
| **G-3** | Programmed Inheritance | Assets transfer after prolonged inactivity |
| **G-4** | Operational Privacy | Daily activity is not correlatable with BTC reserve |
| **G-5** | Error Absorption | Human errors in Mooncoin do not affect BTC |

### 3.3 Non-Guarantees (Negative)

Mooncoin does NOT guarantee:

| Non-Guarantee | Clarification |
|---------------|---------------|
| **NG-1** | No 1:1 backing with BTC |
| **NG-2** | No value stability of MOON |
| **NG-3** | No automatic BTC redemption |
| **NG-4** | No custody of BTC at any point |
| **NG-5** | No solvency guarantee (there is no reserve) |
| **NG-6** | No protection against BTC script errors |

### 3.4 CRITICAL NEGATIVE GUARANTEE

```
┌─────────────────────────────────────────────────────────────────┐
│ NORMATIVE STATEMENT: NON-INTERFERENCE GUARANTEE                  │
├─────────────────────────────────────────────────────────────────┤
│ Mooncoin GUARANTEES that NO mechanism exists by which the       │
│ protocol can prevent, delay, or condition the recovery of       │
│ BTC on Bitcoin.                                                 │
│                                                                 │
│ This is a guarantee by OMISSION, not by action.                 │
│                                                                 │
│ The protocol is architecturally incapable of blocking BTC exit. │
└─────────────────────────────────────────────────────────────────┘
```

### 3.5 Failure Modes

| Failure Scenario | Impact on MOON | Impact on BTC |
|------------------|----------------|---------------|
| Mooncoin network halts | Operations suspended | NONE - BTC unaffected |
| Mooncoin consensus failure | State may be lost | NONE - BTC unaffected |
| 51% attack on Mooncoin | MOON may be stolen | NONE - BTC unaffected |
| Mooncoin wallet loss | MOON lost | BTC recoverable via original script |

---

## 4. SETTLE SPECIFICATION

### 4.1 Definition

SETTLE is the act of recovering BTC from the locked script on Bitcoin. SETTLE occurs EXCLUSIVELY on Bitcoin.

### 4.2 CRITICAL STATEMENT

```
┌─────────────────────────────────────────────────────────────────┐
│ NORMATIVE STATEMENT: SETTLE INDEPENDENCE                         │
├─────────────────────────────────────────────────────────────────┤
│ BTC recovery depends EXCLUSIVELY on:                             │
│   1. The Bitcoin script                                          │
│   2. The passage of time (if timelock applies)                   │
│   3. The user's private key(s)                                   │
│                                                                 │
│ BTC recovery does NOT depend on:                                 │
│   - Mooncoin network state                                       │
│   - Mooncoin consensus                                           │
│   - MOON balance                                                 │
│   - Any action within Mooncoin                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 SETTLE Flow

```
Step 1: [OPTIONAL] User burns MOON in Mooncoin
        └─► Purpose: Operational accounting, social signal
        └─► NOT required for BTC recovery

Step 2: [IF APPLICABLE] User waits for timelock expiration
        └─► Determined by Bitcoin script, not Mooncoin

Step 3: User constructs Bitcoin transaction
        └─► Uses their private key(s)
        └─► References original UTXO
        └─► Mooncoin NOT involved

Step 4: User broadcasts to Bitcoin network
        └─► Standard Bitcoin transaction
        └─► No special protocol required

Step 5: BTC recovered
        └─► User has full control
        └─► LOCK-OPERATE-SETTLE cycle complete
```

### 4.4 MOON Burn Clarification

The burning of MOON during SETTLE is:

| Aspect | Status |
|--------|--------|
| Technical requirement for BTC recovery | NO |
| Operational accounting mechanism | YES |
| Closure of Mooncoin state | YES |
| Social/historical signal | YES |
| Enforced by protocol | NO |

A user MAY recover their BTC without burning MOON. The burn exists for accounting consistency, not for access control.

### 4.5 SETTLE Properties

| Property | Requirement |
|----------|-------------|
| **No delay benefit** | Nobody gains by delaying SETTLE |
| **No blocking benefit** | Nobody gains by blocking SETTLE |
| **No yield** | LOCK produces no interest or rewards |
| **No penalty** | Exiting costs only Bitcoin network fees |
| **No arbitrage** | No protocol-managed BTC/MOON exchange rate |

---

## 5. RESIDUAL RISKS

The following risks CANNOT be eliminated by this model:

### 5.1 Bitcoin-Layer Risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| **R-1** | Loss of BTC private key | NONE - inherent Bitcoin risk |
| **R-2** | Script construction error | Audit scripts before use |
| **R-3** | Bitcoin consensus change | Use only conservative, widely-adopted scripts |
| **R-4** | Timelock too long | Choose reasonable timelock periods |

### 5.2 User-Layer Risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| **R-5** | Misunderstanding of model | Education: Mooncoin ≠ custody |
| **R-6** | Expectation of backing | Clear documentation |
| **R-7** | Confusion about guarantees | This specification |

### 5.3 Risks ELIMINATED by This Model

| Eliminated Risk | How |
|-----------------|-----|
| Counterparty risk | No counterparty exists |
| Custody risk | No custodian exists |
| Insolvency risk | No fractional reserve exists |
| Rug pull risk | No centralized funds exist |
| Protocol capture of BTC | Architecturally impossible |

---

## 6. NO-PEG AND NO-CUSTODY DECLARATION

### 6.1 Formal Statements

The following statements are NORMATIVE and define the relationship between Mooncoin and Bitcoin:

```
STATEMENT 1: Mooncoin does NOT represent BTC
─────────────────────────────────────────────
MOON is not a token representing locked BTC.
MOON is not a claim on BTC.
MOON is not a derivative of BTC.
MOON is an independent asset on an independent chain.

STATEMENT 2: Mooncoin is NOT backed by BTC
─────────────────────────────────────────────
There is no reserve.
There is no backing ratio.
There is no redemption guarantee.
MOON value is independent of any BTC holdings.

STATEMENT 3: Mooncoin does NOT guarantee convertibility
─────────────────────────────────────────────
There is no protocol-level exchange mechanism.
There is no guaranteed exchange rate.
There is no liquidity provision.
Conversion, if desired, occurs outside the protocol.

STATEMENT 4: Mooncoin is NOT a custody layer
─────────────────────────────────────────────
Mooncoin never holds BTC.
Mooncoin never controls BTC keys.
Mooncoin never moves BTC.
Mooncoin never authorizes BTC transactions.

STATEMENT 5: Mooncoin is NOT a Bitcoin sidechain
─────────────────────────────────────────────
There is no two-way peg.
There is no federation.
There is no merge-mining relationship.
There is no consensus dependency.
```

### 6.2 What Mooncoin IS

```
Mooncoin IS:
  ✓ An independent blockchain
  ✓ A human protection layer
  ✓ An operational system for daily use
  ✓ A risk-absorption mechanism for usage errors
  ✓ A complement to Bitcoin, not a competitor

Mooncoin EXISTS to:
  ✓ Reduce human risk in cryptocurrency usage
  ✓ Provide reversibility, recovery, and inheritance
  ✓ Enable private daily operations
  ✓ Separate usage risk from reserve risk
```

### 6.3 Market Interpretation Warning

```
┌─────────────────────────────────────────────────────────────────┐
│ WARNING: MARKET INTERPRETATION                                   │
├─────────────────────────────────────────────────────────────────┤
│ Any market participant, exchange, or service that represents    │
│ Mooncoin as:                                                    │
│   - "Backed by Bitcoin"                                         │
│   - "Pegged to Bitcoin"                                         │
│   - "Wrapped Bitcoin"                                           │
│   - "Bitcoin Layer 2"                                           │
│   - "Bitcoin sidechain"                                         │
│                                                                 │
│ Is providing FALSE information.                                 │
│                                                                 │
│ Mooncoin operates AROUND Bitcoin, not ON Bitcoin.               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. COMPLIANCE

### 7.1 Implementation Requirements

Any implementation claiming conformance with this specification MUST:

1. Support LOCK STANDARD scripts (Section 2.2)
2. Display WARNING (Section 2.7) to users before LOCK
3. Implement NEGATIVE GUARANTEE (Section 3.4) architecturally
4. Never condition BTC recovery on Mooncoin state
5. Include NO-PEG declaration (Section 6) in documentation

### 7.2 Prohibited Behaviors

Conforming implementations MUST NOT:

1. Custody BTC or BTC keys
2. Require MOON burn for BTC recovery
3. Create yield or staking mechanisms for locked BTC
4. Implement governance over Bitcoin-layer operations
5. Market Mooncoin as Bitcoin-backed or Bitcoin-pegged

---

## 8. DOCUMENT CONTROL

### 8.1 Canonical Authority

```
┌─────────────────────────────────────────────────────────────────┐
│ NORMATIVE STATEMENT: CANONICAL AUTHORITY                         │
├─────────────────────────────────────────────────────────────────┤
│ This specification is the SOLE authoritative source for the     │
│ Mooncoin–Bitcoin Operational Model.                             │
│                                                                 │
│ In case of conflict, this document PREVAILS over:               │
│   - Source code                                                 │
│   - README files                                                │
│   - Other documentation                                         │
│   - Implementation behavior                                     │
│   - Community interpretation                                    │
│   - Marketing materials                                         │
│                                                                 │
│ If code contradicts this specification, the code is wrong.      │
│ If documentation contradicts this specification, the            │
│ documentation is wrong.                                         │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 No-Optimization Clause

```
┌─────────────────────────────────────────────────────────────────┐
│ NORMATIVE STATEMENT: NO-OPTIMIZATION CLAUSE                      │
├─────────────────────────────────────────────────────────────────┤
│ The following are NOT valid reasons to amend this specification:│
│                                                                 │
│   ✗ Performance improvements                                    │
│   ✗ User experience enhancements                                │
│   ✗ Economic efficiency                                         │
│   ✗ Market competitiveness                                      │
│   ✗ Adoption acceleration                                       │
│   ✗ Ecosystem integration                                       │
│   ✗ Developer convenience                                       │
│                                                                 │
│ This specification prioritizes CORRECTNESS over optimization.   │
│ The model is intentionally simple and intentionally rigid.      │
│                                                                 │
│ Amendments are permitted ONLY to:                               │
│   ✓ Correct errors that violate stated invariants               │
│   ✓ Clarify ambiguity without changing meaning                  │
│   ✓ Strengthen user sovereignty guarantees                      │
└─────────────────────────────────────────────────────────────────┘
```

### 8.3 Amendment Process

This specification may only be amended if:

1. The amendment does not violate the Foundational Statement (Section 0)
2. The amendment does not violate any Invariant (Section 1.3)
3. The amendment strengthens, not weakens, user sovereignty

### 8.4 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-15 | Initial normative specification |

---

## APPENDIX A: REFERENCE SUMMARY

### A.1 One-Page Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                MOONCOIN–BITCOIN OPERATIONAL MODEL                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  FOUNDATIONAL TRUTH:                                            │
│  "Mooncoin is a human operational system around Bitcoin,        │
│   without touching its sovereignty."                            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  MODEL:        BITCOIN ←──LOCK──→ MOONCOIN ←──SETTLE──→ BITCOIN │
│                                                                 │
│  LOCK:         User locks BTC in time-locked script             │
│                Mooncoin observes but does not control           │
│                                                                 │
│  OPERATE:      User operates in Mooncoin                        │
│                BTC remains untouched on Bitcoin                 │
│                                                                 │
│  SETTLE:       User recovers BTC using original script          │
│                Mooncoin is not involved                         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  MOONCOIN IS NOT:          │  MOONCOIN IS:                      │
│  ✗ Backed by BTC           │  ✓ Independent chain               │
│  ✗ Pegged to BTC           │  ✓ Human protection layer          │
│  ✗ Custodian of BTC        │  ✓ Operational complement          │
│  ✗ Bitcoin sidechain       │  ✓ Risk absorption system          │
│  ✗ Wrapped BTC             │  ✓ Sovereignty-preserving          │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GUARANTEE: No mechanism exists by which Mooncoin can prevent,  │
│             delay, or condition BTC recovery.                   │
│                                                                 │
│  IF MOONCOIN FAILS: BTC remains recoverable on Bitcoin.         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

**END OF SPECIFICATION**

```
Bitcoin is the money that does not move.
Mooncoin is the system that allows using it without losing it.
```
