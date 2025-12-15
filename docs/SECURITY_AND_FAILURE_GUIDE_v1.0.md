# MOONCOIN SECURITY AND FAILURE GUIDE
## v1.0

```
Document Status:    NORMATIVE
Version:            1.0
Date:               2025-12-15
Scope:              Risks, failures, and user responsibilities
Prerequisite:       READING THIS DOCUMENT IS MANDATORY BEFORE USE
```

---

## 0. MANDATORY DECLARATION

```
┌─────────────────────────────────────────────────────────────────┐
│                    READ BEFORE PROCEEDING                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ This document describes risks that Mooncoin CANNOT eliminate.    │
│                                                                 │
│ Reading and understanding this document is REQUIRED before       │
│ using the LOCK–OPERATE–SETTLE system.                           │
│                                                                 │
│ By using this system, you acknowledge that:                      │
│                                                                 │
│   1. You have read this entire document                          │
│   2. You understand all described risks                          │
│   3. You accept full responsibility for these risks              │
│   4. You will not hold Mooncoin responsible for losses           │
│   5. There is no support, no recourse, no authority to help      │
│                                                                 │
│ If you do not accept these conditions, DO NOT USE THIS SYSTEM.   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. FAILURE SCENARIOS

### 1.1 Mooncoin Network Failure

**Scenario:** The Mooncoin network stops functioning entirely.

| Aspect | Impact |
|--------|--------|
| MOON balance | Lost or inaccessible |
| Mooncoin transactions | Cannot be made |
| Vault protections | Non-functional |
| Social Recovery | Non-functional |

**Impact on BTC:**
```
┌─────────────────────────────────────────────────────────────────┐
│                         NONE                                     │
├─────────────────────────────────────────────────────────────────┤
│ Your BTC remains exactly where it was: in the Bitcoin script.    │
│ Mooncoin's failure has ZERO effect on your Bitcoin.              │
└─────────────────────────────────────────────────────────────────┘
```

**Recovery procedure:**
1. Wait for timelock to expire (check Bitcoin block height)
2. Construct exit transaction manually
3. Sign with your recovery private key
4. Broadcast to Bitcoin network
5. BTC recovered

**Requirements for recovery:**
- Your recovery private key (CRITICAL)
- Your redeem script (CRITICAL)
- Access to any Bitcoin node
- Basic ability to construct Bitcoin transactions

**If you don't have these:** Your BTC may be permanently lost.

---

### 1.2 Mooncoin Consensus Failure

**Scenario:** Mooncoin network experiences a consensus split or invalid state.

| Aspect | Impact |
|--------|--------|
| MOON balance | May be disputed or invalid |
| Transaction history | May be inconsistent |
| Lock registrations | May be lost |

**Impact on BTC:** NONE

**Recovery:** Same as 1.1

---

### 1.3 51% Attack on Mooncoin

**Scenario:** Attacker gains majority hashpower on Mooncoin.

| Aspect | Impact |
|--------|--------|
| MOON | May be stolen or double-spent |
| Mooncoin state | May be rewritten |

**Impact on BTC:** NONE

The attacker cannot:
- Move your BTC
- Modify your Bitcoin script
- Accelerate your timelock
- Access your BTC keys

---

### 1.4 User Loses Mooncoin Wallet

**Scenario:** User loses access to their Mooncoin wallet.

| Aspect | Impact |
|--------|--------|
| MOON balance | Lost (unless Social Recovery configured) |
| Lock registration data | Lost locally |

**Impact on BTC:** NONE

**Recovery:**
- If Social Recovery was configured: Use recovery process
- If not: MOON is lost, but BTC is still recoverable via Bitcoin

---

### 1.5 User Loses BTC Private Keys

**Scenario:** User loses the recovery private key used in the LOCK script.

```
┌─────────────────────────────────────────────────────────────────┐
│                    CRITICAL FAILURE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                   BTC IS PERMANENTLY LOST                        │
│                                                                 │
│ There is NO recovery mechanism.                                  │
│ There is NO backdoor.                                            │
│ There is NO authority that can help.                             │
│ There is NO way to recover these funds.                          │
│                                                                 │
│ Mooncoin CANNOT help you.                                        │
│ Bitcoin CANNOT help you.                                         │
│ Nobody CAN help you.                                             │
│                                                                 │
│ This is not a bug. This is how Bitcoin works.                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Prevention:**
- Multiple backups of recovery key
- Geographic distribution of backups
- Test recovery process before large amounts
- Consider using the multisig path for redundancy

---

### 1.6 LOCK Script is Malformed

**Scenario:** User created a script with errors.

**Possible errors:**
- Invalid public key format
- Incorrect opcode sequence
- Wrong timelock encoding
- Typos in hex values

**Impact:**
```
BTC may be PERMANENTLY UNSPENDABLE
```

**Why Mooncoin cannot prevent this:**
```
┌─────────────────────────────────────────────────────────────────┐
│ MOONCOIN VERIFICATION SCOPE                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Mooncoin verifies:                                               │
│   ✓ Script STRUCTURE matches template                            │
│   ✓ UTXO exists on Bitcoin                                       │
│                                                                 │
│ Mooncoin does NOT verify:                                        │
│   ✗ Public keys are valid points on the curve                    │
│   ✗ User controls the corresponding private keys                 │
│   ✗ Script will execute correctly on Bitcoin                     │
│   ✗ Timelock value is reasonable                                 │
│                                                                 │
│ STRUCTURAL MATCH ≠ SEMANTIC CORRECTNESS                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Prevention:**
- Use only LOCK STANDARD templates
- Verify script independently before funding
- Test with small amount first
- Double-check all parameters

---

### 1.7 Timelock Set Too Long

**Scenario:** User chose a timelock of many years.

**Impact:**
- BTC is inaccessible until timelock expires
- Cannot be shortened after funding
- Multisig path may still work (if both keys available)

**Example:**
```
User sets timelock to block 1,000,000 (current: 880,000)
Blocks remaining: 120,000
Time remaining: ~2.3 years

During this time:
- BTC cannot be accessed via recovery path
- Multisig path requires BOTH hot and cold keys
- If either key is lost, must wait for timelock
```

**Prevention:**
- Use reasonable timelocks (weeks to months, not years)
- Understand the tradeoff: longer = safer from theft, but less accessible
- Keep both multisig keys secure for emergency exit

---

### 1.8 Bitcoin Consensus Change

**Scenario:** Bitcoin soft/hard fork changes script validation rules.

**Risk level:** Very low for LOCK STANDARD scripts

**Why:**
- LOCK STANDARD uses only ancient, well-tested opcodes
- OP_IF, OP_CHECKSIG, OP_CHECKMULTISIG, CLTV, CSV
- These are extremely unlikely to be modified

**If it happens:**
- Scripts may become invalid
- Funds may be unspendable

**Mitigation:**
- LOCK STANDARD freeze ensures no experimental opcodes
- Only widely-deployed, battle-tested constructions

---

### 1.9 User Sends BTC to Wrong Address During SETTLE

**Scenario:** User makes an error in the destination address.

```
┌─────────────────────────────────────────────────────────────────┐
│                    IRREVERSIBLE LOSS                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Bitcoin transactions CANNOT be reversed.                         │
│                                                                 │
│ If you send to the wrong address:                                │
│   - The BTC is gone                                              │
│   - There is no undo                                             │
│   - There is no customer support                                 │
│   - There is no dispute resolution                               │
│                                                                 │
│ Mooncoin CANNOT help you.                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Prevention:**
- Triple-check destination address
- Verify address character by character
- Send small test amount first
- Use address verification tools

---

### 1.10 Fee Estimation Error

**Scenario:** User sets too low a fee for the Bitcoin settlement transaction.

**Impact:**
- Transaction stuck in mempool
- May eventually be dropped
- Must re-create and re-broadcast

**Mooncoin's role:** NONE

Fee estimation is entirely the user's responsibility. Mooncoin does not estimate, suggest, or validate Bitcoin fees.

---

## 2. RISKS MOONCOIN CANNOT MITIGATE

The following risks are INHERENT and CANNOT be eliminated:

| Risk | Nature | Why Unmitigable |
|------|--------|-----------------|
| BTC key loss | User responsibility | Keys exist only with user |
| Script errors | User construction | Mooncoin doesn't execute scripts |
| Wrong destination | User decision | Bitcoin is irreversible |
| Long timelock | User choice | Cannot be changed after funding |
| BTC reorg | Bitcoin consensus | Outside Mooncoin's control |
| Hardware failure | Physical | Outside software's control |
| Physical coercion | Violence | Outside technical scope |
| User death | Mortality | Requires inheritance setup |
| Regulatory action | Legal | Outside technical scope |

---

## 3. RESPONSIBILITY MATRIX

### 3.1 Mooncoin Responsibilities

| Responsibility | Status |
|----------------|--------|
| Observe Bitcoin UTXOs | YES |
| Match scripts against templates | YES |
| Report lock status | YES |
| Operate Mooncoin network | YES |
| Process MOON transactions | YES |
| Provide reference tools | YES |

### 3.2 Mooncoin NON-Responsibilities

| NOT Responsible For | Reason |
|---------------------|--------|
| BTC script correctness | User constructs script |
| BTC key security | User holds keys |
| BTC transaction validity | User signs and broadcasts |
| BTC fee levels | User decides |
| BTC destination accuracy | User specifies |
| Recovering lost BTC | Technically impossible |
| Recovering lost MOON (without setup) | By design |
| Network uptime guarantees | Decentralized network |
| Value of MOON | Market determined |
| User decisions | User autonomy |

### 3.3 User Responsibilities

| Responsibility | Consequence of Failure |
|----------------|------------------------|
| Backup recovery key | Permanent BTC loss |
| Backup redeem script | Permanent BTC loss |
| Verify script before funding | Permanent BTC loss |
| Choose appropriate timelock | Extended inaccessibility |
| Secure all private keys | Theft or loss |
| Verify destination addresses | Permanent BTC loss |
| Set appropriate fees | Transaction delays |
| Understand this document | Unexpected losses |

---

## 4. PRE-LOCK CHECKLIST

Before creating ANY lock, verify ALL of the following:

### 4.1 Understanding Checklist

```
[ ] I understand Mooncoin does NOT custody my BTC
[ ] I understand Mooncoin does NOT validate my script semantically
[ ] I understand a malformed script means PERMANENT LOSS
[ ] I understand there is NO recovery mechanism for lost keys
[ ] I understand there is NO support or authority to help me
[ ] I understand this document completely
```

### 4.2 Preparation Checklist

```
[ ] I have generated all required key pairs
[ ] I have backed up my recovery private key in multiple locations
[ ] I have backed up my redeem script in multiple locations
[ ] I have tested my backup restoration process
[ ] I have verified my public keys are correctly formatted
[ ] I have chosen an appropriate timelock duration
```

### 4.3 Verification Checklist

```
[ ] I have verified my script matches a LOCK STANDARD template
[ ] I have independently verified the script structure
[ ] I have tested with a small amount first
[ ] I have confirmed I can construct a spending transaction
[ ] I have confirmed I can sign with my recovery key
```

### 4.4 Final Checklist

```
[ ] I accept all risks described in this document
[ ] I will not blame Mooncoin for any losses
[ ] I am solely responsible for my funds
[ ] I have read this entire document
```

---

## 5. EMERGENCY PROCEDURES

### 5.1 If Mooncoin Network is Down

```
Step 1: Don't panic. Your BTC is safe.
Step 2: Check if timelock has expired (query any Bitcoin node)
Step 3: If expired, construct exit transaction manually:
        - Input: your locked UTXO
        - Output: your destination address
        - Witness: signature + 0x00 + redeem_script
Step 4: Sign with recovery key
Step 5: Broadcast to Bitcoin
```

### 5.2 If You Suspect Key Compromise

```
IF TIMELOCK NOT EXPIRED:
  - Use multisig path immediately (requires both hot + cold keys)
  - Move BTC to new secure address
  
IF TIMELOCK EXPIRED:
  - Race to spend before attacker
  - Use high fee for priority
  - Move to new secure address immediately
```

### 5.3 If You Lost Your Recovery Key But Have Multisig Keys

```
Step 1: You can still exit via multisig path (no timelock wait)
Step 2: Coordinate signing with both hot and cold keys
Step 3: Construct 2-of-2 multisig spend
Step 4: Move to new address with fresh keys
```

### 5.4 If You Lost One Multisig Key But Have Recovery Key

```
Step 1: Wait for timelock to expire
Step 2: Use recovery path
Step 3: Accept that you cannot exit early
```

### 5.5 If You Lost Recovery Key AND One Multisig Key

```
┌─────────────────────────────────────────────────────────────────┐
│ You have lost access to your BTC.                                │
│ There is nothing anyone can do.                                  │
│ This is permanent.                                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. WHAT MOONCOIN IS NOT

To prevent misunderstanding:

### 6.1 Mooncoin is NOT a Bank

```
Banks:
- Hold your money
- Can freeze your account
- Can reverse transactions
- Have customer support
- Are regulated

Mooncoin:
- Never holds your BTC
- Cannot freeze anything
- Cannot reverse anything
- Has no support
- Is not regulated
```

### 6.2 Mooncoin is NOT a Custodian

```
Custodians:
- Store your assets
- Have insurance
- Can recover lost access
- Are legally responsible

Mooncoin:
- Stores nothing
- Has no insurance
- Cannot recover anything
- Has no legal entity
```

### 6.3 Mooncoin is NOT Bitcoin

```
Your BTC:
- Exists only on Bitcoin
- Is controlled only by your keys
- Is subject only to Bitcoin rules

Mooncoin:
- Is a separate network
- Has no control over Bitcoin
- Provides observation, not control
```

---

## 7. FINAL WARNINGS

### 7.1 No Recourse

```
There is no customer support.
There is no dispute resolution.
There is no refund policy.
There is no authority to appeal to.
There is no one who can help you.

The code is the only authority.
Your keys are your only access.
Your backups are your only safety net.
```

### 7.2 The Creator Will Not Help

```
The creator of Mooncoin:
- Will not be available
- Cannot help you recover funds
- Cannot modify the protocol for you
- Has no special access
- Has no special keys

This is by design.
```

### 7.3 Test Before Trust

```
NEVER lock significant funds without:
1. Testing the complete flow with small amounts
2. Verifying you can construct exit transactions
3. Confirming your backups work
4. Understanding every step

If you cannot exit a test lock, DO NOT proceed with real funds.
```

### 7.4 Complexity Kills

```
If you don't understand something:
- DO NOT proceed
- DO NOT assume it will work
- DO NOT trust anyone who says "it's fine"

Confusion = Risk
Risk = Loss
```

---

## 8. ACCEPTANCE

By using the LOCK–OPERATE–SETTLE system, you confirm:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│ I have read and understood this entire document.                 │
│                                                                 │
│ I understand all risks described herein.                         │
│                                                                 │
│ I accept that losses may occur and are my responsibility.        │
│                                                                 │
│ I will not hold Mooncoin, its creators, contributors, or        │
│ anyone else responsible for any losses I may incur.              │
│                                                                 │
│ I understand there is no support, no recourse, and no           │
│ authority that can help me if something goes wrong.              │
│                                                                 │
│ I proceed at my own risk.                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

**END OF SECURITY AND FAILURE GUIDE**

```
The system is designed to work without trust.
That means it also works without help.
You are your own bank.
You are your own support.
You are your own responsibility.
```
