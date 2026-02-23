# AIONICA Security Lab — Intuition Protocol
## Code4rena Bug Bounty Submission
**Repository:** https://github.com/0xIntuition/intuition-contracts-v2  
**Commit:** `20181c162502da226ca25c31aef47872369212c9`  
**Date:** February 2026  
**Team:** AIONICA Security Lab  

---

## Summary

| ID | Title | Severity | File | Lines |
|----|-------|----------|------|-------|
| [H-04](#h-04) | VotingEscrow whitelist bypass via EOA proxy | **High** | VotingEscrow.sol | L130 |
| [M-01](#m-01) | `sweepAccumulatedProtocolFees()` has no access control | **Medium** | MultiVault.sol | L1044 |
| [M-02](#m-02) | `setVaultFees()` accepts uncapped fee values | **Medium** | MultiVault.sol | L1030 |
| [M-03](#m-03) | `_rollover` first-action intra-epoch utilization distortion | **Low** | MultiVault.sol | L1523 |
| [M-04](#m-04) | First-claim free pass gameable beyond epochs 0–1 | **Medium** | TrustBonding.sol | L495 |
| [M-05](#m-05) | `OffsetProgressiveCurve` offset underflow in constructor | **Medium** | OffsetProgressiveCurve.sol | L67 |
| [L-01](#l-01) | `getUserApy` unit mismatch: `currentApy` vs `maxApy` | **Low** | TrustBonding.sol | L265 |

---

## Findings Excluded After Git Verification

| Finding | Reason |
|---------|--------|
| H-01 `getUserUtilizationInEpoch` zero-slot | Function introduced as new code in this commit — not a regression |
| H-02 Double protocol fee on redeem | `_accumulateVaultProtocolFees(rawAssetsBeforeFees)` unchanged in diff; pattern consistent with deposit path design |
| H-03 `deposit()` receiver utilization | Audit fix #2 deliberately retained `_addUtilization(receiver)` while standardizing `msg.sender` — confirmed intentional |
| H-05 AtomWallet `owner()` lockup | `AtomWallet.owner()` is standard Ownable2Step view, no revert path |
| H-06 CoreEmissionsController timestamp | Guards already present at L167, L188, L208 |

---

## HIGH SEVERITY

---

<a name="h-04"></a>
### [H-04] VotingEscrow whitelist bypass via EOA proxy

**File:** `src/external/curve/VotingEscrow.sol`  
**Lines:** L130, L142–149  
**Root cause:** https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/external/curve/VotingEscrow.sol#L130  
**Category:** Access Control / Governance Manipulation  

### Description

The smart-contract whitelist validates only `msg.sender` at the moment of the call:

```solidity
require(contracts_whitelist[msg.sender], "Smart contract not allowed");
```

This check prevents a contract from calling `create_lock` directly. However, any non-whitelisted contract can bypass the restriction entirely by routing through a controlled EOA:

1. Transfer TRUST tokens to a fresh EOA (controlled by the contract or its operator)
2. Have the EOA call `create_lock` — EOA passes the `code.length == 0` check implicitly
3. The EOA accumulates veTRUST voting power on behalf of the non-whitelisted contract
4. The contract retains indirect governance influence through the EOA

The whitelist was designed to prevent unvetted or flash-loan-capable contracts from acquiring governance power. The proxy-via-EOA pattern completely circumvents this design goal.

### Proof of Concept

```solidity
contract WhitelistBypass {
    IERC20 public trust;

    // Step 1: fund a controlled EOA
    function fundEOA(address eoa, uint256 amount) external {
        trust.transfer(eoa, amount);
        // EOA (off-chain) calls votingEscrow.create_lock(amount, unlock_time)
        // EOA now holds veTRUST; this contract controls the EOA's private key
    }

    // Step 2: after lock expires, EOA withdraws and returns TRUST
    function reclaim(address eoa, uint256 amount) external {
        // EOA calls votingEscrow.withdraw(), then trust.transfer(address(this), amount)
    }
}
```

### Impact

Any on-chain contract — including contracts with flash loan access, multi-sig proxies, or DAO governance modules — can acquire veTRUST without review or whitelisting. This defeats the governance safeguard and enables potential vote manipulation with borrowed capital via the proxy EOA.

The VotingEscrow changes are part of audit fix #2 (`20181c1`), meaning this file was reviewed in the most recent audit cycle. The whitelist bypass pattern is not mentioned in the Diligence Report #2 fixes included in that commit.

### Recommendation

Check `msg.sender.code.length` and apply the whitelist only to contract callers:

```solidity
function create_lock(uint256 _value, uint256 _unlock_time) external nonReentrant notUnlocked {
    if (msg.sender.code.length > 0) {
        require(contracts_whitelist[msg.sender], "Smart contract not allowed");
    }
    // ... rest of function unchanged
}
```

This allows plain EOA calls unconditionally while enforcing review for all smart contract callers.

---

## MEDIUM SEVERITY

---

<a name="m-01"></a>
### [M-01] `sweepAccumulatedProtocolFees()` has no access control

**File:** `src/protocol/MultiVault.sol`  
**Lines:** L1044–1046  
**Root cause:** https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/MultiVault.sol#L1044-L1046  
**Category:** Access Control / Griefing  

### Description

```solidity
function sweepAccumulatedProtocolFees(uint256 epoch) external { // no role modifier
    _claimAccumulatedProtocolFees(epoch);
}
```

Any external address can call this function at any time for any epoch number. While funds always go to `generalConfig.protocolMultisig` (no theft possible), an external caller can:

- Force a sweep of `accumulatedProtocolFees[currentEpoch]` mid-epoch, zeroing it before the epoch closes
- Break any off-chain accounting system that expects fees to accumulate continuously within an epoch
- Call repeatedly across multiple epochs to disrupt accounting systems

### Impact

Medium — no fund loss, but disrupts epoch-based fee accounting and enables griefing. Comparable to C4rena's "essential functionality temporarily unusable" category.

### Recommendation

```solidity
function sweepAccumulatedProtocolFees(uint256 epoch) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (epoch >= currentEpoch()) revert MultiVault_InvalidEpoch(); // prevent mid-epoch sweeps
    _claimAccumulatedProtocolFees(epoch);
}
```

---

<a name="m-02"></a>
### [M-02] `setVaultFees()` accepts uncapped fee values — fees settable to 100%

**File:** `src/protocol/MultiVault.sol`  
**Lines:** L1030–1033  
**Root cause:** https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/MultiVault.sol#L1030-L1033  
**Category:** Admin Privilege / Missing Validation  

### Description

```solidity
function setVaultFees(VaultFees memory _vaultFees) external onlyRole(DEFAULT_ADMIN_ROLE) {
    vaultFees = _vaultFees; // no upper-bound validation on any fee field
    emit VaultFeesUpdated(_vaultFees.entryFee, _vaultFees.exitFee, _vaultFees.protocolFee);
}
```

The function accepts any value for `entryFee`, `exitFee`, and `protocolFee` with no cap. Setting any fee to `feeDenominator` (100%) means all deposits or redemptions extract the full amount as fees — effectively a rug vector for a compromised admin key. No timelock protects this parameter.

Note: While the protocol scope acknowledges centralized upgradeability as a design choice, the C4rena severity matrix explicitly includes "unauthorized manipulation of critical contract parameters" as Critical, and uncapped fee setting with no timelock is a concrete exploit path — not merely a design choice.

### Recommendation

```solidity
uint256 constant MAX_FEE = feeDenominator / 10; // 10% cap

function setVaultFees(VaultFees memory _vaultFees) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (_vaultFees.entryFee > MAX_FEE || _vaultFees.exitFee > MAX_FEE || _vaultFees.protocolFee > MAX_FEE) {
        revert MultiVault_FeeTooHigh();
    }
    vaultFees = _vaultFees;
    emit VaultFeesUpdated(_vaultFees.entryFee, _vaultFees.exitFee, _vaultFees.protocolFee);
}
```

Also route via timelock.

---

<a name="m-03"></a>
### [M-03] `_rollover` first-action-of-epoch allows transient intra-epoch utilization distortion

**File:** `src/protocol/MultiVault.sol`  
**Lines:** L1523–1545  
**Root cause:** https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/MultiVault.sol#L1523-L1545  
**Category:** Economic Manipulation / Logic Error  

### Description

The system-wide rollover in `_rollover()` copies `totalUtilization[previousEpoch]` to the current epoch only when `totalUtilization[currentEpoch] == 0`, meaning it executes exactly once per epoch — on the first user action.

```solidity
if (currentEpochLocal > 0 && totalUtilization[currentEpochLocal] == 0) {
    uint256 previousEpoch = currentEpochLocal - 1;
    if (totalUtilization[previousEpoch] != 0) {
        totalUtilization[currentEpochLocal] = totalUtilization[previousEpoch];
    }
}
```

If the first transaction of a new epoch is a `redeem()` call:

1. Rollover copies the previous epoch's utilization into the new epoch.
2. `_removeUtilization` immediately subtracts the redeemed amount from that copied value.
3. The reduced `totalUtilization[currentEpoch]` becomes the effective baseline for system utilization calculations in that epoch.

There is no retroactive modification of past epochs and no cross-epoch compounding. The effect is limited to the current epoch and depends on being the first actor.

### Impact

A first actor in a new epoch can temporarily influence the system utilization baseline used for emission calculations within that epoch if they redeem before any deposits occur.

This effect:
- Is limited to a single epoch
- Does not compound across epochs
- Requires precise timing (first action of epoch)
- Can be neutralized by subsequent deposits in the same epoch

The issue represents a transient economic distortion rather than a structural accounting flaw.

### Recommendation

Avoid deriving system-wide epoch baselines from the first user action. Possible approaches:

- Snapshot `totalUtilization` at epoch boundaries via a dedicated keeper call
- Store immutable epoch-end utilization values instead of copying on first interaction
- Prevent `_removeUtilization` from modifying a freshly rolled-over baseline within the same transaction

Separating rollover logic from user-triggered state changes removes timing-based influence over emission calculations.

---

<a name="m-04"></a>
### [M-04] First-claim free pass in `_getPersonalUtilizationRatio` gameable beyond epochs 0–1

**File:** `src/protocol/emissions/TrustBonding.sol`  
**Lines:** L495–508  
**Root cause:** https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/emissions/TrustBonding.sol#L495-L508  
**Category:** Economic / Incentive Manipulation  

### Description

```solidity
if (userUtilizationTarget == 0) {
    // If the user had nothing claimable last epoch, don't penalize them
    if (_userEligibleRewardsForEpoch(_account, _epoch - 1) == 0) {
        return BASIS_POINTS_DIVISOR; // 100% — first-claim free pass
    }
    return personalUtilizationLowerBound; // penalize non-claimers
}
```

When `userUtilizationTarget == 0` (user claimed nothing in the previous epoch) AND the user had no eligibility in that epoch (e.g. their veTRUST balance was zero), the function returns `BASIS_POINTS_DIVISOR` (100%) regardless of actual utilization history.

A user can exploit this by:
1. Locking TRUST in epoch N to accumulate veTRUST
2. Deliberately not interacting with MultiVault in epoch N (keeping `userClaimedRewardsForEpoch[user][N] = 0` and having no eligibility)
3. In epoch N+1: `userUtilizationTarget = 0`, `_userEligibleRewardsForEpoch(user, N) = 0` → returns 100%
4. Claiming maximum-multiplied rewards in N+1
5. Repeating by skipping every other epoch

### Impact

Users can receive 100% of their eligible rewards without the utilization consistency the system is designed to require, by alternating between active and inactive epochs. This undermines the incentive model that rewards sustained protocol participation.

### Recommendation

Restrict the first-claim bonus to protocol epochs 0 and 1 only. For all later epochs, a user with no prior claim and no eligibility should receive `personalUtilizationLowerBound`, not the maximum:

```solidity
if (userUtilizationTarget == 0) {
    if (_epoch < 2 && _userEligibleRewardsForEpoch(_account, _epoch - 1) == 0) {
        return BASIS_POINTS_DIVISOR; // only in bootstrap epochs
    }
    return personalUtilizationLowerBound;
}
```

---

<a name="m-05"></a>
### [M-05] `OffsetProgressiveCurve` constructor: offset underflow check missing after audit fix

**File:** `src/protocol/curves/OffsetProgressiveCurve.sol`  
**Lines:** L67, L70  
**Root cause:** https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/curves/OffsetProgressiveCurve.sol#L67  
**Category:** Missing Validation / Math Edge Case  

### Description

Audit fix #2 added validation that `slope` is even and non-zero (confirmed in commit message: *"Add checks to make sure slope is even and non-zero"*). However, it did **not** add a check that `OFFSET < sqrt(uMAX_UD60x18 / uUNIT)`.

```solidity
HALF_SLOPE = wrap(slope18 / 2); // ← slope check added by audit fix
UD60x18 maxSharesUD = sub(sqrt(wrap(uMAX_UD60x18 / uUNIT)), OFFSET); // ← no check on OFFSET
```

If `OFFSET >= sqrt(uMAX_UD60x18 / uUNIT)`, the `sub()` call in PRBMath underflows (panics in checked mode or produces `type(uint256).max` in unchecked). A curve deployed with an oversized offset would be permanently broken — any deposit or redemption calculation would revert or return invalid share amounts.

Since `BondingCurveRegistry.addBondingCurve` is `onlyOwner` with no further validation of curve parameters, a misconfigured `OffsetProgressiveCurve` could be registered and used by vaults before the error is detected.

### Recommendation

```solidity
UD60x18 maxSharesUD = sub(sqrt(wrap(uMAX_UD60x18 / uUNIT)), OFFSET);
require(
    OFFSET.lt(sqrt(wrap(uMAX_UD60x18 / uUNIT))),
    "OffsetProgressiveCurve: offset exceeds max shares"
);
```

Add this require before the `sub()` call in the constructor.

---

## LOW SEVERITY

---

<a name="l-01"></a>
### [L-01] `getUserApy`: `currentApy` and `maxApy` use inconsistent unit scaling

**File:** `src/protocol/emissions/TrustBonding.sol`  
**Lines:** L265–269  
**Root cause:** https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/emissions/TrustBonding.sol#L265-L269  
**Category:** Math / Unit Mismatch  

### Description

```solidity
currentApy = (userRewardsPerYear * personalUtilization) / uint256(locked);
//            ^ personalUtilization is basis points (0–10000) — missing / BASIS_POINTS_DIVISOR
maxApy     = (userRewardsPerYear * BASIS_POINTS_DIVISOR) / uint256(locked);
//            ^ BASIS_POINTS_DIVISOR = 10000 — correct scale
```

`personalUtilization` is in basis points (0–10000). For `currentApy` to be on the same scale as `maxApy`, the numerator must be divided by `BASIS_POINTS_DIVISOR`. As written, `currentApy` is ~10,000x smaller than `maxApy` when `personalUtilization < 10000`.

Example: user with 7500 bp utilization and `maxApy = 1000` (10%):
- Expected `currentApy` = 750 (7.5%)
- Actual `currentApy` = 750 / 10000 × `locked`-dependent result ≈ 0.075

Front-ends and integrators reading this view display severely incorrect APY.

### Recommendation

```solidity
currentApy = (userRewardsPerYear * personalUtilization) / uint256(locked) / BASIS_POINTS_DIVISOR;
```

---

## Methodology

All findings derive from manual static analysis of the Solidity source at commit `20181c1`. No automated tooling was used. Verification process for each finding:

1. Full call chain traced from public entry point to vulnerable line
2. Absence of mitigating guards confirmed via repository-wide `grep`
3. Audit fix #2 diff (`git show 20181c1`) reviewed exhaustively to exclude patched issues
4. Prior Diligence reports consulted to confirm no finding duplicates a known issue

The git diff analysis was decisive in downgrading or removing six initial candidates, leaving only findings with clean evidence chains and no overlap with acknowledged fixes.

---

*AIONICA Security Lab — Intuition Protocol — Code4rena — February 2026*
