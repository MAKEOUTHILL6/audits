# Introduction

A time-boxed security review of the **OmegaPay** protocol was done by **MAKEOUTHILL**, with a focus on the security aspects of the application's implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Severity classification

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

**Impact** - the technical, economic and reputation damage of a successful attack

**Likelihood** - the chance that a particular vulnerability gets discovered and exploited

**Severity** - the overall criticality of the risk

# Security Assessment Summary

### Scope 

The following smart contracts were in scope of the audit:

- `src/Disburser`
- `src/OmegaHub`

The following number of issues were found, categorized by their severity:

- Critical & High: 2 issues
- Medium: 2 issues
- Low: 3 issues

---

# Findings Summary

| ID     | Title                        | Severity      |
| ------ | ---------------------------- | ------------- |
| [C-01] | User's earnings can be removed by anyone      | Critical      |
| [H-01] | Possible loss for unclaimed yield          | High          |
| [M-01] | Owner can get more user count votes than intended        | Medium        |
| [M-02] | Access control missing for setting `adminFee`        | Medium        |
| [L-01] | Insufficient permission on unpause           | Low           |
| [L-02] | Insufficient checks for partner's discount           | Low           |
| [L-03] | Misleading comment for MAX_ADMIN_FEE           | Low           |

# Detailed Findings

# [C-01] User's earnings can be removed by anyone

## Severity

**Impact:** High, because user will lose value

**Likelihood:** High, as it doesn't require any preconditions

## Description

Anyone can add token earnings for a user, they are added to their `recipient.earnings` and tokens are sent to the contract, so later the user can claim
by calling `claimEarnings`. Here `uint256 earningsForToken` should have been initialized with the already existing amount of earnings for the respective user, but since it's not, anyone can remove a user's earning by doing the following:

1. Choose a user to send tokens to.
2. Make `payParams.amountIn` to be > 0, for example 1 (there are checks in the function, which validate payParams).
3. Now `recipient.earnings` can be manipulated since `earningsForToken = 0`, `payParams.amountIn = 1`. This will overwrite the already accumulated `recipient.earnings` to 1.

```
function transferTokenEarnings(DataTypes.PaymentParams memory payParams) external whenNotPaused {
        //...

        //this should've been cached with the user's earnings
        uint256 earningsForToken;

        recipient.earnings = earningsForToken + payParams.amountIn;

        IERC20(recipient.outputToken).safeTransferFrom(msg.sender, address(this), payParams.amountIn);

    }
```

## Recommendations
Initialize the `earningsForToken` with the already earned amount of the user.


# [H-01] Possible loss for unclaimed yield

## Severity

**Impact:** High, because of asset loss

**Likelihood:** Medium, as it requires admin permissions

## Description

Preferences are used as options set by a user for a token he wants to receive when being transferred such, the problem here is that the `whitelistedInputTokens` is used insead of `whitelistedOutputTokens`. And since most functions in `Disburser.sol` fully trust `setPreferences` to set the user's preferences the correct way, no further checks are used there which allows the user to set his preferred output token to any arbitrary one and accumulate earnings on it. 

```
function setPreferences(
        DataTypes.Preferences calldata _preferences
    ) external {

        //...
        //@audit should be whitelistedOutputTokens
        if (!(whitelistedInputTokens.contains(_preferences.tokenAddress)))
            revert Errors.InvalidRecipientToken();

        recipientPreferences[msg.sender] = _preferences;

        //...
    }
```
This opens a door for potential loss of assets for a user.

Since the use of **non-whitelisted** output tokens is possible, now in `Disburser` an admin can call `emergencyTransferTokens` maliciously or really in case of an emergency: 

```
function emergencyTransferTokens(address user) external whenPaused onlyHubOwner {

        //... finds the recipient's struct

        address tokenToTransfer = recipient.outputToken;
        if(OMEGA_HUB.isWhitelistedOutputToken(tokenToTransfer)){
            IERC20(tokenToTransfer).safeTransfer(user, recipient.earnings);
        }

        recipient.earnings = 0;

        //...
    }
```

The problem is that this function actually checks if output token is whitelisted and only then it really sends the earnings to the user, but the strange thing is that it removes the earnings even if it is not whitelisted, that is because as I said above, `Disburser` fully trusts `OmegaHub` to set the output options correct. Because earnings can be accumulated for **non-whitelisted** tokens, in case of an emergency the user will lose his assets, because the `if` statement will return false for the `outputToken` since it's a non-whitelisted one but still reset his `recipient.earnings` for that token to **0**.

## Recommendations


Make the following corrections in `setPreferences`:

**--** `if (!(whitelistedInputTokens.contains(_preferences.tokenAddress)))
            revert Errors.InvalidRecipientToken();`

**++** `if (!(isWhitelistedOutputToken.contains(_preferences.tokenAddress)))
            revert Errors.InvalidRecipientToken();`



# [M-01] Owner can get more user count votes than intended

## Severity

**Impact:** Medium, because of breaking protocol's invariants

**Likelihood:** Low, as it requires admin permissions

## Description

Everytime a new owner is accepted, his `countVotes` increase with 2 more.

```
function acceptOwnership() external {

        require(msg.sender == pendingOwner, "Not pending owner");
        owner = pendingOwner;
        //... finds the recipient struct
        recipient.countVotes += 2;

        //@audit but pendingOwner is not reset, meaning `acceptOwnership` can be called infinite amount of times
        //...
```

These votes will be used in order to add attributes for users and other perks in the future, the problem here is that the owner can abuse `acceptOwnership` by calling it as many times as he wants to get infinite amount of votes, because the `pendingOwner` is not reset to `address(0)`

## Recommendations

In `acceptOwnership` after setting the owner, set the `pendingOwner = address(0);`

# [M-02] Access control missing for setting `adminFee` 

## Severity

**Impact:** Medium

**Likelihood:** High, as it doesn't require any prerequisites

## Description

```
/**
     * @dev Admin function to set the fee
     * @param _adminFee the new fee amount
     * Requirements:
     *  - 'adminFee" <= 'MAX_ADMIN_FEE'
     *  - msg.sender is the owner
     */
    function setAdminFee(uint256 _adminFee) external {
        if (_adminFee > MAX_ADMIN_FEE) revert Errors.InvalidAdminFee();
        adminFee = _adminFee;
    }
```

`setAdminFee` can be called by anyone as it is missing access control.

## Recommendations

Add the `onlyHubOwner` modifier to the function.

# [L-01] Insufficient permissions on unpause

## Severity

**Impact:** Low

**Likelihood:**

## Description

```
/**
     * @dev Admin function to unpause payments
      ** msg.sender must be the owner
     */

    function unpause() external {
        require(msg.sender == owner || msg.sender == guardian, "Insufficient permissions");
        _unpause();
    }
```

By the comments above and also with confirmation from the devs, `unpause` should only be called by the owner, unlike `pause` which is supposed to be called by both roles.

## Recommendations
Remove the guardian's permissions from `unpause`



# [L-02] Insufficient checks for partner's discount

## Severity

**Impact:** Low

**Likelihood:**

## Description

```
  /**
     * @param _partner the address of the partner
     * @param _discount the discount
    function setPartnerDiscount(
        address _partner,
        uint256 _discount
    ) external onlyHubOwner {
        partnerDiscounts[_partner] = _discount;
        emit Events.PartnerDiscountSet(_partner, _discount);
    }
```

Partner discount can be set to any arbitrary value, because of forgotten check to ensure that it's smaller than or equal to the `MAX_FEE`.

## Recommendations
In `setPartnerDiscount` set it the following way `if (_discount > MAX_FEE) revert Errors.InvalidPartnerDiscount();`



# [L-03] Misleading comment for MAX_ADMIN_FEE

## Severity

**Impact:** Low

**Likelihood:**

## Description

``` 
   // MAX_ADMIN_FEE is denominated in PRECISION_FACTOR.  I.e. 500 = 5%
    // **Requirements
    // Admin fee should be set equal or smaller than the MAX_ADMIN_FEE
    uint256 public immutable MAX_ADMIN_FEE;
```

Note **Admin fee should be set equal or smaller than the MAX_ADMIN_FEE**, but in the constructor:

```
constructor(uint256 _adminFee, address _omegaHub, address _uniswapSwapRouterAddress, address _wethAddress)
        HubOwnable(_omegaHub)
    {

        //...
        
        MAX_ADMIN_FEE = OMEGA_HUB.MAX_FEE();
      
        require (_adminFee < MAX_ADMIN_FEE, "Above limits");

        //...
```

It's enforced to be `<` and not `<=` as commented for `MAX_ADMIN_FEE`.

## Recommendations

`require (_adminFee <= MAX_ADMIN_FEE, "Above limits");`

