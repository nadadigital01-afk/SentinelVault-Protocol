// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// ============================================================================
// EDUCATIONAL ONLY â€” DO NOT USE VULNERABLE CODE ON LIVE NETWORKS
// ============================================================================
// This contract is a deliberately vulnerable reference implementation,
// written to demonstrate a classic reentrancy bug in a realistic, full-size
// vault. It exists so the bug can be pointed at, tested against, and fixed
// in Remediation.sol. Every line here that matters for the vulnerability is
// commented. Do not copy this withdrawal logic into anything that touches
// real value. Companion file Remediation.sol is the version you'd actually
// ship.
// ============================================================================

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title YieldVault
/// @notice A multi-strategy yield vault with performance fees and a basic
///         governance timelock for parameter changes. Modeled loosely on
///         the share-accounting pattern used by Yearn-style vaults: deposits
///         mint shares at the current price-per-share, yield accrues to the
///         share price, and withdrawals burn shares for the underlying.
/// @dev    Intentionally contains a reentrancy bug in withdraw(). See the
///         block comment above that function for the full breakdown.
contract YieldVault is Ownable {
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    IERC20 public immutable asset;            // underlying deposit token
    uint256 public totalShares;                // total shares outstanding
    uint256 public totalAssets;                // assets the vault believes it holds

    mapping(address => uint256) public shares; // per-user share balances
    mapping(address => uint256) public depositTimestamp; // for withdrawal fee tiering

    // fee config, expressed in basis points (1/100 of a percent)
    uint256 public performanceFeeBps = 1000;    // 10% of realized yield
    uint256 public withdrawalFeeBps = 50;       // 0.5% base withdrawal fee
    uint256 public constant MAX_BPS = 10_000;
    uint256 public constant EARLY_WITHDRAW_WINDOW = 3 days;
    uint256 public constant EARLY_WITHDRAW_PENALTY_BPS = 200; // extra 2% if < 3 days

    address public feeRecipient;
    address public strategist;                  // address allowed to report yield

    // governance timelock for sensitive parameter changes
    struct PendingChange {
        uint256 newValue;
        uint256 executableAfter;
        bool exists;
    }
    mapping(bytes32 => PendingChange) public pendingChanges;
    uint256 public constant TIMELOCK_DELAY = 2 days;

    // simple pausability without external dependency, kept minimal on purpose
    bool public paused;

    // accounting for yield reporting, used to compute performance fees
    uint256 public lastReportedAssets;
    uint256 public cumulativeYieldDistributed;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    event Deposit(address indexed user, uint256 assetsIn, uint256 sharesMinted);
    event Withdraw(address indexed user, uint256 sharesBurned, uint256 assetsOut);
    event YieldReported(uint256 profit, uint256 feeCharged);
    event FeeRecipientUpdated(address newRecipient);
    event StrategistUpdated(address newStrategist);
    event ParameterChangeQueued(bytes32 indexed key, uint256 newValue, uint256 executableAfter);
    event ParameterChangeExecuted(bytes32 indexed key, uint256 newValue);
    event Paused(bool status);

    // ------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------

    modifier whenNotPaused() {
        require(!paused, "YieldVault: paused");
        _;
    }

    modifier onlyStrategist() {
        require(msg.sender == strategist, "YieldVault: not strategist");
        _;
    }

    constructor(address _asset, address _feeRecipient, address _strategist) Ownable(msg.sender) {
        require(_asset != address(0), "YieldVault: zero asset");
        require(_feeRecipient != address(0), "YieldVault: zero fee recipient");
        asset = IERC20(_asset);
        feeRecipient = _feeRecipient;
        strategist = _strategist;
    }

    // ------------------------------------------------------------------
    // Core share math
    // ------------------------------------------------------------------

    /// @notice Converts an asset amount to shares at the current exchange rate.
    /// @dev Uses the standard "shares = assets * totalShares / totalAssets"
    ///      formula. On first deposit, mints 1:1 to avoid a divide-by-zero
    ///      and to seed the share price at 1.0.
    function _convertToShares(uint256 assetAmount) internal view returns (uint256) {
        if (totalShares == 0 || totalAssets == 0) {
            return assetAmount;
        }
        return (assetAmount * totalShares) / totalAssets;
    }

    function _convertToAssets(uint256 shareAmount) internal view returns (uint256) {
        if (totalShares == 0) {
            return 0;
        }
        return (shareAmount * totalAssets) / totalShares;
    }

    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalAssets * 1e18) / totalShares;
    }

    // ------------------------------------------------------------------
    // Deposits
    // ------------------------------------------------------------------

    /// @notice Deposit underlying asset and receive vault shares.
    /// @dev Deposits are safe from reentrancy concerns in the sense that
    ///      pulling tokens in via transferFrom does not hand control to an
    ///      arbitrary recipient â€” the risk in this contract lives entirely
    ///      on the withdraw path, where the vault is the one pushing value
    ///      out to a caller-controlled address.
    function deposit(uint256 assetAmount) external whenNotPaused returns (uint256 mintedShares) {
        require(assetAmount > 0, "YieldVault: zero deposit");

        mintedShares = _convertToShares(assetAmount);
        require(mintedShares > 0, "YieldVault: rounds to zero shares");

        // effects before the external call here, which is the correct order â€”
        // this is deposit, not withdraw, so there's no inverted-order bug.
        shares[msg.sender] += mintedShares;
        totalShares += mintedShares;
        totalAssets += assetAmount;
        depositTimestamp[msg.sender] = block.timestamp;

        asset.safeTransferFrom(msg.sender, address(this), assetAmount);

        emit Deposit(msg.sender, assetAmount, mintedShares);
    }

    // ====================================================================
    // VULNERABLE PATTERN - FOR EDUCATIONAL ANALYSIS ONLY
    // ====================================================================
    //
    // WHERE:
    //   The bug is in withdraw() below. The function computes the payout,
    //   sends the underlying asset to the caller, and only *after* that
    //   external transfer does it decrement the caller's share balance and
    //   the vault's totalShares/totalAssets accounting.
    //
    // WHY THIS IS DANGEROUS:
    //   asset.safeTransfer() (or a raw .call{value}() in an ETH-denominated
    //   vault) hands execution control to the recipient. If the underlying
    //   token has any transfer hook (ERC-777, ERC-677, or a malicious
    //   ERC-20 with a hostile transfer() override), or if "asset" were
    //   native ETH sent via .call, the recipient's code runs *before* this
    //   function has updated `shares[msg.sender]`. State on-chain at that
    //   moment still reflects the caller's pre-withdrawal balance. Any
    //   function the recipient calls back into â€” including withdraw()
    //   itself â€” sees stale, not-yet-decremented state.
    //
    //   This is the same root cause as the DAO hack: an external call is
    //   made while the contract's internal ledger has not yet caught up
    //   with the intent of the current call. The violated invariant is
    //   "shares[user] accurately represents what user is entitled to
    //   withdraw at every point external control could be regained,"
    //   and this function breaks that invariant for the entire duration
    //   of the safeTransfer() call.
    //
    // HOW AN ATTACKER COULD EXPLOIT IT (description only, no working
    // exploit code is included in this educational file):
    //   1. Attacker deploys a contract that holds vault shares and
    //      implements a callback (e.g. tokensReceived for ERC-777, or a
    //      fallback function if this were ETH) that calls vault.withdraw()
    //      again.
    //   2. Attacker calls withdraw() for their full share balance.
    //   3. Vault computes assetsOut from the attacker's real share
    //      balance, calls safeTransfer to send funds to the attacker
    //      contract.
    //   4. Before that transfer call returns, the attacker's callback
    //      fires and calls withdraw() again. Because shares[attacker]
    //      has NOT been decremented yet, the vault recomputes the SAME
    //      assetsOut and sends funds a second time.
    //   5. This repeats â€” bounded only by the vault's available asset
    //      balance or a gas limit â€” draining far more than the attacker's
    //      legitimate share of the vault. Every other depositor's funds
    //      are exposed because totalAssets is a shared pool.
    //
    // The fix (Checks-Effects-Interactions + ReentrancyGuard + pull
    // payments) is implemented in Remediation.sol, with line-by-line
    // annotations explaining each mitigation.
    // ====================================================================

    /// @notice Burn shares and withdraw the underlying asset.
    /// @dev VULNERABLE PATTERN - FOR EDUCATIONAL ANALYSIS ONLY. State is
    ///      updated AFTER the external transfer, violating
    ///      Checks-Effects-Interactions. See block comment above.
    function withdraw(uint256 shareAmount) external whenNotPaused returns (uint256 assetsOut) {
        require(shareAmount > 0, "YieldVault: zero withdraw");
        require(shares[msg.sender] >= shareAmount, "YieldVault: insufficient shares");

        // --- CHECKS (partially correct) ---
        assetsOut = _convertToAssets(shareAmount);
        require(assetsOut > 0, "YieldVault: rounds to zero assets");

        uint256 fee = _calculateWithdrawalFee(msg.sender, assetsOut);
        uint256 netAssetsOut = assetsOut - fee;

        // --- INTERACTIONS (happening before EFFECTS â€” this is the bug) ---
        // The vault pushes funds out here while shares[msg.sender] and
        // totalShares/totalAssets still reflect the pre-withdrawal state.
        // If `asset` ever has a transfer hook, or this pattern is copied
        // into a contract that sends native ETH via a low-level call, the
        // recipient can re-enter withdraw() right here and pass the
        // require() checks above again with the same stale share balance.
        asset.safeTransfer(msg.sender, netAssetsOut);
        if (fee > 0) {
            asset.safeTransfer(feeRecipient, fee);
        }

        // --- EFFECTS (too late â€” should have happened before the transfer) ---
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        totalAssets -= assetsOut;

        emit Withdraw(msg.sender, shareAmount, netAssetsOut);
    }

    function _calculateWithdrawalFee(address user, uint256 assetsOut) internal view returns (uint256) {
        uint256 feeBps = withdrawalFeeBps;
        if (block.timestamp < depositTimestamp[user] + EARLY_WITHDRAW_WINDOW) {
            feeBps += EARLY_WITHDRAW_PENALTY_BPS;
        }
        return (assetsOut * feeBps) / MAX_BPS;
    }

    // ------------------------------------------------------------------
    // Yield reporting / performance fees
    // ------------------------------------------------------------------

    /// @notice Strategist reports realized profit, vault mints fee shares
    ///         to feeRecipient diluting other holders proportionally.
    /// @dev This is a trusted-role function, not a public attack surface,
    ///      but it's included so the share-price math used elsewhere in
    ///      the contract is fully specified for the audit.
    function reportYield(uint256 newTotalAssets) external onlyStrategist {
        require(newTotalAssets >= totalAssets, "YieldVault: reported loss not supported here");

        uint256 profit = newTotalAssets - totalAssets;
        uint256 feeAssets = (profit * performanceFeeBps) / MAX_BPS;

        // mint fee shares to feeRecipient at the CURRENT (pre-update) price,
        // so the fee is denominated in the value just created
        if (feeAssets > 0 && totalAssets > 0) {
            uint256 feeShares = (feeAssets * totalShares) / totalAssets;
            shares[feeRecipient] += feeShares;
            totalShares += feeShares;
        }

        totalAssets = newTotalAssets;
        lastReportedAssets = newTotalAssets;
        cumulativeYieldDistributed += profit;

        emit YieldReported(profit, feeAssets);
    }

    // ------------------------------------------------------------------
    // Governance â€” timelocked parameter changes
    // ------------------------------------------------------------------

    /// @notice Queue a change to a uint parameter, executable after the
    ///         timelock delay. Keeps governance from instantly rugging
    ///         fee parameters on depositors.
    function queueParameterChange(bytes32 key, uint256 newValue) external onlyOwner {
        pendingChanges[key] = PendingChange({
            newValue: newValue,
            executableAfter: block.timestamp + TIMELOCK_DELAY,
            exists: true
        });
        emit ParameterChangeQueued(key, newValue, block.timestamp + TIMELOCK_DELAY);
    }

    function executeParameterChange(bytes32 key) external onlyOwner {
        PendingChange memory change = pendingChanges[key];
        require(change.exists, "YieldVault: no pending change");
        require(block.timestamp >= change.executableAfter, "YieldVault: timelock not expired");

        if (key == keccak256("performanceFeeBps")) {
            require(change.newValue <= 3000, "YieldVault: fee too high"); // hard cap 30%
            performanceFeeBps = change.newValue;
        } else if (key == keccak256("withdrawalFeeBps")) {
            require(change.newValue <= 500, "YieldVault: fee too high"); // hard cap 5%
            withdrawalFeeBps = change.newValue;
        } else {
            revert("YieldVault: unknown parameter key");
        }

        delete pendingChanges[key];
        emit ParameterChangeExecuted(key, change.newValue);
    }

    // ------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------

    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "YieldVault: zero address");
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(newRecipient);
    }

    function setStrategist(address newStrategist) external onlyOwner {
        require(newStrategist != address(0), "YieldVault: zero address");
        strategist = newStrategist;
        emit StrategistUpdated(newStrategist);
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;
        emit Paused(status);
    }

    // ------------------------------------------------------------------
    // View helpers
    // ------------------------------------------------------------------

    function balanceOfAssets(address user) external view returns (uint256) {
        return _convertToAssets(shares[user]);
    }

    function previewWithdraw(uint256 shareAmount) external view returns (uint256) {
        uint256 assetsOut = _convertToAssets(shareAmount);
        uint256 fee = _calculateWithdrawalFee(msg.sender, assetsOut);
        return assetsOut - fee;
    }

    function previewDeposit(uint256 assetAmount) external view returns (uint256) {
        return _convertToShares(assetAmount);
    }

    function getPendingChange(bytes32 key) external view returns (uint256 newValue, uint256 executableAfter, bool exists) {
        PendingChange memory change = pendingChanges[key];
        return (change.newValue, change.executableAfter, change.exists);
    }

    function isTimelockExpired(bytes32 key) external view returns (bool) {
        PendingChange memory change = pendingChanges[key];
        if (!change.exists) return false;
        return block.timestamp >= change.executableAfter;
    }

    function timeUntilUnlock(address user) external view returns (uint256) {
        uint256 unlockTime = depositTimestamp[user] + EARLY_WITHDRAW_WINDOW;
        if (block.timestamp >= unlockTime) return 0;
        return unlockTime - block.timestamp;
    }

    // ------------------------------------------------------------------
    // Multi-user batch helpers
    // ------------------------------------------------------------------

    /// @notice Returns share balances for several users in one call, to
    ///         save RPC round trips for front-ends and keeper bots that
    ///         need to render or process multiple positions at once.
    function balanceOfBatch(address[] calldata users) external view returns (uint256[] memory balances) {
        balances = new uint256[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            balances[i] = shares[users[i]];
        }
    }

    function assetBalanceOfBatch(address[] calldata users) external view returns (uint256[] memory balances) {
        balances = new uint256[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            balances[i] = _convertToAssets(shares[users[i]]);
        }
    }

    // ------------------------------------------------------------------
    // Emergency controls
    // ------------------------------------------------------------------

    /// @notice Lets the owner recover ERC-20 tokens accidentally sent
    ///         directly to the vault (not via deposit()), excluding the
    ///         vault's own underlying asset so this can never be used to
    ///         siphon depositor funds.
    /// @dev Restricting `token != address(asset)` is the key invariant
    ///      here â€” without it, this function would just be an admin-gated
    ///      version of the same fund-draining problem described in the
    ///      reentrancy finding, except requiring owner privileges instead
    ///      of exploiting a bug. Scoping it to non-asset tokens only keeps
    ///      this a genuine "rescue stray tokens" utility, not a backdoor.
    function sweepForeignToken(address token, address to) external onlyOwner {
        require(token != address(asset), "YieldVault: cannot sweep underlying asset");
        require(to != address(0), "YieldVault: zero address");
        uint256 balance = IERC20(token).balanceOf(address(this));
        require(balance > 0, "YieldVault: nothing to sweep");
        IERC20(token).safeTransfer(to, balance);
    }

    /// @notice Emergency shutdown that pauses the vault AND clears the
    ///         strategist role in one call, for use if the strategist key
    ///         is suspected compromised. Separated from setPaused() so the
    ///         two concerns (temporary pause vs. revoking a trusted role)
    ///         remain auditable as distinct governance actions.
    function emergencyShutdown() external onlyOwner {
        paused = true;
        strategist = address(0);
        emit Paused(true);
        emit StrategistUpdated(address(0));
    }

    // ------------------------------------------------------------------
    // ERC-4626-style metadata, kept minimal â€” this contract does not
    // implement the full ERC-4626 interface, only enough read-only
    // surface for integrators to introspect the vault's accounting.
    // ------------------------------------------------------------------

    function decimalsOffset() external pure returns (uint8) {
        // share decimals match asset decimals 1:1 in this implementation;
        // a nonzero offset would be used to mitigate inflation-attack
        // share-price manipulation on first deposit, noted here for
        // completeness even though this vault relies on its 1:1 seed
        // mint in _convertToShares() instead.
        return 0;
    }

    function totalSupply() external view returns (uint256) {
        return totalShares;
    }
}
