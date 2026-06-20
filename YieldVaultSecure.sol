// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// ============================================================================
// EDUCATIONAL ONLY â€” DO NOT USE VULNERABLE CODE ON LIVE NETWORKS
// ============================================================================
// This file is the remediated counterpart to Vault.sol. It is intended as a
// reference for what the fix looks like in a full-size contract, not as a
// drop-in audited deployment â€” get an independent audit before shipping any
// vault that holds real value, remediated or not. Every change relative to
// Vault.sol is called out with a SECURE PATTERN comment explaining the
// specific mechanism, so this can be read side by side with the vulnerable
// version during a review or training session.
// ============================================================================

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title YieldVaultSecure
/// @notice Remediated version of YieldVault. Same external interface and
///         economic behavior, restructured so that state is never left
///         inconsistent across an external call.
/// @dev    SECURE PATTERN - PRODUCTION READY (subject to independent audit
///         before mainnet deployment â€” see SecurityReport.md).
contract YieldVaultSecure is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    IERC20 public immutable asset;
    uint256 public totalShares;
    uint256 public totalAssets;

    mapping(address => uint256) public shares;
    mapping(address => uint256) public depositTimestamp;

    // SECURE PATTERN: pull-payment ledger for fees.
    // Instead of pushing fee tokens to feeRecipient inside withdraw() (an
    // extra external call on the hot path, and an extra place for a
    // malicious or merely non-standard fee recipient to interfere with
    // execution), we credit an internal balance and let the recipient pull
    // it via claimFees(). This shrinks the attack surface of withdraw()
    // down to a single external call, and means a misbehaving fee
    // recipient can only ever harm itself, never other depositors.
    mapping(address => uint256) public claimableFees;

    uint256 public performanceFeeBps = 1000;
    uint256 public withdrawalFeeBps = 50;
    uint256 public constant MAX_BPS = 10_000;
    uint256 public constant EARLY_WITHDRAW_WINDOW = 3 days;
    uint256 public constant EARLY_WITHDRAW_PENALTY_BPS = 200;

    address public feeRecipient;
    address public strategist;

    struct PendingChange {
        uint256 newValue;
        uint256 executableAfter;
        bool exists;
    }
    mapping(bytes32 => PendingChange) public pendingChanges;
    uint256 public constant TIMELOCK_DELAY = 2 days;

    bool public paused;

    uint256 public lastReportedAssets;
    uint256 public cumulativeYieldDistributed;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    event Deposit(address indexed user, uint256 assetsIn, uint256 sharesMinted);
    event Withdraw(address indexed user, uint256 sharesBurned, uint256 assetsOut);
    event FeesAccrued(address indexed recipient, uint256 amount);
    event FeesClaimed(address indexed recipient, uint256 amount);
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
        require(!paused, "YieldVaultSecure: paused");
        _;
    }

    modifier onlyStrategist() {
        require(msg.sender == strategist, "YieldVaultSecure: not strategist");
        _;
    }

    constructor(address _asset, address _feeRecipient, address _strategist) Ownable(msg.sender) {
        require(_asset != address(0), "YieldVaultSecure: zero asset");
        require(_feeRecipient != address(0), "YieldVaultSecure: zero fee recipient");
        asset = IERC20(_asset);
        feeRecipient = _feeRecipient;
        strategist = _strategist;
    }

    // ------------------------------------------------------------------
    // Core share math â€” unchanged from Vault.sol, the bug was never in
    // the math, it was in the ordering of operations during withdraw.
    // ------------------------------------------------------------------

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

    // SECURE PATTERN: nonReentrant added here too, even though deposit was
    // never the vulnerable function. Defense in depth â€” if a future change
    // adds a hook or callback to the deposit path, the guard is already in
    // place rather than being something someone has to remember to add.
    function deposit(uint256 assetAmount) external whenNotPaused nonReentrant returns (uint256 mintedShares) {
        require(assetAmount > 0, "YieldVaultSecure: zero deposit");

        mintedShares = _convertToShares(assetAmount);
        require(mintedShares > 0, "YieldVaultSecure: rounds to zero shares");

        // EFFECTS before INTERACTIONS, same as the original â€” this part
        // was already correct, kept identical for behavioral parity.
        shares[msg.sender] += mintedShares;
        totalShares += mintedShares;
        totalAssets += assetAmount;
        depositTimestamp[msg.sender] = block.timestamp;

        asset.safeTransferFrom(msg.sender, address(this), assetAmount);

        emit Deposit(msg.sender, assetAmount, mintedShares);
    }

    // ====================================================================
    // SECURE PATTERN - PRODUCTION READY
    // ====================================================================
    // Three independent mitigations are stacked here, deliberately
    // redundant. Any one of them alone would stop the specific exploit
    // described in Vault.sol; using all three means the fix doesn't
    // depend on getting any single one perfectly right.
    //
    //   1. nonReentrant (ReentrancyGuard) â€” a mutex on the function. If
    //      somehow a reentrant call still reached this function despite
    //      the reordering below, the guard reverts it outright. This is
    //      the backstop, not the primary fix.
    //
    //   2. Checks-Effects-Interactions â€” all state mutations (shares,
    //      totalShares, totalAssets) happen BEFORE the external
    //      safeTransfer call. By the time control could possibly be
    //      handed to another contract, the ledger already reflects the
    //      withdrawal as complete. A reentrant call into withdraw() at
    //      that point would see the caller's correctly-reduced share
    //      balance and simply fail the `shares[msg.sender] >= shareAmount`
    //      check, or withdraw a legitimately smaller remaining balance â€”
    //      either way, no double-spend.
    //
    //   3. Pull-payment for fees â€” the fee portion is never pushed to
    //      feeRecipient synchronously. It's credited to claimableFees and
    //      pulled separately. This removes a second external call from
    //      withdraw() entirely, which removes a second reentrancy surface
    //      and a second point where an unexpected recipient (e.g. a fee
    //      recipient that's a contract with a failing receive()) could
    //      brick withdrawals for everyone.
    // ====================================================================

    /// @notice Burn shares and withdraw the underlying asset.
    /// @dev SECURE PATTERN - PRODUCTION READY. State is fully updated
    ///      before any external call, and the function is guarded against
    ///      reentrancy as a second line of defense.
    function withdraw(uint256 shareAmount) external whenNotPaused nonReentrant returns (uint256 assetsOut) {
        require(shareAmount > 0, "YieldVaultSecure: zero withdraw");

        // --- CHECKS ---
        uint256 callerShares = shares[msg.sender];
        require(callerShares >= shareAmount, "YieldVaultSecure: insufficient shares");

        assetsOut = _convertToAssets(shareAmount);
        require(assetsOut > 0, "YieldVaultSecure: rounds to zero assets");

        uint256 fee = _calculateWithdrawalFee(msg.sender, assetsOut);
        uint256 netAssetsOut = assetsOut - fee;

        // --- EFFECTS ---
        // Every piece of state that withdraw() is responsible for is
        // finalized here, before any external call exists in this
        // function. This is the line-by-line core of the fix relative to
        // Vault.sol: in the vulnerable version these three lines appeared
        // AFTER the safeTransfer calls below. Moving them up means a
        // reentrant call landing inside the safeTransfer() call below sees
        // shares[msg.sender] already decremented.
        shares[msg.sender] = callerShares - shareAmount;
        totalShares -= shareAmount;
        totalAssets -= assetsOut;

        // fee is credited, not transferred â€” see pull-payment note above.
        // This also moves the fee bookkeeping into the EFFECTS phase,
        // since claimableFees is part of the contract's internal ledger,
        // not an external call.
        if (fee > 0) {
            claimableFees[feeRecipient] += fee;
            emit FeesAccrued(feeRecipient, fee);
        }

        // --- INTERACTIONS ---
        // The single external call left in this function, happening last,
        // after every invariant the contract cares about has already been
        // restored. Even if `asset` has a transfer hook and the recipient
        // reenters right here, every check above will see correct,
        // fully-updated state â€” and nonReentrant blocks the reentrant call
        // before it gets that far regardless.
        asset.safeTransfer(msg.sender, netAssetsOut);

        emit Withdraw(msg.sender, shareAmount, netAssetsOut);
    }

    /// @notice Fee recipient pulls accrued fees on their own schedule.
    /// @dev SECURE PATTERN - PRODUCTION READY. This is the other half of
    ///      the pull-payment split. nonReentrant here too: claimableFees
    ///      is zeroed before the transfer, so even a malicious feeRecipient
    ///      contract re-entering this function just finds a zero balance.
    function claimFees() external nonReentrant {
        uint256 amount = claimableFees[msg.sender];
        require(amount > 0, "YieldVaultSecure: nothing to claim");

        // EFFECTS before INTERACTIONS, same discipline as withdraw().
        claimableFees[msg.sender] = 0;

        asset.safeTransfer(msg.sender, amount);

        emit FeesClaimed(msg.sender, amount);
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

    /// @dev Performance fees are minted as shares, which was never the
    ///      vulnerable mechanism (no external call here at all â€” minting
    ///      shares is a purely internal accounting operation). Left as-is
    ///      apart from the nonReentrant guard, added for defense in depth
    ///      since this function mutates the same shared totalShares state
    ///      that withdraw() depends on.
    function reportYield(uint256 newTotalAssets) external onlyStrategist nonReentrant {
        require(newTotalAssets >= totalAssets, "YieldVaultSecure: reported loss not supported here");

        uint256 profit = newTotalAssets - totalAssets;
        uint256 feeAssets = (profit * performanceFeeBps) / MAX_BPS;

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
    // Governance â€” timelocked parameter changes (unchanged logic, no
    // external calls involved, not part of the reentrancy surface)
    // ------------------------------------------------------------------

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
        require(change.exists, "YieldVaultSecure: no pending change");
        require(block.timestamp >= change.executableAfter, "YieldVaultSecure: timelock not expired");

        if (key == keccak256("performanceFeeBps")) {
            require(change.newValue <= 3000, "YieldVaultSecure: fee too high");
            performanceFeeBps = change.newValue;
        } else if (key == keccak256("withdrawalFeeBps")) {
            require(change.newValue <= 500, "YieldVaultSecure: fee too high");
            withdrawalFeeBps = change.newValue;
        } else {
            revert("YieldVaultSecure: unknown parameter key");
        }

        delete pendingChanges[key];
        emit ParameterChangeExecuted(key, change.newValue);
    }

    // ------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------

    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "YieldVaultSecure: zero address");
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(newRecipient);
    }

    function setStrategist(address newStrategist) external onlyOwner {
        require(newStrategist != address(0), "YieldVaultSecure: zero address");
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

    function previewWithdraw(address user, uint256 shareAmount) external view returns (uint256) {
        // SECURE PATTERN: this preview function takes `user` as an explicit
        // parameter instead of reading msg.sender, unlike the equivalent
        // function in Vault.sol. That original version used msg.sender
        // inside a `view` function called previewWithdraw, which silently
        // returns a wrong answer for anyone other than the caller â€” not a
        // reentrancy bug, but a correctness footgun worth fixing while
        // this contract is already being rewritten line by line.
        uint256 assetsOut = _convertToAssets(shareAmount);
        uint256 fee = _calculateWithdrawalFee(user, assetsOut);
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
    ///         directly to the vault, excluding the underlying asset.
    /// @dev SECURE PATTERN: also nonReentrant, since safeTransfer to an
    ///      arbitrary `to` address is itself an external call. The
    ///      `token != address(asset)` guard remains the primary invariant
    ///      protecting depositor funds â€” reentrancy protection here is
    ///      belt-and-suspenders for an admin-gated function, not the main
    ///      defense, since onlyOwner already limits who can reach it.
    function sweepForeignToken(address token, address to) external onlyOwner nonReentrant {
        require(token != address(asset), "YieldVaultSecure: cannot sweep underlying asset");
        require(to != address(0), "YieldVaultSecure: zero address");
        uint256 balance = IERC20(token).balanceOf(address(this));
        require(balance > 0, "YieldVaultSecure: nothing to sweep");
        IERC20(token).safeTransfer(to, balance);
    }

    function emergencyShutdown() external onlyOwner {
        paused = true;
        strategist = address(0);
        emit Paused(true);
        emit StrategistUpdated(address(0));
    }

    // ------------------------------------------------------------------
    // ERC-4626-style metadata
    // ------------------------------------------------------------------

    function decimalsOffset() external pure returns (uint8) {
        return 0;
    }

    function totalSupply() external view returns (uint256) {
        return totalShares;
    }
}
