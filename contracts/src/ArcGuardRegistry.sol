// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ArcGuardRegistry
 * @notice An append-only, ownerless registry of addresses that Arc users have
 *         publicly reported as drainers, fake bridges, fake tokens or phishing
 *         sites.
 *
 * Design notes, because the design *is* the security argument here:
 *
 * - No owner, no admin, no upgrade path. There is nothing to seize, bribe or
 *   phish. That also means there is no one who can delete a false report.
 *
 * - Reports are public and attributed. The front end shows the reporter address
 *   and the timestamp for every report, so a Sybil cluster is visible as a
 *   cluster. The contract stores raw claims and never labels anything
 *   "malicious" itself — consumers decide.
 *
 * - Filing a report costs a small bond in native USDC (Arc's gas asset, 18
 *   decimals). Retracting your own report returns the bond. This makes a
 *   drive-by false accusation cost money rather than nothing, which is the
 *   cheapest honest Sybil mitigation available without introducing an owner.
 *
 * - Deposits attached to reports that are never retracted stay in this contract
 *   permanently, because there is no owner to withdraw them. That is the price
 *   of having no privileged role, and it is stated rather than hidden.
 *
 * - A report against an address that Circle publishes as an official Arc system
 *   contract is almost certainly a false-flag campaign. The front end detects
 *   that case and downgrades it; the contract stays dumb and neutral.
 *
 * Deployed on Arc mainnet. Arc's native asset is USDC, so `msg.value` is USDC.
 */
contract ArcGuardRegistry {
    /// @notice What kind of problem is being reported.
    enum Tag {
        Unknown,
        Drainer,
        FakeBridge,
        FakeToken,
        PhishingSite,
        TestnetMislabel,
        Other
    }

    struct Report {
        address reporter;
        uint64 timestamp;
        Tag tag;
        uint256 deposit;
        string note;
    }

    /// @notice Bond required to file a report, in native USDC base units (18 decimals).
    uint256 public constant MIN_BOND = 1e18; // 1 USDC

    mapping(address => Report[]) private _reports;
    mapping(address => mapping(address => bool)) public hasReported;
    mapping(address => mapping(address => uint256)) private _indexPlusOne;

    error BondTooSmall(uint256 required, uint256 received);
    error AlreadyReported(address target, address reporter);
    error NoReportFiled(address target, address reporter);
    error RefundFailed();

    event Reported(
        address indexed target,
        address indexed reporter,
        Tag indexed tag,
        string note,
        uint256 deposit
    );
    event Retracted(address indexed target, address indexed reporter);

    /// @notice File a public report against `target`. Costs at least MIN_BOND.
    function report(address target, Tag tag, string calldata note) external payable {
        if (msg.value < MIN_BOND) revert BondTooSmall(MIN_BOND, msg.value);
        if (hasReported[target][msg.sender]) revert AlreadyReported(target, msg.sender);

        hasReported[target][msg.sender] = true;
        _reports[target].push(
            Report({
                reporter: msg.sender,
                // Casting to uint64 is safe: a Unix timestamp exceeds uint64 max
                // (1.8e19) only around the year 584 billion. Storing 8 bytes
                // instead of 32 keeps the report struct cheap.
                // forge-lint: disable-next-line(unsafe-typecast)
                timestamp: uint64(block.timestamp),
                tag: tag,
                deposit: msg.value,
                note: note
            })
        );
        _indexPlusOne[target][msg.sender] = _reports[target].length; // stored +1

        emit Reported(target, msg.sender, tag, note, msg.value);
    }

    /// @notice Withdraw your own report and get the bond back.
    function retract(address target) external {
        if (!hasReported[target][msg.sender]) revert NoReportFiled(target, msg.sender);

        uint256 index = _indexPlusOne[target][msg.sender] - 1;
        Report[] storage list = _reports[target];
        uint256 lastIndex = list.length - 1;
        uint256 deposit = list[index].deposit;

        if (index != lastIndex) {
            list[index] = list[lastIndex];
            _indexPlusOne[target][list[index].reporter] = index + 1;
        }
        list.pop();

        delete _indexPlusOne[target][msg.sender];
        // `Retracted` is emitted immediately below, so this state change is not
        // silent. The lint keys off the `mapping[address][address] = bool`
        // assignment and does not associate the event with it.
        // forge-lint: disable-next-line(missing-events-access-control)
        hasReported[target][msg.sender] = false;

        emit Retracted(target, msg.sender);

        (bool ok, ) = msg.sender.call{value: deposit}("");
        if (!ok) revert RefundFailed();
    }

    /// @notice Number of reports currently held against `target`.
    function reportCount(address target) external view returns (uint256) {
        return _reports[target].length;
    }

    /// @notice Every report for `target`. Unbounded; call off-chain for large sets.
    function getReports(address target) external view returns (Report[] memory) {
        return _reports[target];
    }

    /// @notice The reporters currently holding a report against `target`.
    function reporters(address target) external view returns (address[] memory out) {
        Report[] storage list = _reports[target];
        out = new address[](list.length);
        for (uint256 i = 0; i < list.length; i++) {
            out[i] = list[i].reporter;
        }
    }
}
