// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ArcGuardRegistry} from "../src/ArcGuardRegistry.sol";

contract ArcGuardRegistryTest is Test {
    ArcGuardRegistry internal registry;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal carol = address(0xCA401);
    address internal scam = address(0x5CA11);

    uint256 internal constant BOND = 1e18;

    function setUp() public {
        registry = new ArcGuardRegistry();
        vm.deal(alice, 10e18);
        vm.deal(bob, 10e18);
        vm.deal(carol, 10e18);
    }

    function test_report_requires_the_bond() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(ArcGuardRegistry.BondTooSmall.selector, BOND, BOND - 1)
        );
        registry.report{value: BOND - 1}(scam, ArcGuardRegistry.Tag.Drainer, "drained a wallet");
    }

    function test_report_stores_an_attributed_claim() public {
        vm.prank(alice);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.FakeBridge, "pretends to be CCTP");

        assertEq(registry.reportCount(scam), 1);
        assertTrue(registry.hasReported(scam, alice));

        ArcGuardRegistry.Report[] memory reports = registry.getReports(scam);
        assertEq(reports[0].reporter, alice);
        assertEq(uint8(reports[0].tag), uint8(ArcGuardRegistry.Tag.FakeBridge));
        assertEq(reports[0].deposit, BOND);
        assertEq(reports[0].note, "pretends to be CCTP");
    }

    function test_one_report_per_reporter_per_target() public {
        vm.startPrank(alice);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "first");
        vm.expectRevert(
            abi.encodeWithSelector(ArcGuardRegistry.AlreadyReported.selector, scam, alice)
        );
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "second");
        vm.stopPrank();
    }

    function test_several_reporters_accumulate() public {
        vm.prank(alice);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "a");
        vm.prank(bob);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.FakeToken, "b");

        assertEq(registry.reportCount(scam), 2);
        address[] memory who = registry.reporters(scam);
        assertEq(who.length, 2);
        assertEq(who[0], alice);
        assertEq(who[1], bob);
    }

    function test_retract_refunds_and_removes() public {
        vm.prank(alice);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "sorry, wrong address");

        uint256 before = alice.balance;
        vm.prank(alice);
        registry.retract(scam);

        assertEq(alice.balance, before + BOND);
        assertEq(registry.reportCount(scam), 0);
        assertFalse(registry.hasReported(scam, alice));
    }

    function test_retract_without_a_report_reverts() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(ArcGuardRegistry.NoReportFiled.selector, scam, alice)
        );
        registry.retract(scam);
    }

    /// The swap-and-pop is the one place an off-by-one silently corrupts the
    /// index map, so remove the middle entry and prove the survivors stay
    /// retractable.
    function test_retract_middle_keeps_other_reports_intact() public {
        vm.prank(alice);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "a");
        vm.prank(bob);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "b");
        vm.prank(carol);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "c");

        vm.prank(bob);
        registry.retract(scam);

        assertEq(registry.reportCount(scam), 2);
        assertEq(registry.reporters(scam)[0], alice);
        assertEq(registry.reporters(scam)[1], carol);

        // Both survivors must still be able to withdraw their bond.
        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        registry.retract(scam);
        assertEq(alice.balance, aliceBefore + BOND);

        uint256 carolBefore = carol.balance;
        vm.prank(carol);
        registry.retract(scam);
        assertEq(carol.balance, carolBefore + BOND);

        assertEq(registry.reportCount(scam), 0);
    }

    function test_reports_are_per_target() public {
        address other = address(0x0BAD);
        vm.prank(alice);
        registry.report{value: BOND}(scam, ArcGuardRegistry.Tag.Drainer, "x");

        assertEq(registry.reportCount(scam), 1);
        assertEq(registry.reportCount(other), 0);
    }

    function testFuzz_any_address_can_hold_reports(address target, uint96 amount) public {
        vm.assume(target != address(0));
        uint256 bond = uint256(amount) + BOND;
        vm.deal(alice, bond);
        vm.prank(alice);
        registry.report{value: bond}(target, ArcGuardRegistry.Tag.Other, "note");

        assertEq(registry.reportCount(target), 1);
        ArcGuardRegistry.Report[] memory reports = registry.getReports(target);
        assertEq(reports[0].deposit, bond);
    }
}
