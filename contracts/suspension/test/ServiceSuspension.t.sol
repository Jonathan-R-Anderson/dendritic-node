// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "../src/ServiceSuspension.sol";

interface Vm {
    function prank(address) external;
    function expectRevert() external;
}

/// The exact seam AxonGovernance.execute() calls, so this test proves the ABI
/// matches: a DAO pointed at ServiceSuspension governs it with no adapter.
interface IAxonRegistryGovernance {
    function prune(bytes32, uint256) external;
    function seize(bytes32, uint256) external;
    function restore(bytes32, uint256) external;
}

contract ServiceSuspensionTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ServiceSuspension s;
    address gov = address(0x60F);
    address alice = address(0xa11ce);
    bytes32 constant KEY = bytes32(uint256(0xABC));
    bytes32 constant KEY2 = bytes32(uint256(0xDEF));

    function setUp() public {
        s = new ServiceSuspension(address(this));
    }

    function wireGovernor() internal {
        s.setGovernor(gov);
    }

    // Inert until a governor is wired (the AxonRegistry F-94.1 safety).
    function testInertUntilGovernorSet() public {
        vm.expectRevert();
        s.prune(KEY, 1);
    }

    function testSetGovernorOnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert();
        s.setGovernor(alice);
    }

    function testOnlyGovernorMaySuspend() public {
        wireGovernor();
        vm.prank(alice);
        vm.expectRevert();
        s.prune(KEY, 1);
    }

    function testZeroKeyRefused() public {
        wireGovernor();
        vm.prank(gov);
        vm.expectRevert();
        s.prune(bytes32(0), 1);
    }

    function testSuspendThenRestoreLifecycle() public {
        wireGovernor();
        vm.prank(gov);
        s.prune(KEY, 7);

        require(s.isSuspended(KEY), "should be suspended");
        require(s.stateOf(KEY) == ServiceSuspension.ServiceState.SUSPENDED, "state");
        require(s.blockedCount() == 1 && s.blockedAt(0) == KEY, "blocked set");
        require(s.recordOf(KEY).proposalId == 7, "proposalId recorded");
        require(s.historyOf(KEY).length == 1, "history 1");

        vm.prank(gov);
        s.restore(KEY, 8);
        require(!s.isSuspended(KEY), "should be active");
        require(s.stateOf(KEY) == ServiceSuspension.ServiceState.ACTIVE, "state active");
        require(s.blockedCount() == 0, "blocked set empty");
        require(s.historyOf(KEY).length == 2, "history 2");
    }

    function testPruneTwiceReverts() public {
        wireGovernor();
        vm.prank(gov);
        s.prune(KEY, 1);
        vm.prank(gov);
        vm.expectRevert();
        s.prune(KEY, 2);
    }

    function testRestoreActiveReverts() public {
        wireGovernor();
        vm.prank(gov);
        vm.expectRevert();
        s.restore(KEY, 1);
    }

    function testSeizeIsPermanent() public {
        wireGovernor();
        vm.prank(gov);
        s.seize(KEY, 3);
        require(s.stateOf(KEY) == ServiceSuspension.ServiceState.BANNED, "banned");
        require(s.isSuspended(KEY), "banned is suspended for routing");
        vm.prank(gov);
        vm.expectRevert();
        s.restore(KEY, 4); // CannotRestoreBanned
    }

    function testSeizeTwiceReverts() public {
        wireGovernor();
        vm.prank(gov);
        s.seize(KEY, 1);
        vm.prank(gov);
        vm.expectRevert();
        s.seize(KEY, 2);
    }

    // Suspended set stays correct through a swap-remove.
    function testBlockedSetSwapRemove() public {
        wireGovernor();
        vm.prank(gov);
        s.prune(KEY, 1);
        vm.prank(gov);
        s.prune(KEY2, 2);
        require(s.blockedCount() == 2, "two blocked");

        vm.prank(gov);
        s.restore(KEY, 3); // KEY was at index 0; KEY2 swaps into its slot
        require(s.blockedCount() == 1, "one blocked");
        require(s.blockedAt(0) == KEY2, "KEY2 survived the swap-remove");
    }

    // Driving it through the governance interface proves ABI compatibility with
    // AxonGovernance.execute(), which calls prune/seize/restore(bytes32,uint256).
    function testGovernanceInterfaceCompatibility() public {
        wireGovernor();
        IAxonRegistryGovernance g = IAxonRegistryGovernance(address(s));
        vm.prank(gov);
        g.prune(KEY, 11);
        require(s.isSuspended(KEY), "prune via interface");
        vm.prank(gov);
        g.restore(KEY, 12);
        require(!s.isSuspended(KEY), "restore via interface");
    }
}
