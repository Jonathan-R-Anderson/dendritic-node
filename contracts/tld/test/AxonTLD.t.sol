// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "../src/AxonTLD.sol";

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
    function expectRevert() external;
    function warp(uint256) external;
}

/// Minimal ERC-20-balance stand-in for the DAO vote token.
contract MockVotes {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
}

contract AxonTLDTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    AxonTLD r;
    MockVotes token;
    address alice = address(0xa11ce);
    address bob = address(0xb0b);
    bytes32 constant KEY = bytes32(uint256(123));
    receive() external payable {}

    function setUp() public {
        token = new MockVotes();
        r = new AxonTLD(10, 2, 3, address(token), 100, 1000);
        // `com` is an ICANN root TLD: the admin marks it and may enable it directly.
        r.markIcann("com", true);
        r.setSuffix("com", true);
        vm.deal(address(this), 100000);
        vm.deal(alice, 100000);
        vm.deal(bob, 100000);
    }

    function reg() internal {
        vm.prank(alice);
        r.register{value: 10}("Example.COM.", KEY);
    }

    function testRegistrationNormalizationAndSuffix() public {
        reg();
        (bytes32 k, address owner,) = r.resolveName("example.com");
        require(k == KEY && owner == alice);
        require(r.nodeOf("EXAMPLE.COM.") == keccak256("example.com"));
        vm.expectRevert();
        r.register{value: 10}("example.com", KEY);
        vm.expectRevert();
        r.register{value: 10}("example.net", KEY);
        vm.expectRevert();
        r.register{value: 10}("example.notcom", KEY);
        r.register{value: 10}("old.axon", KEY);
    }

    function testSubdomainOwnershipInheritanceAndDelegation() public {
        reg();
        vm.prank(bob); vm.expectRevert(); r.register{value:10}("api.example.com", KEY);
        vm.prank(alice); r.register{value:10}("api.example.com", KEY);
        vm.prank(alice); r.register{value:10}("v1.api.example.com", KEY);
        vm.prank(alice); r.transfer{value:3}("example.com", bob);
        vm.prank(bob); r.acceptTransfer("example.com");
        require(r.ownerOf(r.nodeOf("api.example.com")) == bob);
        require(r.ownerOf(r.nodeOf("v1.api.example.com")) == bob);
        vm.prank(alice); vm.expectRevert(); r.setKey{value:2}("api.example.com",KEY);
        vm.prank(bob); r.transfer{value:3}("api.example.com", alice);
        vm.prank(alice); r.acceptTransfer("api.example.com");
        require(r.ownerOf(r.nodeOf("v1.api.example.com")) == alice);
        vm.prank(bob); vm.expectRevert(); r.setKey{value:2}("api.example.com",KEY);
        require(r.childrenPage(r.nodeOf("example.com"),0,128).length==1);
    }

    function testAncestorReleaseCannotReviveDescendantsOrPendingTransfers() public {
        reg();
        vm.prank(alice); r.register{value:10}("api.example.com", KEY);
        vm.prank(alice); r.register{value:10}("v1.api.example.com", KEY);
        vm.prank(alice); r.transfer{value:3}("api.example.com", bob);
        vm.prank(alice); r.release("example.com");
        bytes32 node=r.nodeOf("api.example.com");
        require(r.ownerOf(node)==address(0));
        (bytes32 key,address owner,)=r.resolve(node); require(key==0 && owner==address(0));
        require(r.recordsPage(node,0,32).length==0);
        require(r.pendingTransfer(node)==address(0));
        vm.prank(bob); vm.expectRevert(); r.acceptTransfer("api.example.com");
        vm.prank(bob); r.register{value:10}("example.com", KEY);
        require(r.ownerOf(node)==address(0));
        vm.prank(bob); r.register{value:10}("api.example.com",bytes32(0));
        (key,owner,)=r.resolve(node); require(key==0 && owner==bob);
        require(r.ownerOf(r.nodeOf("v1.api.example.com"))==address(0));
        require(r.childrenPage(r.nodeOf("example.com"),0,128).length==1);
    }

    function testInheritedTransferProposalInvalidatedByParentTransfer() public {
        reg();
        vm.prank(alice); r.register{value:10}("api.example.com", KEY);
        vm.prank(alice); r.transfer{value:3}("api.example.com", address(this));
        vm.prank(alice); r.transfer{value:3}("example.com",bob);
        vm.prank(bob); r.acceptTransfer("example.com");
        require(r.pendingTransfer(r.nodeOf("api.example.com"))==address(0));
        vm.expectRevert(); r.acceptTransfer("api.example.com");
    }

    function testDNSNamesAndGenericRecordEnvelope() public {
        reg();
        vm.prank(alice); r.register{value:10}("*.example.com", bytes32(0));
        vm.prank(alice); r.register{value:10}("_tcp.example.com", bytes32(0));
        vm.prank(alice); r.register{value:10}("_sip._tcp.example.com", bytes32(0));
        // TXT wire RDATA: type 16, one character-string 'hello'.
        vm.prank(alice); r.setRecord{value:2}("example.com",0,AxonTLD.Kind.DNS,300,hex"00100568656c6c6f");
        vm.prank(alice); vm.expectRevert(); r.setRecord{value:2}("example.com",0,AxonTLD.Kind.DNS,300,hex"00ff");
        vm.prank(alice); vm.expectRevert(); r.register{value:10}("bad*.example.com",bytes32(0));
        vm.prank(alice); vm.expectRevert(); r.register{value:10}("a.*.example.com",bytes32(0));
        vm.prank(alice); vm.expectRevert(); r.register{value:10}("a.missing.example.com",bytes32(0));
    }

    function testRemovingNonprimaryPreservesSelection() public {
        reg();
        vm.prank(alice); r.setRecord{value:2}("example.com",0,AxonTLD.Kind.AXON,300,abi.encodePacked(bytes32(uint256(456))));
        vm.prank(alice); r.setRecord{value:2}("example.com",0,AxonTLD.Kind.A,300,hex"01020304");
        vm.prank(alice); r.setPrimary{value:2}("example.com",2);
        vm.prank(alice); r.removeRecord{value:2}("example.com",3);
        (bytes32 key,,)=r.resolveName("example.com"); require(key==bytes32(uint256(456)));
    }

    function testCanonicalHashCompatibility() public {
        require(r.nodeOf("AI.EPIN.AXON.") == 0xcc8efeb2dbc9ba52f80357c73a6aad0817d87c5a0f4de2740a623faa82b26174);
    }

    function testMutationFeesAndUpdates() public {
        reg();
        vm.prank(alice);
        vm.expectRevert();
        r.setKey{value: 1}("example.com", KEY);
        vm.prank(alice);
        vm.expectRevert();
        r.setKey{value: 3}("example.com", KEY);
        vm.prank(alice);
        vm.expectRevert();
        r.removeRecord{value: 1}("example.com", 1);
        vm.prank(alice);
        vm.expectRevert();
        r.transfer{value: 4}("example.com", bob);
        require(r.accrued() == 10);
        vm.prank(alice);
        r.setRecord{value: 2}("example.com", 1, AxonTLD.Kind.A, 0, hex"01020304");
        (bytes32 key, address owner,) = r.resolveName("example.com");
        require(key == 0 && owner == alice);
        vm.prank(alice);
        r.setKey{value: 2}("example.com", KEY);
        vm.prank(alice);
        r.removeRecord{value: 2}("example.com", 2);
        (key, owner,) = r.resolveName("example.com");
        require(key == 0 && owner == alice);
        r.setFees(20, 4, 6);
        vm.prank(alice);
        vm.expectRevert();
        r.setKey{value: 2}("example.com", KEY);
        vm.prank(alice);
        r.setKey{value: 4}("example.com", KEY);
        require(r.accrued() == 20);
    }

    function testInvalidNames() public {
        string[10] memory bad =
            [
            "key.axon",
            "x.key.axon",
            "com",
            "x..com",
            " x.com",
            "x.com..",
            "-x.com",
            "x-.com",
            "x_.com",
            unicode"é.com"
        ];
        for (uint256 i; i < bad.length; i++) {
            vm.expectRevert();
            r.register{value: 10}(bad[i], KEY);
        }
        vm.expectRevert();
        r.setSuffix("co.uk", true);
    }

    function testDisabledSuffixPreservesOwnerRights() public {
        reg();
        r.setSuffix("com", false);
        vm.expectRevert();
        r.register{value: 10}("new.com", KEY);
        vm.prank(alice);
        r.setKey{value: 2}("example.com", bytes32(uint256(456)));
        vm.prank(alice);
        r.transfer{value: 3}("example.com", bob);
        vm.prank(bob);
        r.acceptTransfer("example.com");
        (, address owner,) = r.resolveName("example.com");
        require(owner == bob);
        vm.prank(bob);
        r.release("example.com");
    }

    function testUnauthorizedAndTwoStepTransfer() public {
        reg();
        vm.prank(bob);
        vm.expectRevert();
        r.setSuffix("net", true);
        vm.prank(bob);
        vm.expectRevert();
        r.setFees(0, 0, 0);
        vm.prank(bob);
        vm.expectRevert();
        r.setKey{value: 2}("example.com", KEY);
        vm.prank(bob);
        vm.expectRevert();
        r.release("example.com");
        vm.prank(bob);
        vm.expectRevert();
        r.transfer{value: 3}("example.com", bob);
        vm.prank(alice);
        vm.expectRevert();
        r.transfer{value: 3}("example.com", address(0));
        vm.prank(alice);
        r.transfer{value: 3}("example.com", bob);
        (, address beforeOwner,) = r.resolveName("example.com");
        require(beforeOwner == alice);
        vm.expectRevert();
        r.acceptTransfer("example.com");
        vm.prank(bob);
        r.acceptTransfer("example.com");
        (bytes32 k, address owner,) = r.resolveName("example.com");
        require(k == KEY && owner == bob);
        vm.prank(alice);
        vm.expectRevert();
        r.setKey{value: 2}("example.com", KEY);
        vm.prank(alice);
        vm.expectRevert();
        r.release("example.com");
        vm.prank(alice);
        vm.expectRevert();
        r.transfer{value: 3}("example.com", alice);
    }

    function testMultipleTypedRecordsPrimaryAndCleanup() public {
        reg();
        vm.prank(alice);
        uint64 second =
            r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.AXON, 0, abi.encodePacked(bytes32(uint256(456))));
        vm.prank(alice);
        r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.A, 60, hex"7f000001");
        vm.prank(alice);
        r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.AAAA, 60, abi.encodePacked(uint128(1)));
        vm.prank(alice);
        r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.MX, 60, abi.encodePacked(uint16(10), "mail.example.com"));
        vm.prank(alice);
        r.setPrimary{value: 2}("example.com", second);
        (address owner, bytes32[32] memory keys, uint256 count) = r.lookupAxon(r.nodeOf("example.com"));
        require(owner == alice && count == 2 && keys[0] == bytes32(uint256(456)) && keys[1] == KEY);
        require(r.recordsPage(r.nodeOf("example.com"), 2, 2).length == 2);
        vm.prank(alice);
        r.removeRecord{value: 2}("example.com", second);
        (bytes32 k,,) = r.resolveName("example.com");
        require(k == KEY);
        vm.prank(alice);
        r.transfer{value: 3}("example.com", bob);
        vm.prank(alice);
        r.release("example.com");
        require(r.pendingTransfer(r.nodeOf("example.com")) == address(0));
        require(r.recordsPage(r.nodeOf("example.com"), 0, 32).length == 0);
        vm.prank(bob);
        vm.expectRevert();
        r.acceptTransfer("example.com");
        vm.prank(bob);
        r.register{value: 10}("example.com", bytes32(0));
        (k, owner,) = r.resolveName("example.com");
        require(k == 0 && owner == bob);
    }

    function testRecordValidationBoundsAndAtomicBatch() public {
        reg();
        AxonTLD.Entry[] memory batch = new AxonTLD.Entry[](2);
        batch[0] = AxonTLD.Entry(0, AxonTLD.Kind.A, 1, hex"01020304");
        batch[1] = AxonTLD.Entry(0, AxonTLD.Kind.AAAA, 1, hex"01");
        vm.prank(alice);
        vm.expectRevert();
        r.setRecords{value: 4}("example.com", batch);
        require(r.accrued() == 10 && r.recordsPage(r.nodeOf("example.com"), 0, 32).length == 1);
        batch[1] = AxonTLD.Entry(0, AxonTLD.Kind.A, 1, hex"01020305");
        vm.prank(alice);
        vm.expectRevert();
        r.setRecords{value: 2}("example.com", batch);
        vm.prank(alice);
        r.setRecords{value: 4}("example.com", batch);
        require(r.accrued() == 14);
        vm.prank(alice);
        vm.expectRevert();
        r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.A, 1, hex"01020304");
        vm.prank(alice);
        vm.expectRevert();
        r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.MX, 1, abi.encodePacked(uint16(1), "Bad.COM"));
        vm.prank(alice);
        vm.expectRevert();
        r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.A, 604801, hex"01020306");
        vm.prank(alice);
        vm.expectRevert();
        r.setKey{value: 2}("example.com", bytes32(0));
        for (uint256 i = 3; i < 32; i++) {
            vm.prank(alice);
            r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.AXON, 60, abi.encodePacked(bytes32(i)));
        }
        vm.prank(alice);
        vm.expectRevert();
        r.setRecord{value: 2}("example.com", 0, AxonTLD.Kind.AXON, 60, abi.encodePacked(bytes32(uint256(999))));
    }

    function testFeesAdminAndBeneficiary() public {
        vm.expectRevert();
        r.register{value: 9}("x.com", KEY);
        vm.expectRevert();
        r.register{value: 11}("x.com", KEY);
        require(r.accrued() == 0);
        reg();
        r.proposeAdministrator(bob);
        vm.prank(alice);
        vm.expectRevert();
        r.acceptAdministrator();
        vm.prank(bob);
        r.acceptAdministrator();
        vm.expectRevert();
        r.setFees(0, 0, 0);
        vm.prank(bob);
        r.setFees(0, 0, 0);
        r.register("free.com", KEY);
        vm.prank(bob);
        vm.expectRevert();
        r.withdraw(payable(bob));
        uint256 beforeBalance = address(this).balance;
        r.withdraw(payable(address(this)));
        require(address(this).balance == beforeBalance + 10 && r.accrued() == 0 && r.beneficiary() == address(this));
        vm.prank(bob);
        vm.expectRevert();
        r.setKey("example.com", KEY);
    }

    function testWithdrawalFailureAndReentrancy() public {
        reg();
        Reject reject = new Reject();
        vm.expectRevert();
        r.withdraw(payable(address(reject)));
        require(r.accrued() == 10);
        Attack a = new Attack();
        a.run{value: 10}();
        require(a.blocked());
    }

    function testTldGovernanceAdmitsNonIcannAndDisableKeepsNames() public {
        // Admin cannot unilaterally enable a non-ICANN TLD.
        vm.expectRevert();
        r.setSuffix("foo", true);
        vm.prank(alice);
        vm.expectRevert();
        r.register{value: 10}("x.foo", KEY);

        // Propose -> token-weighted vote -> execute admits and enables it.
        token.mint(alice, 2000);
        token.mint(bob, 500);
        uint256 id = r.proposeSuffix("FOO.");
        vm.prank(alice);
        r.voteSuffix(id, true);
        vm.prank(bob);
        r.voteSuffix(id, false);
        vm.expectRevert(); // cannot finalise before the deadline
        r.executeSuffix(id);
        vm.warp(block.timestamp + 101);
        r.executeSuffix(id);
        require(r.suffixEnabled("foo") && r.daoApproved("foo"), "not admitted");

        vm.prank(alice);
        r.register{value: 10}("x.foo", KEY);
        (bytes32 k, address owner,) = r.resolveName("x.foo");
        require(k == KEY && owner == alice, "register under admitted tld");

        // Admin disable blocks NEW registrations but preserves the existing name + owner rights.
        r.setSuffix("foo", false);
        vm.prank(bob);
        vm.expectRevert();
        r.register{value: 10}("y.foo", KEY);
        (, address owner2,) = r.resolveName("x.foo");
        require(owner2 == alice, "existing name lost on disable");
        vm.prank(alice);
        r.setKey{value: 2}("x.foo", bytes32(uint256(9))); // owner still controls it
    }

    function testTldGovernanceRejectsBelowQuorumAndIcannIsIndependent() public {
        token.mint(alice, 500); // below quorum (1000)
        uint256 id = r.proposeSuffix("bar");
        vm.prank(alice);
        r.voteSuffix(id, true);
        vm.warp(block.timestamp + 101);
        r.executeSuffix(id);
        require(!r.suffixEnabled("bar") && !r.daoApproved("bar"), "should not pass");
        // A non-voter has no weight.
        vm.prank(bob);
        vm.expectRevert();
        r.voteSuffix(id, true);
        // ICANN marking is the independent admin path, no vote needed.
        r.markIcann("bar", true);
        r.setSuffix("bar", true);
        require(r.suffixEnabled("bar"), "icann enable");
    }
}

contract Reject {
    receive() external payable {
        revert();
    }
}

contract Attack {
    AxonTLD r;
    bool public blocked;

    function run() external payable {
        r = new AxonTLD(10, 0, 0, address(0), 0, 0);
        r.register{value: 10}("attack.axon", bytes32(uint256(1)));
        r.withdraw(payable(address(this)));
    }

    receive() external payable {
        (bool ok,) = address(r).call(abi.encodeCall(r.withdraw, (payable(address(this)))));
        blocked = !ok;
    }
}
