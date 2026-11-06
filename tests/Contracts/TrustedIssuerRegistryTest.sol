// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;
import "../../contracts/TrustedIssuerRegistry.sol";

interface RegistryVm {
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter) external;
}

contract TrustedIssuerRegistryTest {
    RegistryVm private constant vm = RegistryVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    TrustedIssuerRegistry private registry;
    address private constant NEXT = address(0x1234);
    address private constant OTHER = address(0x5678);
    string private constant ISSUER = "did:example:issuer";
    string private constant VCT = "urn:example:credential";

    event IssuerSet(bytes32 indexed key, string issuer, string vct, bool trusted, address indexed by);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed proposedOwner);

    function setUp() external {
        registry = new TrustedIssuerRegistry();
    }

    function testDeploymentOwnershipEvent() external {
        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferred(address(0), address(this));
        TrustedIssuerRegistry deployed = new TrustedIssuerRegistry();
        require(deployed.owner() == address(this), "wrong deployer owner");
        require(deployed.pendingOwner() == address(0), "pending owner set");
    }

    function testUnknownAndRevokedPairsAreFalse() external {
        require(!registry.isTrusted(ISSUER, VCT), "unknown trusted");
        registry.setIssuer(ISSUER, VCT, true);
        require(registry.isTrusted(ISSUER, VCT), "grant missing");
        registry.setIssuer(ISSUER, VCT, false);
        require(!registry.isTrusted(ISSUER, VCT), "revocation missing");
    }

    function testExactPairsAndUnambiguousEncoding() external {
        registry.setIssuer("ab", "c", true);
        require(!registry.isTrusted("a", "bc"), "packed collision");
        require(!registry.isTrusted("c", "ab"), "swapped pair trusted");
        registry.setIssuer(ISSUER, VCT, true);
        require(!registry.isTrusted(ISSUER, "urn:example:other"), "other vct trusted");
        require(!registry.isTrusted("did:example:other", VCT), "other issuer trusted");
        require(!registry.isTrusted("DID:example:issuer", VCT), "case normalized");
        registry.setIssuer("", "", true);
        require(registry.isTrusted("", ""), "empty pair not exact");
        require(!registry.isTrusted("", VCT), "empty issuer wildcard");
        require(!registry.isTrusted(ISSUER, ""), "empty vct wildcard");
        registry.setIssuer("ab", "c", false);
        require(registry.isTrusted(ISSUER, VCT), "unrelated pair revoked");
    }

    function testIssuerEventsOnGrantRepeatAndRevoke() external {
        bytes32 key = keccak256(abi.encode(ISSUER, VCT));
        for (uint256 i; i < 3; i++) {
            bool trusted = i < 2;
            vm.expectEmit(true, true, false, true, address(registry));
            emit IssuerSet(key, ISSUER, VCT, trusted, address(this));
            registry.setIssuer(ISSUER, VCT, trusted);
        }
    }

    function testOnlyOwnerCanSetIssuer() external {
        vm.prank(OTHER);
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.setIssuer(ISSUER, VCT, true);
        registry.setIssuer(ISSUER, VCT, true);
        vm.prank(OTHER);
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.setIssuer(ISSUER, VCT, false);
        require(registry.isTrusted(ISSUER, VCT), "unauthorized revocation");
    }

    function testTwoStepOwnership() external {
        vm.expectEmit(true, true, false, true, address(registry));
        emit OwnershipTransferStarted(address(this), NEXT);
        registry.transferOwnership(NEXT);
        require(registry.owner() == address(this), "owner changed before acceptance");
        require(registry.pendingOwner() == NEXT, "nomination missing");
        vm.prank(NEXT);
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.setIssuer(ISSUER, VCT, true);
        registry.setIssuer(ISSUER, VCT, true);
        vm.prank(OTHER);
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.acceptOwnership();
        vm.expectEmit(true, true, false, true, address(registry));
        emit OwnershipTransferred(address(this), NEXT);
        vm.prank(NEXT);
        registry.acceptOwnership();
        require(registry.owner() == NEXT, "acceptance failed");
        require(registry.pendingOwner() == address(0), "nomination not cleared");
        require(registry.isTrusted(ISSUER, VCT), "policy lost on transfer");
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.setIssuer(ISSUER, VCT, false);
        vm.prank(NEXT);
        registry.setIssuer(ISSUER, VCT, false);
        require(!registry.isTrusted(ISSUER, VCT), "new owner cannot revoke");
        vm.prank(NEXT);
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.acceptOwnership();
    }

    function testOwnershipRejectsUnauthorizedAndZeroNominations() external {
        vm.prank(OTHER);
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.transferOwnership(NEXT);
        vm.expectRevert(TrustedIssuerRegistry.ZeroAddress.selector);
        registry.transferOwnership(address(0));
        require(registry.pendingOwner() == address(0), "invalid nomination persisted");
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.acceptOwnership();
    }

    function testOwnerCanReplacePendingOwner() external {
        registry.transferOwnership(NEXT);
        registry.transferOwnership(OTHER);
        vm.prank(NEXT);
        vm.expectRevert(TrustedIssuerRegistry.NotOwner.selector);
        registry.acceptOwnership();
        vm.prank(OTHER);
        registry.acceptOwnership();
        require(registry.owner() == OTHER, "replacement cannot accept");
    }
}
