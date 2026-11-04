// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;
import "../../contracts/SsiLoginAttestor.sol";
contract NewOwner {
    function accept(SsiLoginAttestor target) external { target.acceptOwnership(); }
    function set(SsiLoginAttestor target, address who) external { target.setVerifier(who, true); }
}
contract OwnershipTest {
    function testTwoStepOwnership() external {
        SsiLoginAttestor target = new SsiLoginAttestor(address(0));
        NewOwner proposed = new NewOwner();
        target.transferOwnership(address(123));
        require(target.owner() == address(this), "proposal changed owner");
        target.transferOwnership(address(proposed));
        try target.acceptOwnership() { revert("unproposed caller accepted"); }
        catch(bytes memory reason) { require(bytes4(reason) == SsiLoginAttestor.NotOwner.selector); }
        proposed.accept(target);
        require(target.owner() == address(proposed), "accept did not transfer");
        require(target.pendingOwner() == address(0), "proposal not cleared");
        proposed.set(target, address(456));
        try target.setVerifier(address(456), false) { revert("old owner retained authority"); }
        catch(bytes memory reason) { require(bytes4(reason) == SsiLoginAttestor.NotOwner.selector); }
    }
}
