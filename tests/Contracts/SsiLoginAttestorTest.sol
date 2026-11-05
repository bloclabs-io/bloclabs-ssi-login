// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;
import "../../contracts/SsiLoginAttestor.sol";

contract SsiLoginAttestorTest {
    function testDuplicateDecision() external {
        SsiLoginAttestor attestor = new SsiLoginAttestor(address(this));
        bytes32 correlation = bytes32(uint256(1));
        attestor.attest(correlation, 2, bytes32(0), bytes32(0));
        require(attestor.attested(correlation), "decision not recorded");
        try attestor.attest(correlation, 1, bytes32(uint256(2)), bytes32(uint256(3))) {
            revert("duplicate decision accepted");
        } catch (bytes memory reason) {
            require(bytes4(reason) == SsiLoginAttestor.AlreadyAttested.selector, "wrong rejection");
        }
        attestor.attest(bytes32(uint256(2)), 1, bytes32(uint256(2)), bytes32(uint256(3)));
    }
}
