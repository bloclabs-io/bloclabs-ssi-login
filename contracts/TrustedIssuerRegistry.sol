// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

/// @title TrustedIssuerRegistry
/// @notice Owner-governed trust for exact issuer and credential-type (vct) pairs.
/// @dev Issuer and vct strings are public policy, recorded verbatim in events.
contract TrustedIssuerRegistry {
    address public owner;
    address public pendingOwner;
    mapping(bytes32 => bool) private trustedIssuers;

    event IssuerSet(bytes32 indexed key, string issuer, string vct, bool trusted, address indexed by);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed proposedOwner);

    error NotOwner();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function setIssuer(string calldata issuer, string calldata vct, bool trusted) external onlyOwner {
        bytes32 key = keccak256(abi.encode(issuer, vct));
        trustedIssuers[key] = trusted;
        emit IssuerSet(key, issuer, vct, trusted, msg.sender);
    }

    function isTrusted(string calldata issuer, string calldata vct) external view returns (bool) {
        return trustedIssuers[keccak256(abi.encode(issuer, vct))];
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }
}
