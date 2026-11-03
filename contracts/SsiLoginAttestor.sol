// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

/// @title SsiLoginAttestor
/// @notice An append-only record of login decisions made by authorised verifiers.
/// @dev Holds no state per login: the event log is the record. FireFly listens for
///      LoginAttested and streams it to WordPress. Only commitments go on chain,
///      never claims, DIDs or anything personal:
///        correlationId     random per attempt, known to WordPress and the verifier
///        subjectCommitment sha256(hex(correlationId) ":" subjectId), unlinkable across logins
///        presentationHash  sha256 of the presentation as the verifier received it
contract SsiLoginAttestor {
    uint8 public constant RESULT_VERIFIED = 1;
    uint8 public constant RESULT_REJECTED = 2;

    address public owner;
    mapping(address => bool) public isVerifier;

    event LoginAttested(
        bytes32 indexed correlationId,
        uint8 result,
        bytes32 subjectCommitment,
        bytes32 presentationHash,
        address indexed verifier
    );
    event VerifierSet(address indexed verifier, bool allowed);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotVerifier();
    error BadResult();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address firstVerifier) {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        if (firstVerifier != address(0)) {
            isVerifier[firstVerifier] = true;
            emit VerifierSet(firstVerifier, true);
        }
    }

    /// @notice Records one verifier decision. Called by the verifier bridge through FireFly.
    function attest(
        bytes32 correlationId,
        uint8 result,
        bytes32 subjectCommitment,
        bytes32 presentationHash
    ) external {
        if (!isVerifier[msg.sender]) revert NotVerifier();
        if (result != RESULT_VERIFIED && result != RESULT_REJECTED) revert BadResult();
        emit LoginAttested(correlationId, result, subjectCommitment, presentationHash, msg.sender);
    }

    function setVerifier(address verifier, bool allowed) external onlyOwner {
        if (verifier == address(0)) revert ZeroAddress();
        isVerifier[verifier] = allowed;
        emit VerifierSet(verifier, allowed);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
