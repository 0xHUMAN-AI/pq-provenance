// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Arc precompile at 0x1800...0004: SLH-DSA-SHA2-128s (FIPS 205) verification.
interface ISlhDsaVerifier {
    function verifySlhDsaSha2128s(bytes calldata vk, bytes calldata msg_, bytes calldata sig)
        external
        view
        returns (bool);
}

/// @title PQ Provenance
/// @notice A post-quantum provenance registry. A publisher is an SLH-DSA-SHA2-128s public key, not an
///         address: every state change is authorised by a signature that Arc verifies on-chain, so
///         anyone can relay it and pay the gas. A key attests 32-byte subjects (file hashes, release
///         digests) or the runtime code of a contract; other contracts can ask `isAttested` or
///         `isCodeAttested` before trusting an artifact. No admin, no upgrade path, no funds held.
contract PQProvenance {
    enum Status {
        Unknown,
        Active,
        Rotated,
        Revoked
    }

    struct Key {
        Status status;
        uint64 registeredAt;
        uint64 closedAt; // rotation or revocation time
        bytes32 successor; // set on rotation
        bytes32 label; // free-form short name chosen by the key holder
    }

    struct Attestation {
        uint64 attestedAt;
        uint64 retractedAt;
        bytes32 uriHash; // keccak256 of a URI describing the subject, 0 if none
    }

    uint256 public constant SIG_LENGTH = 7856;

    ISlhDsaVerifier public constant VERIFIER = ISlhDsaVerifier(0x1800000000000000000000000000000000000004);

    mapping(bytes32 vk => Key) public keys;
    mapping(bytes32 vk => mapping(bytes32 subject => Attestation)) public attestations;
    mapping(bytes32 vk => mapping(bytes32 codehash => Attestation)) public codeAttestations;
    mapping(bytes32 vk => uint256) public attestationCount;

    event KeyRegistered(bytes32 indexed vk, bytes32 label);
    event KeyRotated(bytes32 indexed vk, bytes32 indexed successor);
    event KeyRevoked(bytes32 indexed vk);
    event Attested(bytes32 indexed vk, bytes32 indexed subject, bytes32 uriHash, string uri);
    event CodeAttested(bytes32 indexed vk, address indexed target, bytes32 indexed codehash);
    event Retracted(bytes32 indexed vk, bytes32 indexed subject);
    event CodeRetracted(bytes32 indexed vk, bytes32 indexed codehash);

    error BadSignature();
    error KeyExists();
    error KeyNotActive();
    error AlreadyAttested();
    error NotAttested();
    error NoCode();
    error ZeroValue();
    error ChainTooLong();

    // ---------- writes, each authorised by an SLH-DSA signature ----------

    /// Registers `vk`. The signature is a proof of possession of the secret key.
    function register(bytes32 vk, bytes32 label, bytes calldata sig) external {
        if (vk == 0) revert ZeroValue();
        if (keys[vk].status != Status.Unknown) revert KeyExists();
        _verify(vk, registerDigest(vk, label), sig);
        keys[vk] = Key(Status.Active, uint64(block.timestamp), 0, 0, label);
        emit KeyRegistered(vk, label);
    }

    /// Attests a 32-byte subject, for example the SHA-256 of a release file.
    function attest(bytes32 vk, bytes32 subject, string calldata uri, bytes calldata sig) external {
        bytes32 uriHash = bytes(uri).length == 0 ? bytes32(0) : keccak256(bytes(uri));
        _attest(attestations[vk], vk, subject, uriHash, attestDigest(vk, subject, uriHash), sig);
        emit Attested(vk, subject, uriHash, uri);
    }

    /// Attests the runtime code currently deployed at `target`, bound to its codehash. The attestation
    /// covers that bytecode wherever it is deployed, not the address: identical proxies share one
    /// codehash whatever they point to, so attest implementations, not proxies. Stored in
    /// `codeAttestations`, a mapping separate from data subjects: no data attestation, whatever its
    /// subject, can make `isCodeAttested` true.
    function attestCode(bytes32 vk, address target, bytes calldata sig) external {
        bytes32 codehash = target.codehash;
        if (target.code.length == 0) revert NoCode();
        _attest(codeAttestations[vk], vk, codehash, 0, attestCodeDigest(vk, target, codehash), sig);
        emit CodeAttested(vk, target, codehash);
    }

    /// Withdraws a data attestation, for example of a release found to be faulty.
    function retract(bytes32 vk, bytes32 subject, bytes calldata sig) external {
        _retract(attestations[vk][subject], vk, retractDigest(vk, subject), sig);
        emit Retracted(vk, subject);
    }

    /// Withdraws a code attestation.
    function retractCode(bytes32 vk, bytes32 codehash, bytes calldata sig) external {
        _retract(codeAttestations[vk][codehash], vk, retractCodeDigest(vk, codehash), sig);
        emit CodeRetracted(vk, codehash);
    }

    /// Hands over to `successor`. Past attestations stay valid; the old key cannot attest again.
    /// Both keys sign, so the successor is proven to be held by the same publisher. Revoking a key
    /// later does not revoke its successor: a publisher who loses a key must revoke every key it
    /// could have rotated to, and integrators should pin keys, not labels.
    function rotate(bytes32 vk, bytes32 successor, bytes calldata sig, bytes calldata successorSig) external {
        if (keys[vk].status != Status.Active) revert KeyNotActive();
        if (successor == 0) revert ZeroValue();
        if (keys[successor].status != Status.Unknown) revert KeyExists();
        bytes32 digest = rotateDigest(vk, successor);
        _verify(vk, digest, sig);
        _verify(successor, digest, successorSig);
        Key storage k = keys[vk];
        k.status = Status.Rotated;
        k.closedAt = uint64(block.timestamp);
        k.successor = successor;
        keys[successor] = Key(Status.Active, uint64(block.timestamp), 0, 0, k.label);
        emit KeyRotated(vk, successor);
        emit KeyRegistered(successor, k.label);
    }

    /// Revokes `vk` as compromised: all its attestations stop being valid, including those made
    /// before a rotation. A rotated key keeps this power, so retired secret keys must stay secret.
    function revoke(bytes32 vk, bytes calldata sig) external {
        Key storage k = keys[vk];
        if (k.status == Status.Unknown || k.status == Status.Revoked) revert KeyNotActive();
        _verify(vk, revokeDigest(vk), sig);
        k.status = Status.Revoked;
        k.closedAt = uint64(block.timestamp);
        emit KeyRevoked(vk);
    }

    // ---------- views ----------

    /// True if `vk` attested the data `subject`, has not retracted it and has not been revoked.
    function isAttested(bytes32 vk, bytes32 subject) external view returns (bool) {
        return _valid(vk, attestations[vk][subject]);
    }

    /// True if the code currently at `target` is attested by `vk`, not retracted, `vk` not revoked.
    function isCodeAttested(bytes32 vk, address target) external view returns (bool) {
        return target.code.length != 0 && _valid(vk, codeAttestations[vk][target.codehash]);
    }

    /// Follows rotations from `vk` to the last key of the chain, which may be Revoked: callers check
    /// its status. Reverts after 64 hops instead of returning a key that is not the end.
    function currentKey(bytes32 vk) external view returns (bytes32) {
        for (uint256 i = 0; i < 64; i++) {
            if (keys[vk].status != Status.Rotated) return vk;
            vk = keys[vk].successor;
        }
        if (keys[vk].status == Status.Rotated) revert ChainTooLong();
        return vk;
    }

    // Digests: the exact 32 bytes the key signs. Bound to this chain and this contract.

    function registerDigest(bytes32 vk, bytes32 label) public view returns (bytes32) {
        return keccak256(abi.encode("PQP/register", block.chainid, address(this), vk, label));
    }

    function attestDigest(bytes32 vk, bytes32 subject, bytes32 uriHash) public view returns (bytes32) {
        return keccak256(abi.encode("PQP/attest", block.chainid, address(this), vk, subject, uriHash));
    }

    function attestCodeDigest(bytes32 vk, address target, bytes32 codehash) public view returns (bytes32) {
        return keccak256(abi.encode("PQP/attest-code", block.chainid, address(this), vk, target, codehash));
    }

    function retractDigest(bytes32 vk, bytes32 subject) public view returns (bytes32) {
        return keccak256(abi.encode("PQP/retract", block.chainid, address(this), vk, subject));
    }

    function retractCodeDigest(bytes32 vk, bytes32 codehash) public view returns (bytes32) {
        return keccak256(abi.encode("PQP/retract-code", block.chainid, address(this), vk, codehash));
    }

    function rotateDigest(bytes32 vk, bytes32 successor) public view returns (bytes32) {
        return keccak256(abi.encode("PQP/rotate", block.chainid, address(this), vk, successor));
    }

    function revokeDigest(bytes32 vk) public view returns (bytes32) {
        return keccak256(abi.encode("PQP/revoke", block.chainid, address(this), vk));
    }

    // ---------- internals ----------

    function _attest(
        mapping(bytes32 => Attestation) storage book,
        bytes32 vk,
        bytes32 subject,
        bytes32 uriHash,
        bytes32 digest,
        bytes calldata sig
    ) internal {
        if (keys[vk].status != Status.Active) revert KeyNotActive();
        if (book[subject].attestedAt != 0) revert AlreadyAttested();
        _verify(vk, digest, sig);
        book[subject] = Attestation(uint64(block.timestamp), 0, uriHash);
        attestationCount[vk] += 1;
    }

    function _retract(Attestation storage a, bytes32 vk, bytes32 digest, bytes calldata sig) internal {
        if (a.attestedAt == 0 || a.retractedAt != 0) revert NotAttested();
        if (keys[vk].status == Status.Revoked) revert KeyNotActive();
        _verify(vk, digest, sig);
        a.retractedAt = uint64(block.timestamp);
    }

    function _valid(bytes32 vk, Attestation storage a) internal view returns (bool) {
        return a.attestedAt != 0 && a.retractedAt == 0 && keys[vk].status != Status.Revoked;
    }

    function _verify(bytes32 vk, bytes32 digest, bytes calldata sig) internal view {
        if (sig.length != SIG_LENGTH) revert BadSignature();
        if (!VERIFIER.verifySlhDsaSha2128s(abi.encodePacked(vk), abi.encodePacked(digest), sig)) {
            revert BadSignature();
        }
    }
}
