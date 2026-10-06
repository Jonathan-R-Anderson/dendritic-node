// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AxonTLD — a minimal, working name registry for the dendritic network's `.axon` root.
///
/// This is the pragmatic, end-to-end form of the three-layer AXON naming design
/// (roadmap/axon/09-naming-registry.md): a human name under the fixed `.axon` root
/// maps, on-chain, to a Layer-1 self-certifying identity, and a resolver turns that
/// identity back into the canonical `<56-base32>.key.axon` service address the AXON
/// overlay dials. The full governed-namespace system (TLDRegistry + per-namespace
/// registrars, commit-reveal, bonds, confusable skeletons, blind-token anti-sybil)
/// is a much larger subsystem; this contract keeps the load-bearing property — the
/// name→key binding is owned and verifiable on Ethereum — in a shape that actually
/// runs today and that the node's resolver reads with a single eth_call.
///
/// A record is keyed by `node = keccak256(bytes(lowercased full name))`, e.g.
/// keccak256("ai.epin.axon"). `key` is the 32-byte Ed25519 public key that IS the
/// Layer-1 AXON identity (the resolver renders `<56-base32>.key.axon` from it).
contract AxonTLD {
    /// The fixed root suffix. Not votable (mirrors params.RootSuffix / name/const.go).
    string public constant ROOT_SUFFIX = "axon";

    struct Record {
        bytes32 key; // 32-byte Ed25519 Layer-1 identity (0 = unset)
        address owner; // Ethereum owner of the name
        uint64 updatedAt; // last change, for staleness checks
    }

    mapping(bytes32 => Record) private records; // node => record

    event Registered(bytes32 indexed node, string name, bytes32 key, address indexed owner);
    event KeySet(bytes32 indexed node, bytes32 key);
    event Transferred(bytes32 indexed node, address indexed from, address indexed to);
    event Released(bytes32 indexed node);

    error NameTaken();
    error NotOwner();
    error RootNotAllowed();

    /// Register a free name, or update the key of one you already own. Reverts if
    /// someone else holds it. First-come ownership; renewal/expiry is out of scope
    /// for this minimal registry (the governed system adds terms + bonds).
    function register(string calldata name, bytes32 key) external {
        bytes32 node = keccak256(bytes(name));
        Record storage r = records[node];
        if (r.owner != address(0) && r.owner != msg.sender) revert NameTaken();
        if (r.owner == address(0)) r.owner = msg.sender;
        r.key = key;
        r.updatedAt = uint64(block.timestamp);
        emit Registered(node, name, key, r.owner);
    }

    /// Point an owned name at a (new) Layer-1 key.
    function setKey(string calldata name, bytes32 key) external {
        bytes32 node = keccak256(bytes(name));
        if (records[node].owner != msg.sender) revert NotOwner();
        records[node].key = key;
        records[node].updatedAt = uint64(block.timestamp);
        emit KeySet(node, key);
    }

    /// Hand a name to a new owner.
    function transfer(string calldata name, address to) external {
        bytes32 node = keccak256(bytes(name));
        if (records[node].owner != msg.sender) revert NotOwner();
        address from = records[node].owner;
        records[node].owner = to;
        emit Transferred(node, from, to);
    }

    /// Give up a name entirely.
    function release(string calldata name) external {
        bytes32 node = keccak256(bytes(name));
        if (records[node].owner != msg.sender) revert NotOwner();
        delete records[node];
        emit Released(node);
    }

    /// Resolve by node hash — the single eth_call the node's resolver makes.
    function resolve(bytes32 node) external view returns (bytes32 key, address owner, uint64 updatedAt) {
        Record storage r = records[node];
        return (r.key, r.owner, r.updatedAt);
    }

    /// Convenience view for humans / CLI: resolve by the full name string.
    function resolveName(string calldata name) external view returns (bytes32 key, address owner, uint64 updatedAt) {
        Record storage r = records[keccak256(bytes(name))];
        return (r.key, r.owner, r.updatedAt);
    }

    /// The node hash for a name, so off-chain callers key records the same way.
    function nodeOf(string calldata name) external pure returns (bytes32) {
        return keccak256(bytes(name));
    }
}
