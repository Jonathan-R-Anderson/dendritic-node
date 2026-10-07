// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title ServiceSuspension — the DAO's suspension list for self-certifying AXON
///        hidden services, keyed by the service's identity key.
///
/// Why this contract exists. The existing on-chain suspension mechanism
/// (AxonRegistry) keys on a registered DOMAIN name (a nameHash) and works by
/// zeroing that name's key so its descriptors stop validating. A bare
/// `<56 base32>.key.axon` hidden service has no registered name and no on-chain
/// domain record, so the DAO could not reach it. This registry closes that gap:
/// it records suspension state against the 32-byte ed25519 SERVICE key itself.
///
/// How it is governed. It implements the same IAxonRegistryGovernance seam that
/// AxonGovernance already drives (`prune`/`seize`/`restore(bytes32, proposalId)`),
/// so an AxonGovernance DAO instance pointed at this contract suspends a service
/// only through a passed, quorum-met proposal — the vote happens in the DAO, the
/// state lives here. For a service the three verbs mean:
///   - prune   => SUSPENDED (reversible: the network should stop routing to it)
///   - seize   => BANNED    (permanent: never restorable)
///   - restore => ACTIVE    (lifts a SUSPENDED service; a BANNED one cannot be)
///
/// How nodes read it. Nodes do NOT call this on their dial path. A policy
/// authority reads `suspendedKeys()` here (and the evidence from the matching
/// AxonGovernance proposal), publishes a signed service-policy document, and
/// every node applies it at its client dial gate. This keeps the hot path free
/// of chain reads, exactly as the rest of the overlay does.
///
/// Safety. Like AxonRegistry, nothing can be suspended until the owner wires a
/// governor with `setGovernor`; before that the list is inert. The DAO never
/// holds any key and cannot edit a service's content — it can only mark routing
/// state, which each node then honours by its own choice.
contract ServiceSuspension {
    enum ServiceState {
        ACTIVE, // never suspended, or restored
        SUSPENDED, // reversible: stop routing
        BANNED // permanent: stop routing forever
    }

    struct Record {
        ServiceState state;
        uint64 since; // block timestamp of this state
        uint256 proposalId; // the DAO proposal that set it (0 before any action)
    }

    address public owner;
    address public governor;

    mapping(bytes32 => Record) private _rec;
    mapping(bytes32 => Record[]) private _history;

    // The live set of services that are SUSPENDED or BANNED, so a policy
    // authority can enumerate exactly what to publish. A key is added when it
    // leaves ACTIVE and removed when it is restored; bounded by the number of
    // active suspensions, which a DAO keeps small.
    bytes32[] private _blocked;
    mapping(bytes32 => uint256) private _blockedIndexPlus1; // 0 = absent

    event GovernorChanged(address indexed previous, address indexed current);
    event OwnershipTransferred(address indexed previous, address indexed current);
    event Suspended(bytes32 indexed serviceKey, uint256 indexed proposalId);
    event Banned(bytes32 indexed serviceKey, uint256 indexed proposalId);
    event Restored(bytes32 indexed serviceKey, uint256 indexed proposalId);

    error NotOwner();
    error NotGovernor();
    error GovernorUnset();
    error ZeroKey();
    error AlreadyInState();
    error CannotRestoreBanned();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyGovernor() {
        if (governor == address(0)) revert GovernorUnset();
        if (msg.sender != governor) revert NotGovernor();
        _;
    }

    constructor(address owner_) {
        owner = owner_ == address(0) ? msg.sender : owner_;
        emit OwnershipTransferred(address(0), owner);
    }

    // --- administration -----------------------------------------------------

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// Wire the DAO (or a transition multisig) that may suspend. Until this is
    /// set, the list is inert — the same deliberate off-by-default as AxonRegistry.
    function setGovernor(address governor_) external onlyOwner {
        emit GovernorChanged(governor, governor_);
        governor = governor_;
    }

    // --- governed actions (IAxonRegistryGovernance) -------------------------

    /// Suspend a service (reversible). Equivalent to AxonRegistry.prune for a
    /// self-certifying service key.
    function prune(bytes32 serviceKey, uint256 proposalId) external onlyGovernor {
        if (serviceKey == bytes32(0)) revert ZeroKey();
        if (_rec[serviceKey].state == ServiceState.SUSPENDED) revert AlreadyInState();
        if (_rec[serviceKey].state == ServiceState.BANNED) revert AlreadyInState();
        _set(serviceKey, ServiceState.SUSPENDED, proposalId);
        _addBlocked(serviceKey);
        emit Suspended(serviceKey, proposalId);
    }

    /// Permanently ban a service (never restorable). Equivalent to seize.
    function seize(bytes32 serviceKey, uint256 proposalId) external onlyGovernor {
        if (serviceKey == bytes32(0)) revert ZeroKey();
        if (_rec[serviceKey].state == ServiceState.BANNED) revert AlreadyInState();
        _set(serviceKey, ServiceState.BANNED, proposalId);
        _addBlocked(serviceKey);
        emit Banned(serviceKey, proposalId);
    }

    /// Lift a suspension. A BANNED service cannot be restored.
    function restore(bytes32 serviceKey, uint256 proposalId) external onlyGovernor {
        ServiceState s = _rec[serviceKey].state;
        if (s == ServiceState.BANNED) revert CannotRestoreBanned();
        if (s == ServiceState.ACTIVE) revert AlreadyInState();
        _set(serviceKey, ServiceState.ACTIVE, proposalId);
        _removeBlocked(serviceKey);
        emit Restored(serviceKey, proposalId);
    }

    // --- views --------------------------------------------------------------

    /// True when the network should not route to the service (SUSPENDED or BANNED).
    function isSuspended(bytes32 serviceKey) external view returns (bool) {
        return _rec[serviceKey].state != ServiceState.ACTIVE;
    }

    function stateOf(bytes32 serviceKey) external view returns (ServiceState) {
        return _rec[serviceKey].state;
    }

    function recordOf(bytes32 serviceKey) external view returns (Record memory) {
        return _rec[serviceKey];
    }

    function historyOf(bytes32 serviceKey) external view returns (Record[] memory) {
        return _history[serviceKey];
    }

    /// Number of currently blocked (SUSPENDED or BANNED) services.
    function blockedCount() external view returns (uint256) {
        return _blocked.length;
    }

    function blockedAt(uint256 i) external view returns (bytes32) {
        return _blocked[i];
    }

    /// The whole live block set, for a policy authority building the signed
    /// service-policy document. Bounded by the number of active suspensions.
    function blockedKeys() external view returns (bytes32[] memory) {
        return _blocked;
    }

    // --- internals ----------------------------------------------------------

    function _set(bytes32 key, ServiceState state, uint256 proposalId) private {
        Record memory r = Record({state: state, since: uint64(block.timestamp), proposalId: proposalId});
        _rec[key] = r;
        _history[key].push(r);
    }

    function _addBlocked(bytes32 key) private {
        if (_blockedIndexPlus1[key] == 0) {
            _blocked.push(key);
            _blockedIndexPlus1[key] = _blocked.length; // 1-based
        }
    }

    function _removeBlocked(bytes32 key) private {
        uint256 idxPlus1 = _blockedIndexPlus1[key];
        if (idxPlus1 == 0) return;
        uint256 idx = idxPlus1 - 1;
        uint256 lastIdx = _blocked.length - 1;
        if (idx != lastIdx) {
            bytes32 moved = _blocked[lastIdx];
            _blocked[idx] = moved;
            _blockedIndexPlus1[moved] = idx + 1;
        }
        _blocked.pop();
        _blockedIndexPlus1[key] = 0;
    }
}
