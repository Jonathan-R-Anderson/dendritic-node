// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Vote weight source for TLD governance (any ERC-20; balanceOf is the weight).
interface IVotes {
    function balanceOf(address account) external view returns (uint256);
}

/// Network-local aliases, not public DNS ownership. Reads are free; mutations pay protocol fees.
///
/// TLD admission is governed. A suffix the administrator has marked as an ICANN
/// root-zone TLD (icannSuffix) may be enabled by the administrator directly; any
/// OTHER (network-native) TLD may be enabled only by a passing token-holder vote
/// (proposeSuffix/voteSuffix/executeSuffix), which stops the namespace being
/// flooded with low-quality roots. The administrator can always DISABLE a suffix
/// (blocking new registrations) and can never seize a name or edit its records.
contract AxonTLD {
    string public constant ROOT_SUFFIX = "axon";
    uint256 public constant MAX_RECORDS = 32;
    enum Kind {
        AXON,
        A,
        AAAA,
        MX,
        DNS
    }

    struct Entry {
        uint64 id;
        Kind kind;
        uint32 ttl;
        bytes data;
    }

    struct Domain {
        address owner;
        address pending;
        address pendingFrom;
        bytes32 pendingAuthority;
        uint256 controlNonce;
        bytes32 parent;
        uint256 parentGeneration;
        bool delegated;
        uint64 updatedAt;
        uint64 nextId;
        uint64 primary;
        Entry[] entries;
    }

    struct Fees {
        uint256 registration;
        uint256 record;
        uint256 transfer;
    }
    mapping(bytes32 => Domain) private domains;
    // Kept outside Domain: release/re-registration must never revive old descendants.
    mapping(bytes32 => uint256) public generation;
    mapping(bytes32 => string[]) private childNames;
    mapping(bytes32 => bool) private enumerated;
    mapping(string => bool) public suffixEnabled;
    address public immutable beneficiary;
    address public administrator;
    address public pendingAdministrator;
    Fees public fees;
    uint256 public accrued;
    bool private withdrawing;

    // TLD governance. voteToken is the DAO's vote-weight token (0 => no DAO, so
    // only ICANN suffixes can ever be enabled). icannSuffix marks admin-asserted
    // IANA root-zone TLDs; daoApproved marks TLDs a vote has admitted.
    IVotes public immutable voteToken;
    uint256 public immutable votingPeriod;
    uint256 public immutable quorumVotes;
    mapping(string => bool) public icannSuffix;
    mapping(string => bool) public daoApproved;

    struct Proposal {
        string suffix;
        uint64 deadline;
        bool executed;
        uint256 forVotes;
        uint256 againstVotes;
        mapping(address => bool) voted;
    }
    mapping(uint256 => Proposal) private proposals;
    uint256 public proposalCount;

    event SuffixChanged(string suffix, bool enabled);
    event IcannSuffixSet(string suffix, bool icann);
    event SuffixProposed(uint256 indexed id, string suffix, uint64 deadline);
    event SuffixVoted(uint256 indexed id, address indexed voter, bool support, uint256 weight);
    event SuffixProposalExecuted(uint256 indexed id, string suffix, bool approved);
    event FeesChanged(uint256 registration, uint256 record, uint256 transfer);
    event AdministratorProposed(address indexed recipient);
    event AdministratorChanged(address indexed previous, address indexed current);
    event Registered(bytes32 indexed node, string name, bytes32 key, address indexed owner);
    event RecordChanged(bytes32 indexed node, uint64 indexed id, Kind kind, uint32 ttl, bytes data);
    event RecordRemoved(bytes32 indexed node, uint64 indexed id);
    event PrimaryChanged(bytes32 indexed node, uint64 id);
    event TransferInitiated(bytes32 indexed node, address indexed from, address indexed to);
    event Transferred(bytes32 indexed node, address indexed from, address indexed to);
    event Released(bytes32 indexed node);
    event SubdomainCreated(bytes32 indexed node, bytes32 indexed parent);
    event Withdrawn(address indexed recipient, uint256 amount);

    modifier admin() {
        require(msg.sender == administrator, "not administrator");
        _;
    }

    // Direct deployment only: original deploying wallet is both initial admin and immutable beneficiary.
    // voteToken_/votingPeriod_/quorumVotes_ configure the DAO that admits network-native TLDs; a zero
    // voteToken_ disables the DAO path entirely (only ICANN suffixes can then be enabled).
    constructor(
        uint256 registrationFee,
        uint256 recordFee,
        uint256 transferFee,
        address voteToken_,
        uint256 votingPeriod_,
        uint256 quorumVotes_
    ) {
        beneficiary = msg.sender;
        administrator = msg.sender;
        voteToken = IVotes(voteToken_);
        votingPeriod = votingPeriod_;
        quorumVotes = quorumVotes_;
        // The network's own root is built in: grandfathered, enabled, re-enable-able without a vote.
        daoApproved["axon"] = true;
        suffixEnabled["axon"] = true;
        emit SuffixChanged("axon", true);
        fees = Fees(registrationFee, recordFee, transferFee);
        emit FeesChanged(registrationFee, recordFee, transferFee);
    }

    function protocolVersion() external pure returns (uint256) { return 3; }

    // Mark (or unmark) a suffix as an ICANN root-zone TLD. Admin-asserted against the
    // IANA root zone; it only decides whether the admin may enable the suffix without a
    // DAO vote, and can never affect existing names or records.
    function markIcann(string calldata suffix, bool isIcann) external admin {
        string memory s = canonical(suffix);
        require(bytes(s).length >= 1 && bytes(s).length <= 63 && !containsDot(bytes(s)), "single TLD required");
        icannSuffix[s] = isIcann;
        emit IcannSuffixSet(s, isIcann);
    }

    // Enable requires the suffix to be ICANN (admin path) or DAO-approved; disable is
    // always the administrator's to make (it blocks new registrations only).
    function setSuffix(string calldata suffix, bool enabled) external admin {
        string memory s = canonical(suffix);
        require(bytes(s).length <= 63 && !containsDot(bytes(s)), "single TLD required");
        if (enabled) {
            require(icannSuffix[s] || daoApproved[s], "non-ICANN TLD requires DAO approval");
        }
        suffixEnabled[s] = enabled;
        emit SuffixChanged(s, enabled);
    }

    // Propose admitting a network-native (non-ICANN) TLD. Anyone may propose; token
    // holders then vote. Needs the DAO configured (voteToken != 0).
    function proposeSuffix(string calldata suffix) external returns (uint256 id) {
        require(address(voteToken) != address(0), "governance disabled");
        string memory s = canonical(suffix);
        require(bytes(s).length >= 1 && bytes(s).length <= 63 && !containsDot(bytes(s)), "single TLD required");
        require(!icannSuffix[s] && !daoApproved[s] && !suffixEnabled[s], "already available");
        id = ++proposalCount;
        Proposal storage p = proposals[id];
        p.suffix = s;
        p.deadline = uint64(block.timestamp + votingPeriod);
        emit SuffixProposed(id, s, p.deadline);
    }

    // Cast a token-weighted vote (weight = current voteToken balance; one vote per
    // address). A production DAO should snapshot weights via ERC20Votes; this reads
    // the live balance, which is adequate while that is not wired.
    function voteSuffix(uint256 id, bool support) external {
        Proposal storage p = proposals[id];
        require(p.deadline != 0 && block.timestamp < p.deadline && !p.executed, "voting closed");
        require(!p.voted[msg.sender], "already voted");
        uint256 weight = voteToken.balanceOf(msg.sender);
        require(weight > 0, "no voting weight");
        p.voted[msg.sender] = true;
        if (support) {
            p.forVotes += weight;
        } else {
            p.againstVotes += weight;
        }
        emit SuffixVoted(id, msg.sender, support, weight);
    }

    // Finalise a proposal after its deadline. Approval (quorum met and more for than
    // against) admits the suffix and enables it; anyone can execute.
    function executeSuffix(uint256 id) external {
        Proposal storage p = proposals[id];
        require(p.deadline != 0 && block.timestamp >= p.deadline && !p.executed, "not finalisable");
        p.executed = true;
        bool approved = p.forVotes >= quorumVotes && p.forVotes > p.againstVotes;
        if (approved) {
            daoApproved[p.suffix] = true;
            suffixEnabled[p.suffix] = true;
            emit SuffixChanged(p.suffix, true);
        }
        emit SuffixProposalExecuted(id, p.suffix, approved);
    }

    // Read-only proposal view (the vote map is omitted; use hasVoted).
    function proposalInfo(uint256 id)
        external
        view
        returns (string memory suffix, uint64 deadline, bool executed, uint256 forVotes, uint256 againstVotes)
    {
        Proposal storage p = proposals[id];
        return (p.suffix, p.deadline, p.executed, p.forVotes, p.againstVotes);
    }

    function hasVoted(uint256 id, address voter) external view returns (bool) {
        return proposals[id].voted[voter];
    }

    function setFees(uint256 registrationFee, uint256 recordFee, uint256 transferFee) external admin {
        fees = Fees(registrationFee, recordFee, transferFee);
        emit FeesChanged(registrationFee, recordFee, transferFee);
    }

    function proposeAdministrator(address to) external admin {
        require(to != address(0), "zero recipient");
        pendingAdministrator = to;
        emit AdministratorProposed(to);
    }

    function acceptAdministrator() external {
        require(msg.sender == pendingAdministrator, "not recipient");
        emit AdministratorChanged(administrator, msg.sender);
        administrator = msg.sender;
        pendingAdministrator = address(0);
    }

    function charge(uint256 amount) private {
        require(msg.value == amount, "exact fee required");
        accrued += amount;
    }

    function withdraw(address payable to) external {
        require(msg.sender == beneficiary && to != address(0) && !withdrawing, "withdraw denied");
        withdrawing = true;
        uint256 amount = accrued;
        accrued = 0;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "payment failed");
        withdrawing = false;
        emit Withdrawn(to, amount);
    }

    function containsDot(bytes memory b) private pure returns (bool) {
        for (uint256 i; i < b.length; ++i) {
            if (b[i] == 0x2e) return true;
        }
        return false;
    }

    /// ASCII LDH only; uppercase folded, one final dot removed, no whitespace or IDNA conversion.
    function canonical(string memory name) public pure returns (string memory) {
        return canonicalLabels(name, false);
    }

    function canonicalLabels(string memory name, bool dnsOwner) private pure returns (string memory) {
        bytes memory b = bytes(name);
        uint256 len = b.length;
        if (len > 0 && b[len - 1] == 0x2e) --len;
        require(len > 0 && len <= 253, "name length");
        bytes memory out = new bytes(len);
        uint256 label;
        for (uint256 i; i < len; ++i) {
            uint8 c = uint8(b[i]);
            if (c >= 65 && c <= 90) c += 32;
            if (c == 46) {
                require(label > 0 && out[i - 1] != 0x2d, "label boundary");
                label = 0;
            } else {
                require((c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c == 45
                    || (dnsOwner && c == 95)
                    || (dnsOwner && c == 42 && i == 0 && len > 1 && b[1] == 0x2e), "invalid label character");
                require(!(label == 0 && c == 45), "leading hyphen");
                require(++label <= 63, "label length");
            }
            out[i] = bytes1(c);
        }
        require(label > 0 && out[len - 1] != 0x2d, "label boundary");
        return string(out);
    }

    function domainName(string memory name) private pure returns (string memory n, string memory suffix) {
        n = canonicalLabels(name, true);
        bytes memory b = bytes(n);
        uint256 start;
        uint256 registrableStart;
        for (uint256 i; i < b.length; ++i) {
            if (b[i] == 0x2e) { registrableStart = start; start = i + 1; }
        }
        require(start > 0, "domain needs TLD");
        bytes memory registrable = new bytes(b.length - registrableStart);
        for (uint256 i; i < registrable.length; ++i) registrable[i] = b[registrableStart + i];
        canonical(string(registrable));
        bytes memory s = new bytes(b.length - start);
        for (uint256 i; i < s.length; ++i) {
            s[i] = b[start + i];
        }
        suffix = string(s);
        require(keccak256(bytes(canonical(suffix))) == keccak256(s), "invalid TLD");
        bytes memory reserved = bytes("key.axon");
        if (b.length >= reserved.length) {
            uint256 offset = b.length - reserved.length;
            bool equal = true;
            for (uint256 i; i < reserved.length; ++i) {
                if (b[offset + i] != reserved[i]) equal = false;
            }
            require(!(equal && (offset == 0 || b[offset - 1] == 0x2e)), "reserved namespace");
        }
    }

    function nodeOf(string memory name) public pure returns (bytes32) {
        (string memory n,) = domainName(name);
        return keccak256(bytes(n));
    }

    function owned(string memory name) private view returns (bytes32 node) {
        node = nodeOf(name);
        require(ownerOf(node) == msg.sender, "not owner");
    }

    /// Immediate parent; a second-level registration has no registrable parent.
    function parentOf(string memory name) public pure returns (bytes32) {
        (string memory n,) = domainName(name);
        bytes memory b = bytes(n);
        uint256 dots;
        uint256 first;
        for (uint256 i; i < b.length; ++i) {
            if (b[i] == 0x2e) {
                if (dots == 0) first = i;
                ++dots;
            }
        }
        if (dots == 1) return bytes32(0);
        bytes memory parent = new bytes(b.length - first - 1);
        for (uint256 i; i < parent.length; ++i) parent[i] = b[first + 1 + i];
        return keccak256(parent);
    }

    /// Inherited control until explicit two-step transfer delegates a subtree.
    /// Ancestor release invalidates descendants without an unbounded deletion loop.
    function ownerOf(bytes32 node) public view returns (address owner) {
        (owner,) = authorityOf(node);
    }

    function authorityOf(bytes32 node) private view returns (address owner, bytes32 authority) {
        bytes32 cursor = node;
        while (cursor != bytes32(0)) {
            Domain storage d = domains[cursor];
            if (d.owner == address(0)) return (address(0), bytes32(0));
            if (owner == address(0) && (d.delegated || d.parent == bytes32(0))) {
                owner = d.owner;
                authority = keccak256(abi.encode(cursor, generation[cursor], d.controlNonce));
            }
            if (d.parent != bytes32(0) && generation[d.parent] != d.parentGeneration) return (address(0), bytes32(0));
            cursor = d.parent;
        }
    }

    function touch(Domain storage d) private {
        d.updatedAt = uint64(block.timestamp);
    }

    // Includes an optional initial AXON record, priced solely at registrationFee.
    function register(string calldata name, bytes32 key) external payable {
        (string memory n, string memory suffix) = domainName(name);
        require(suffixEnabled[suffix], "suffix disabled");
        bytes32 node = keccak256(bytes(n));
        require(ownerOf(node) == address(0), "name taken");
        bytes32 parent = parentOf(n);
        if (parent != bytes32(0)) require(ownerOf(parent) == msg.sender, "not parent owner");
        charge(fees.registration);
        // This may reclaim stale storage after ancestor release; no old record survives.
        delete domains[node];
        ++generation[node];
        if (!enumerated[node]) {
            childNames[parent].push(n);
            enumerated[node] = true;
        }
        Domain storage d = domains[node];
        d.owner = msg.sender;
        d.parent = parent;
        d.parentGeneration = generation[parent];
        if (parent != bytes32(0)) emit SubdomainCreated(node, parent);
        d.nextId = 1;
        touch(d);
        if (key != bytes32(0)) put(node, 0, Kind.AXON, 300, abi.encodePacked(key));
        emit Registered(node, n, key, msg.sender);
    }

    function validate(Kind kind, uint32 ttl, bytes memory data) private pure {
        require(ttl <= 604800, "TTL exceeds week");
        if (kind == Kind.AXON) {
            require(data.length == 32 && bytes32(data) != bytes32(0), "invalid AXON key");
        } else if (kind == Kind.A) {
            require(data.length == 4, "IPv4 bytes required");
        } else if (kind == Kind.AAAA) {
            require(data.length == 16, "IPv6 bytes required");
        } else if (kind == Kind.MX) {
            require(data.length >= 3 && data.length <= 255, "MX size");
            bytes memory host = new bytes(data.length - 2);
            for (uint256 i; i < host.length; ++i) {
                host[i] = data[i + 2];
            }
            require(keccak256(bytes(canonical(string(host)))) == keccak256(host), "canonical MX host required");
        } else {
            // uint16 RR TYPE followed by uncompressed wire RDATA (RFC 3597).
            // Full type-specific/zone validation is performed by the authoritative publisher.
            require(data.length >= 2 && data.length <= 4098, "DNS payload size");
            uint16 rrtype = (uint16(uint8(data[0])) << 8) | uint16(uint8(data[1]));
            require(rrtype != 0 && rrtype != 41 && !(rrtype >= 249 && rrtype <= 255), "DNS meta type");
        }
    }

    function put(bytes32 node, uint64 id, Kind kind, uint32 ttl, bytes memory data) private returns (uint64) {
        validate(kind, ttl, data);
        Domain storage d = domains[node];
        uint256 index = d.entries.length;
        for (uint256 i; i < d.entries.length; ++i) {
            Entry storage e = d.entries[i];
            if (e.id == id) index = i;
            else require(e.kind != kind || keccak256(e.data) != keccak256(data), "duplicate record");
        }
        if (id == 0) {
            require(d.entries.length < MAX_RECORDS, "record limit");
            id = d.nextId++;
            d.entries.push(Entry(id, kind, ttl, data));
        } else {
            require(index < d.entries.length, "unknown record");
            d.entries[index] = Entry(id, kind, ttl, data);
        }
        if (d.primary == id && kind != Kind.AXON) d.primary = 0;
        if (d.primary == 0) choosePrimary(d);
        touch(d);
        emit RecordChanged(node, id, kind, ttl, data);
        return id;
    }

    function choosePrimary(Domain storage d) private {
        for (uint256 i; i < d.entries.length; ++i) {
            Entry storage e = d.entries[i];
            if (e.kind == Kind.AXON && (d.primary == 0 || e.id < d.primary)) d.primary = e.id;
        }
    }

    function setRecord(string calldata name, uint64 id, Kind kind, uint32 ttl, bytes calldata data)
        external
        payable
        returns (uint64)
    {
        bytes32 node = owned(name);
        charge(fees.record);
        return put(node, id, kind, ttl, data);
    }

    // Atomic batch; each entry costs recordFee, including updates. id=0 allocates a new stable ID.
    function setRecords(string calldata name, Entry[] calldata entries) external payable {
        bytes32 node = owned(name);
        require(entries.length > 0 && entries.length <= MAX_RECORDS, "batch size");
        charge(fees.record * entries.length);
        for (uint256 i; i < entries.length; ++i) {
            Entry calldata e = entries[i];
            put(node, e.id, e.kind, e.ttl, e.data);
        }
    }

    function setKey(string calldata name, bytes32 key) external payable {
        bytes32 node = owned(name);
        charge(fees.record);
        put(node, domains[node].primary, Kind.AXON, 300, abi.encodePacked(key));
    }

    function setPrimary(string calldata name, uint64 id) external payable {
        bytes32 node = owned(name);
        charge(fees.record);
        Domain storage d = domains[node];
        for (uint256 i; i < d.entries.length; ++i) {
            if (d.entries[i].id == id && d.entries[i].kind == Kind.AXON) {
                d.primary = id;
                touch(d);
                emit PrimaryChanged(node, id);
                return;
            }
        }
        revert("unknown AXON record");
    }

    function removeRecord(string calldata name, uint64 id) external payable {
        bytes32 node = owned(name);
        charge(fees.record);
        Domain storage d = domains[node];
        for (uint256 i; i < d.entries.length; ++i) {
            if (d.entries[i].id == id) {
                for (uint256 j = i; j + 1 < d.entries.length; ++j) {
                    d.entries[j] = d.entries[j + 1];
                }
                d.entries.pop();
                if (d.primary == id) {
                    d.primary = 0;
                    choosePrimary(d);
                }
                touch(d);
                emit RecordRemoved(node, id);
                return;
            }
        }
        revert("unknown record");
    }

    function transfer(string calldata name, address to) external payable {
        bytes32 node = owned(name);
        require(to != address(0), "zero recipient");
        charge(fees.transfer);
        domains[node].pending = to;
        domains[node].pendingFrom = msg.sender;
        (,domains[node].pendingAuthority) = authorityOf(node);
        emit TransferInitiated(node, msg.sender, to);
    }

    function cancelTransfer(string calldata name) external {
        bytes32 node = owned(name);
        domains[node].pending = address(0);
        domains[node].pendingFrom = address(0);
        domains[node].pendingAuthority = bytes32(0);
        emit TransferInitiated(node, msg.sender, address(0));
    }

    function acceptTransfer(string calldata name) external {
        bytes32 node = nodeOf(name);
        Domain storage d = domains[node];
        (address currentOwner, bytes32 authority) = authorityOf(node);
        require(currentOwner != address(0) && d.pendingFrom == currentOwner && d.pendingAuthority == authority && d.pending == msg.sender, "not recipient");
        emit Transferred(node, currentOwner, msg.sender);
        d.owner = msg.sender;
        d.delegated = true;
        ++d.controlNonce;
        d.pendingAuthority = bytes32(0);
        d.pending = address(0);
        d.pendingFrom = address(0);
        touch(d);
    }

    function release(string calldata name) external {
        bytes32 node = owned(name);
        delete domains[node];
        ++generation[node];
        emit Released(node);
    }

    /// Paginated immediate children, including historical tombstones. Check ownerOf at the same block.
    function childrenPage(bytes32 parent, uint256 offset, uint256 limit) external view returns (string[] memory page) {
        require(limit > 0 && limit <= 128, "page limit");
        string[] storage list = childNames[parent];
        if (offset >= list.length) return new string[](0);
        uint256 n = list.length - offset;
        if (n > limit) n = limit;
        page = new string[](n);
        for (uint256 i; i < n; ++i) page[i] = list[offset + i];
    }

    function pendingTransfer(bytes32 node) external view returns (address) {
        (address owner, bytes32 authority) = authorityOf(node);
        if (owner == address(0) || domains[node].pendingFrom != owner || domains[node].pendingAuthority != authority) return address(0);
        return domains[node].pending;
    }

    function resolve(bytes32 node) public view returns (bytes32 key, address owner, uint64 updatedAt) {
        owner = ownerOf(node);
        if (owner == address(0)) return (bytes32(0), address(0), 0);
        Domain storage d = domains[node];
        for (uint256 i; i < d.entries.length; ++i) {
            if (d.entries[i].id == d.primary) key = bytes32(d.entries[i].data);
        }
        return (key, owner, d.updatedAt);
    }

    function resolveName(string calldata name) external view returns (bytes32, address, uint64) {
        return resolve(nodeOf(name));
    }

    // Versioned fixed-size ABI: owner, primary-first keys, count. No ambiguous legacy-method fallback.
    function lookupAxon(bytes32 node) external view returns (address owner, bytes32[32] memory keys, uint256 count) {
        Domain storage d = domains[node];
        owner = ownerOf(node);
        if (owner == address(0)) return (owner, keys, 0);
        (bytes32 primary,,) = resolve(node);
        if (primary != 0) keys[count++] = primary;
        for (uint256 i; i < d.entries.length; ++i) {
            if (d.entries[i].kind == Kind.AXON && d.entries[i].id != d.primary) {
                keys[count++] = bytes32(d.entries[i].data);
            }
        }
    }

    function recordsPage(bytes32 node, uint256 offset, uint256 limit) external view returns (Entry[] memory page) {
        require(limit <= MAX_RECORDS, "page limit");
        if (ownerOf(node) == address(0)) return new Entry[](0);
        Domain storage d = domains[node];
        if (offset >= d.entries.length) return new Entry[](0);
        uint256 n = d.entries.length - offset;
        if (n > limit) n = limit;
        page = new Entry[](n);
        for (uint256 i; i < n; ++i) {
            page[i] = d.entries[offset + i];
        }
    }
}
