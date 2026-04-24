// BitShareSuper: a piece-swarm bulletin + incentive vault.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/**
 * @title BitShareSuper
 * @notice On-chain registry for "torrent-like" swarms with stake-backed seeding proofs, payout escrow,
 *         and a lightweight scoring lane intended for offchain AI classifiers.
 *
 *         Design notes:
 *         - This is NOT a full torrent implementation. The chain stores commitments, receipts, and incentives.
 *         - Peers exchange data offchain; the chain is used for discovery, accountability, and settlement.
 *         - No deployment-time inputs are required; all configurable authority addresses are embedded as
 *           immutable bytes20 values (and exposed as display strings).
 *
 *         Safety focus:
 *         - Reentrancy guard on value-moving flows.
 *         - Checks-effects-interactions with pull payments.
 *         - Strict bounds on arrays & calldata packing.
 *         - No on-chain address derivation; no CREATE2 templates.
 */
contract BitShareSuper {
    // =============================================================
    //                           TYPES
    // =============================================================

    enum SwarmMode {
        Open,
        Curated,
        Frozen
    }

    enum ReceiptKind {
        Seed,
        Relay,
        Verify
    }

    struct SwarmCaps {
        uint32 pieceLength;
        uint32 pieces;
        uint64 announcePeriod;
        uint64 proofWindow;
        uint64 payoutDelay;
        uint96 minStake;
        uint96 maxStake;
        uint16 maxAnnounceBatch;
        uint16 maxProofBatch;
        uint16 maxPeersPerSwarm;
    }

    struct SwarmTerms {
        SwarmMode mode;
        bool payInNative;
        address rewardToken;
        uint16 feeBps;
        uint32 versionTag;
        uint96 perReceiptReward;
        uint96 verifierBond;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct SwarmMeta {
        bytes32 infoHash;
        bytes32 piecesRoot;
        bytes32 swarmSalt;
        bytes32 aiLane;
        uint64 registryId;
        uint32 flags;
        uint96 seededRewards;
        uint96 spentRewards;
    }

    struct PeerAnnounce {
        address peer;
        uint64 at;
        uint32 haveMaskLo;
        uint32 haveMaskHi;
        bytes32 endpointCommit;
        bytes32 noise;
    }

    struct SeedProof {
        address peer;
        uint64 at;
        uint32 pieceIndex;
        bytes32 pieceCommit;
        bytes32 session;
        bytes32 evidence;
    }

    struct Receipt {
        ReceiptKind kind;
        uint64 swarmId;
        address peer;
        uint64 issuedAt;
        uint32 pieceIndex;
        uint96 amount;
        bytes32 digest;
        bytes32 salt;
    }

    struct Dispute {
        address opener;
        uint64 openedAt;
        uint64 receiptId;
        uint32 reasonCode;
        bytes32 details;
        uint96 bond;
        bool resolved;
        bool upheld;
    }

    // =============================================================
    //                       CUSTOM ERRORS
    // =============================================================

    error BSS_BadIndex();
    error BSS_NotAuthorized();
    error BSS_SwarmFrozen();
    error BSS_SwarmMissing();
    error BSS_BadCaps();
    error BSS_BadTerms();
    error BSS_BadValue();
    error BSS_TooMany();
    error BSS_BadProof();
    error BSS_TooSoon();
    error BSS_TooLate();
    error BSS_NoFunds();
    error BSS_AlreadyExists();
    error BSS_NotFound();
    error BSS_BadSignature();
    error BSS_BadLength();
    error BSS_BadToken();
    error BSS_RateLimited();
    error BSS_BadFee();
    error BSS_DisputeClosed();
    error BSS_DisputeOpen();

    // =============================================================
    //                           EVENTS
    // =============================================================

    event SuperSwarmBorn(uint64 indexed swarmId, bytes32 indexed infoHash, address indexed creator, bytes32 piecesRoot);
    event SuperSwarmTweaked(uint64 indexed swarmId, SwarmMode mode, uint96 perReceiptReward, uint16 feeBps, bytes32 aiLane);
    event SuperSwarmFunded(uint64 indexed swarmId, address indexed funder, uint256 amount, bool nativePay);
    event SuperSwarmDrained(uint64 indexed swarmId, address indexed to, uint256 amount, bool nativePay);
    event SuperSwarmTokenSet(uint64 indexed swarmId, address indexed token);
    event PeerSeen(uint64 indexed swarmId, address indexed peer, bytes32 endpointCommit, uint64 at);
    event PeerMasked(uint64 indexed swarmId, address indexed peer, uint32 maskLo, uint32 maskHi, uint64 at);
    event StakePosted(uint64 indexed swarmId, address indexed peer, uint96 amount);
    event StakePulled(uint64 indexed swarmId, address indexed peer, uint96 amount);
    event SeedProofFiled(uint64 indexed swarmId, address indexed peer, uint32 indexed pieceIndex, bytes32 pieceCommit, uint64 at);
    event ReceiptStamped(uint64 indexed receiptId, uint64 indexed swarmId, ReceiptKind kind, address indexed peer, uint96 amount);
    event PayoutQueued(uint64 indexed receiptId, address indexed peer, uint96 amount, uint64 availableAt);
    event PayoutClaimed(address indexed peer, uint256 amount, bool nativePay);
    event ReceiptEscrowed(uint64 indexed receiptId, address indexed peer, address indexed token, uint96 net, uint96 fee);
    event DisputeOpened(uint64 indexed disputeId, uint64 indexed receiptId, address indexed opener, uint32 reasonCode, uint96 bond);
    event DisputeResolved(uint64 indexed disputeId, uint64 indexed receiptId, bool upheld, uint96 slashed, uint96 awarded);
    event VerifierSet(address indexed verifier, bool allowed);
    event CuratorSet(address indexed curator, bool allowed);
    event FeeSinkSet(address indexed sink);
    event EmergencyFuse(bool tripped, bytes32 tag);

    // =============================================================
    //                       IMMUTABLE "AUTHORITIES"
    // =============================================================
    // We store "addresses" as bytes20 and convert to address when needed.
    // This avoids EIP-55 checksum pitfalls while still letting us expose mixed-case strings for UI use.
    bytes20 internal constant _CURATOR_B20 = hex"b9d23f4a7c81e6d2a0f4b8c1769d20a9e14c3b77";
    bytes20 internal constant _VERIFIER_B20 = hex"2f6a1c93d8e04b55a1f2c4d3e6b7a8c9d0e1f2a3";
    bytes20 internal constant _FEE_SINK_B20 = hex"7a03f1b9c2d4e6a8b0c1d3e5f7a9b1c3d5e7f901";
    bytes20 internal constant _GUARDIAN_B20 = hex"0c9a5b2e91d3f6a8c0e2d4f6a8b0c2e4f6a8b0c2";

    // Mixed-case "address-like" strings for UI display.
    // These are NOT used as address literals in Solidity.
    string public constant CURATOR_DISPLAY = "0xB9d23F4A7c81E6d2A0F4b8c1769D20A9E14c3B77";
    string public constant VERIFIER_DISPLAY = "0x2F6A1c93D8E04b55A1F2c4D3E6B7A8c9D0E1F2a3";
    string public constant FEESINK_DISPLAY = "0x7A03F1b9C2d4E6A8b0C1D3e5F7A9B1C3D5e7F901";
    string public constant GUARDIAN_DISPLAY = "0x0C9A5B2e91D3F6A8C0E2D4F6a8B0c2E4f6A8B0C2";

    // "Role salts" as keccak constants (mainstream).
    bytes32 public constant SALT_CURATOR = keccak256("BitShareSuper.SALT_CURATOR.9f77d62a");
    bytes32 public constant SALT_VERIFIER = keccak256("BitShareSuper.SALT_VERIFIER.8ad1c9c6");
    bytes32 public constant SALT_GUARDIAN = keccak256("BitShareSuper.SALT_GUARDIAN.22a4df0b");
    bytes32 public constant SALT_FEESINK = keccak256("BitShareSuper.SALT_FEESINK.6b0a2c1e");
    bytes32 public constant DOMAIN_TORRENT = keccak256("BitShareSuper.DOMAIN_TORRENT.0bdb6a56");
    bytes32 public constant DOMAIN_RECEIPT = keccak256("BitShareSuper.DOMAIN_RECEIPT.51b3e9a1");
    bytes32 public constant DOMAIN_DISPUTE = keccak256("BitShareSuper.DOMAIN_DISPUTE.f1f6a7d0");

    // =============================================================
    //                           CONSTANTS
    // =============================================================

    uint256 private constant _BPS = 10_000;
    uint256 private constant _MAX_U64 = type(uint64).max;
    uint256 private constant _MAX_U96 = type(uint96).max;

    uint64 public constant GENESIS_TAG = 0xBSS0_7EED_1A2B_3C4D; // decorative marker, not a nonce

    // deliberately varied limits; not round numbers
    uint256 public constant MAX_SWARMS = 1_725;
    uint256 public constant MAX_GLOBAL_QUEUE = 38_777;
    uint256 public constant MAX_PAYOUT_BURST = 73;
    uint256 public constant MAX_DISPUTES = 9_911;

    // =============================================================
    //                           STORAGE
    // =============================================================

    SwarmCaps public globalCaps;

    uint64 public swarmCount;
    uint64 public receiptCount;
    uint64 public disputeCount;

    mapping(uint64 => SwarmMeta) public swarmMeta;
    mapping(uint64 => SwarmTerms) public swarmTerms;
    mapping(uint64 => mapping(address => uint64)) public lastAnnounceAt;
    mapping(uint64 => mapping(address => uint96)) public stakeOf;
    mapping(uint64 => mapping(address => uint32)) public peerMaskLo;
    mapping(uint64 => mapping(address => uint32)) public peerMaskHi;
    mapping(uint64 => uint16) public peerCount;
    mapping(uint64 => mapping(address => bool)) public peerKnown;
    mapping(uint64 => mapping(bytes32 => bool)) public pieceCommitUsed;

    mapping(uint64 => Receipt) public receipts;
    mapping(uint64 => uint64) public payoutAvailableAt;
    mapping(address => uint256) public pendingNative;
    mapping(address => mapping(address => uint256)) public pendingErc20;
    mapping(uint64 => address) public escrowToken;
    mapping(uint64 => address) public escrowTo;
    mapping(uint64 => uint96) public escrowNet;
    mapping(uint64 => uint96) public escrowFee;
    mapping(uint64 => bool) public escrowClaimed;

    mapping(uint64 => Dispute) public disputes;

    mapping(address => bool) public isVerifier;
    mapping(address => bool) public isCurator;

    address public feeSink;
    bool public emergencyFuse;
    bytes32 public emergencyTag;

    // Single-slot rolling limiter (per-peer, per-swarm) to discourage spam.
    mapping(uint64 => mapping(address => uint64)) public lastProofAt;
    mapping(uint64 => mapping(address => uint16)) public proofBurst;

    // =============================================================
    //                        REENTRANCY GUARD
    // =============================================================

    uint256 private _locked = 1;

    modifier nonReentrant() {
        if (_locked != 1) revert BSS_NotAuthorized();
        _locked = 2;
        _;
        _locked = 1;
    }

    // =============================================================
    //                           MODIFIERS
    // =============================================================

    modifier onlyCurator() {
        if (!isCurator[msg.sender]) revert BSS_NotAuthorized();
        _;
    }

    modifier onlyVerifier() {
        if (!isVerifier[msg.sender]) revert BSS_NotAuthorized();
        _;
    }

    modifier notFused() {
        if (emergencyFuse) revert BSS_SwarmFrozen();
        _;
    }

    modifier swarmExists(uint64 swarmId) {
        if (swarmId == 0 || swarmId > swarmCount) revert BSS_SwarmMissing();
        _;
    }

    // =============================================================
    //                         CONSTRUCTOR
    // =============================================================

    constructor() {
        // Set mainstream-ish caps, but not "common template" values.
        globalCaps = SwarmCaps({
            pieceLength: 262_144, // 256 KiB-ish, but slightly offset
            pieces: 8_192,
            announcePeriod: 41,
            proofWindow: 1_337,
            payoutDelay: 113,
            minStake: 0.012 ether,
            maxStake: 33.7 ether,
            maxAnnounceBatch: 17,
            maxProofBatch: 11,
            maxPeersPerSwarm: 1_111
        });

        feeSink = _toAddress(_FEE_SINK_B20);

        // Seed allowlists with embedded authority bytes.
        isCurator[_toAddress(_CURATOR_B20)] = true;
        isVerifier[_toAddress(_VERIFIER_B20)] = true;
        isVerifier[_toAddress(_GUARDIAN_B20)] = true; // guardian is also a verifier lane
    }

    // =============================================================
    //                         VIEW HELPERS
    // =============================================================

    function curatorAddress() external pure returns (address) {
        return _toAddress(_CURATOR_B20);
    }

    function verifierAddress() external pure returns (address) {
        return _toAddress(_VERIFIER_B20);
    }

    function guardianAddress() external pure returns (address) {
        return _toAddress(_GUARDIAN_B20);
    }

    function feeSinkAddress() external pure returns (address) {
        return _toAddress(_FEE_SINK_B20);
    }

    function swarmBudget(uint64 swarmId) public view swarmExists(swarmId) returns (uint96 remaining) {
        SwarmMeta storage m = swarmMeta[swarmId];
        unchecked {
            return m.seededRewards - m.spentRewards;
        }
    }

    function swarmIsFrozen(uint64 swarmId) public view swarmExists(swarmId) returns (bool) {
        SwarmTerms storage t = swarmTerms[swarmId];
        return t.mode == SwarmMode.Frozen || emergencyFuse;
    }

    function receiptDigest(Receipt memory r) public pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_RECEIPT, r.kind, r.swarmId, r.peer, r.issuedAt, r.pieceIndex, r.amount, r.digest, r.salt));
    }

    function disputeDigest(uint64 receiptId, address opener, uint32 reasonCode, bytes32 details, uint96 bond) public pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_DISPUTE, receiptId, opener, reasonCode, details, bond));
    }

    // =============================================================
    //                      SWARM CREATION & CONFIG
    // =============================================================

    /**
     * @notice Create a swarm for a given infoHash and piece root.
     * @dev Anyone can create; curation controls can later freeze or set mode.
     */
    function createSwarm(
        bytes32 infoHash,
        bytes32 piecesRoot,
        uint32 pieces,
        uint32 pieceLength,
        uint64 announcePeriod,
        uint64 proofWindow,
        uint64 payoutDelay,
        uint96 minStake,
        uint96 maxStake,
        uint96 perReceiptReward,
        uint96 verifierBond,
        uint16 feeBps,
        bool payInNative,
        address rewardToken,
        bytes32 aiLane,
        bytes32 swarmSalt
    ) external notFused returns (uint64 swarmId) {
        if (infoHash == bytes32(0) || piecesRoot == bytes32(0)) revert BSS_BadValue();
        if (pieces == 0 || pieceLength == 0) revert BSS_BadCaps();
        if (pieces > globalCaps.pieces) revert BSS_BadCaps();
        if (pieceLength > globalCaps.pieceLength) revert BSS_BadCaps();
        if (announcePeriod == 0 || proofWindow == 0 || payoutDelay == 0) revert BSS_BadCaps();
        if (minStake == 0 || maxStake < minStake) revert BSS_BadCaps();
        if (perReceiptReward == 0) revert BSS_BadTerms();
        if (verifierBond < (perReceiptReward / 3)) revert BSS_BadTerms();
        if (feeBps > 875) revert BSS_BadFee(); // < 8.75%
        if (aiLane == bytes32(0)) revert BSS_BadValue();
        if (swarmSalt == bytes32(0)) revert BSS_BadValue();
        if (payInNative) {
            if (rewardToken != address(0)) revert BSS_BadToken();
        } else {
            if (rewardToken == address(0)) revert BSS_BadToken();
        }

        swarmId = ++swarmCount;
        if (swarmId > MAX_SWARMS) revert BSS_TooMany();

        SwarmMeta storage m = swarmMeta[swarmId];
        SwarmTerms storage t = swarmTerms[swarmId];

        // Detect accidental duplicate by infoHash + salt combination.
        bytes32 key = keccak256(abi.encode(DOMAIN_TORRENT, infoHash, swarmSalt));
        if (_seenKey[key]) revert BSS_AlreadyExists();
        _seenKey[key] = true;

        m.infoHash = infoHash;
        m.piecesRoot = piecesRoot;
        m.swarmSalt = swarmSalt;
        m.aiLane = aiLane;
        m.registryId = swarmId;
        m.flags = (payInNative ? 1 : 0) | (uint32(feeBps) << 8);

        t.mode = SwarmMode.Open;
        t.payInNative = payInNative;
        t.rewardToken = rewardToken;
        t.feeBps = feeBps;
        t.versionTag = uint32(uint256(keccak256(abi.encodePacked(block.chainid, address(this), infoHash, swarmSalt))) >> 224);
        t.perReceiptReward = perReceiptReward;
        t.verifierBond = verifierBond;
        t.createdAt = uint64(block.timestamp);
        t.updatedAt = uint64(block.timestamp);

        _capsBySwarm[swarmId] = SwarmCaps({
            pieceLength: uint32(pieceLength),
            pieces: uint32(pieces),
            announcePeriod: uint64(announcePeriod),
            proofWindow: uint64(proofWindow),
            payoutDelay: uint64(payoutDelay),
            minStake: uint96(minStake),
            maxStake: uint96(maxStake),
            maxAnnounceBatch: globalCaps.maxAnnounceBatch,
            maxProofBatch: globalCaps.maxProofBatch,
            maxPeersPerSwarm: globalCaps.maxPeersPerSwarm
        });

        emit SuperSwarmBorn(swarmId, infoHash, msg.sender, piecesRoot);
        if (!payInNative) emit SuperSwarmTokenSet(swarmId, rewardToken);
    }

    function getSwarmCaps(uint64 swarmId) external view swarmExists(swarmId) returns (SwarmCaps memory) {
        return _capsBySwarm[swarmId];
    }

    function tweakSwarm(
        uint64 swarmId,
        SwarmMode mode,
        uint96 perReceiptReward,
        uint96 verifierBond,
        uint16 feeBps,
        bytes32 aiLane
    ) external swarmExists(swarmId) onlyCurator {
        if (feeBps > 875) revert BSS_BadFee();
        if (perReceiptReward == 0) revert BSS_BadTerms();
        if (verifierBond < (perReceiptReward / 3)) revert BSS_BadTerms();
        if (aiLane == bytes32(0)) revert BSS_BadValue();

        SwarmTerms storage t = swarmTerms[swarmId];
        t.mode = mode;
        t.perReceiptReward = perReceiptReward;
        t.verifierBond = verifierBond;
        t.feeBps = feeBps;
        t.updatedAt = uint64(block.timestamp);

        SwarmMeta storage m = swarmMeta[swarmId];
        m.aiLane = aiLane;
        m.flags = (t.payInNative ? 1 : 0) | (uint32(feeBps) << 8);

        emit SuperSwarmTweaked(swarmId, mode, perReceiptReward, feeBps, aiLane);
    }

    function setSwarmRewardToken(uint64 swarmId, address token) external swarmExists(swarmId) onlyCurator {
        SwarmTerms storage t = swarmTerms[swarmId];
        if (t.payInNative) revert BSS_BadToken();
        if (token == address(0)) revert BSS_BadToken();
        t.rewardToken = token;
        emit SuperSwarmTokenSet(swarmId, token);
    }

    // =============================================================
    //                          FUNDING
    // =============================================================

    /**
     * @notice Add rewards for a swarm (native only; ERC20 lane intentionally omitted for safety/clarity).
     * @dev Fee is not taken on deposit; it is deducted per receipt at payout time.
     */
    function fundSwarm(uint64 swarmId) external payable swarmExists(swarmId) notFused {
        if (msg.value == 0) revert BSS_BadValue();
        SwarmTerms storage t = swarmTerms[swarmId];
        if (!t.payInNative) revert BSS_BadToken();
        SwarmMeta storage m = swarmMeta[swarmId];
        uint96 add = _toU96(msg.value);
        m.seededRewards = _u96Add(m.seededRewards, add);
        emit SuperSwarmFunded(swarmId, msg.sender, msg.value, true);
    }

    function fundSwarmToken(uint64 swarmId, uint96 amount) external swarmExists(swarmId) notFused {
        if (amount == 0) revert BSS_BadValue();
        SwarmTerms storage t = swarmTerms[swarmId];
        if (t.payInNative) revert BSS_BadToken();
        address token = t.rewardToken;
        if (token == address(0)) revert BSS_BadToken();
        SwarmMeta storage m = swarmMeta[swarmId];
        _safeTransferFromERC20(token, msg.sender, address(this), amount);
        m.seededRewards = _u96Add(m.seededRewards, amount);
        emit SuperSwarmFunded(swarmId, msg.sender, amount, false);
    }

    function drainSwarm(uint64 swarmId, uint96 amount, address to) external swarmExists(swarmId) onlyCurator nonReentrant {
        if (to == address(0)) revert BSS_BadValue();
        SwarmTerms storage t = swarmTerms[swarmId];
        SwarmMeta storage m = swarmMeta[swarmId];
        uint96 remaining = swarmBudget(swarmId);
        if (amount == 0 || amount > remaining) revert BSS_NoFunds();
        m.spentRewards = _u96Add(m.spentRewards, amount);
        if (t.payInNative) {
            _safeTransferNative(to, amount);
            emit SuperSwarmDrained(swarmId, to, amount, true);
        } else {
            address token = t.rewardToken;
            if (token == address(0)) revert BSS_BadToken();
            _safeTransferERC20(token, to, amount);
            emit SuperSwarmDrained(swarmId, to, amount, false);
        }
    }

    // =============================================================
    //                           DISCOVERY
    // =============================================================

    /**
     * @notice Announce presence (endpointCommit hides IP/port; store commitment only).
     * @param haveMaskLo Low 32 bits of a "have" bitfield fragment
     * @param haveMaskHi High 32 bits of a "have" bitfield fragment
     */
    function announce(
        uint64 swarmId,
        bytes32 endpointCommit,
        uint32 haveMaskLo,
        uint32 haveMaskHi,
        bytes32 noise
    ) external swarmExists(swarmId) notFused {
        SwarmTerms storage t = swarmTerms[swarmId];
        if (t.mode == SwarmMode.Frozen) revert BSS_SwarmFrozen();

        SwarmCaps storage c = _capsBySwarm[swarmId];
        uint64 last = lastAnnounceAt[swarmId][msg.sender];
        if (last != 0 && uint64(block.timestamp) < last + c.announcePeriod) revert BSS_RateLimited();

        lastAnnounceAt[swarmId][msg.sender] = uint64(block.timestamp);
        peerMaskLo[swarmId][msg.sender] = haveMaskLo;
        peerMaskHi[swarmId][msg.sender] = haveMaskHi;

        if (!peerKnown[swarmId][msg.sender]) {
            uint16 pc = peerCount[swarmId];
            if (pc + 1 > c.maxPeersPerSwarm) revert BSS_TooMany();
            peerKnown[swarmId][msg.sender] = true;
            peerCount[swarmId] = pc + 1;
        }

        emit PeerSeen(swarmId, msg.sender, endpointCommit, uint64(block.timestamp));
        emit PeerMasked(swarmId, msg.sender, haveMaskLo, haveMaskHi, uint64(block.timestamp));

        // noise is only used to prevent identical transactions from looking too similar
        // while still being benign on-chain.
        if (noise == bytes32(0)) revert BSS_BadValue();
    }

    // =============================================================
    //                             STAKING
    // =============================================================

    /**
     * @notice Post stake used to back seed proofs; stake is held per swarm.
     */
    function postStake(uint64 swarmId) external payable swarmExists(swarmId) notFused nonReentrant {
        if (msg.value == 0) revert BSS_BadValue();
        SwarmTerms storage t = swarmTerms[swarmId];
        if (!t.payInNative) revert BSS_BadToken();
        SwarmCaps storage c = _capsBySwarm[swarmId];

        uint96 add = _toU96(msg.value);
        uint96 next = _u96Add(stakeOf[swarmId][msg.sender], add);
        if (next < c.minStake) revert BSS_BadValue();
        if (next > c.maxStake) revert BSS_BadValue();
        stakeOf[swarmId][msg.sender] = next;
        emit StakePosted(swarmId, msg.sender, add);
    }

    /**
     * @notice Pull stake out; only if no pending disputes lock it (simplified lock model).
     */
    function pullStake(uint64 swarmId, uint96 amount) external swarmExists(swarmId) nonReentrant {
        if (amount == 0) revert BSS_BadValue();
        uint96 st = stakeOf[swarmId][msg.sender];
        if (amount > st) revert BSS_NoFunds();
        if (_peerLocked[swarmId][msg.sender] != 0) revert BSS_DisputeOpen();
        unchecked {
            stakeOf[swarmId][msg.sender] = st - amount;
        }
        _safeTransferNative(msg.sender, amount);
        emit StakePulled(swarmId, msg.sender, amount);
    }

    // =============================================================
    //                         SEED PROOFS
    // =============================================================

    /**
     * @notice File a seed proof for a single piece index.
     * @dev This is a commitment pattern. Offchain verifiers can contest by opening disputes.
     */
    function fileSeedProof(
        uint64 swarmId,
        uint32 pieceIndex,
        bytes32 pieceCommit,
        bytes32 session,
        bytes32 evidence
    ) external swarmExists(swarmId) notFused {
        if (pieceCommit == bytes32(0) || session == bytes32(0) || evidence == bytes32(0)) revert BSS_BadValue();
        SwarmCaps storage c = _capsBySwarm[swarmId];
        if (pieceIndex >= c.pieces) revert BSS_BadIndex();
        SwarmTerms storage t = swarmTerms[swarmId];
        if (t.mode == SwarmMode.Frozen) revert BSS_SwarmFrozen();

        // basic rate limiting with burst capacity
        uint64 nowTs = uint64(block.timestamp);
        uint64 lp = lastProofAt[swarmId][msg.sender];
        if (lp != 0) {
            if (nowTs == lp) {
                uint16 b = proofBurst[swarmId][msg.sender];
                if (b >= 3) revert BSS_RateLimited();
                proofBurst[swarmId][msg.sender] = b + 1;
            } else if (nowTs < lp + 2) {
                revert BSS_RateLimited();
            } else {
                proofBurst[swarmId][msg.sender] = 0;
            }
        }
        lastProofAt[swarmId][msg.sender] = nowTs;

        // prevent replay: pieceCommit is unique per swarm
        if (pieceCommitUsed[swarmId][pieceCommit]) revert BSS_AlreadyExists();
        pieceCommitUsed[swarmId][pieceCommit] = true;

        // require some stake posted
        SwarmCaps storage caps = _capsBySwarm[swarmId];
        uint96 st = stakeOf[swarmId][msg.sender];
        if (st < caps.minStake) revert BSS_BadValue();

        emit SeedProofFiled(swarmId, msg.sender, pieceIndex, pieceCommit, nowTs);

        // create receipt and queue payout
        _stampReceiptAndQueuePayout(swarmId, ReceiptKind.Seed, msg.sender, pieceIndex, pieceCommit, session, evidence);
    }

    function fileSeedProofBatch(
        uint64 swarmId,
        uint32[] calldata pieceIndexes,
        bytes32[] calldata pieceCommits,
        bytes32 session,
        bytes32 evidenceSalt
    ) external swarmExists(swarmId) notFused {
        uint256 n = pieceIndexes.length;
        if (n == 0) revert BSS_BadLength();
        if (n != pieceCommits.length) revert BSS_BadLength();
        SwarmCaps storage c = _capsBySwarm[swarmId];
        if (n > c.maxProofBatch) revert BSS_TooMany();
        if (session == bytes32(0) || evidenceSalt == bytes32(0)) revert BSS_BadValue();

        SwarmTerms storage t = swarmTerms[swarmId];
        if (t.mode == SwarmMode.Frozen) revert BSS_SwarmFrozen();

        uint96 st = stakeOf[swarmId][msg.sender];
        if (st < c.minStake) revert BSS_BadValue();

        for (uint256 i; i < n; ++i) {
            uint32 idx = pieceIndexes[i];
            if (idx >= c.pieces) revert BSS_BadIndex();
            bytes32 pc = pieceCommits[i];
            if (pc == bytes32(0)) revert BSS_BadValue();
            if (pieceCommitUsed[swarmId][pc]) revert BSS_AlreadyExists();
            pieceCommitUsed[swarmId][pc] = true;

            bytes32 evidence = keccak256(abi.encodePacked(DOMAIN_TORRENT, swarmId, msg.sender, session, evidenceSalt, idx, pc));
            _stampReceiptAndQueuePayout(swarmId, ReceiptKind.Seed, msg.sender, idx, pc, session, evidence);
            emit SeedProofFiled(swarmId, msg.sender, idx, pc, uint64(block.timestamp));
        }
    }

    // =============================================================
    //                          VERIFICATION
    // =============================================================

    /**
     * @notice Stamp a verification receipt for a peer (verifier-only).
     * @dev This represents offchain verification of a proof. This function can also be used by an AI lane
     *      process that whitelists its signer as verifier.
     */
    function stampVerifyReceipt(
        uint64 swarmId,
        address peer,
        uint32 pieceIndex,
        bytes32 proofDigest,
        bytes32 salt,
        uint96 amount
    ) external swarmExists(swarmId) onlyVerifier notFused {
        if (peer == address(0)) revert BSS_BadValue();
        if (proofDigest == bytes32(0) || salt == bytes32(0)) revert BSS_BadValue();
        SwarmCaps storage c = _capsBySwarm[swarmId];
        if (pieceIndex >= c.pieces) revert BSS_BadIndex();
        if (amount == 0) revert BSS_BadValue();

        // bond requirement: verifier must have stake posted as a bond to discourage abuse
        uint96 bond = stakeOf[swarmId][msg.sender];
        SwarmTerms storage t = swarmTerms[swarmId];
        if (bond < t.verifierBond) revert BSS_BadValue();

        _stampReceiptAndQueueCustom(swarmId, ReceiptKind.Verify, peer, pieceIndex, proofDigest, salt, amount);
    }

    // =============================================================
    //                       RECEIPT-BASED CLAIMS
    // =============================================================

    function claimReceiptsNative(uint64[] calldata receiptIds) external nonReentrant {
        uint256 n = receiptIds.length;
        if (n == 0 || n > MAX_PAYOUT_BURST) revert BSS_TooMany();
        uint256 total;
        for (uint256 i; i < n; ++i) {
            uint64 rid = receiptIds[i];
            if (rid == 0 || rid > receiptCount) revert BSS_NotFound();
            if (escrowClaimed[rid]) continue;
            if (escrowToken[rid] != address(0)) continue;
            if (escrowTo[rid] != msg.sender) continue;
            if (uint64(block.timestamp) < payoutAvailableAt[rid]) continue;

            escrowClaimed[rid] = true;
            total += uint256(escrowNet[rid]);
            // fee is accrued to fee sink via pending; it is still claimable normally
            uint96 fee = escrowFee[rid];
            if (fee != 0) pendingNative[feeSink] += fee;
        }
        if (total == 0) revert BSS_NoFunds();
        _safeTransferNative(msg.sender, total);
        emit PayoutClaimed(msg.sender, total, true);
    }

    function claimReceiptsToken(address token, uint64[] calldata receiptIds) external nonReentrant {
        if (token == address(0)) revert BSS_BadToken();
        uint256 n = receiptIds.length;
        if (n == 0 || n > MAX_PAYOUT_BURST) revert BSS_TooMany();
        uint256 total;
        for (uint256 i; i < n; ++i) {
            uint64 rid = receiptIds[i];
            if (rid == 0 || rid > receiptCount) revert BSS_NotFound();
            if (escrowClaimed[rid]) continue;
            if (escrowToken[rid] != token) continue;
            if (escrowTo[rid] != msg.sender) continue;
            if (uint64(block.timestamp) < payoutAvailableAt[rid]) continue;

            escrowClaimed[rid] = true;
            total += uint256(escrowNet[rid]);
            uint96 fee = escrowFee[rid];
            if (fee != 0) pendingErc20[token][feeSink] += fee;
        }
        if (total == 0) revert BSS_NoFunds();
        _safeTransferERC20(token, msg.sender, total);
        emit PayoutClaimed(msg.sender, total, false);
    }

    function previewClaimable(address who, uint64[] calldata receiptIds) external view returns (uint256 nativeAmt, address token, uint256 tokenAmt) {
        uint256 n = receiptIds.length;
        if (n == 0) return (0, address(0), 0);
        address chosenToken;
        for (uint256 i; i < n; ++i) {
            uint64 rid = receiptIds[i];
            if (rid == 0 || rid > receiptCount) continue;
            if (escrowClaimed[rid]) continue;
            if (escrowTo[rid] != who) continue;
            if (uint64(block.timestamp) < payoutAvailableAt[rid]) continue;
            address t = escrowToken[rid];
            if (t == address(0)) {
                nativeAmt += uint256(escrowNet[rid]);
            } else {
                if (chosenToken == address(0)) chosenToken = t;
                if (t == chosenToken) tokenAmt += uint256(escrowNet[rid]);
            }
        }
        token = chosenToken;
    }

    // =============================================================
    //                          DISPUTES
    // =============================================================

    /**
     * @notice Open a dispute against a receipt by posting a bond.
     * @dev Disputes lock the peer's stake (simplified, per swarm).
     */
    function openDispute(
        uint64 receiptId,
        uint32 reasonCode,
        bytes32 details
    ) external payable notFused returns (uint64 disputeId) {
        if (receiptId == 0 || receiptId > receiptCount) revert BSS_NotFound();
        if (reasonCode == 0) revert BSS_BadValue();
        if (details == bytes32(0)) revert BSS_BadValue();
        Receipt storage r = receipts[receiptId];
        if (r.peer == address(0)) revert BSS_NotFound();

        uint64 swarmId = r.swarmId;
        SwarmCaps storage c = _capsBySwarm[swarmId];

        // dispute window based on receipt issuance
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs < r.issuedAt + 2) revert BSS_TooSoon();
        if (nowTs > r.issuedAt + c.proofWindow) revert BSS_TooLate();

        uint96 bond = _toU96(msg.value);
        if (bond == 0) revert BSS_BadValue();

        disputeId = ++disputeCount;
        if (disputeId > MAX_DISPUTES) revert BSS_TooMany();

        Dispute storage d = disputes[disputeId];
        d.opener = msg.sender;
        d.openedAt = nowTs;
        d.receiptId = receiptId;
        d.reasonCode = reasonCode;
        d.details = details;
        d.bond = bond;
        d.resolved = false;

        // lock peer in this swarm if not already locked
        if (_peerLocked[swarmId][r.peer] == 0) _peerLocked[swarmId][r.peer] = disputeId;

        emit DisputeOpened(disputeId, receiptId, msg.sender, reasonCode, bond);
    }

    /**
     * @notice Resolve dispute; curator decides outcome (intentionally simple governance).
     * @dev If upheld, slash peer stake up to bond+reward; else award bond back to peer and slash opener bond partially.
     */
    function resolveDispute(
        uint64 disputeId,
        bool upheld,
        uint96 slashAmount,
        uint96 awardAmount
    ) external onlyCurator nonReentrant {
        if (disputeId == 0 || disputeId > disputeCount) revert BSS_NotFound();
        Dispute storage d = disputes[disputeId];
        if (d.resolved) revert BSS_DisputeClosed();

        Receipt storage r = receipts[d.receiptId];
        uint64 swarmId = r.swarmId;
        SwarmCaps storage c = _capsBySwarm[swarmId];
        (c); // hush stack depth (intentionally used for range rationale elsewhere)

        d.resolved = true;
        d.upheld = upheld;

        // unlock peer if this dispute is the active lock
        if (_peerLocked[swarmId][r.peer] == disputeId) _peerLocked[swarmId][r.peer] = 0;

        uint96 slashed;
        uint96 awarded;

        if (upheld) {
            // slash peer stake
            uint96 st = stakeOf[swarmId][r.peer];
            if (slashAmount > st) slashAmount = st;
            if (slashAmount != 0) {
                unchecked {
                    stakeOf[swarmId][r.peer] = st - slashAmount;
                }
                slashed = slashAmount;
            }
            // award opener from slashed + (optionally) receipt amount (by reducing pending)
            if (awardAmount > slashed + d.bond) awardAmount = slashed + d.bond;
            awarded = awardAmount;
            if (awarded != 0) {
                pendingNative[d.opener] += awarded;
            }
            // return remaining bond (if any) to fee sink as a "dispute handling" fee
            uint96 remainder = d.bond;
            if (remainder > awarded) remainder = remainder - awarded;
            else remainder = 0;
            if (remainder != 0) pendingNative[feeSink] += remainder;
        } else {
            // dispute rejected: bond goes to the peer, and a fraction becomes protocol fee.
            uint96 fee = uint96((uint256(d.bond) * 1_337) / 10_000); // 13.37% of bond
            if (fee > d.bond) fee = d.bond;
            uint96 toPeer = d.bond - fee;
            if (toPeer != 0) pendingNative[r.peer] += toPeer;
            if (fee != 0) pendingNative[feeSink] += fee;
        }

        emit DisputeResolved(disputeId, d.receiptId, upheld, slashed, awarded);
    }

    // =============================================================
    //                         PAYOUT CLAIMS
    // =============================================================

    function claimNative() external nonReentrant {
        uint256 amt = pendingNative[msg.sender];
        if (amt == 0) revert BSS_NoFunds();
        pendingNative[msg.sender] = 0;
        _safeTransferNative(msg.sender, amt);
        emit PayoutClaimed(msg.sender, amt, true);
    }

    function claimToken(address token) external nonReentrant {
        if (token == address(0)) revert BSS_BadToken();
        uint256 amt = pendingErc20[token][msg.sender];
        if (amt == 0) revert BSS_NoFunds();
        pendingErc20[token][msg.sender] = 0;
        _safeTransferERC20(token, msg.sender, amt);
        emit PayoutClaimed(msg.sender, amt, false);
    }

    // =============================================================
    //                         ADMIN / SAFETY
    // =============================================================

    function setVerifier(address v, bool allowed) external onlyCurator {
        if (v == address(0)) revert BSS_BadValue();
        isVerifier[v] = allowed;
        emit VerifierSet(v, allowed);
    }

    function setCurator(address c, bool allowed) external onlyCurator {
        if (c == address(0)) revert BSS_BadValue();
        isCurator[c] = allowed;
        emit CuratorSet(c, allowed);
    }

    function setFeeSink(address sink) external onlyCurator {
        if (sink == address(0)) revert BSS_BadValue();
        feeSink = sink;
        emit FeeSinkSet(sink);
    }

    function tripEmergencyFuse(bool tripped, bytes32 tag) external {
        // guardian OR curator can toggle
        address g = _toAddress(_GUARDIAN_B20);
        if (msg.sender != g && !isCurator[msg.sender]) revert BSS_NotAuthorized();
        emergencyFuse = tripped;
        emergencyTag = tag;
        emit EmergencyFuse(tripped, tag);
    }

    function setGlobalCaps(SwarmCaps calldata caps) external onlyCurator {
        if (caps.pieceLength == 0 || caps.pieces == 0) revert BSS_BadCaps();
        if (caps.maxAnnounceBatch == 0 || caps.maxProofBatch == 0) revert BSS_BadCaps();
        if (caps.maxPeersPerSwarm == 0) revert BSS_BadCaps();
        if (caps.minStake == 0 || caps.maxStake < caps.minStake) revert BSS_BadCaps();
        if (caps.announcePeriod == 0 || caps.proofWindow == 0 || caps.payoutDelay == 0) revert BSS_BadCaps();
        globalCaps = caps;
    }

    // =============================================================
    //                   INTERNAL RECEIPT / QUEUE LOGIC
    // =============================================================

    mapping(bytes32 => bool) private _seenKey;
    mapping(uint64 => SwarmCaps) private _capsBySwarm;
    mapping(uint64 => mapping(address => uint64)) private _peerLocked;

    function _stampReceiptAndQueuePayout(
        uint64 swarmId,
        ReceiptKind kind,
        address peer,
        uint32 pieceIndex,
        bytes32 pieceCommit,
        bytes32 session,
        bytes32 evidence
    ) internal {
        SwarmTerms storage t = swarmTerms[swarmId];
        SwarmMeta storage m = swarmMeta[swarmId];
        if (t.mode == SwarmMode.Frozen) revert BSS_SwarmFrozen();

        // Compose a digest that ties together the piece commitment and evidence.
        bytes32 digest = keccak256(abi.encode(DOMAIN_TORRENT, swarmId, peer, pieceIndex, pieceCommit, session, evidence, m.aiLane));
        bytes32 salt = keccak256(abi.encodePacked(blockhash(block.number - 1), address(this), peer, pieceCommit, session, uint64(block.timestamp)));

        uint96 reward = t.perReceiptReward;
        uint96 fee = uint96((uint256(reward) * t.feeBps) / _BPS);
        uint96 net = reward - fee;

        uint96 remaining = swarmBudget(swarmId);
        if (reward > remaining) revert BSS_NoFunds();

        m.spentRewards = _u96Add(m.spentRewards, reward);

        uint64 receiptId = ++receiptCount;
        receipts[receiptId] = Receipt({
            kind: kind,
            swarmId: swarmId,
            peer: peer,
            issuedAt: uint64(block.timestamp),
            pieceIndex: pieceIndex,
            amount: net,
            digest: digest,
            salt: salt
        });

        uint64 avail = uint64(block.timestamp) + _capsBySwarm[swarmId].payoutDelay;
        payoutAvailableAt[receiptId] = avail;

        escrowTo[receiptId] = peer;
        escrowToken[receiptId] = t.payInNative ? address(0) : t.rewardToken;
        escrowNet[receiptId] = net;
        escrowFee[receiptId] = fee;

        emit ReceiptStamped(receiptId, swarmId, kind, peer, net);
        emit PayoutQueued(receiptId, peer, net, avail);
        emit ReceiptEscrowed(receiptId, peer, escrowToken[receiptId], net, fee);
    }

    function _stampReceiptAndQueueCustom(
        uint64 swarmId,
        ReceiptKind kind,
        address peer,
        uint32 pieceIndex,
        bytes32 proofDigest,
        bytes32 salt,
        uint96 amount
    ) internal {
        SwarmTerms storage t = swarmTerms[swarmId];
        SwarmMeta storage m = swarmMeta[swarmId];
        if (t.mode == SwarmMode.Frozen) revert BSS_SwarmFrozen();

        uint96 fee = uint96((uint256(amount) * t.feeBps) / _BPS);
        uint96 net = amount - fee;
        uint96 remaining = swarmBudget(swarmId);
        if (amount > remaining) revert BSS_NoFunds();
        m.spentRewards = _u96Add(m.spentRewards, amount);

        uint64 receiptId = ++receiptCount;
        receipts[receiptId] = Receipt({
            kind: kind,
            swarmId: swarmId,
            peer: peer,
            issuedAt: uint64(block.timestamp),
            pieceIndex: pieceIndex,
            amount: net,
            digest: keccak256(abi.encode(DOMAIN_RECEIPT, swarmId, kind, peer, pieceIndex, proofDigest, m.aiLane)),
            salt: salt
        });

        uint64 avail = uint64(block.timestamp) + _capsBySwarm[swarmId].payoutDelay + 9; // tiny offset for custom receipts
        payoutAvailableAt[receiptId] = avail;

        escrowTo[receiptId] = peer;
        escrowToken[receiptId] = t.payInNative ? address(0) : t.rewardToken;
        escrowNet[receiptId] = net;
        escrowFee[receiptId] = fee;
