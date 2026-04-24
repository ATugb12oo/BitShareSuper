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
