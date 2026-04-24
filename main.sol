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
