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
