// Copyright (c) 2024 The Fractal Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_INDEXER_H
#define BITCOIN_PRIMITIVES_INDEXER_H

#include <array>
#include <cstdint>
#include <memory>
#include <serialize.h>
#include <uint256.h>
#include <pubkey.h>

class CBlockHeader;
class CPureBlockHeader;

/**
 * Indexer Proof structure for Indexer blocks.
 * Total size: 168 bytes
 *
 * Indexer blocks are a third block type in Fractal Bitcoin, used to incentivize
 * providers running Bitcoin L2 inscription data indexing services.
 */
class CIndexerProof
{
public:
    /** Hot wallet x-only public key (32 bytes) */
    XOnlyPubKey hotPubKey;

    /** Authorization expiry timestamp - block time must be <= this value (4 bytes) */
    uint32_t nAuthTimestamp{0};

    /** Cursor range start (inclusive) (2 bytes) */
    uint16_t nRangeStart{0};

    /** Cursor range end (inclusive) (2 bytes) */
    uint16_t nRangeEnd{0};

    /** Cold wallet signature over (hotPubKey || nAuthTimestamp || nRangeStart || nRangeEnd) (64 bytes) */
    std::array<unsigned char, 64> coldSignature;

    /** Hot wallet signature over blockHash (64 bytes) */
    std::array<unsigned char, 64> hotSignature;

    CIndexerProof()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CIndexerProof, obj)
    {
        READWRITE(obj.hotPubKey);
        READWRITE(obj.nAuthTimestamp);
        READWRITE(obj.nRangeStart);
        READWRITE(obj.nRangeEnd);
        READWRITE(obj.coldSignature);
        READWRITE(obj.hotSignature);
    }

    void SetNull()
    {
        hotPubKey = XOnlyPubKey();
        nAuthTimestamp = 0;
        nRangeStart = 0;
        nRangeEnd = 0;
        coldSignature.fill(0);
        hotSignature.fill(0);
    }

    bool IsNull() const
    {
        return nAuthTimestamp == 0;
    }

    /**
     * Get the hash used for proof of work verification.
     * This hash is designed to prevent ASIC mining by including block header data.
     * The hotPubKey binds the PoW work to a specific hot wallet.
     * Message: hotPubKey || blockheader
     * @param header The block header (CPureBlockHeader, 80 bytes).
     * @return The 256-bit hash for PoW verification.
     */
    uint256 GetProofOfWorkHash(const CPureBlockHeader& header) const;

    /** Size of serialized proof (168 bytes) */
    static constexpr size_t SIZE = 32 + 4 + 2 + 2 + 64 + 64;

    /**
     * Calculate cursor from previous block hash.
     * The cursor determines which indexer can produce the next block.
     * @param prevBlockHash The hash of the previous block.
     * @return A 16-bit cursor value derived from the hash.
     */
    static uint16_t GetCursor(const uint256& prevBlockHash);

    /**
     * Check if the cursor is within the authorized range.
     * The range is defined as [nRangeStart, nRangeEnd], both inclusive.
     * Requires nRangeStart <= nRangeEnd.
     * @param cursor The cursor value to check.
     * @return True if cursor is in range [nRangeStart, nRangeEnd].
     */
    bool IsCursorInRange(uint16_t cursor) const;

    /**
     * Get the hash that the cold wallet signs.
     * Message: hotPubKey || nAuthTimestamp || nRangeStart || nRangeEnd
     * @return The 256-bit hash of the authorization message.
     */
    uint256 GetColdSignatureHash() const;

    /**
     * Verify the cold wallet signature.
     * @param coldPubKey The cold wallet x-only public key.
     * @return True if the cold signature is valid.
     */
    bool VerifyColdSignature(const XOnlyPubKey& coldPubKey) const;

    /**
     * Verify the hot wallet signature over the block hash.
     * @param blockHash The hash of the block being signed.
     * @return True if the hot signature is valid.
     */
    bool VerifyHotSignature(const uint256& blockHash) const;

    /**
     * Constructs a minimal CIndexerProof object for the given block header.
     * The proof is initialised with default/null values and should be filled
     * in later with the actual indexer data.
     * @param header The block header to initialise the indexer proof for.
     * @return A pointer to the created CIndexerProof object.
     */
    static std::unique_ptr<CIndexerProof> createIndexerProof(const CPureBlockHeader& header);

    /**
     * Initialises the indexer proof of the given block header. This builds a minimal
     * indexer proof object like createIndexerProof and sets it on the block header.
     * Returns a reference to the proof so it can be filled in with actual data.
     * @param header The block header to initialise.
     * @return Reference to the CIndexerProof object for filling in data.
     */
    static CIndexerProof& initIndexerProof(CBlockHeader& header);
};

#endif // BITCOIN_PRIMITIVES_INDEXER_H
