// Copyright (c) 2024 The Fractal Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/indexer.h>
#include <primitives/block.h>
#include <primitives/pureheader.h>
#include <hash.h>
#include <pubkey.h>

uint16_t CIndexerProof::GetCursor(const uint256& prevBlockHash)
{
    // Use the last 2 bytes of the previous block hash as cursor
    const unsigned char* data = prevBlockHash.begin();
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

uint256 CIndexerProof::GetProofOfWorkHash(const CPureBlockHeader& header) const
{
    // Hash for PoW verification: hash(hotPubKey || blockheader)
    // This design prevents ASIC mining by requiring the block header in the hash calculation.
    // The hotPubKey binds the PoW work to a specific hot wallet.
    // Authorization parameters (nAuthTimestamp, nRangeStart, nRangeEnd) are already
    // verified through the cold wallet signature, so they don't need to be in the PoW hash.
    HashWriter ss{};
    ss << hotPubKey;
    ss << header;  // CPureBlockHeader is 80 bytes
    return ss.GetHash();
}

bool CIndexerProof::IsCursorInRange(uint16_t cursor) const
{
    // Check if cursor is in range [nRangeStart, nRangeEnd] (both inclusive)
    // Requires nRangeStart <= nRangeEnd
    return cursor >= nRangeStart && cursor <= nRangeEnd;
}

uint256 CIndexerProof::GetColdSignatureHash() const
{
    // Message: hotPubKey || nAuthTimestamp || nRangeStart || nRangeEnd
    HashWriter ss{};
    ss << hotPubKey;
    ss << nAuthTimestamp;
    ss << nRangeStart;
    ss << nRangeEnd;
    return ss.GetHash();
}

bool CIndexerProof::VerifyColdSignature(const XOnlyPubKey& coldPubKey) const
{
    uint256 hash = GetColdSignatureHash();
    return coldPubKey.VerifySchnorr(hash, coldSignature);
}

bool CIndexerProof::VerifyHotSignature(const uint256& blockHash) const
{
    return hotPubKey.VerifySchnorr(blockHash, hotSignature);
}

std::unique_ptr<CIndexerProof>
CIndexerProof::createIndexerProof(const CPureBlockHeader& header)
{
    assert(header.IsIndexer());

    // Create a minimal CIndexerProof object with default/null values.
    // The actual values (pubkeys, signatures, range) should be filled in later.
    std::unique_ptr<CIndexerProof> proof(new CIndexerProof());
    // proof is already initialized with SetNull() via the constructor

    return proof;
}

CIndexerProof&
CIndexerProof::initIndexerProof(CBlockHeader& header)
{
    // Set auxpow version flag and INDEXER_CHAIN_ID on the header.
    // This must be done before we create the proof since the block hash
    // may be used later.
    header.SetAuxpowVersion(true);
    header.SetChainId(CPureBlockHeader::INDEXER_CHAIN_ID);

    std::unique_ptr<CIndexerProof> proof = createIndexerProof(header);
    CIndexerProof& result = *proof;
    header.SetIndexerProof(std::move(proof));

    return result;
}
