// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

void CBlockHeader::SetAuxpow (std::unique_ptr<CAuxPow> apow)
{
    if (apow != nullptr)
    {
        auxpow.reset(apow.release());
        SetAuxpowVersion(true);
        SetChainId(AUXPOW_CHAIN_ID);
    } else
    {
        auxpow.reset();
        SetAuxpowVersion(false);
    }
}

void CBlockHeader::SetIndexerProof(std::unique_ptr<CIndexerProof> proof)
{
    if (proof != nullptr)
    {
        indexerProof.reset(proof.release());
        // Set VERSION_AUXPOW flag and INDEXER_CHAIN_ID
        SetAuxpowVersion(true);
        SetChainId(INDEXER_CHAIN_ID);
    } else
    {
        indexerProof.reset();
        // Note: We don't clear the auxpow version flag here as it might be used for auxpow
    }
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
