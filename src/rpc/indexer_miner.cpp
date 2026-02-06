// Copyright (c) 2026 The Fractal Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/indexer_miner.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <net.h>
#include <node/context.h>
#include <primitives/indexer.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server_util.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <cassert>

namespace
{

using interfaces::Mining;

void indexerMiningCheck(const node::NodeContext& node)
{
  const auto& connman = EnsureConnman (node);
  const auto& chainman = EnsureChainman (node);

  if (connman.GetNodeCount (ConnectionDirection::Both) == 0
        && !Params ().MineBlocksOnDemand ())
    throw JSONRPCError (RPC_CLIENT_NOT_CONNECTED,
                        "Fractal Bitcoin is not connected!");

  if (chainman.IsInitialBlockDownload ()
        && !Params ().MineBlocksOnDemand ())
    throw JSONRPCError (RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                        "Fractal Bitcoin is downloading blocks...");

  // Check if indexer blocks are enabled (nActivationHeight > 0)
  const auto& indexerParams = Params().GetConsensus().indexerParams;
  if (indexerParams.nActivationHeight <= 0)
    throw JSONRPCError (RPC_MISC_ERROR,
                        "Indexer blocks are not enabled on this network");
}

}  // anonymous namespace

const CBlock*
IndexerMiner::getCurrentBlock (const ChainstateManager& chainman, Mining& miner,
                              const CTxMemPool& mempool,
                              const CScript& scriptPubKey, uint256& target)
{
  AssertLockHeld (cs);
  const CBlock* pblockCur = nullptr;

  {
    LOCK (cs_main);
    CScriptID scriptID (scriptPubKey);
    auto iter = curBlocks.find(scriptID);
    if (iter != curBlocks.end())
      pblockCur = iter->second;

    if (pblockCur == nullptr
        || pindexPrev != chainman.ActiveChain ().Tip ()
        || (mempool.GetTransactionsUpdated () != txUpdatedLast
            && GetTime () - startTime > 60))
      {
        if (pindexPrev != chainman.ActiveChain ().Tip ())
          {
            /* Clear old blocks since they're obsolete now.  */
            blocks.clear ();
            mapBlocks.clear ();
            curBlocks.clear ();
          }

        /* Create new block with nonce = 0 and extraNonce = 1.  */
        node::BlockCreateOptions opt;
        opt.coinbase_output_script = scriptPubKey;
        opt.set_indexer = true;  // Use indexer flag for indexer blocks
        std::unique_ptr<interfaces::BlockTemplate> newTemplate
            = miner.createNewBlock (opt);
        if (newTemplate == nullptr)
          throw JSONRPCError (RPC_OUT_OF_MEMORY, "out of memory");
        blocks.push_back (std::make_unique<CBlock> (newTemplate->getBlock ()));
        CBlock& newBlock = *blocks.back ();

        /* Update state only when CreateNewBlock succeeded.  */
        txUpdatedLast = mempool.GetTransactionsUpdated ();
        pindexPrev = chainman.ActiveTip ();
        startTime = GetTime ();

        /* Finalise it by setting the version and building the merkle root.  */
        newBlock.hashMerkleRoot = BlockMerkleRoot (newBlock);
        newBlock.SetAuxpowVersion (true);
        newBlock.SetChainId (CPureBlockHeader::INDEXER_CHAIN_ID);

        /* Save in our map of constructed blocks.  */
        pblockCur = &newBlock;
        curBlocks.emplace(scriptID, pblockCur);
        mapBlocks[pblockCur->hashPrevBlock] = pblockCur;
      }
  }

  /* At this point, pblockCur is always initialised:  If we make it here
     without creating a new block above, it means that, in particular,
     pindexPrev == ::ChainActive ().Tip().  But for that to happen, we must
     already have created a pblockCur in a previous call, as pindexPrev is
     initialised only when pblockCur is.  */
  assert (pblockCur);

  arith_uint256 arithTarget;
  bool fNegative, fOverflow;
  arithTarget.SetCompact (pblockCur->nBits, &fNegative, &fOverflow);
  if (fNegative || fOverflow || arithTarget == 0)
    throw std::runtime_error ("invalid difficulty bits in block");
  target = ArithToUint256 (arithTarget);

  return pblockCur;
}

const CBlock*
IndexerMiner::lookupSavedBlock (const std::string& prevHashHex) const
{
  AssertLockHeld (cs);

  const auto hash = uint256::FromHex (prevHashHex);
  if (!hash)
    throw JSONRPCError (RPC_INVALID_PARAMETER, "invalid previousblockhash hex");

  const auto iter = mapBlocks.find (*hash);
  if (iter == mapBlocks.end ())
    throw JSONRPCError (RPC_INVALID_PARAMETER, "block with this previousblockhash unknown");

  return iter->second;
}

UniValue
IndexerMiner::createIndexerBlock (const JSONRPCRequest& request,
                                  const CScript& scriptPubKey)
{
  LOCK (cs);

  const auto& node = EnsureAnyNodeContext (request.context);
  indexerMiningCheck (node);
  const auto& mempool = EnsureMemPool (node);
  const auto& chainman = EnsureChainman (node);
  auto& mining = EnsureMining (node);

  uint256 target;
  const CBlock* pblock = getCurrentBlock (chainman, mining, mempool,
                                          scriptPubKey, target);

  // Calculate cursor from previous block hash
  uint16_t cursor = CIndexerProof::GetCursor(pblock->hashPrevBlock);

  UniValue result(UniValue::VOBJ);
  // Return all block header fields needed for PoW mining
  result.pushKV ("version", pblock->nVersion);
  result.pushKV ("previousblockhash", pblock->hashPrevBlock.GetHex ());
  result.pushKV ("merkleroot", pblock->hashMerkleRoot.GetHex ());
  result.pushKV ("time", static_cast<int64_t>(pblock->nTime));
  result.pushKV ("bits", strprintf ("%08x", pblock->nBits));
  result.pushKV ("chainid", pblock->GetChainId ());
  result.pushKV ("coinbasevalue",
                 static_cast<int64_t> (pblock->vtx[0]->vout[0].nValue));
  result.pushKV ("height", static_cast<int64_t> (pindexPrev->nHeight + 1));
  result.pushKV ("cursor", cursor);
  result.pushKV ("target", HexStr (target));

  return result;
}

bool
IndexerMiner::submitIndexerBlock (const JSONRPCRequest& request,
                                  const std::string& prevHashHex,
                                  uint32_t nTime,
                                  uint32_t nNonce,
                                  const std::string& indexerProofHex) const
{
  const auto& node = EnsureAnyNodeContext (request.context);
  indexerMiningCheck (node);
  auto& chainman = EnsureChainman (node);

  std::shared_ptr<CBlock> shared_block;
  {
    LOCK (cs);
    const CBlock* pblock = lookupSavedBlock (prevHashHex);
    shared_block = std::make_shared<CBlock> (*pblock);
  }

  // Set the time and nonce found by the indexer miner
  shared_block->nTime = nTime;
  shared_block->nNonce = nNonce;

  const std::vector<unsigned char> vchIndexerProof = ParseHex (indexerProofHex);
  DataStream ss(vchIndexerProof);
  std::unique_ptr<CIndexerProof> proof(new CIndexerProof ());
  ss >> *proof;
  shared_block->SetIndexerProof (std::move (proof));

  return chainman.ProcessNewBlock (shared_block, /*force_processing=*/true,
                                   /*min_pow_checked=*/true, nullptr);
}

IndexerMiner&
IndexerMiner::get ()
{
  static IndexerMiner* instance = nullptr;
  static RecursiveMutex lock;

  LOCK (lock);
  if (instance == nullptr)
    instance = new IndexerMiner ();

  return *instance;
}
