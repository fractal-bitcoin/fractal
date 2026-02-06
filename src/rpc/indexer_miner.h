// Copyright (c) 2024 The Fractal Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_INDEXER_MINER_H
#define BITCOIN_RPC_INDEXER_MINER_H

#include <interfaces/mining.h>
#include <node/miner.h>
#include <rpc/request.h>
#include <script/script.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <univalue.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

class ChainstateManager;

/**
 * This class holds "global" state used to construct blocks for the indexer
 * mining RPCs and the map of already constructed blocks to look them up
 * in the submitindexerblock RPC.
 *
 * It is used as a singleton that is initialised during startup.
 */
class IndexerMiner
{

private:

  /** The lock used for state in this object.  */
  mutable RecursiveMutex cs;
  /** All currently "active" blocks.  */
  std::vector<std::unique_ptr<CBlock>> blocks;
  /** Maps block hashes to pointers in blocks vector.  Does not own the memory.  */
  std::map<uint256, const CBlock*> mapBlocks;
  /** Maps coinbase script hashes to pointers in blocks vector.  Does not own the memory.  */
  std::map<CScriptID, const CBlock*> curBlocks;

  /* Some data about when the current block (pblock) was constructed.  */
  unsigned txUpdatedLast;
  const CBlockIndex* pindexPrev = nullptr;
  uint64_t startTime;

  /**
   * Constructs a new current block if necessary (checking the current state to
   * see if "enough changed" for this), and returns a pointer to the block
   * that should be returned to a miner for working on at the moment.  Also
   * fills in the difficulty target value.
   */
  const CBlock* getCurrentBlock (const ChainstateManager& chainman,
                                 interfaces::Mining& miner,
                                 const CTxMemPool& mempool,
                                 const CScript& scriptPubKey, uint256& target)
      EXCLUSIVE_LOCKS_REQUIRED (cs);

  /**
   * Looks up a previously constructed block by its previous block hash (hex-encoded).
   * If the block is found, it is returned.  Otherwise, a JSONRPCError is thrown.
   */
  const CBlock* lookupSavedBlock (const std::string& prevHashHex) const
      EXCLUSIVE_LOCKS_REQUIRED (cs);

public:

  IndexerMiner () = default;

  /**
   * Performs the main work for the "createindexerblock" RPC:  Construct a new block
   * to work on with the given address for the block reward and return the
   * necessary information for the indexer to sign it.
   */
  UniValue createIndexerBlock (const JSONRPCRequest& request,
                               const CScript& scriptPubKey);

  /**
   * Performs the main work for the "submitindexerblock" RPC:  Look up the block
   * previously created for the given previousblockhash, set the time and nonce
   * found by the indexer miner, attach the given indexer proof to it and try
   * to submit it. Returns true if all was successful and the block was accepted.
   */
  bool submitIndexerBlock (const JSONRPCRequest& request,
                           const std::string& prevHashHex,
                           uint32_t nTime,
                           uint32_t nNonce,
                           const std::string& indexerProofHex) const;

  /**
   * Returns the singleton instance of IndexerMiner that is used for RPCs.
   */
  static IndexerMiner& get ();

};

#endif // BITCOIN_RPC_INDEXER_MINER_H
