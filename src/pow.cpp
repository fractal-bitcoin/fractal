// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <logging.h>
#include <primitives/block.h>
#include <uint256.h>

/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 600 seconds), and we calculate the
 * difficulty based on how far the most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or behind schedule we get, we
 * double or halve the difficulty.
 */
static uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                         const CBlockHeader *pblock,
                                         const Consensus::Params &params) noexcept {
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    const Consensus::Params::ASERTAnchor &anchorParams = params.asertAnchorParams;

    // We make no further assumptions other than the height of the prev block must be >= that of the anchor block.
    assert(anchorParams.nHeight > 0);
    assert(pindexPrev->nHeight > anchorParams.nHeight);

    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    // For nTimeDiff calculation, the timestamp of the parent to the anchor block is used,
    // as per the absolute formulation of ASERT.
    // This is somewhat counterintuitive since it is referred to as the anchor timestamp, but
    // as per the formula the timestamp of block M-1 must be used if the anchor is M.
    assert(pindexPrev->pprev != nullptr);

    uint32_t anchornBits = anchorParams.nBitsLegacy;
    int64_t nPowTargetSpacing = params.nPowTargetSpacingLegacy;
    if (pblock->IsAuxpow()) {
        anchornBits = anchorParams.nBitsAuxPow;
        nPowTargetSpacing = params.nPowTargetSpacingAuxPow;
    }
    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(anchornBits);

    // Time difference is from anchor block's timestamp
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - anchorParams.nBlockTime;
    // Height difference is from current block to anchor block
    int nHeightDiff = pindexPrev->nHeight - anchorParams.nHeight;

    int64_t nTimeStart = GetTimeMicros();
    while (pindexPrev != nullptr && pindexPrev->nHeight > anchorParams.nHeight) {
        if (pindexPrev->GetPureHeader().IsAuxpow() != pblock->IsAuxpow()) {
            nHeightDiff--;
        }
        pindexPrev = pindexPrev->pprev;
    }
    int64_t nTime = GetTimeMicros();
    LogPrint(BCLog::BENCH, "GetNextASERTWorkRequired() height diff: %.2fms\n", 0.001 * (nTime - nTimeStart));

    // Do the actual target adaptation calculation in separate
    // CalculateASERT() function
    arith_uint256 nextTarget = CalculateASERT(refBlockTarget,
                                              nPowTargetSpacing,
                                              nTimeDiff,
                                              nHeightDiff,
                                              powLimit,
                                              params.nASERTHalfLife);

    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

// ASERT calculation function.
// Clamps to powLimit.
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept {

    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > 0 && refTarget <= powLimit);

    // We need some leading zero bits in powLimit in order to have room to handle
    // overflows easily. 32 leading zero bits is more than enough.
    assert((powLimit >> 224) == 0);

    // Height diff should NOT be negative.
    assert(nHeightDiff > 0);

    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from anchor block target value.

    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert( llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)) );
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff)) * 65536) / nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
    // The truncated exponent tells us how many shifts we need to do
    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unpecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    // Now we compute an approximated target * 2^(exponent/65536.0)

    // First decompose exponent into 'integer' and 'fractional' parts:
    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
    // Error versus actual 2^x is less than 0.013%.
    const uint32_t factor = 65536 + ((
        + 195766423245049ull * frac
        + 971821376ull * frac * frac
        + 5127ull * frac * frac * frac
        + (1ull << 47)
        ) >> 48);
    // this is always < 2^241 since refTarget < 2^224
    arith_uint256 nextTarget = refTarget * factor;

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0) {
        nextTarget >>= -shifts;
    } else {
        // Detect overflow that would discard high bits
        const auto nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget) {
            // If we had wider integers, the final value of nextTarget would
            // be >= 2^256 so it would have just ended up as powLimit anyway.
            nextTarget = powLimit;
        } else {
            // Shifting produced no overflow, can assign value
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0) {
        // 0 is not a valid target, but 1 is.
        nextTarget = arith_uint256(1);
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    // we return from only 1 place for copy elision
    return nextTarget;
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    assert(params.asertAnchorParams.nHeight > 0);
    if (pindexLast->nHeight <= params.asertAnchorParams.nHeight) {
        return params.asertAnchorParams.nBitsLegacy;
    }

    // Special difficulty rule for testnet
    // If the new block's timestamp is more than 2 * 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexLast->GetBlockTime() + 2 * params.nPowTargetSpacingAuxPow)) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Slow path: walk back until we find the first same version block
    const CBlockIndex *pindexPrev = pindexLast;

    while (pindexPrev->GetPureHeader().IsAuxpow() != pblock->IsAuxpow()) {
        if (pindexPrev->nHeight <= params.asertAnchorParams.nHeight) {
            if (pblock->IsAuxpow()) {
                return params.asertAnchorParams.nBitsAuxPow;
            } else {
                return params.asertAnchorParams.nBitsLegacy;
            }
        }
        pindexPrev = pindexPrev->pprev;
    }

    if (pindexPrev->nHeight <= params.asertAnchorParams.nHeight) {
        if (pblock->IsAuxpow()) {
            return params.asertAnchorParams.nBitsAuxPow;
        } else {
            return params.asertAnchorParams.nBitsLegacy;
        }
    }

    return GetNextASERTWorkRequired(pindexPrev, pblock, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
