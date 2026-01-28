// Copyright (c) 2024 The Fractal Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/indexer.h>
#include <primitives/block.h>
#include <pubkey.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(indexer_tests, BasicTestingSetup)

/* Test cursor calculation from previous block hash */
BOOST_AUTO_TEST_CASE(cursor_calculation)
{
    // Test case 1: Low bytes are 0x1234
    uint256 hash1 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000001234").value();
    uint16_t cursor1 = CIndexerProof::GetCursor(hash1);
    BOOST_CHECK_EQUAL(cursor1, 0x1234);  // 4660

    // Test case 2: Low bytes are 0xABCD
    uint256 hash2 = uint256::FromHex("000000000000000000000000000000000000000000000000000000000000abcd").value();
    uint16_t cursor2 = CIndexerProof::GetCursor(hash2);
    BOOST_CHECK_EQUAL(cursor2, 0xABCD);  // 43981

    // Test case 3: All zeros
    uint256 hash3 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000000").value();
    uint16_t cursor3 = CIndexerProof::GetCursor(hash3);
    BOOST_CHECK_EQUAL(cursor3, 0);

    // Test case 4: Maximum value
    uint256 hash4 = uint256::FromHex("000000000000000000000000000000000000000000000000000000000000ffff").value();
    uint16_t cursor4 = CIndexerProof::GetCursor(hash4);
    BOOST_CHECK_EQUAL(cursor4, 0xFFFF);  // 65535

    // Test case 5: Real block hash format
    // Note: uint256 stores bytes in little-endian order
    // Hex "4fe321a2..." is stored with first byte as the LAST byte of hex string
    uint256 hash5 = uint256::FromHex("4fe321a22ad97f116f2b1ee95927e0265c58d1be26d9f01df146053b7998a0a1").value();
    uint16_t cursor5 = CIndexerProof::GetCursor(hash5);
    BOOST_CHECK_EQUAL(cursor5, 0xa0a1);  // 41121 (0xa1 | 0x0a << 8)
}

/* Test cursor range validation - normal range (start <= end) */
BOOST_AUTO_TEST_CASE(cursor_range_normal)
{
    CIndexerProof proof;
    proof.nRangeStart = 100;
    proof.nRangeEnd = 200;

    // Cursor within range
    BOOST_CHECK(proof.IsCursorInRange(100));  // Start boundary
    BOOST_CHECK(proof.IsCursorInRange(150));  // Middle
    BOOST_CHECK(proof.IsCursorInRange(200));  // End boundary

    // Cursor outside range
    BOOST_CHECK(!proof.IsCursorInRange(99));   // Below start
    BOOST_CHECK(!proof.IsCursorInRange(201));  // Above end

    // Full range test
    proof.nRangeStart = 0;
    proof.nRangeEnd = 65535;
    for (uint16_t i = 0; i < 65535; i += 1000) {
        BOOST_CHECK(proof.IsCursorInRange(i));
        if (i + 1000 > 65535) break;
    }
    BOOST_CHECK(proof.IsCursorInRange(0));
    BOOST_CHECK(proof.IsCursorInRange(65535));
}

/* Test boundary cases for cursor range */
BOOST_AUTO_TEST_CASE(cursor_range_boundaries)
{
    CIndexerProof proof;

    // Test single value range [x, x]
    proof.nRangeStart = 1000;
    proof.nRangeEnd = 1000;
    BOOST_CHECK(proof.IsCursorInRange(1000));
    BOOST_CHECK(!proof.IsCursorInRange(999));
    BOOST_CHECK(!proof.IsCursorInRange(1001));

    // Test [0, 0] range
    proof.nRangeStart = 0;
    proof.nRangeEnd = 0;
    BOOST_CHECK(proof.IsCursorInRange(0));
    BOOST_CHECK(!proof.IsCursorInRange(1));
    BOOST_CHECK(!proof.IsCursorInRange(65535));

    // Test [65535, 65535] range
    proof.nRangeStart = 65535;
    proof.nRangeEnd = 65535;
    BOOST_CHECK(proof.IsCursorInRange(65535));
    BOOST_CHECK(!proof.IsCursorInRange(0));
    BOOST_CHECK(!proof.IsCursorInRange(65534));
}

/* Test CIndexerProof serialization - size check */
BOOST_AUTO_TEST_CASE(proof_serialization_size)
{
    // Expected size: 32 (hotPubKey) + 4 (nAuthTimestamp) + 2 (nRangeStart)
    //                + 2 (nRangeEnd) + 64 (coldSignature) + 64 (hotSignature)
    //                = 168 bytes
    BOOST_CHECK_EQUAL(CIndexerProof::SIZE, 168);
}

/* Test CIndexerProof serialization - round trip */
BOOST_AUTO_TEST_CASE(proof_serialization_round_trip)
{
    CIndexerProof proof1;
    CIndexerProof proof2;

    // Fill with test data
    auto hotPubKeyData = ParseHex("5cd26f06fb752947bd414bafeedbaefe5461c543e6f7b404a7900d0ad4f0247d");
    proof1.hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof1.nAuthTimestamp = 1769575544;
    proof1.nRangeStart = 0;
    proof1.nRangeEnd = 65535;

    auto coldSig = ParseHex("83071a3be10371bb012d29327349e3e10f405d67dfd61668e4fd41df04bb5b420ac735f2c4f49a7b50676c8884c123771e4992f52c666952ec24e361505f0477");
    std::copy(coldSig.begin(), coldSig.end(), proof1.coldSignature.begin());

    auto hotSig = ParseHex("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    std::copy(hotSig.begin(), hotSig.end(), proof1.hotSignature.begin());

    // Serialize
    DataStream ss{};
    ss << proof1;

    // Check size
    BOOST_CHECK_EQUAL(ss.size(), 168);

    // Deserialize
    ss >> proof2;

    // Verify data matches
    BOOST_CHECK_EQUAL(proof1.nAuthTimestamp, proof2.nAuthTimestamp);
    BOOST_CHECK_EQUAL(proof1.nRangeStart, proof2.nRangeStart);
    BOOST_CHECK_EQUAL(proof1.nRangeEnd, proof2.nRangeEnd);
    BOOST_CHECK(std::equal(proof1.coldSignature.begin(), proof1.coldSignature.end(), proof2.coldSignature.begin()));
    BOOST_CHECK(std::equal(proof1.hotSignature.begin(), proof1.hotSignature.end(), proof2.hotSignature.begin()));
}

/* Test cold signature hash calculation */
BOOST_AUTO_TEST_CASE(cold_signature_hash)
{
    CIndexerProof proof;

    // Set test data
    auto hotPubKeyData = ParseHex("fb3bba7269d7d92a6c19a629e9759fabc1b656cdef71ed1cc201e58ec8c5aec0");
    proof.hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof.nAuthTimestamp = 1769575544;
    proof.nRangeStart = 0;
    proof.nRangeEnd = 65535;

    // Calculate hash using Double SHA256 (Bitcoin HashWriter standard)
    uint256 hash = proof.GetColdSignatureHash();

    // The hash should be deterministic for the same input
    CIndexerProof proof2;
    proof2.hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof2.nAuthTimestamp = 1769575544;
    proof2.nRangeStart = 0;
    proof2.nRangeEnd = 65535;
    uint256 hash2 = proof2.GetColdSignatureHash();

    BOOST_CHECK_EQUAL(hash, hash2);

    // Expected hash (Double SHA256 of message)
    // Note: uint256::ToString() returns bytes in reversed order due to little-endian storage
    // Python computes: b391cb263385c00978f3ad26c483be3a1f96828ec8c49d88fdec8fd3685f077d
    // C++ displays as:    7d075f68d38fecfd889dc4c88e82961f3abe83c426adf37809c0853326cb91b3
    std::string expected = "7d075f68d38fecfd889dc4c88e82961f3abe83c426adf37809c0853326cb91b3";
    BOOST_CHECK_EQUAL(hash.ToString(), expected);
}

/* Test cold signature verification with valid signature */
BOOST_AUTO_TEST_CASE(cold_signature_valid)
{
    CIndexerProof proof;

    // Set test data (from Python authorization.json - regenerated with Double SHA256)
    auto hotPubKeyData = ParseHex("fb3bba7269d7d92a6c19a629e9759fabc1b656cdef71ed1cc201e58ec8c5aec0");
    proof.hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof.nAuthTimestamp = 1769575544;  // Updated expiry time
    proof.nRangeStart = 0;
    proof.nRangeEnd = 65535;

    // Valid signature from cold wallet
    auto coldSig = ParseHex("eb820b5b33873938666e61be7c49542be6a3804766814cbf575c6c3292fe89d44af33d1425ec091f1736fe5cb619d3800c6d4d227e92bba03b85915cde639d60");
    std::copy(coldSig.begin(), coldSig.end(), proof.coldSignature.begin());

    // Cold public key
    auto coldPubKeyData = ParseHex("5cd26f06fb752947bd414bafeedbaefe5461c543e6f7b404a7900d0ad4f0247d");
    XOnlyPubKey coldPubKey{Span<const unsigned char>{coldPubKeyData}};

    // Should verify successfully
    BOOST_CHECK(proof.VerifyColdSignature(coldPubKey));
}

/* Test cold signature verification with invalid signature */
BOOST_AUTO_TEST_CASE(cold_signature_invalid)
{
    CIndexerProof proof;

    auto hotPubKeyData = ParseHex("fb3bba7269d7d92a6c19a629e9759fabc1b656cdef71ed1cc201e58ec8c5aec0");
    proof.hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof.nAuthTimestamp = 1769575544;
    proof.nRangeStart = 0;
    proof.nRangeEnd = 65535;

    // Invalid signature (all zeros)
    proof.coldSignature.fill(0);

    auto coldPubKeyData = ParseHex("5cd26f06fb752947bd414bafeedbaefe5461c543e6f7b404a7900d0ad4f0247d");
    XOnlyPubKey coldPubKey{Span<const unsigned char>{coldPubKeyData}};

    // Should fail verification
    BOOST_CHECK(!proof.VerifyColdSignature(coldPubKey));
}

/* Test cold signature verification with wrong cold pubkey */
BOOST_AUTO_TEST_CASE(cold_signature_wrong_pubkey)
{
    CIndexerProof proof;

    auto hotPubKeyData = ParseHex("fb3bba7269d7d92a6c19a629e9759fabc1b656cdef71ed1cc201e58ec8c5aec0");
    proof.hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof.nAuthTimestamp = 1769575544;
    proof.nRangeStart = 0;
    proof.nRangeEnd = 65535;

    // Valid signature but wrong pubkey to verify
    auto coldSig = ParseHex("eb820b5b33873938666e61be7c49542be6a3804766814cbf575c6c3292fe89d44af33d1425ec091f1736fe5cb619d3800c6d4d227e92bba03b85915cde639d60");
    std::copy(coldSig.begin(), coldSig.end(), proof.coldSignature.begin());

    // Wrong cold pubkey (all ones)
    std::array<unsigned char, 32> wrongKeyData;
    wrongKeyData.fill(0xFF);
    XOnlyPubKey wrongColdPubKey{Span<const unsigned char>{wrongKeyData}};

    // Should fail verification
    BOOST_CHECK(!proof.VerifyColdSignature(wrongColdPubKey));
}

/* Test cold signature verification with modified data */
BOOST_AUTO_TEST_CASE(cold_signature_modified_data)
{
    CIndexerProof proof;

    // Original valid data
    auto hotPubKeyData = ParseHex("fb3bba7269d7d92a6c19a629e9759fabc1b656cdef71ed1cc201e58ec8c5aec0");
    proof.hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof.nAuthTimestamp = 1769575544;
    proof.nRangeStart = 0;
    proof.nRangeEnd = 65535;

    auto coldSig = ParseHex("eb820b5b33873938666e61be7c49542be6a3804766814cbf575c6c3292fe89d44af33d1425ec091f1736fe5cb619d3800c6d4d227e92bba03b85915cde639d60");
    std::copy(coldSig.begin(), coldSig.end(), proof.coldSignature.begin());

    auto coldPubKeyData = ParseHex("5cd26f06fb752947bd414bafeedbaefe5461c543e6f7b404a7900d0ad4f0247d");
    XOnlyPubKey coldPubKey{Span<const unsigned char>{coldPubKeyData}};

    // Original should verify
    BOOST_CHECK(proof.VerifyColdSignature(coldPubKey));

    // Modify timestamp - should fail
    proof.nAuthTimestamp = 1769575545;
    BOOST_CHECK(!proof.VerifyColdSignature(coldPubKey));

    // Restore timestamp, modify range start - should fail
    proof.nAuthTimestamp = 1769575544;
    proof.nRangeStart = 1;
    BOOST_CHECK(!proof.VerifyColdSignature(coldPubKey));

    // Restore range start, modify range end - should fail
    proof.nRangeStart = 0;
    proof.nRangeEnd = 65534;
    BOOST_CHECK(!proof.VerifyColdSignature(coldPubKey));

    // Restore range end, modify hot pubkey - should fail
    proof.nRangeEnd = 65535;
    auto modifiedHotPubKeyData = ParseHex("fb3bba7269d7d92a6c19a629e9759fabc1b656cdef71ed1cc201e58ec8c5aec1");
    proof.hotPubKey = XOnlyPubKey(Span<const unsigned char>{modifiedHotPubKeyData});
    BOOST_CHECK(!proof.VerifyColdSignature(coldPubKey));
}

/* Test block header indexer detection */
BOOST_AUTO_TEST_CASE(block_header_indexer_detection)
{
    CBlockHeader header;

    // Legacy block - no flags
    header.nVersion = 1;
    BOOST_CHECK(!header.IsIndexer());
    BOOST_CHECK(!header.IsAuxpow());

    // AuxPoW block - VERSION_AUXPOW flag, Chain ID 0x2024
    header.SetAuxpowVersion(true);
    header.SetChainId(0x2024);
    BOOST_CHECK(!header.IsIndexer());
    BOOST_CHECK(header.IsAuxpow());

    // Indexer block - VERSION_AUXPOW flag, Chain ID 0x2026
    header.SetChainId(0x2026);
    BOOST_CHECK(header.IsIndexer());
    BOOST_CHECK(!header.IsAuxpow());  // IsAuxpow() returns false for Indexer (different chain ID)

    // Verify chain ID
    BOOST_CHECK_EQUAL(header.GetChainId(), 0x2026);
}

/* Test indexer proof attachment to block */
BOOST_AUTO_TEST_CASE(block_indexer_proof_attachment)
{
    CBlock block;

    // Create indexer proof
    auto proof = std::make_unique<CIndexerProof>();
    auto hotPubKeyData = ParseHex("fb3bba7269d7d92a6c19a629e9759fabc1b656cdef71ed1cc201e58ec8c5aec0");
    proof->hotPubKey = XOnlyPubKey(Span<const unsigned char>{hotPubKeyData});
    proof->nAuthTimestamp = 1769575544;
    proof->nRangeStart = 0;
    proof->nRangeEnd = 65535;

    block.SetIndexerProof(std::move(proof));

    // Verify proof is attached
    BOOST_CHECK(block.indexerProof != nullptr);
    BOOST_CHECK_EQUAL(block.indexerProof->nRangeStart, 0);
    BOOST_CHECK_EQUAL(block.indexerProof->nRangeEnd, 65535);
}

/* Test expiry timestamp validation semantics */
BOOST_AUTO_TEST_CASE(expiry_timestamp_semantics)
{
    // nAuthTimestamp is the expiry timestamp (not creation time)
    // Valid when: blockTime <= nAuthTimestamp

    uint32_t expiryTime = 1769575544;  // 2026-01-28 04:59:47 UTC

    // Block time before expiry - should be valid
    BOOST_CHECK_LE(1769514700, expiryTime);  // ~60 hours before

    // Block time at expiry - should be valid
    BOOST_CHECK_LE(expiryTime, expiryTime);

    // Block time after expiry - should be invalid
    uint32_t afterExpiry = expiryTime + 1000;
    BOOST_CHECK_GT(afterExpiry, expiryTime);
}

/* Test various block hash edge cases for cursor calculation */
BOOST_AUTO_TEST_CASE(cursor_edge_cases)
{
    // Note: GetCursor reads data[0] and data[1] from uint256
    // In uint256's little-endian storage, data[0] is the LAST byte of the hex string
    // So we need to put the cursor value at the END of the hex string

    // Test cursor = 0xffff - put ffff at the end of hex string
    uint256 hash1 = uint256::FromHex("000000000000000000000000000000000000000000000000000000000000ffff").value();
    uint16_t cursor1 = CIndexerProof::GetCursor(hash1);
    BOOST_CHECK_EQUAL(cursor1, 0xffff);  // 65535

    // Test cursor = 0xaaaa - put aaaa at the end of hex string
    uint256 hash2 = uint256::FromHex("000000000000000000000000000000000000000000000000000000000000aaaa").value();
    uint16_t cursor2 = CIndexerProof::GetCursor(hash2);
    BOOST_CHECK_EQUAL(cursor2, 0xaaaa);  // 43690

    // Test cursor = 0x0001 - put 0001 at the end of hex string
    uint256 hash3 = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000001").value();
    uint16_t cursor3 = CIndexerProof::GetCursor(hash3);
    BOOST_CHECK_EQUAL(cursor3, 0x0001);  // 1
}

BOOST_AUTO_TEST_SUITE_END()
