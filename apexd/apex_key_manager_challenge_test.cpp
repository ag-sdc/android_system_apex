/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apex_key_manager.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/result-gmock.h>
#include <android-base/strings.h>
#include <endian.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libavb/libavb.h>
#include <sys/stat.h>

#include <atomic>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace android {
namespace apex {

namespace fs = std::filesystem;

using android::base::ReadFileToString;
using android::base::WriteStringToFile;
using android::base::testing::Ok;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::Not;

static std::string CreateRawAvbPublicKey(
    uint32_t key_num_bits, uint32_t n0inv = 0x12345678, uint8_t lsb = 0x01,
    std::optional<size_t> custom_total_length = std::nullopt,
    uint8_t fill = 0x5b) {
  size_t expected_total_size =
      sizeof(AvbRSAPublicKeyHeader) + 2 * (key_num_bits / 8);
  size_t total_size = custom_total_length.value_or(expected_total_size);
  std::string data(total_size, static_cast<char>(fill));

  if (total_size >= sizeof(AvbRSAPublicKeyHeader)) {
    AvbRSAPublicKeyHeader* header =
        reinterpret_cast<AvbRSAPublicKeyHeader*>(&data[0]);
    header->key_num_bits = htobe32(key_num_bits);
    header->n0inv = htobe32(n0inv);
  }

  if (key_num_bits > 0) {
    size_t lsb_offset = sizeof(AvbRSAPublicKeyHeader) + (key_num_bits / 8) - 1;
    if (lsb_offset < total_size) {
      data[lsb_offset] = static_cast<char>(lsb);
    }
  }
  return data;
}

class ApexKeyManagerChallengeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    product_keys_dir_ = std::string(td_.path) + "/product_keys";
    data_keys_dir_ = std::string(td_.path) + "/data_keys";
    ASSERT_EQ(0, mkdir(product_keys_dir_.c_str(), 0755));
    ASSERT_EQ(0, mkdir(data_keys_dir_.c_str(), 0755));
    ApexKeyManager::GetInstance().Reset();
  }

  void TearDown() override { ApexKeyManager::GetInstance().Reset(); }

  std::string WriteKey(const std::string& dir, const std::string& filename,
                       const std::string& key_bytes) {
    std::string path = dir + "/" + filename;
    EXPECT_TRUE(WriteStringToFile(key_bytes, path));
    return path;
  }

  std::string WritePolicyXml(const std::string& dir,
                             const std::string& content) {
    std::string path = dir + "/apex-key-policy.xml";
    EXPECT_TRUE(WriteStringToFile(content, path));
    return path;
  }

  TemporaryDir td_;
  std::string product_keys_dir_;
  std::string data_keys_dir_;
};

// =========================================================================
// SECTION 1: AVB Validation Stress Tests
// =========================================================================

// 1.1 Zero-length keys
TEST_F(ApexKeyManagerChallengeTest, AvbValidationZeroLengthKey) {
  auto res = ApexKeyManager::ValidateAvbPublicKey("");
  EXPECT_THAT(res, Not(Ok()));
  EXPECT_THAT(res.error().message(), HasSubstr("Key data too short: 0 bytes"));

  // Put a 0-byte key in directory
  WriteKey(product_keys_dir_, "zero.avbpubkey", "");
  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));
  EXPECT_EQ(0u, manager.ListKeys().size());
}

// 1.2 Corrupt headers (< 8 bytes)
TEST_F(ApexKeyManagerChallengeTest, AvbValidationCorruptHeadersLessThan8Bytes) {
  for (size_t len = 1; len < sizeof(AvbRSAPublicKeyHeader); ++len) {
    std::string bad_header(len, '\x5a');
    auto res = ApexKeyManager::ValidateAvbPublicKey(bad_header);
    EXPECT_THAT(res, Not(Ok()));
    EXPECT_THAT(res.error().message(), HasSubstr("Key data too short"));

    std::string filename = "corrupt_" + std::to_string(len) + ".avbpubkey";
    WriteKey(product_keys_dir_, filename, bad_header);
  }

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));
  EXPECT_EQ(0u, manager.ListKeys().size());
}

// 1.3 Unsupported bit lengths: 0, 512, 1024, 1536, 2047, 2049, 3072, 4095, 4097, 8191, 8193, 16384, 65536
TEST_F(ApexKeyManagerChallengeTest, AvbValidationUnsupportedBitLengths) {
  const std::vector<uint32_t> unsupported_bits = {
      0, 512, 1024, 1536, 2047, 2049, 3072, 4095, 4097, 8191, 8193, 16384, 65536};

  for (uint32_t bits : unsupported_bits) {
    std::string key = CreateRawAvbPublicKey(bits);
    auto res = ApexKeyManager::ValidateAvbPublicKey(key);
    EXPECT_THAT(res, Not(Ok())) << "Expected failure for unsupported bits: " << bits;
    EXPECT_THAT(res.error().message(), HasSubstr("Unsupported RSA key bit-length"));

    std::string filename = "bad_bits_" + std::to_string(bits) + ".avbpubkey";
    WriteKey(product_keys_dir_, filename, key);
  }

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));
  EXPECT_EQ(0u, manager.ListKeys().size());
}

// 1.4 Buffer length mismatches: truncated and trailing bytes for 2048, 4096, 8192
TEST_F(ApexKeyManagerChallengeTest, AvbValidationBufferLengthMismatches) {
  const std::vector<uint32_t> supported_bits = {2048, 4096, 8192};

  for (uint32_t bits : supported_bits) {
    size_t expected_size = sizeof(AvbRSAPublicKeyHeader) + 2 * (bits / 8);

    // Truncated by 1 byte
    std::string truncated = CreateRawAvbPublicKey(bits, 0x12345678, 0x01, expected_size - 1);
    auto res_trunc = ApexKeyManager::ValidateAvbPublicKey(truncated);
    EXPECT_THAT(res_trunc, Not(Ok()));
    EXPECT_THAT(res_trunc.error().message(), HasSubstr("Key size mismatch"));

    // Severely truncated (only 16 bytes)
    std::string severely_trunc = CreateRawAvbPublicKey(bits, 0x12345678, 0x01, 16);
    auto res_sev = ApexKeyManager::ValidateAvbPublicKey(severely_trunc);
    EXPECT_THAT(res_sev, Not(Ok()));
    EXPECT_THAT(res_sev.error().message(), HasSubstr("Key size mismatch"));

    // Trailing garbage (1 extra byte)
    std::string extra_1 = CreateRawAvbPublicKey(bits, 0x12345678, 0x01, expected_size + 1);
    auto res_extra1 = ApexKeyManager::ValidateAvbPublicKey(extra_1);
    EXPECT_THAT(res_extra1, Not(Ok()));
    EXPECT_THAT(res_extra1.error().message(), HasSubstr("Key size mismatch"));

    // Trailing garbage (128 extra bytes)
    std::string extra_128 = CreateRawAvbPublicKey(bits, 0x12345678, 0x01, expected_size + 128);
    auto res_extra128 = ApexKeyManager::ValidateAvbPublicKey(extra_128);
    EXPECT_THAT(res_extra128, Not(Ok()));
    EXPECT_THAT(res_extra128.error().message(), HasSubstr("Key size mismatch"));
  }
}

// 1.5 Even modulus check (n[0] & 1 == 0)
TEST_F(ApexKeyManagerChallengeTest, AvbValidationEvenModulus) {
  const std::vector<uint32_t> test_bits = {2048, 4096, 8192};

  for (uint32_t bits : test_bits) {
    // Even modulus LSB byte values: 0x00, 0x02, 0x5a, 0xfe
    const std::vector<uint8_t> even_lsbs = {0x00, 0x02, 0x5a, 0xfe};
    for (uint8_t lsb : even_lsbs) {
      std::string key = CreateRawAvbPublicKey(bits, 0x12345678, lsb);
      auto res = ApexKeyManager::ValidateAvbPublicKey(key);
      EXPECT_THAT(res, Not(Ok())) << "Expected failure for even modulus with LSB " << (int)lsb;
      EXPECT_THAT(res.error().message(),
                  HasSubstr("Malformed RSA modulus: least significant bit is even"));
    }

    // Odd modulus LSB byte values: 0x01, 0x03, 0x5b, 0xff
    const std::vector<uint8_t> odd_lsbs = {0x01, 0x03, 0x5b, 0xff};
    for (uint8_t lsb : odd_lsbs) {
      std::string key = CreateRawAvbPublicKey(bits, 0x12345678, lsb);
      auto res = ApexKeyManager::ValidateAvbPublicKey(key);
      ASSERT_RESULT_OK(res) << "Expected success for odd modulus with LSB " << (int)lsb;
      EXPECT_EQ(bits, *res);
    }
  }
}

// 1.6 Directory fail-safe: mixed valid and corrupt keys in product directory
TEST_F(ApexKeyManagerChallengeTest, AvbValidationFailSafeDirectoryLoading) {
  auto valid_2048 = CreateRawAvbPublicKey(2048, 0x1111, 0x01);
  auto valid_4096 = CreateRawAvbPublicKey(4096, 0x2222, 0x03);

  WriteKey(product_keys_dir_, "valid_2048.avbpubkey", valid_2048);
  WriteKey(product_keys_dir_, "valid_4096.avbpubkey", valid_4096);

  // Corrupt keys
  WriteKey(product_keys_dir_, "corrupt_zero.avbpubkey", "");
  WriteKey(product_keys_dir_, "corrupt_header.avbpubkey", "short");
  WriteKey(product_keys_dir_, "corrupt_bits.avbpubkey", CreateRawAvbPublicKey(1024));
  WriteKey(product_keys_dir_, "corrupt_trunc.avbpubkey",
           CreateRawAvbPublicKey(2048).substr(0, 300));
  WriteKey(product_keys_dir_, "corrupt_extra.avbpubkey",
           CreateRawAvbPublicKey(4096) + "trailing");
  WriteKey(product_keys_dir_, "corrupt_even.avbpubkey",
           CreateRawAvbPublicKey(2048, 0x12345678, 0x00));

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(2u, keys.size());
  EXPECT_TRUE(manager.IsKeyTrusted("com.any.pkg", valid_2048));
  EXPECT_TRUE(manager.IsKeyTrusted("com.any.pkg", valid_4096));
}

// =========================================================================
// SECTION 2: XML Policy Stress Tests
// =========================================================================

// 2.1 Malformed tags & syntax errors fail closed (skip directory with warning)
TEST_F(ApexKeyManagerChallengeTest, XmlPolicyMalformedTagsAndSyntax) {
  auto valid_key = CreateRawAvbPublicKey(4096, 0x1234, 0x01);
  WriteKey(product_keys_dir_, "valid.avbpubkey", valid_key);

  const std::vector<std::string> malformed_xmls = {
      "<key-policy><broken>",
      "<?xml version=\"1.0\"?>",  // No root element
      "<key-policy><key file=\"valid.avbpubkey\"><allow></key-policy>",
      "<wrong-root><key file=\"valid.avbpubkey\" /></wrong-root>",
      "Random garbage text not xml",
      "\x00\x01\x02\x03\xff\xfe",
  };

  for (const auto& bad_xml : malformed_xmls) {
    ApexKeyManager::GetInstance().Reset();
    WritePolicyXml(product_keys_dir_, bad_xml);

    auto& manager = ApexKeyManager::GetInstance();
    ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));
    // Fail-closed: directory is skipped, so 0 keys loaded
    EXPECT_EQ(0u, manager.ListKeys().size());
  }
}

// 2.2 Empty attributes in XML policy
TEST_F(ApexKeyManagerChallengeTest, XmlPolicyEmptyAttributes) {
  auto key1 = CreateRawAvbPublicKey(4096, 0x101, 0x01);
  auto key2 = CreateRawAvbPublicKey(4096, 0x102, 0x01);
  WriteKey(product_keys_dir_, "k1.avbpubkey", key1);
  WriteKey(product_keys_dir_, "k2.avbpubkey", key2);

  // XML with:
  // - empty file attr (should be skipped)
  // - missing file attr (should be skipped)
  // - empty name attr (stem should be used)
  // - missing name attr (stem should be used)
  // - allow with empty package attr (ignored)
  // - allow with missing package attr (ignored)
  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<key-policy>
  <key file="" name="empty_file" />
  <key name="no_file" />
  <key file="k1.avbpubkey" name="">
    <allow package="" />
    <allow />
    <allow package="com.valid.p1" />
  </key>
  <key file="k2.avbpubkey">
    <allow package="com.valid.p2" />
  </key>
</key-policy>)";

  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(2u, keys.size());

  // k1 has empty name attribute, so name is stem ("k1")
  EXPECT_EQ("k1", keys[0].name);
  EXPECT_THAT(keys[0].allowed_packages, ElementsAre("com.valid.p1"));
  EXPECT_TRUE(manager.IsKeyTrusted("com.valid.p1", key1));
  EXPECT_FALSE(manager.IsKeyTrusted("com.other.p1", key1));

  // k2 has no name attribute, so name is stem ("k2")
  EXPECT_EQ("k2", keys[1].name);
  EXPECT_THAT(keys[1].allowed_packages, ElementsAre("com.valid.p2"));
  EXPECT_TRUE(manager.IsKeyTrusted("com.valid.p2", key2));
  EXPECT_FALSE(manager.IsKeyTrusted("com.other.p2", key2));
}

// 2.3 Unclosed elements
TEST_F(ApexKeyManagerChallengeTest, XmlPolicyUnclosedElements) {
  auto key = CreateRawAvbPublicKey(4096, 0x201, 0x01);
  WriteKey(product_keys_dir_, "key.avbpubkey", key);

  std::string xml = "<key-policy><key name=\"unclosed\" file=\"key.avbpubkey\"><allow package=\"com.test\">";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));
  EXPECT_EQ(0u, manager.ListKeys().size());
}

// 2.4 Comments and formatting whitespace
TEST_F(ApexKeyManagerChallengeTest, XmlPolicyCommentsAndWhitespace) {
  auto key = CreateRawAvbPublicKey(4096, 0x301, 0x01);
  WriteKey(product_keys_dir_, "commented.avbpubkey", key);

  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<!-- Top level header comment -->
<key-policy>
  <!-- Comment before key -->
  <key name="commented-key" file="commented.avbpubkey">
    <!-- Comment inside key -->
    <allow package="com.pkg.alpha" />
    <!-- Comment between allows -->
    <allow package="com.pkg.beta" />
  </key>
  <!-- Comment after key -->
</key-policy>
<!-- Footer comment -->
)";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ("commented-key", keys[0].name);
  EXPECT_THAT(keys[0].allowed_packages, ElementsAre("com.pkg.alpha", "com.pkg.beta"));
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg.alpha", key));
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg.beta", key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.pkg.gamma", key));
}

// 2.5 CDATA blocks
TEST_F(ApexKeyManagerChallengeTest, XmlPolicyCDataSections) {
  auto key = CreateRawAvbPublicKey(4096, 0x401, 0x01);
  WriteKey(product_keys_dir_, "cdata.avbpubkey", key);

  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<key-policy>
  <![CDATA[ <random_cdata_not_a_tag> ]]>
  <key name="cdata-key" file="cdata.avbpubkey">
    <![CDATA[ arbitrary text content ]]>
    <allow package="com.cdata.pkg" />
  </key>
</key-policy>
)";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ("cdata-key", keys[0].name);
  EXPECT_THAT(keys[0].allowed_packages, ElementsAre("com.cdata.pkg"));
  EXPECT_TRUE(manager.IsKeyTrusted("com.cdata.pkg", key));
}

// 2.6 Huge inputs: 1,000 keys and 2,000 allow tags
TEST_F(ApexKeyManagerChallengeTest, XmlPolicyHugeInputs) {
  auto key = CreateRawAvbPublicKey(2048, 0x501, 0x01);
  WriteKey(product_keys_dir_, "common.avbpubkey", key);

  std::string xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<key-policy>\n";
  xml += "<key name=\"heavy-key\" file=\"common.avbpubkey\">\n";
  for (int i = 0; i < 2000; ++i) {
    xml += "  <allow package=\"com.bulk.package." + std::to_string(i) + "\" />\n";
  }
  xml += "</key>\n";

  // Add 1,000 dummy key entries pointing to nonexistent files
  for (int i = 0; i < 1000; ++i) {
    xml += "  <key name=\"dummy_" + std::to_string(i) +
           "\" file=\"dummy_" + std::to_string(i) + ".avbpubkey\">\n";
    xml += "    <allow package=\"com.dummy.pkg\" />\n";
    xml += "  </key>\n";
  }
  xml += "</key-policy>\n";

  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ("heavy-key", keys[0].name);
  EXPECT_EQ(2000u, keys[0].allowed_packages.size());

  EXPECT_TRUE(manager.IsKeyTrusted("com.bulk.package.0", key));
  EXPECT_TRUE(manager.IsKeyTrusted("com.bulk.package.1999", key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.bulk.package.2000", key));
}

// 2.7 Path traversal attempts via XML and AddKey
TEST_F(ApexKeyManagerChallengeTest, XmlPolicyPathTraversalAttempts) {
  auto valid_key = CreateRawAvbPublicKey(4096, 0x601, 0x01);
  WriteKey(product_keys_dir_, "legit.avbpubkey", valid_key);

  const std::vector<std::string> traversal_filenames = {
      "../secret.avbpubkey",
      "../../secret.avbpubkey",
      "../../../secret.avbpubkey",
      "/etc/passwd",
      "/data/apex/keys/evil.avbpubkey",
      "sub/dir.avbpubkey",
      "sub\\dir.avbpubkey",
      "..",
      ".",
      "./legit.avbpubkey",
      "valid/../legit.avbpubkey",
  };

  std::string xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<key-policy>\n";
  xml += "  <key name=\"legit\" file=\"legit.avbpubkey\"><allow package=\"com.legit\" /></key>\n";
  for (size_t i = 0; i < traversal_filenames.size(); ++i) {
    xml += "  <key name=\"traversal_" + std::to_string(i) + "\" file=\"" +
           traversal_filenames[i] + "\"><allow package=\"com.evil\" /></key>\n";
  }
  xml += "</key-policy>\n";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ("legit", keys[0].name);
  EXPECT_TRUE(manager.IsKeyTrusted("com.legit", valid_key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.evil", valid_key));

  // Also test AddKey path traversal rejection
  std::string dummy_file = std::string(td_.path) + "/temp.avbpubkey";
  auto extra_key = CreateRawAvbPublicKey(2048, 0x602, 0x01);
  ASSERT_TRUE(WriteStringToFile(extra_key, dummy_file));

  const std::vector<std::string> bad_key_names = {
      "../bad_name", "bad/name", "bad\\name", ".."
  };
  for (const auto& bad_name : bad_key_names) {
    auto res = manager.AddKey(dummy_file, bad_name, {"com.bad"});
    EXPECT_THAT(res, Not(Ok())) << "Expected AddKey to reject name: " << bad_name;
  }
}

// =========================================================================
// SECTION 3: Concurrency and Thread Safety Stress Tests
// =========================================================================

TEST_F(ApexKeyManagerChallengeTest, ConcurrencyReadersDuringReload) {
  auto prod_key = CreateRawAvbPublicKey(4096, 0x701, 0x01);
  auto data_key_1 = CreateRawAvbPublicKey(4096, 0x702, 0x01);
  auto data_key_2 = CreateRawAvbPublicKey(4096, 0x703, 0x01);

  WriteKey(product_keys_dir_, "prod.avbpubkey", prod_key);
  WriteKey(data_keys_dir_, "data1.avbpubkey", data_key_1);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  std::atomic<bool> stop_flag = false;
  std::atomic<int> read_count = 0;

  // Launch 4 concurrent reader threads
  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i) {
    readers.emplace_back([&]() {
      while (!stop_flag.load(std::memory_order_relaxed)) {
        bool prod_trusted = manager.IsKeyTrusted("com.test", prod_key);
        EXPECT_TRUE(prod_trusted);
        auto keys = manager.ListKeys();
        EXPECT_GE(keys.size(), 1u);
        read_count.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }

  // Writer thread alternates adding and removing data2.avbpubkey and reloading
  for (int iter = 0; iter < 50; ++iter) {
    if (iter % 2 == 0) {
      WriteKey(data_keys_dir_, "data2.avbpubkey", data_key_2);
    } else {
      fs::remove(data_keys_dir_ + "/data2.avbpubkey");
    }
    ASSERT_RESULT_OK(manager.ReloadDataKeys());
    std::this_thread::yield();
  }

  stop_flag.store(true);
  for (auto& t : readers) {
    t.join();
  }

  LOG(INFO) << "Completed " << read_count.load() << " concurrent reads without error.";
  EXPECT_GT(read_count.load(), 500);
}

}  // namespace apex
}  // namespace android
