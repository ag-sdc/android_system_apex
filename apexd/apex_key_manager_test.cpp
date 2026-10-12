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

#include <filesystem>
#include <string>
#include <vector>

namespace android {
namespace apex {

namespace fs = std::filesystem;

using android::base::ReadFileToString;
using android::base::WriteStringToFile;
using android::base::testing::Ok;
using ::testing::ElementsAre;
using ::testing::Not;

static std::string CreateTestAvbPublicKey(uint32_t key_num_bits,
                                          uint8_t fill = 0x5b) {
  size_t payload_bytes = 2 * (key_num_bits / 8);
  size_t total_size = sizeof(AvbRSAPublicKeyHeader) + payload_bytes;
  std::string data(total_size, static_cast<char>(fill));

  AvbRSAPublicKeyHeader* header =
      reinterpret_cast<AvbRSAPublicKeyHeader*>(&data[0]);
  header->key_num_bits = htobe32(key_num_bits);
  header->n0inv = htobe32(0x12345678);

  // Set lowest bit of RSA modulus to 1 (odd modulus sanity check)
  size_t lsb_offset = sizeof(AvbRSAPublicKeyHeader) + (key_num_bits / 8) - 1;
  data[lsb_offset] |= 0x01;
  return data;
}

class ApexKeyManagerTest : public ::testing::Test {
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

// 1. Load keys from both product and data directories
TEST_F(ApexKeyManagerTest, LoadKeysFromBothDirectories) {
  auto key_prod = CreateTestAvbPublicKey(4096, 0x11);
  auto key_data = CreateTestAvbPublicKey(4096, 0x22);

  WriteKey(product_keys_dir_, "prod.avbpubkey", key_prod);
  WriteKey(data_keys_dir_, "data.avbpubkey", key_data);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(2u, keys.size());

  EXPECT_TRUE(manager.IsKeyTrusted("com.any.pkg", key_prod));
  EXPECT_TRUE(manager.IsKeyTrusted("com.any.pkg", key_data));
}

// 2. Product key priority on conflict
TEST_F(ApexKeyManagerTest, ProductKeyTakesPriorityOnSameFilename) {
  auto key_prod = CreateTestAvbPublicKey(4096, 0x11);
  auto key_data = CreateTestAvbPublicKey(4096, 0x22);

  // Identical filename in both directories
  WriteKey(product_keys_dir_, "common.avbpubkey", key_prod);
  WriteKey(data_keys_dir_, "common.avbpubkey", key_data);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_TRUE(keys[0].from_product);
  EXPECT_EQ(key_prod, keys[0].pubkey);

  // Product key is trusted; data key is shadowed
  EXPECT_TRUE(manager.IsKeyTrusted("com.test.pkg", key_prod));
  EXPECT_FALSE(manager.IsKeyTrusted("com.test.pkg", key_data));
}

// 3. Shared key authorizing multiple packages via XML policy
TEST_F(ApexKeyManagerTest, SharedKeyAuthorizesMultiplePackages) {
  auto key = CreateTestAvbPublicKey(4096, 0x33);
  WriteKey(product_keys_dir_, "shared.avbpubkey", key);

  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<key-policy>
  <key name="shared-vendor" file="shared.avbpubkey">
    <allow package="com.vendor.foo.app" />
    <allow package="com.vendor.foo.lib" />
  </key>
</key-policy>)";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  // Allowed packages
  EXPECT_TRUE(manager.IsKeyTrusted("com.vendor.foo.app", key));
  EXPECT_TRUE(manager.IsKeyTrusted("com.vendor.foo.lib", key));

  // Disallowed package with same key
  EXPECT_FALSE(manager.IsKeyTrusted("com.vendor.unauthorized", key));
}

// 4. Directory without XML policy treats key as unrestricted
TEST_F(ApexKeyManagerTest, NoPolicyFileAllowsAnyPackage) {
  auto key = CreateTestAvbPublicKey(4096, 0x44);
  WriteKey(data_keys_dir_, "open.avbpubkey", key);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  EXPECT_TRUE(manager.IsKeyTrusted("com.app.alpha", key));
  EXPECT_TRUE(manager.IsKeyTrusted("org.app.beta", key));
}

// 5. XML policy with empty allowlist treats key as unrestricted
TEST_F(ApexKeyManagerTest, EmptyAllowlistInPolicyAllowsAnyPackage) {
  auto key = CreateTestAvbPublicKey(4096, 0x45);
  WriteKey(data_keys_dir_, "unrestricted.avbpubkey", key);

  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<key-policy>
  <key name="unrestricted-key" file="unrestricted.avbpubkey">
  </key>
</key-policy>)";
  WritePolicyXml(data_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  EXPECT_TRUE(manager.IsKeyTrusted("com.arbitrary.one", key));
  EXPECT_TRUE(manager.IsKeyTrusted("org.arbitrary.two", key));
}

// 6. Disallowed package rejected by restricted key
TEST_F(ApexKeyManagerTest, DisallowedPackageRejected) {
  auto key = CreateTestAvbPublicKey(4096, 0x46);
  WriteKey(product_keys_dir_, "restricted.avbpubkey", key);

  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<key-policy>
  <key name="restricted-key" file="restricted.avbpubkey">
    <allow package="com.package.a" />
  </key>
</key-policy>)";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  EXPECT_TRUE(manager.IsKeyTrusted("com.package.a", key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.package.b", key));
}

// 7. Fail-safe: missing product directory
TEST_F(ApexKeyManagerTest, FailSafeMissingProductDirectory) {
  auto key = CreateTestAvbPublicKey(4096, 0x47);
  WriteKey(data_keys_dir_, "data.avbpubkey", key);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(
      manager.Initialize("/nonexistent/product/keys", data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_FALSE(keys[0].from_product);
  EXPECT_TRUE(manager.IsKeyTrusted("com.test", key));
}

// 8. Fail-safe: missing data directory
TEST_F(ApexKeyManagerTest, FailSafeMissingDataDirectory) {
  auto key = CreateTestAvbPublicKey(4096, 0x48);
  WriteKey(product_keys_dir_, "prod.avbpubkey", key);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(
      manager.Initialize(product_keys_dir_, "/nonexistent/data/keys"));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_TRUE(keys[0].from_product);
  EXPECT_TRUE(manager.IsKeyTrusted("com.test", key));
}

// 9. Fail-safe: both directories missing
TEST_F(ApexKeyManagerTest, FailSafeBothDirectoriesMissing) {
  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(
      manager.Initialize("/nonexistent/product", "/nonexistent/data"));

  EXPECT_EQ(0u, manager.ListKeys().size());
}

// 10. Fail-safe: corrupt XML policy syntax
TEST_F(ApexKeyManagerTest, FailSafeCorruptXmlSyntax) {
  auto key = CreateTestAvbPublicKey(4096, 0x55);
  WriteKey(product_keys_dir_, "valid.avbpubkey", key);
  WritePolicyXml(product_keys_dir_, "<key-policy><unclosed_tag>");

  auto& manager = ApexKeyManager::GetInstance();
  // Must not abort/crash; logs warning and skips directory (fail-closed)
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));
  EXPECT_EQ(0u, manager.ListKeys().size());
}

// 11. Fail-safe: corrupt key file smaller than header size (< 8 bytes)
TEST_F(ApexKeyManagerTest, FailSafeCorruptKeyTooShort) {
  auto key_valid = CreateTestAvbPublicKey(4096, 0x61);
  WriteKey(product_keys_dir_, "valid.avbpubkey", key_valid);
  WriteKey(product_keys_dir_, "bad_short.avbpubkey", "tiny");

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ(key_valid, keys[0].pubkey);
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key_valid));
}

// 12. Fail-safe: corrupt key with invalid key_num_bits
TEST_F(ApexKeyManagerTest, FailSafeCorruptKeyInvalidNumBits) {
  auto key_valid = CreateTestAvbPublicKey(4096, 0x62);
  WriteKey(product_keys_dir_, "valid.avbpubkey", key_valid);
  WriteKey(product_keys_dir_, "bad_bits.avbpubkey", CreateTestAvbPublicKey(1024));

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ(key_valid, keys[0].pubkey);
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key_valid));
}

// 13. Fail-safe: corrupt key truncated
TEST_F(ApexKeyManagerTest, FailSafeCorruptKeyTruncated) {
  auto key_valid = CreateTestAvbPublicKey(4096, 0x63);
  WriteKey(product_keys_dir_, "valid.avbpubkey", key_valid);
  WriteKey(product_keys_dir_, "bad_trunc.avbpubkey",
           CreateTestAvbPublicKey(4096).substr(0, 500));

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ(key_valid, keys[0].pubkey);
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key_valid));
}

// 14. Fail-safe: corrupt key with trailing garbage
TEST_F(ApexKeyManagerTest, FailSafeCorruptKeyTrailingGarbage) {
  auto key_valid = CreateTestAvbPublicKey(4096, 0x64);
  WriteKey(product_keys_dir_, "valid.avbpubkey", key_valid);
  WriteKey(product_keys_dir_, "bad_extra.avbpubkey",
           CreateTestAvbPublicKey(4096) + "garbage_bytes");

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ(key_valid, keys[0].pubkey);
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key_valid));
}

// 15. Security: Path traversal in XML policy rejected
TEST_F(ApexKeyManagerTest, PathTraversalInXmlPolicyBlocked) {
  auto key = CreateTestAvbPublicKey(4096, 0x77);
  WriteKey(product_keys_dir_, "valid.avbpubkey", key);

  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<key-policy>
  <key name="valid-key" file="valid.avbpubkey">
    <allow package="com.valid.pkg" />
  </key>
  <key name="evil1" file="../etc/passwd">
    <allow package="com.evil1" />
  </key>
  <key name="evil2" file="/etc/shadow">
    <allow package="com.evil2" />
  </key>
  <key name="evil3" file="sub\\dir.avbpubkey">
    <allow package="com.evil3" />
  </key>
</key-policy>)";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  // Traversal keys are rejected; valid key is loaded and restricted
  EXPECT_TRUE(manager.IsKeyTrusted("com.valid.pkg", key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.evil1", key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.evil2", key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.evil3", key));

  auto keys = manager.ListKeys();
  ASSERT_EQ(1u, keys.size());
  EXPECT_EQ("valid-key", keys[0].name);
}

// 16. Dynamic hot-reload adds newly written key
TEST_F(ApexKeyManagerTest, HotReloadAddsNewDataKey) {
  auto key1 = CreateTestAvbPublicKey(4096, 0x81);
  auto key2 = CreateTestAvbPublicKey(4096, 0x82);

  WriteKey(product_keys_dir_, "key1.avbpubkey", key1);
  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key1));
  EXPECT_FALSE(manager.IsKeyTrusted("com.pkg", key2));

  // Dynamically add key2 into data directory
  WriteKey(data_keys_dir_, "key2.avbpubkey", key2);
  ASSERT_RESULT_OK(manager.ReloadDataKeys());

  // Now key2 is immediately trusted without restart
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key1));
  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key2));
}

// 17. Dynamic hot-reload removes deleted key
TEST_F(ApexKeyManagerTest, HotReloadRemovesDeletedDataKey) {
  auto key = CreateTestAvbPublicKey(4096, 0x85);
  WriteKey(data_keys_dir_, "removable.avbpubkey", key);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  EXPECT_TRUE(manager.IsKeyTrusted("com.pkg", key));
  ASSERT_EQ(1u, manager.ListKeys().size());

  // Delete file from data directory and reload
  fs::remove(data_keys_dir_ + "/removable.avbpubkey");
  ASSERT_RESULT_OK(manager.ReloadDataKeys());

  EXPECT_FALSE(manager.IsKeyTrusted("com.pkg", key));
  EXPECT_EQ(0u, manager.ListKeys().size());
}

// 18. Public API validation (GetKeyForPackage, ListKeys, AddKey, RemoveKey, Reset)
TEST_F(ApexKeyManagerTest, PublicApiValidation) {
  auto prod_key = CreateTestAvbPublicKey(4096, 0x91);
  WriteKey(product_keys_dir_, "prod.avbpubkey", prod_key);

  std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<key-policy>
  <key name="prod-key" file="prod.avbpubkey">
    <allow package="com.specific.app" />
  </key>
</key-policy>)";
  WritePolicyXml(product_keys_dir_, xml);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  // 1. GetKeyForPackage with allowed package
  auto retrieved = manager.GetKeyForPackage("com.specific.app");
  ASSERT_RESULT_OK(retrieved);
  EXPECT_EQ(prod_key, *retrieved);

  // 2. GetKeyForPackage with bundled key overload
  auto bundled_ok = manager.GetKeyForPackage("com.specific.app", prod_key);
  ASSERT_RESULT_OK(bundled_ok);
  EXPECT_EQ(prod_key, *bundled_ok);

  auto bundled_fail = manager.GetKeyForPackage("com.unmapped.app", prod_key);
  EXPECT_THAT(bundled_fail, Not(Ok()));

  // 3. GetKeyForPackage with unmapped package
  auto unmapped = manager.GetKeyForPackage("com.unmapped.app");
  EXPECT_THAT(unmapped, Not(Ok()));

  // 4. ListKeys
  auto list = manager.ListKeys();
  ASSERT_EQ(1u, list.size());
  EXPECT_EQ("prod-key", list[0].name);
  EXPECT_EQ(product_keys_dir_ + "/prod.avbpubkey", list[0].path);
  EXPECT_TRUE(list[0].from_product);
  EXPECT_THAT(list[0].allowed_packages, ElementsAre("com.specific.app"));

  // 5. AddKey
  auto extra_key = CreateTestAvbPublicKey(4096, 0x92);
  std::string temp_key_file = std::string(td_.path) + "/external.avbpubkey";
  ASSERT_TRUE(WriteStringToFile(extra_key, temp_key_file));

  ASSERT_RESULT_OK(
      manager.AddKey(temp_key_file, "external-key", {"com.external.app"}));
  EXPECT_TRUE(manager.IsKeyTrusted("com.external.app", extra_key));
  EXPECT_FALSE(manager.IsKeyTrusted("com.other.app", extra_key));

  auto retrieved_added = manager.GetKeyForPackage("com.external.app");
  ASSERT_RESULT_OK(retrieved_added);
  EXPECT_EQ(extra_key, *retrieved_added);

  // 6. Attempt to remove product key (must fail)
  auto remove_prod = manager.RemoveKey("prod-key");
  EXPECT_THAT(remove_prod, Not(Ok()));

  // 7. Remove added key (must succeed)
  ASSERT_RESULT_OK(manager.RemoveKey("external-key"));
  EXPECT_FALSE(manager.IsKeyTrusted("com.external.app", extra_key));

  // 8. Reset
  manager.Reset();
  EXPECT_EQ(0u, manager.ListKeys().size());
  EXPECT_FALSE(manager.IsKeyTrusted("com.specific.app", prod_key));
}

// 19. Validate supported key bit lengths: RSA-2048, RSA-4096, RSA-8192
TEST_F(ApexKeyManagerTest, SupportedRsaKeyBitLengths) {
  auto key2048 = CreateTestAvbPublicKey(2048, 0x21);
  auto key4096 = CreateTestAvbPublicKey(4096, 0x41);
  auto key8192 = CreateTestAvbPublicKey(8192, 0x81);

  EXPECT_EQ(520u, key2048.size());
  EXPECT_EQ(1032u, key4096.size());
  EXPECT_EQ(2056u, key8192.size());

  WriteKey(product_keys_dir_, "k2048.avbpubkey", key2048);
  WriteKey(product_keys_dir_, "k4096.avbpubkey", key4096);
  WriteKey(product_keys_dir_, "k8192.avbpubkey", key8192);

  auto& manager = ApexKeyManager::GetInstance();
  ASSERT_RESULT_OK(manager.Initialize(product_keys_dir_, data_keys_dir_));

  EXPECT_TRUE(manager.IsKeyTrusted("com.test", key2048));
  EXPECT_TRUE(manager.IsKeyTrusted("com.test", key4096));
  EXPECT_TRUE(manager.IsKeyTrusted("com.test", key8192));
}

}  // namespace apex
}  // namespace android
