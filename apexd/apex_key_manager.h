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

#pragma once

#include <android-base/result.h>
#include <android-base/thread_annotations.h>

#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace android {
namespace apex {

struct ApexKeyRecord {
  std::string name;
  std::string path;
  std::string pubkey;                         // raw bytes of .avbpubkey
  std::vector<std::string> allowed_packages;  // empty = unrestricted
  bool from_product = false;

  bool operator==(const ApexKeyRecord& other) const {
    return name == other.name && path == other.path && pubkey == other.pubkey &&
           allowed_packages == other.allowed_packages &&
           from_product == other.from_product;
  }
};

class ApexKeyManager {
 public:
  static ApexKeyManager& GetInstance();

  android::base::Result<void> Initialize(const std::string& product_keys_dir,
                                         const std::string& data_keys_dir)
      REQUIRES(!lock_);
  android::base::Result<void> ReloadDataKeys() REQUIRES(!lock_);

  bool IsKeyTrusted(const std::string& package_name,
                    const std::string& pubkey_bytes) const REQUIRES(!lock_);

  android::base::Result<std::string> GetKeyForPackage(
      const std::string& package_name) const REQUIRES(!lock_);

  android::base::Result<std::string> GetKeyForPackage(
      const std::string& package_name, const std::string& bundled_key) const
      REQUIRES(!lock_);

  std::vector<ApexKeyRecord> ListKeys() const REQUIRES(!lock_);

  android::base::Result<void> AddKey(
      const std::string& key_path, const std::optional<std::string>& key_name,
      const std::vector<std::string>& allowed_packages) REQUIRES(!lock_);

  android::base::Result<void> RemoveKey(const std::string& key_name)
      REQUIRES(!lock_);

  static android::base::Result<size_t> ValidateAvbPublicKey(
      std::string_view key_bytes);

  void Reset() REQUIRES(!lock_);

 private:
  ApexKeyManager() = default;
  ~ApexKeyManager() = default;
  ApexKeyManager(const ApexKeyManager&) = delete;
  ApexKeyManager& operator=(const ApexKeyManager&) = delete;

  static android::base::Result<std::vector<ApexKeyRecord>> LoadKeysFromDir(
      const std::string& dir_path, bool is_product);

  // To fix thread safety negative capability warning
  class CAPABILITY("mutex") Mutex : public std::mutex {
   public:
    // for negative capabilities
    const Mutex& operator!() const { return *this; }
  };
  mutable Mutex lock_;
  std::mutex disk_mutation_lock_;
  std::string product_keys_dir_ GUARDED_BY(lock_);
  std::string data_keys_dir_ GUARDED_BY(lock_);
  bool initialized_ GUARDED_BY(lock_) = false;

  std::vector<ApexKeyRecord> product_keys_ GUARDED_BY(lock_);
  std::vector<ApexKeyRecord> data_keys_ GUARDED_BY(lock_);
};

}  // namespace apex
}  // namespace android
