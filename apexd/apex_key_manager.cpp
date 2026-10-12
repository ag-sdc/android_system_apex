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
#include <android-base/strings.h>
#include <libavb/libavb.h>
#include <tinyxml2.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <unordered_map>
#include <unordered_set>

namespace android {
namespace apex {

using android::base::Error;
using android::base::Result;

ApexKeyManager& ApexKeyManager::GetInstance() {
  static ApexKeyManager instance;
  return instance;
}

Result<size_t> ApexKeyManager::ValidateAvbPublicKey(
    std::string_view key_bytes) {
  const size_t length = key_bytes.size();
  if (length < sizeof(AvbRSAPublicKeyHeader)) {
    return Error() << "Key data too short: " << length << " bytes (minimum "
                   << sizeof(AvbRSAPublicKeyHeader) << " bytes)";
  }

  const uint8_t* data = reinterpret_cast<const uint8_t*>(key_bytes.data());
  AvbRSAPublicKeyHeader header;
  if (!avb_rsa_public_key_header_validate_and_byteswap(
          reinterpret_cast<const AvbRSAPublicKeyHeader*>(data), &header)) {
    return Error() << "Invalid AvbRSAPublicKeyHeader structure";
  }

  if (header.key_num_bits != 2048 && header.key_num_bits != 4096 &&
      header.key_num_bits != 8192) {
    return Error() << "Unsupported RSA key bit-length: " << header.key_num_bits
                   << " bits (supported: 2048, 4096, 8192)";
  }

  const size_t expected_length =
      sizeof(AvbRSAPublicKeyHeader) + 2 * (header.key_num_bits / 8);
  if (length != expected_length) {
    return Error() << "Key size mismatch: got " << length << " bytes, expected "
                   << expected_length << " bytes for " << header.key_num_bits
                   << "-bit RSA key";
  }

  const size_t lsb_offset =
      sizeof(AvbRSAPublicKeyHeader) + (header.key_num_bits / 8) - 1;
  if ((data[lsb_offset] & 0x01) == 0) {
    return Error() << "Malformed RSA modulus: least significant bit is even";
  }

  return header.key_num_bits;
}

Result<std::vector<ApexKeyRecord>> ApexKeyManager::LoadKeysFromDir(
    const std::string& dir_path, bool is_product) {
  std::error_code ec;
  if (!std::filesystem::exists(dir_path, ec) ||
      !std::filesystem::is_directory(dir_path, ec)) {
    LOG(INFO) << "Apex key directory does not exist or is not a directory: "
              << dir_path;
    return std::vector<ApexKeyRecord>{};
  }

  struct PolicyEntry {
    std::string name;
    std::vector<std::string> allowed_packages;
  };
  std::unordered_map<std::string, PolicyEntry> policy_by_filename;

  std::string policy_file =
      (std::filesystem::path(dir_path) / "apex-key-policy.xml").string();
  if (std::filesystem::exists(policy_file, ec)) {
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLError err = doc.LoadFile(policy_file.c_str());
    if (err != tinyxml2::XML_SUCCESS) {
      LOG(WARNING) << "Failed to parse XML key policy at " << policy_file
                   << " (line " << doc.ErrorLineNum() << "): " << doc.ErrorStr()
                   << "; skipping directory " << dir_path;
      return std::vector<ApexKeyRecord>{};
    }
    const tinyxml2::XMLElement* root = doc.RootElement();
    if (root == nullptr || std::string_view(root->Name()) != "key-policy") {
      LOG(WARNING) << "Invalid root element in " << policy_file
                   << "; skipping directory " << dir_path;
      return std::vector<ApexKeyRecord>{};
    }
    for (const tinyxml2::XMLElement* key_elem = root->FirstChildElement("key");
         key_elem != nullptr; key_elem = key_elem->NextSiblingElement("key")) {
      const char* file_attr = key_elem->Attribute("file");
      const char* name_attr = key_elem->Attribute("name");
      if (file_attr == nullptr || file_attr[0] == '\0') {
        LOG(WARNING) << "Key element missing 'file' attribute in "
                     << policy_file;
        continue;
      }
      std::string filename = file_attr;
      if (filename.find('/') != std::string::npos ||
          filename.find('\\') != std::string::npos ||
          filename.find("..") != std::string::npos) {
        LOG(ERROR)
            << "Path traversal attempt detected in key policy file attribute: '"
            << filename << "'";
        continue;
      }
      std::string name = (name_attr != nullptr && name_attr[0] != '\0')
                             ? name_attr
                             : std::filesystem::path(filename).stem().string();
      std::vector<std::string> allowed_packages;
      for (const tinyxml2::XMLElement* allow_elem =
               key_elem->FirstChildElement("allow");
           allow_elem != nullptr;
           allow_elem = allow_elem->NextSiblingElement("allow")) {
        const char* pkg_attr = allow_elem->Attribute("package");
        if (pkg_attr != nullptr && pkg_attr[0] != '\0') {
          allowed_packages.push_back(pkg_attr);
        }
      }
      policy_by_filename[filename] =
          PolicyEntry{.name = std::move(name),
                      .allowed_packages = std::move(allowed_packages)};
    }
  }

  std::vector<std::filesystem::directory_entry> entries;
  for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
    if (ec) {
      LOG(WARNING) << "Error reading directory " << dir_path << ": "
                   << ec.message();
      break;
    }
    if (entry.is_regular_file(ec)) {
      entries.push_back(entry);
    }
  }
  std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
    return a.path().filename().string() < b.path().filename().string();
  });

  std::vector<ApexKeyRecord> loaded_keys;
  std::unordered_set<std::string> seen_names;

  for (const auto& entry : entries) {
    std::string filename = entry.path().filename().string();
    if (!android::base::EndsWith(filename, ".avbpubkey")) {
      continue;
    }
    std::string file_path = entry.path().string();
    std::string key_bytes;
    if (!android::base::ReadFileToString(file_path, &key_bytes)) {
      LOG(ERROR) << "Failed to read key file: " << file_path;
      continue;
    }
    auto val_res = ValidateAvbPublicKey(key_bytes);
    if (!val_res.ok()) {
      LOG(ERROR) << "Invalid AVB public key at " << file_path << ": "
                 << val_res.error();
      continue;
    }

    std::string key_name;
    std::vector<std::string> allowed_packages;
    auto it = policy_by_filename.find(filename);
    if (it != policy_by_filename.end()) {
      key_name = it->second.name;
      allowed_packages = it->second.allowed_packages;
    } else {
      key_name = entry.path().stem().string();
    }

    if (!seen_names.insert(key_name).second) {
      LOG(WARNING) << "Duplicate key name '" << key_name << "' in " << dir_path
                   << "; skipping duplicate";
      continue;
    }

    loaded_keys.push_back(ApexKeyRecord{
        .name = std::move(key_name),
        .path = std::move(file_path),
        .pubkey = std::move(key_bytes),
        .allowed_packages = std::move(allowed_packages),
        .from_product = is_product,
    });
  }

  return loaded_keys;
}

Result<void> ApexKeyManager::Initialize(const std::string& product_keys_dir,
                                        const std::string& data_keys_dir)
    REQUIRES(!lock_) {
  std::lock_guard disk_lock(disk_mutation_lock_);
  auto prod_res = LoadKeysFromDir(product_keys_dir, /*is_product=*/true);
  if (!prod_res.ok()) {
    return prod_res.error();
  }
  std::vector<ApexKeyRecord> new_product_keys = std::move(*prod_res);

  auto data_res = LoadKeysFromDir(data_keys_dir, /*is_product=*/false);
  if (!data_res.ok()) {
    return data_res.error();
  }
  std::vector<ApexKeyRecord> raw_data_keys = std::move(*data_res);

  std::vector<ApexKeyRecord> filtered_data_keys;
  for (auto& dk : raw_data_keys) {
    bool name_conflict = false;
    for (const auto& pk : new_product_keys) {
      if (pk.name == dk.name) {
        LOG(WARNING)
            << "Data key name '" << dk.name
            << "' conflicts with product key; product key takes precedence";
        name_conflict = true;
        break;
      }
    }
    if (name_conflict) continue;

    bool content_conflict = false;
    for (const auto& pk : new_product_keys) {
      if (pk.pubkey == dk.pubkey) {
        LOG(WARNING) << "Data key at " << dk.path << " duplicates product key '"
                     << pk.name << "'; product key takes precedence";
        content_conflict = true;
        break;
      }
    }
    if (content_conflict) continue;

    filtered_data_keys.push_back(std::move(dk));
  }

  std::lock_guard lock(lock_);
  product_keys_dir_ = product_keys_dir;
  data_keys_dir_ = data_keys_dir;
  product_keys_ = std::move(new_product_keys);
  data_keys_ = std::move(filtered_data_keys);
  initialized_ = true;

  LOG(INFO) << "ApexKeyManager initialized with " << product_keys_.size()
            << " product keys and " << data_keys_.size() << " data keys";
  return {};
}

Result<void> ApexKeyManager::ReloadDataKeys() REQUIRES(!lock_) {
  std::lock_guard disk_lock(disk_mutation_lock_);
  std::string data_dir;
  std::vector<ApexKeyRecord> current_product_keys;
  {
    std::lock_guard lock(lock_);
    if (!initialized_) {
      return Error() << "ApexKeyManager is not initialized";
    }
    data_dir = data_keys_dir_;
    current_product_keys = product_keys_;
  }

  // Load outside lock (double buffering)
  auto data_res = LoadKeysFromDir(data_dir, /*is_product=*/false);
  if (!data_res.ok()) {
    return data_res.error();
  }
  std::vector<ApexKeyRecord> raw_data_keys = std::move(*data_res);

  std::vector<ApexKeyRecord> filtered_data_keys;
  for (auto& dk : raw_data_keys) {
    bool name_conflict = false;
    for (const auto& pk : current_product_keys) {
      if (pk.name == dk.name) {
        LOG(WARNING)
            << "Data key name '" << dk.name
            << "' conflicts with product key; product key takes precedence";
        name_conflict = true;
        break;
      }
    }
    if (name_conflict) continue;

    bool content_conflict = false;
    for (const auto& pk : current_product_keys) {
      if (pk.pubkey == dk.pubkey) {
        LOG(WARNING) << "Data key at " << dk.path << " duplicates product key '"
                     << pk.name << "'; product key takes precedence";
        content_conflict = true;
        break;
      }
    }
    if (content_conflict) continue;

    filtered_data_keys.push_back(std::move(dk));
  }

  size_t reloaded_count = 0;
  // Atomic swap under lock
  {
    std::lock_guard lock(lock_);
    data_keys_ = std::move(filtered_data_keys);
    reloaded_count = data_keys_.size();
  }

  LOG(INFO) << "ApexKeyManager reloaded " << reloaded_count << " data keys";
  return {};
}

bool ApexKeyManager::IsKeyTrusted(const std::string& package_name,
                                  const std::string& pubkey_bytes) const
    REQUIRES(!lock_) {
  std::lock_guard lock(lock_);

  // Priority 1: Check if any product key explicitly claims package_name.
  for (const auto& pk : product_keys_) {
    if (!pk.allowed_packages.empty()) {
      if (std::find(pk.allowed_packages.begin(), pk.allowed_packages.end(),
                    package_name) != pk.allowed_packages.end()) {
        return pk.pubkey == pubkey_bytes;
      }
    }
  }

  // Priority 2: Check matching product keys
  for (const auto& pk : product_keys_) {
    if (pk.pubkey == pubkey_bytes) {
      if (pk.allowed_packages.empty()) {
        return true;  // Unrestricted product key
      }
      return false;
    }
  }

  // Priority 3: Check matching data keys
  for (const auto& dk : data_keys_) {
    if (dk.pubkey == pubkey_bytes) {
      if (dk.allowed_packages.empty()) {
        return true;  // Unrestricted data key
      }
      if (std::find(dk.allowed_packages.begin(), dk.allowed_packages.end(),
                    package_name) != dk.allowed_packages.end()) {
        return true;  // In data key allowlist
      }
      return false;
    }
  }

  return false;
}

Result<std::string> ApexKeyManager::GetKeyForPackage(
    const std::string& package_name) const REQUIRES(!lock_) {
  std::lock_guard lock(lock_);

  // 1. Search product keys with explicit allowlist for package_name
  for (const auto& pk : product_keys_) {
    if (!pk.allowed_packages.empty() &&
        std::find(pk.allowed_packages.begin(), pk.allowed_packages.end(),
                  package_name) != pk.allowed_packages.end()) {
      return pk.pubkey;
    }
  }

  // 2. Search data keys with explicit allowlist for package_name
  for (const auto& dk : data_keys_) {
    if (!dk.allowed_packages.empty() &&
        std::find(dk.allowed_packages.begin(), dk.allowed_packages.end(),
                  package_name) != dk.allowed_packages.end()) {
      return dk.pubkey;
    }
  }

  // 3. Count unrestricted keys across both stores
  std::vector<const ApexKeyRecord*> unrestricted;
  for (const auto& pk : product_keys_) {
    if (pk.allowed_packages.empty()) unrestricted.push_back(&pk);
  }
  for (const auto& dk : data_keys_) {
    if (dk.allowed_packages.empty()) unrestricted.push_back(&dk);
  }

  if (unrestricted.size() == 1) {
    return unrestricted[0]->pubkey;
  }
  if (unrestricted.empty()) {
    return Error() << "No trusted public key found authorizing package "
                   << package_name;
  }

  return Error() << "Multiple unrestricted keys available for package "
                 << package_name << "; provide bundled key to match";
}

Result<std::string> ApexKeyManager::GetKeyForPackage(
    const std::string& package_name, const std::string& bundled_key) const
    REQUIRES(!lock_) {
  if (IsKeyTrusted(package_name, bundled_key)) {
    return bundled_key;
  }
  return Error() << "Bundled key is not trusted for package " << package_name;
}

std::vector<ApexKeyRecord> ApexKeyManager::ListKeys() const REQUIRES(!lock_) {
  std::lock_guard lock(lock_);
  std::vector<ApexKeyRecord> result = product_keys_;
  result.insert(result.end(), data_keys_.begin(), data_keys_.end());
  return result;
}

Result<void> ApexKeyManager::AddKey(
    const std::string& key_path, const std::optional<std::string>& key_name,
    const std::vector<std::string>& allowed_packages) REQUIRES(!lock_) {
  std::lock_guard disk_lock(disk_mutation_lock_);
  std::string key_bytes;
  if (!android::base::ReadFileToString(key_path, &key_bytes)) {
    return Error() << "Failed to read key file from " << key_path;
  }
  auto val_res = ValidateAvbPublicKey(key_bytes);
  if (!val_res.ok()) {
    return Error() << "Invalid AVB public key at " << key_path << ": "
                   << val_res.error();
  }

  std::string resolved_name;
  if (key_name.has_value() && !key_name->empty()) {
    resolved_name = *key_name;
  } else {
    resolved_name = std::filesystem::path(key_path).stem().string();
  }

  if (resolved_name.empty() || resolved_name.find('/') != std::string::npos ||
      resolved_name.find('\\') != std::string::npos ||
      resolved_name.find("..") != std::string::npos) {
    return Error() << "Invalid key name: " << resolved_name;
  }

  std::string data_dir;
  {
    std::lock_guard lock(lock_);
    if (!initialized_) {
      return Error() << "ApexKeyManager is not initialized";
    }
    for (const auto& pk : product_keys_) {
      if (pk.name == resolved_name) {
        return Error() << "Key name '" << resolved_name
                       << "' conflicts with pre-installed product key";
      }
      if (pk.pubkey == key_bytes) {
        return Error() << "Key content duplicates pre-installed product key '"
                       << pk.name << "'";
      }
    }
    data_dir = data_keys_dir_;
  }

  std::error_code ec;
  if (!std::filesystem::exists(data_dir, ec)) {
    if (!std::filesystem::create_directories(data_dir, ec)) {
      return Error() << "Failed to create data keys directory " << data_dir
                     << ": " << ec.message();
    }
  }

  std::string dest_filename = resolved_name + ".avbpubkey";
  std::string dest_path =
      (std::filesystem::path(data_dir) / dest_filename).string();

  if (!android::base::WriteStringToFile(key_bytes, dest_path, 0644, getuid(),
                                        getgid())) {
    return Error() << "Failed to write key to " << dest_path;
  }

  std::string policy_path =
      (std::filesystem::path(data_dir) / "apex-key-policy.xml").string();
  if (!allowed_packages.empty() || std::filesystem::exists(policy_path, ec)) {
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLElement* root = nullptr;
    if (std::filesystem::exists(policy_path, ec)) {
      if (doc.LoadFile(policy_path.c_str()) == tinyxml2::XML_SUCCESS) {
        root = doc.RootElement();
      }
    }
    if (root == nullptr) {
      doc.Clear();
      tinyxml2::XMLDeclaration* decl =
          doc.NewDeclaration("xml version=\"1.0\" encoding=\"utf-8\"");
      doc.InsertFirstChild(decl);
      root = doc.NewElement("key-policy");
      doc.InsertEndChild(root);
    }

    for (tinyxml2::XMLElement* k = root->FirstChildElement("key");
         k != nullptr;) {
      tinyxml2::XMLElement* next = k->NextSiblingElement("key");
      const char* attr_name = k->Attribute("name");
      const char* attr_file = k->Attribute("file");
      if ((attr_name != nullptr && resolved_name == attr_name) ||
          (attr_file != nullptr && dest_filename == attr_file)) {
        root->DeleteChild(k);
      }
      k = next;
    }

    tinyxml2::XMLElement* key_elem = doc.NewElement("key");
    key_elem->SetAttribute("name", resolved_name.c_str());
    key_elem->SetAttribute("file", dest_filename.c_str());
    for (const auto& pkg : allowed_packages) {
      tinyxml2::XMLElement* allow_elem = doc.NewElement("allow");
      allow_elem->SetAttribute("package", pkg.c_str());
      key_elem->InsertEndChild(allow_elem);
    }
    root->InsertEndChild(key_elem);

    if (doc.SaveFile(policy_path.c_str()) != tinyxml2::XML_SUCCESS) {
      return Error() << "Failed to save updated XML policy to " << policy_path;
    }
  }

  return ReloadDataKeys();
}

Result<void> ApexKeyManager::RemoveKey(const std::string& key_name)
    REQUIRES(!lock_) {
  std::lock_guard disk_lock(disk_mutation_lock_);
  std::string data_dir;
  std::string target_file_path;
  std::string target_filename;
  {
    std::lock_guard lock(lock_);
    if (!initialized_) {
      return Error() << "ApexKeyManager is not initialized";
    }
    for (const auto& pk : product_keys_) {
      if (pk.name == key_name) {
        return Error() << "Cannot remove pre-installed product key '"
                       << key_name << "'";
      }
    }
    auto it = std::find_if(
        data_keys_.begin(), data_keys_.end(),
        [&key_name](const ApexKeyRecord& k) { return k.name == key_name; });
    if (it == data_keys_.end()) {
      return Error() << "Key '" << key_name << "' not found in data keys";
    }
    target_file_path = it->path;
    target_filename = std::filesystem::path(it->path).filename().string();
    data_dir = data_keys_dir_;
  }

  std::error_code ec;
  if (!target_file_path.empty() &&
      std::filesystem::exists(target_file_path, ec)) {
    if (!std::filesystem::remove(target_file_path, ec)) {
      LOG(WARNING) << "Failed to remove key file " << target_file_path << ": "
                   << ec.message();
    }
  }

  std::string policy_path =
      (std::filesystem::path(data_dir) / "apex-key-policy.xml").string();
  if (std::filesystem::exists(policy_path, ec)) {
    tinyxml2::XMLDocument doc;
    if (doc.LoadFile(policy_path.c_str()) == tinyxml2::XML_SUCCESS) {
      tinyxml2::XMLElement* root = doc.RootElement();
      if (root != nullptr) {
        bool modified = false;
        for (tinyxml2::XMLElement* k = root->FirstChildElement("key");
             k != nullptr;) {
          tinyxml2::XMLElement* next = k->NextSiblingElement("key");
          const char* attr_name = k->Attribute("name");
          const char* attr_file = k->Attribute("file");
          if ((attr_name != nullptr && key_name == attr_name) ||
              (attr_file != nullptr && target_filename == attr_file)) {
            root->DeleteChild(k);
            modified = true;
          }
          k = next;
        }
        if (modified) {
          doc.SaveFile(policy_path.c_str());
        }
      }
    }
  }

  return ReloadDataKeys();
}

void ApexKeyManager::Reset() REQUIRES(!lock_) {
  std::lock_guard lock(lock_);
  product_keys_.clear();
  data_keys_.clear();
  product_keys_dir_.clear();
  data_keys_dir_.clear();
  initialized_ = false;
}

}  // namespace apex
}  // namespace android
