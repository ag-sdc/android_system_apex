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

#include <android-base/strings.h>
#include <android/apex/ApexTrustedKey.h>
#include <android/apex/IApexService.h>
#include <binder/IServiceManager.h>
#include <binder/Status.h>
#include <utils/String16.h>

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using android::IBinder;
using android::IServiceManager;
using android::sp;
using android::String16;
using android::apex::ApexTrustedKey;
using android::apex::IApexService;
using android::binder::Status;

namespace {

constexpr size_t kMaxKeyFileSize = 10 * 1024 * 1024;  // 10 MB

void PrintUsage(std::ostream& out) {
  out << "Usage: apex_key_manager <add|remove|list|reload> [OPTIONS]\n"
      << "Commands:\n"
      << "  add <key_path> <key_name> [--allow=pkg1,pkg2]  Install key\n"
      << "  remove <key_name>                              Remove key\n"
      << "  list                                           List trusted keys\n"
      << "  reload                                         Reload data keys\n";
  out.flush();
}

bool IsAllWhitespace(const std::string& str) {
  return str.find_first_not_of(" \t\n\v\f\r") == std::string::npos;
}

sp<IApexService> ConnectToApexService() {
  sp<IServiceManager> sm = android::defaultServiceManager();
  if (sm == nullptr) {
    std::cerr << "Error: Failed to get default service manager\n";
    std::cerr.flush();
    return nullptr;
  }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  sp<IBinder> binder = sm->getService(String16("apexservice"));
#pragma clang diagnostic pop
  if (binder == nullptr) {
    std::cerr << "Error: Failed to connect to apexd (apexservice is "
                 "unresponsive or not running)\n";
    std::cerr.flush();
    return nullptr;
  }
  return android::interface_cast<IApexService>(binder);
}

int HandleStatus(const Status& status) {
  if (status.isOk()) {
    return 0;
  }
  if (status.exceptionCode() == Status::EX_SECURITY) {
    std::cerr << "SecurityException: " << status.toString8().c_str() << "\n";
    std::cerr.flush();
    return 126;
  }
  std::cerr << "Error: " << status.toString8().c_str() << "\n";
  std::cerr.flush();
  return 1;
}

int HandleAdd(const sp<IApexService>& service, int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "Error: Missing required arguments for 'add'. Usage: add "
                 "<key_path> <key_name>\n";
    std::cerr.flush();
    return 1;
  }

  std::string key_path = argv[2];
  std::string key_name = argv[3];

  if (IsAllWhitespace(key_name)) {
    std::cerr << "Error: Key name cannot be empty\n";
    std::cerr.flush();
    return 1;
  }

  std::error_code ec;
  if (!std::filesystem::exists(key_path, ec)) {
    std::cerr << "Error: Key file '" << key_path << "' does not exist\n";
    std::cerr.flush();
    return 1;
  }

  auto file_size = std::filesystem::file_size(key_path, ec);
  if (!ec && file_size > kMaxKeyFileSize) {
    std::cerr << "Error: Key file '" << key_path
              << "' exceeds maximum size limit (10MB)\n";
    std::cerr.flush();
    return 1;
  }

  std::vector<std::string> allowed_packages;
  for (int i = 4; i < argc; ++i) {
    std::string arg = argv[i];
    if (android::base::StartsWith(arg, "--allow=")) {
      std::string pkgs = arg.substr(8);
      std::vector<std::string> parts = android::base::Split(pkgs, ",");
      for (auto& p : parts) {
        std::string trimmed = android::base::Trim(p);
        if (!trimmed.empty()) {
          allowed_packages.push_back(trimmed);
        }
      }
    } else if (android::base::StartsWith(arg, "--allowed-packages=")) {
      std::string pkgs = arg.substr(19);
      std::vector<std::string> parts = android::base::Split(pkgs, ",");
      for (auto& p : parts) {
        std::string trimmed = android::base::Trim(p);
        if (!trimmed.empty()) {
          allowed_packages.push_back(trimmed);
        }
      }
    }
  }

  std::optional<std::string> opt_key_name;
  if (!key_name.empty()) {
    opt_key_name = key_name;
  }

  std::optional<std::vector<std::optional<std::string>>> opt_allowed_packages;
  if (!allowed_packages.empty()) {
    std::vector<std::optional<std::string>> pkgs;
    pkgs.reserve(allowed_packages.size());
    for (const auto& pkg : allowed_packages) {
      pkgs.push_back(pkg);
    }
    opt_allowed_packages = std::move(pkgs);
  }

  Status status =
      service->addTrustedKey(key_path, opt_key_name, opt_allowed_packages);
  int code = HandleStatus(status);
  if (code == 0) {
    std::cout << "Key '" << key_name
              << "' successfully installed to /data/apex/keys/\n";
    std::cout.flush();
  }
  return code;
}

int HandleRemove(const sp<IApexService>& service, int argc, char** argv) {
  if (argc < 3 || IsAllWhitespace(argv[2])) {
    std::cerr << "Error: Missing or empty key name argument for 'remove'\n";
    std::cerr.flush();
    return 1;
  }

  std::string key_name = argv[2];
  Status status = service->removeTrustedKey(key_name);
  int code = HandleStatus(status);
  if (code == 0) {
    std::cout << "Key '" << key_name << "' successfully removed\n";
    std::cout.flush();
  }
  return code;
}

int HandleList(const sp<IApexService>& service) {
  std::vector<ApexTrustedKey> keys;
  Status status = service->listTrustedKeys(&keys);
  int code = HandleStatus(status);
  if (code != 0) {
    return code;
  }

  std::cout << "Trusted Apex Keys:\n";
  for (const auto& k : keys) {
    std::string origin = k.fromProduct ? "[product]" : "[data]";
    std::string allowed = k.allowedPackages.empty()
                              ? "All (unrestricted)"
                              : android::base::Join(k.allowedPackages, ", ");
    size_t bits = 0;
    if (k.pubkey.size() >= 4) {
      bits = (static_cast<size_t>(k.pubkey[0]) << 24) |
             (static_cast<size_t>(k.pubkey[1]) << 16) |
             (static_cast<size_t>(k.pubkey[2]) << 8) |
             static_cast<size_t>(k.pubkey[3]);
    }
    std::cout << "  " << origin << " " << k.name;
    if (bits > 0) {
      std::cout << " (" << bits << " bits)";
    }
    std::cout << ": Allowed: " << allowed << "\n";
  }
  std::cout.flush();
  return 0;
}

int HandleReload(const sp<IApexService>& service) {
  Status status = service->reloadKeys();
  int code = HandleStatus(status);
  if (code == 0) {
    std::cout << "Keys successfully reloaded from /data/apex/keys/\n";
    std::cout.flush();
  }
  return code;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    PrintUsage(std::cerr);
    return 1;
  }

  std::string cmd = argv[1];
  if (cmd == "--help" || cmd == "-h" || cmd == "help") {
    PrintUsage(std::cout);
    return 0;
  }

  if (cmd != "add" && cmd != "remove" && cmd != "list" && cmd != "reload") {
    std::cerr << "Error: Unknown command: '" << cmd
              << "'. Supported commands: add, remove, list, reload\n";
    std::cerr.flush();
    return 1;
  }

  sp<IApexService> service = ConnectToApexService();
  if (service == nullptr) {
    return 1;
  }

  if (cmd == "add") {
    return HandleAdd(service, argc, argv);
  } else if (cmd == "remove") {
    return HandleRemove(service, argc, argv);
  } else if (cmd == "list") {
    return HandleList(service);
  } else if (cmd == "reload") {
    return HandleReload(service);
  }

  return 1;
}
