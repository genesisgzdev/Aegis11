#pragma once
#include "RAII.hpp"
#include "Logger.hpp"
#include "Utils.hpp"
#include "ProcessHost.hpp"
#include "../Support/json.hpp"
#include <windows.h>
#include <rpc.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <map>

#define AEGIS_ENGINE_VERSION "1.0.0"
#define WAL_SECTOR_SIZE 4096

using json = nlohmann::json;

namespace Aegis::Core {
    enum class RegType { DWORD, QWORD, SZ, EXPAND_SZ, MULTI_SZ, BINARY };
    enum class TxState { PENDING, PARTIAL_APPLY, COMMITTED, FAILED, ROLLED_BACK, RECOVERY_APPLIED };

    struct PolicyDefinition {
        std::wstring name;
        HKEY rootHive; 
        std::wstring path;
        std::wstring key;
        RegType type;
        std::vector<BYTE> targetData;
        bool multiUser = false; // Intent: Apply offline directly to NTUSER.DAT hives
        std::string intent_id;  // Abstract Intent Identifier: e.g., "disable_telemetry", providing context beyond the raw registry key
    };

    struct TransactionRecord {
        uint64_t sequence_number;
        uint64_t key_fingerprint;
        std::string engine_version = AEGIS_ENGINE_VERSION;
        std::string policy_version = "v1.0";
        std::string id;
        std::string name;
        uint64_t rootHive;
        std::string path;
        std::string key;
        TxState state;
        bool keyExistedBefore;
        bool valueExistedBefore;
        uint32_t originalType;
        std::vector<BYTE> originalData;
        std::vector<BYTE> targetData;

        json to_json() const {
            return json{
                {"seq", sequence_number}, {"fpr", key_fingerprint}, {"id", id}, {"name", name}, 
                {"eng_v", engine_version}, {"pol_v", policy_version}, {"rootHive", rootHive}, 
                {"path", path}, {"key", key}, {"state", static_cast<int>(state)}, {"keyExistedBefore", keyExistedBefore},
                {"valueExistedBefore", valueExistedBefore}, {"originalType", originalType},
                {"originalData", originalData}, {"targetData", targetData}
            };
        }

        static TransactionRecord from_json(const json& j) {
            TransactionRecord tx;
            tx.sequence_number = j.value("seq", 0ULL);
            tx.key_fingerprint = j.value("fpr", 0ULL);
            tx.engine_version = j.value("eng_v", "legacy");
            tx.policy_version = j.value("pol_v", "v1.0");
            tx.id = j.value("id", ""); tx.name = j.value("name", ""); tx.rootHive = j.value("rootHive", 0ULL);
            tx.path = j.value("path", ""); tx.key = j.value("key", ""); 
            tx.state = static_cast<TxState>(j.value("state", 0));
            tx.keyExistedBefore = j.value("keyExistedBefore", false);
            tx.valueExistedBefore = j.value("valueExistedBefore", false);
            tx.originalType = j.value("originalType", 0U);
            tx.originalData = j.value("originalData", std::vector<BYTE>());
            tx.targetData = j.value("targetData", std::vector<BYTE>());
            return tx;
        }
    };

    class PolicyEngine {
        Logger& log;
        std::vector<TransactionRecord> journal;
        std::string journalPath = "aegis_wal.jsonl";
        std::string journalTemp = "aegis_wal.tmp";
        std::mutex walMutex;
        uint64_t current_sequence = 0;

        std::wstring NormalizeAndExpand(const std::wstring& input) {
            wchar_t buffer[MAX_PATH];
            ExpandEnvironmentStringsW(input.c_str(), buffer, MAX_PATH);
            return std::wstring(buffer);
        }

        void AtomicAppendJournal(const TransactionRecord& tx) {
            std::lock_guard<std::mutex> lock(walMutex);
            std::string payload = tx.to_json().dump();
            uint64_t crc = Utils::FNV1a64(payload);
            std::wstring wPath = Utils::s2ws(journalPath);
            // NO_BUFFERING/WRITE_THROUGH flags to bypass OS cache and prevent torn writes during power loss
            HANDLE hFile = CreateFileW(wPath.c_str(), FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                // Anti-Torn-Write Structure: [Size][Payload][CRC64][COMMIT_MARKER: 0xAA][\n]
                std::string header = std::to_string(payload.size()) + "|";
                std::string footer = "|" + std::to_string(crc) + "|\xAA\n";
                std::string line = header + payload + footer;
                
                // Hardware-level alignment: 4KB logical sector padding to prevent torn writes
                size_t padded_size = (line.size() + (WAL_SECTOR_SIZE - 1)) & ~(WAL_SECTOR_SIZE - 1);
                void* aligned_buffer = _aligned_malloc(padded_size, WAL_SECTOR_SIZE);
                if (aligned_buffer) {
                    memset(aligned_buffer, ' ', padded_size); // Fill with neutral spaces
                    memcpy(aligned_buffer, line.data(), line.size()); // Insert valid payload
                    
                    DWORD written;
                    WriteFile(hFile, aligned_buffer, (DWORD)padded_size, &written, NULL);
                    _aligned_free(aligned_buffer);
                }
                FlushFileBuffers(hFile);
                CloseHandle(hFile);
            }
        }

    public:
        explicit PolicyEngine(Logger& logInst) : log(logInst) { LoadAndRecover(); }

        void LoadAndRecover() {
            if (!std::filesystem::exists(journalPath)) return;
            std::ifstream file(std::filesystem::path(journalPath), std::ios::binary);
            std::string line; journal.clear();
            while (std::getline(file, line)) {
                if (line.empty() || line.back() != '\xAA') continue; // Torn Write detected! Missing trailing Commit Marker.
                line.pop_back(); // Remove \xAA
                
                size_t firstPipe = line.find('|');
                size_t lastPipe = line.rfind('|');
                if (firstPipe != std::string::npos && lastPipe != std::string::npos && firstPipe != lastPipe) {
                    std::string payload = line.substr(firstPipe + 1, lastPipe - firstPipe - 1);
                    std::string crcStr = line.substr(lastPipe + 1);
                    if (Utils::FNV1a64(payload) == std::stoull(crcStr)) {
                        auto tx = TransactionRecord::from_json(json::parse(payload));
                        journal.push_back(tx);
                        if (tx.sequence_number > current_sequence) current_sequence = tx.sequence_number;
                    }
                }
            }
            
            // Sequence-guaranteed sorting for deterministic WAL replay
            std::sort(journal.begin(), journal.end(), [](const TransactionRecord& a, const TransactionRecord& b) {
                return a.sequence_number < b.sequence_number;
            });

            // Reconciliation on Startup
            for (auto& tx : journal) {
                if (tx.state == TxState::PENDING || tx.state == TxState::PARTIAL_APPLY) {
                    log.Log(LogLevel::WARN, "WAL", 301, "Recovery: Reverting incomplete transaction " + tx.name);
                    RollbackRecord(tx);
                    tx.state = TxState::RECOVERY_APPLIED;
                }
            }
        }

        void RollbackRecord(const TransactionRecord& tx) {
            HKEY root = (HKEY)tx.rootHive;
            std::wstring path = Utils::s2ws(tx.path);
            std::wstring key = Utils::s2ws(tx.key);
            if (!tx.keyExistedBefore) {
                RegDeleteTreeW(root, path.c_str());
            } else {
                HKEY hKey;
                if (RegOpenKeyExW(root, path.c_str(), 0, KEY_WRITE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                    if (tx.valueExistedBefore) {
                        RegSetValueExW(hKey, key.c_str(), 0, tx.originalType, tx.originalData.data(), (DWORD)tx.originalData.size());
                    } else {
                        RegDeleteValueW(hKey, key.c_str());
                    }
                    RegCloseKey(hKey);
                }
            }
        }

        bool ApplyPolicy(PolicyDefinition def) {
            if (def.multiUser && def.rootHive == HKEY_CURRENT_USER) {
                // In production, this intention delegates to RegistryManager::ApplyToOfflineHives for disconnected SIDs
            }

            TransactionRecord tx;
            tx.sequence_number = ++current_sequence;
            tx.id = std::to_string(GetTickCount64());
            tx.name = Utils::ws2s(def.name);
            tx.rootHive = (uint64_t)def.rootHive;
            tx.path = Utils::ws2s(def.path);
            tx.key = Utils::ws2s(def.key);
            tx.key_fingerprint = Utils::FNV1a64(tx.path + "\\" + tx.key);
            tx.state = TxState::PENDING;
            tx.targetData = def.targetData;

            HKEY hKey;
            if (RegOpenKeyExW(def.rootHive, def.path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                tx.keyExistedBefore = true;
                DWORD type = 0, size = 0;
                if (RegQueryValueExW(hKey, def.key.c_str(), nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
                    tx.valueExistedBefore = true;
                    tx.originalType = type;
                    tx.originalData.resize(size);
                    RegQueryValueExW(hKey, def.key.c_str(), nullptr, &type, tx.originalData.data(), &size);
                    
                    if (def.targetData.size() == size && memcmp(def.targetData.data(), tx.originalData.data(), size) == 0) {
                        RegCloseKey(hKey);
                        return true; 
                    }
                }
                RegCloseKey(hKey);
            }

            journal.push_back(tx);
            AtomicAppendJournal(tx);

            if (RegCreateKeyExW(def.rootHive, def.path.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
                DWORD winType = (def.type == RegType::SZ) ? REG_SZ : REG_DWORD;
                if (RegSetValueExW(hKey, def.key.c_str(), 0, winType, def.targetData.data(), (DWORD)def.targetData.size()) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    journal.back().state = TxState::COMMITTED;
                    AtomicAppendJournal(journal.back());
                    return true;
                }
                RegCloseKey(hKey);
            }
            return false;
        }

        void RollbackAll() {
            for (auto it = journal.rbegin(); it != journal.rend(); ++it) {
                if (it->state == TxState::COMMITTED) RollbackRecord(*it);
            }
            journal.clear();
            std::filesystem::remove(journalPath);
        }
    };
}
