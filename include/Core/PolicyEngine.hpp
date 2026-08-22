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
#include <unordered_map>
#include <algorithm>
#include <limits>
#include <exception>
#include <cstring>
#include <malloc.h>

#define AEGIS_ENGINE_VERSION "0.1.2"
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
        uint32_t targetType = REG_BINARY;
        std::vector<BYTE> targetData;

        json to_json() const {
            return json{
                {"seq", sequence_number}, {"fpr", key_fingerprint}, {"id", id}, {"name", name}, 
                {"eng_v", engine_version}, {"pol_v", policy_version}, {"rootHive", rootHive}, 
                {"path", path}, {"key", key}, {"state", static_cast<int>(state)}, {"keyExistedBefore", keyExistedBefore},
                {"valueExistedBefore", valueExistedBefore}, {"originalType", originalType},
                {"originalData", originalData}, {"targetType", targetType}, {"targetData", targetData}
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
            tx.targetType = j.value("targetType", REG_BINARY);
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

        bool AtomicAppendJournal(const TransactionRecord& tx) {
            std::lock_guard<std::mutex> lock(walMutex);
            std::string payload = tx.to_json().dump();
            uint64_t crc = Utils::FNV1a64(payload);
            std::wstring wPath = Utils::s2ws(journalPath);
            // NO_BUFFERING/WRITE_THROUGH flags to bypass OS cache and prevent torn writes during power loss
            HANDLE hFile = CreateFileW(wPath.c_str(), FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return false;
            bool ok = false;
            {
                // Anti-Torn-Write Structure: [Size][Payload][CRC64][COMMIT_MARKER: 0xAA][\n]
                std::string header = std::to_string(payload.size()) + "|";
                std::string footer = "|" + std::to_string(crc) + "|\xAA\n";
                std::string line = header + payload + footer;
                
                // Hardware-level alignment: 4KB logical sector padding to prevent torn writes
                size_t padded_size = (line.size() + (WAL_SECTOR_SIZE - 1)) & ~(WAL_SECTOR_SIZE - 1);
                if (padded_size > std::numeric_limits<DWORD>::max()) {
                    CloseHandle(hFile);
                    return false;
                }
                void* aligned_buffer = _aligned_malloc(padded_size, WAL_SECTOR_SIZE);
                if (aligned_buffer) {
                    memset(aligned_buffer, ' ', padded_size); // Fill with neutral spaces
                    memcpy(aligned_buffer, line.data(), line.size()); // Insert valid payload
                    
                    DWORD written;
                    ok = WriteFile(hFile, aligned_buffer, (DWORD)padded_size, &written, NULL) && written == padded_size;
                    _aligned_free(aligned_buffer);
                }
                ok = ok && FlushFileBuffers(hFile);
            }
            ok = CloseHandle(hFile) && ok;
            return ok;
        }

    public:
        explicit PolicyEngine(Logger& logInst) : log(logInst) { LoadAndRecover(); }

        void LoadAndRecover() {
            if (!std::filesystem::exists(journalPath)) return;
            std::ifstream file(std::filesystem::path(journalPath), std::ios::binary);
            std::string line; journal.clear();
            while (std::getline(file, line)) {
                line.erase(0, line.find_first_not_of(' '));
                if (line.empty() || line.back() != '\xAA') continue; // Torn Write detected! Missing trailing Commit Marker.
                line.pop_back(); // Remove \xAA
                
                size_t firstPipe = line.find('|');
                if (firstPipe != std::string::npos) {
                    try {
                        const size_t payloadSize = std::stoull(line.substr(0, firstPipe));
                        const size_t payloadStart = firstPipe + 1;
                        const size_t crcSeparator = payloadStart + payloadSize;
                        const size_t crcEnd = line.find('|', crcSeparator + 1);
                        if (crcEnd == std::string::npos || crcSeparator >= line.size() || line[crcSeparator] != '|' || crcEnd + 1 != line.size()) {
                            continue;
                        }
                        std::string payload = line.substr(payloadStart, payloadSize);
                        std::string crcStr = line.substr(crcSeparator + 1, crcEnd - crcSeparator - 1);
                        if (std::stoull(crcStr) == Utils::FNV1a64(payload)) {
                            auto tx = TransactionRecord::from_json(json::parse(payload));
                            journal.push_back(tx);
                            if (tx.sequence_number > current_sequence) current_sequence = tx.sequence_number;
                        }
                    } catch (const std::exception&) {
                        log.Log(LogLevel::WARN, "WAL", 302, "Ignoring malformed journal record during recovery.");
                    }
                }
            }
            
            // Sequence-guaranteed sorting for deterministic WAL replay.
            std::sort(journal.begin(), journal.end(), [](const TransactionRecord& a, const TransactionRecord& b) {
                return a.sequence_number < b.sequence_number;
            });

            // A transaction writes more than one record (PENDING, then COMMITTED
            // or a recovery result). Replay only its latest durable state. If
            // this collapse is skipped, a successful transaction is followed by
            // its historical PENDING record and gets rolled back on every boot.
            std::vector<TransactionRecord> latest;
            std::unordered_map<std::string, size_t> latestById;
            for (const auto& tx : journal) {
                if (tx.id.empty()) {
                    latest.push_back(tx);
                    continue;
                }
                const auto found = latestById.find(tx.id);
                if (found == latestById.end()) {
                    latestById.emplace(tx.id, latest.size());
                    latest.push_back(tx);
                } else {
                    latest[found->second] = tx;
                }
            }
            journal = std::move(latest);
            std::sort(journal.begin(), journal.end(), [](const TransactionRecord& a, const TransactionRecord& b) {
                return a.sequence_number < b.sequence_number;
            });

            // Reconciliation on Startup
            for (auto& tx : journal) {
                if (tx.state == TxState::PENDING || tx.state == TxState::PARTIAL_APPLY) {
                    log.Log(LogLevel::WARN, "WAL", 301, "Recovery: Reverting incomplete transaction " + tx.name);
                    const bool recovered = RollbackRecord(tx);
                    tx.state = recovered ? TxState::RECOVERY_APPLIED : TxState::FAILED;
                    if (!AtomicAppendJournal(tx)) {
                        log.Log(LogLevel::ERR, "WAL", 305, "Unable to persist recovery result for transaction " + tx.name);
                    }
                }
            }
        }

        bool RollbackRecord(const TransactionRecord& tx) {
            HKEY root = (HKEY)tx.rootHive;
            std::wstring path = Utils::s2ws(tx.path);
            std::wstring key = Utils::s2ws(tx.key);
            HKEY hKey;
            const LONG openResult = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hKey);
            if (openResult == ERROR_FILE_NOT_FOUND || openResult == ERROR_PATH_NOT_FOUND) {
                return !tx.keyExistedBefore;
            }
            if (openResult != ERROR_SUCCESS) return false;

            DWORD currentType = 0;
            DWORD currentSize = 0;
            const LONG querySize = RegQueryValueExW(hKey, key.c_str(), nullptr, &currentType, nullptr, &currentSize);
            if (querySize == ERROR_FILE_NOT_FOUND) {
                RegCloseKey(hKey);
                return !tx.valueExistedBefore;
            }
            if (querySize != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return false;
            }

            std::vector<BYTE> currentData(currentSize);
            const LONG queryData = RegQueryValueExW(hKey, key.c_str(), nullptr, &currentType, currentData.data(), &currentSize);
            if (queryData != ERROR_SUCCESS || currentType != tx.targetType || currentSize != tx.targetData.size() ||
                (currentSize != 0 && memcmp(currentData.data(), tx.targetData.data(), currentSize) != 0)) {
                // Do not overwrite a value that changed after this transaction.
                RegCloseKey(hKey);
                return false;
            }

            LONG result = ERROR_SUCCESS;
            if (tx.keyExistedBefore) {
                if (tx.valueExistedBefore) {
                    result = RegSetValueExW(hKey, key.c_str(), 0, tx.originalType, tx.originalData.data(), (DWORD)tx.originalData.size());
                } else {
                    result = RegDeleteValueW(hKey, key.c_str());
                }
            } else {
                // Remove only the value created by this transaction. The key is
                // deleted only when Windows confirms that nothing else remains.
                result = RegDeleteValueW(hKey, key.c_str());
            }
            RegCloseKey(hKey);
            if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) return false;
            if (!tx.keyExistedBefore) {
                const LONG deleteKey = RegDeleteKeyW(root, path.c_str());
                return deleteKey == ERROR_SUCCESS || deleteKey == ERROR_FILE_NOT_FOUND || deleteKey == ERROR_PATH_NOT_FOUND || deleteKey == ERROR_DIR_NOT_EMPTY;
            }
            return true;
        }

        bool ApplyPolicy(PolicyDefinition def) {
            TransactionRecord tx;
            tx.sequence_number = ++current_sequence;
            // Sequence numbers are already durable and monotonic. Using the
            // clock alone can collide when two policies start in one tick,
            // which would make recovery collapse unrelated transactions.
            tx.id = "tx-" + std::to_string(tx.sequence_number);
            tx.name = Utils::ws2s(def.name);
            tx.rootHive = (uint64_t)def.rootHive;
            tx.path = Utils::ws2s(def.path);
            tx.key = Utils::ws2s(def.key);
            tx.key_fingerprint = Utils::FNV1a64(tx.path + "\\" + tx.key);
            tx.state = TxState::PENDING;
            switch (def.type) {
                case RegType::DWORD: tx.targetType = REG_DWORD; break;
                case RegType::QWORD: tx.targetType = REG_QWORD; break;
                case RegType::SZ: tx.targetType = REG_SZ; break;
                case RegType::EXPAND_SZ: tx.targetType = REG_EXPAND_SZ; break;
                case RegType::MULTI_SZ: tx.targetType = REG_MULTI_SZ; break;
                case RegType::BINARY: tx.targetType = REG_BINARY; break;
            }
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
                    
                    if (type == tx.targetType && def.targetData.size() == size &&
                        memcmp(def.targetData.data(), tx.originalData.data(), size) == 0) {
                        RegCloseKey(hKey);
                        return true; 
                    }
                }
                RegCloseKey(hKey);
            }

            journal.push_back(tx);
            if (!AtomicAppendJournal(tx)) {
                log.Log(LogLevel::ERR, "WAL", 303, "Unable to durably append pending transaction; policy was not applied.");
                journal.pop_back();
                return false;
            }

            if (RegCreateKeyExW(def.rootHive, def.path.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
                DWORD winType = REG_BINARY;
                switch (def.type) {
                    case RegType::DWORD: winType = REG_DWORD; break;
                    case RegType::QWORD: winType = REG_QWORD; break;
                    case RegType::SZ: winType = REG_SZ; break;
                    case RegType::EXPAND_SZ: winType = REG_EXPAND_SZ; break;
                    case RegType::MULTI_SZ: winType = REG_MULTI_SZ; break;
                    case RegType::BINARY: winType = REG_BINARY; break;
                }
                if (RegSetValueExW(hKey, def.key.c_str(), 0, winType, def.targetData.data(), (DWORD)def.targetData.size()) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    journal.back().state = TxState::COMMITTED;
                    if (AtomicAppendJournal(journal.back())) return true;
                    log.Log(LogLevel::FATAL, "WAL", 304, "Unable to durably append committed transaction; reverting policy.");
                    const bool rolledBack = RollbackRecord(journal.back());
                    journal.back().state = rolledBack ? TxState::ROLLED_BACK : TxState::FAILED;
                    if (!AtomicAppendJournal(journal.back())) {
                        log.Log(LogLevel::ERR, "WAL", 306, "Unable to persist the failed commit recovery result.");
                    }
                    return false;
                }
                RegCloseKey(hKey);
                // The mutation did not reach the requested value. Record the
                // partial state and compensate before returning so the current
                // process does not continue with an untracked registry change.
                journal.back().state = TxState::PARTIAL_APPLY;
                AtomicAppendJournal(journal.back());
                const bool rolledBack = RollbackRecord(journal.back());
                journal.back().state = rolledBack ? TxState::ROLLED_BACK : TxState::FAILED;
                if (!AtomicAppendJournal(journal.back())) {
                    log.Log(LogLevel::ERR, "WAL", 307, "Unable to persist the registry write failure result.");
                }
                return false;
            }
            // A pending record must not be left as the only durable outcome
            // when the target key could not be opened or created.
            journal.back().state = TxState::FAILED;
            if (!AtomicAppendJournal(journal.back())) {
                log.Log(LogLevel::ERR, "WAL", 308, "Unable to persist the registry open failure result.");
            }
            return false;
        }

        bool RollbackAll() {
            bool allRolledBack = true;
            for (auto it = journal.rbegin(); it != journal.rend(); ++it) {
                if (it->state != TxState::COMMITTED) continue;
                if (!RollbackRecord(*it)) {
                    allRolledBack = false;
                    it->state = TxState::FAILED;
                    if (!AtomicAppendJournal(*it)) {
                        log.Log(LogLevel::ERR, "WAL", 309, "Unable to persist an interactive rollback failure.");
                    }
                    continue;
                }
                it->state = TxState::ROLLED_BACK;
                if (!AtomicAppendJournal(*it)) {
                    allRolledBack = false;
                    log.Log(LogLevel::ERR, "WAL", 310, "Unable to persist an interactive rollback result.");
                }
            }
            if (!allRolledBack) {
                log.Log(LogLevel::ERR, "WAL", 311, "Rollback incomplete; the WAL was retained for another recovery attempt.");
                return false;
            }
            std::error_code removeError;
            const bool removed = std::filesystem::remove(journalPath, removeError);
            if (removeError || (!removed && std::filesystem::exists(journalPath))) {
                log.Log(LogLevel::ERR, "WAL", 312, "Rollback completed but the WAL could not be removed.");
                return false;
            }
            journal.clear();
            return true;
        }
    };
}
