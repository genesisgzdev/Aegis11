        bool RestoreRegistryValue(HKEY root, const std::wstring& path, const std::wstring& valueName,
                                  bool shouldExist, DWORD desiredType, const std::vector<BYTE>& desiredData,
                                  REGSAM view) {
            (void)view;
            if (shouldExist) {
                PolicyDefinition definition{};
                definition.name = L"snapshot-restore " + valueName;
                definition.rootHive = root;
                definition.path = path;
                definition.key = valueName;
                definition.targetData = desiredData;
                switch (desiredType) {
                    case REG_DWORD: definition.type = RegType::DWORD; break;
                    case REG_QWORD: definition.type = RegType::QWORD; break;
                    case REG_SZ: definition.type = RegType::SZ; break;
                    case REG_EXPAND_SZ: definition.type = RegType::EXPAND_SZ; break;
                    case REG_MULTI_SZ: definition.type = RegType::MULTI_SZ; break;
                    default: definition.type = RegType::BINARY; break;
                }
                return ApplyPolicy(definition);
            }

            TransactionRecord tx{};
            tx.sequence_number = ++current_sequence;
            tx.id = "tx-" + std::to_string(tx.sequence_number);
            tx.name = "snapshot-restore-absent " + Utils::ws2s(valueName);
            tx.rootHive = (uint64_t)root;
            tx.path = Utils::ws2s(path);
            tx.key = Utils::ws2s(valueName);
            tx.key_fingerprint = Utils::FNV1a64(tx.path + "\\" + tx.key);
            tx.state = TxState::PENDING;
            tx.targetType = REG_NONE;

            HKEY hKey = nullptr;
            const LONG openResult = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hKey);
            if (openResult == ERROR_FILE_NOT_FOUND || openResult == ERROR_PATH_NOT_FOUND) {
                return true;
            }
            if (openResult != ERROR_SUCCESS) {
                log.Log(LogLevel::ERR, "WAL", 314, "Cannot open registry key for absence restore.");
                return false;
            }
            tx.keyExistedBefore = true;
            DWORD type = 0, size = 0;
            const LONG query = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, nullptr, &size);
            if (query == ERROR_FILE_NOT_FOUND) {
                RegCloseKey(hKey);
                return true;
            }
            if (query != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return false;
            }
            tx.valueExistedBefore = true;
            tx.originalType = type;
            tx.originalData.resize(size);
            DWORD readSize = size;
            if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type,
                    tx.originalData.empty() ? nullptr : tx.originalData.data(), &readSize) != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return false;
            }
            tx.originalData.resize(readSize);
            journal.push_back(tx);
            if (!AtomicAppendJournal(tx)) {
                journal.pop_back();
                RegCloseKey(hKey);
                return false;
            }
            const LONG deleted = RegDeleteValueW(hKey, valueName.c_str());
            RegCloseKey(hKey);
            if (deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND) {
                journal.back().state = TxState::PARTIAL_APPLY;
                AtomicAppendJournal(journal.back());
                const bool rolledBack = RollbackRecord(journal.back());
                journal.back().state = rolledBack ? TxState::ROLLED_BACK : TxState::FAILED;
                AtomicAppendJournal(journal.back());
                return false;
            }
            journal.back().state = TxState::COMMITTED;
            if (AtomicAppendJournal(journal.back())) return true;
            const bool rolledBack = RollbackRecord(journal.back());
            journal.back().state = rolledBack ? TxState::ROLLED_BACK : TxState::FAILED;
            AtomicAppendJournal(journal.back());
            return false;
        }
