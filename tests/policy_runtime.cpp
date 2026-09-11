#include "Core/PolicyEngine.hpp"
#include <stdexcept>
#include <iostream>

using namespace Aegis::Core;
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::vector<BYTE> bytes(DWORD value) {
    const auto* begin = reinterpret_cast<const BYTE*>(&value);
    return {begin, begin + sizeof(value)};
}
void write(const std::wstring& path, const wchar_t* name, DWORD value) {
    HKEY key = nullptr;
    require(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                           nullptr, &key, nullptr) == ERROR_SUCCESS, "create test key");
    const LONG result = RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
    require(result == ERROR_SUCCESS, "write test value");
}
DWORD read(const std::wstring& path, const wchar_t* name) {
    DWORD value = 0, size = sizeof(value);
    require(RegGetValueW(HKEY_CURRENT_USER, path.c_str(), name, RRF_RT_REG_DWORD, nullptr,
                         &value, &size) == ERROR_SUCCESS, "read test value");
    return value;
}
int main() {
    const auto cwd = std::filesystem::current_path();
    const auto directory = std::filesystem::temp_directory_path() / ("aegis-policy-test-" + std::to_string(GetCurrentProcessId()));
    const auto key = L"Software\\Aegis11Tests\\" + std::to_wstring(GetCurrentProcessId());
    std::filesystem::create_directories(directory);
    std::filesystem::current_path(directory);
    int code = 0;
    try {
        Logger logger;
        PolicyDefinition definition{L"runtime test", HKEY_CURRENT_USER, key, L"Owned", RegType::DWORD, bytes(1)};
        {
            PolicyEngine engine(logger);
            require(engine.ApplyPolicy(definition), "apply absent value");
            write(key, L"OtherWriter", 42);
            require(engine.RollbackAll(), "rollback created value");
            require(read(key, L"OtherWriter") == 42, "rollback erased unrelated state");
        }
        write(key, L"Owned", 7);
        {
            PolicyEngine engine(logger);
            require(engine.ApplyPolicy(definition), "apply existing value");
            write(key, L"Owned", 99);
            require(!engine.RollbackAll(), "conflict must fail");
            require(!engine.RollbackAll(), "retry must retain conflict");
            require(std::filesystem::exists("aegis_wal.jsonl"), "failed recovery discarded WAL");
            write(key, L"Owned", 1);
            require(engine.RollbackAll(), "retry compensation");
            require(read(key, L"Owned") == 7, "original value not restored");
        }
        {
            PolicyEngine engine(logger);
            require(engine.ApplyPolicy(definition), "persist commit");
        }
        {
            PolicyEngine reopened(logger);
            require(read(key, L"Owned") == 1, "recovery replayed historical PENDING record");
            require(reopened.RollbackAll(), "rollback reopened journal");
            require(read(key, L"Owned") == 7, "reopened preimage mismatch");
        }
        std::cout << "Native registry recovery tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        code = 1;
    }
    RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
    std::filesystem::current_path(cwd);
    std::filesystem::remove_all(directory);
    return code;
}
