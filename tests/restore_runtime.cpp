#include "Core/PolicyEngine.hpp"
#include "Core/StateEngine.hpp"
#include "Modules/RegistryManager.hpp"
#include "Modules/ServiceManager.hpp"
#include "Modules/TaskManager.hpp"
#include <stdexcept>
#include <iostream>
#include <fstream>

using namespace Aegis::Core;
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::vector<BYTE> bytes(DWORD value) {
    const auto* begin = reinterpret_cast<const BYTE*>(&value);
    return {begin, begin + sizeof(value)};
}
DWORD readOrMissing(const std::wstring& path, const wchar_t* name, bool& exists) {
    DWORD value = 0, size = sizeof(value);
    const LONG result = RegGetValueW(HKEY_CURRENT_USER, path.c_str(), name, RRF_RT_REG_DWORD, nullptr, &value, &size);
    exists = result == ERROR_SUCCESS;
    return value;
}
int main() {
    const auto cwd = std::filesystem::current_path();
    const auto directory = std::filesystem::temp_directory_path() / ("aegis-restore-test-" + std::to_string(GetCurrentProcessId()));
    const auto key = L"Software\\Aegis11RestoreTests\\" + std::to_wstring(GetCurrentProcessId());
    std::filesystem::create_directories(directory);
    std::filesystem::current_path(directory);
    int code = 0;
    try {
        Logger logger;
        PolicyEngine engine(logger);
        bool exists = false;
        require(engine.RestoreRegistryValue(HKEY_CURRENT_USER, key, L"Owned", true, REG_DWORD, bytes(11), KEY_WOW64_64KEY), "restore create");
        require(readOrMissing(key, L"Owned", exists) == 11 && exists, "created value missing");
        require(engine.RestoreRegistryValue(HKEY_CURRENT_USER, key, L"Owned", false, REG_NONE, {}, KEY_WOW64_64KEY), "restore absence");
        readOrMissing(key, L"Owned", exists);
        require(!exists, "absence restore left the value");
        require(engine.RestoreRegistryValue(HKEY_CURRENT_USER, key, L"Owned", true, REG_DWORD, bytes(7), KEY_WOW64_64KEY), "restore recreate");
        require(readOrMissing(key, L"Owned", exists) == 7 && exists, "recreate mismatch");

        Aegis::Modules::ServiceManager services(logger);
        Aegis::Modules::RegistryManager registry(logger);
        Aegis::Modules::TaskManager tasks(logger);
        Aegis::Engine::StateController state(logger, services, registry, tasks);
        const auto rejected = directory / "bad-schema.json";
        {
            std::ofstream out(rejected);
            out << R"({"schemaVersion":"9","timestamp":"x","osVersion":"10.0.1","services":{},"registry":{},"tasks":{}})";
        }
        require(!state.RestoreBaseline(rejected.string(), engine), "incompatible schema must fail");
        std::cout << "Native snapshot restore tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        code = 1;
    }
    RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
    std::filesystem::current_path(cwd);
    std::filesystem::remove_all(directory);
    return code;
}
