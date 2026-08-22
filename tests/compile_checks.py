from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(path: str, text: str) -> None:
    content = (ROOT / path).read_text(encoding="utf-8-sig")
    if text not in content:
        raise AssertionError(f"{path} does not contain required marker: {text}")

require("CMakeLists.txt", 'project(Aegis11 VERSION 0.1.1 LANGUAGES CXX RC)')
require("include/Core/PolicyEngine.hpp", '#define AEGIS_ENGINE_VERSION "0.1.1"')
require("include/Core/PolicyEngine.hpp", 'case RegType::QWORD: winType = REG_QWORD; break;')
require("include/Core/PolicyEngine.hpp", 'case RegType::MULTI_SZ: winType = REG_MULTI_SZ; break;')
require("CMakeLists.txt", 'add_executable(aegis11\n')
require("include/Core/Logger.hpp", 'EscapeJsonString')
require("include/Modules/NetworkWfp.hpp", 'FwpmFilterAdd0')
require("include/Core/PolicyEngine.hpp", 'written == padded_size')
require("include/Core/PolicyEngine.hpp", 'const size_t crcSeparator = payloadStart + payloadSize;')
require("include/Core/PolicyEngine.hpp", 'tx.state = recovered ? TxState::RECOVERY_APPLIED : TxState::FAILED;')
require("include/Core/PolicyEngine.hpp", 'const LONG result = RegDeleteTreeW(root, path.c_str());')

for path in ROOT.rglob("*"):
    if path.is_file() and path.suffix in {".cpp", ".hpp", ".h", ".bat", ".yml", ".yaml"}:
        content = path.read_text(encoding="utf-8-sig")
        if "Simulating build" in content:
            raise AssertionError(f"placeholder build remains in {path}")

print("Aegis11 repository compile checks: OK")
