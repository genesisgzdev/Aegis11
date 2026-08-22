from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(path: str, text: str) -> None:
    content = (ROOT / path).read_text(encoding="utf-8-sig")
    if text not in content:
        raise AssertionError(f"{path} does not contain required marker: {text}")

require("CMakeLists.txt", 'project(Aegis11 VERSION 0.1.2 LANGUAGES CXX RC)')
require("include/Core/PolicyEngine.hpp", '#define AEGIS_ENGINE_VERSION "0.1.2"')
require("include/Core/PolicyEngine.hpp", 'case RegType::QWORD: tx.targetType = REG_QWORD; break;')
require("include/Core/PolicyEngine.hpp", 'case RegType::MULTI_SZ: tx.targetType = REG_MULTI_SZ; break;')
require("CMakeLists.txt", 'add_executable(aegis11\n')
require("include/Core/Logger.hpp", 'EscapeJsonString')
require("include/Modules/NetworkWfp.hpp", 'FwpmFilterAdd0')
require("include/Core/PolicyEngine.hpp", 'written == padded_size')
require("include/Core/PolicyEngine.hpp", 'const size_t crcSeparator = payloadStart + payloadSize;')
require("include/Core/PolicyEngine.hpp", 'tx.state = recovered ? TxState::RECOVERY_APPLIED : TxState::FAILED;')
require("include/Core/PolicyEngine.hpp", 'tx.state = TxState::CONFLICT;')
require("include/Core/PolicyEngine.hpp", 'bool* conflictDetected = nullptr')
require("include/Core/PolicyEngine.hpp", 'latestById')
require("include/Core/PolicyEngine.hpp", 'tx-" + std::to_string(tx.sequence_number)')
require("include/Core/PolicyEngine.hpp", 'Unable to persist the failed commit recovery result.')
require("include/Core/PolicyEngine.hpp", 'Never overwrite a value changed by another actor')
require("include/Core/PolicyEngine.hpp", 'targetType')
require("include/Core/PolicyEngine.hpp", 'const LONG deleteKeyResult = RegDeleteTreeW(root, path.c_str());')
require("include/Core/StateEngine.hpp", 'SysInfo::GetCapabilities')
require("include/Core/StateEngine.hpp", 'MOVEFILE_WRITE_THROUGH')
if 'Windows 11 (Dynamic)' in (ROOT / "include/Core/StateEngine.hpp").read_text(encoding="utf-8-sig"):
    raise AssertionError("snapshot must not contain a hardcoded operating-system version")

for path in ROOT.rglob("*"):
    if path.is_file() and path.suffix in {".cpp", ".hpp", ".h", ".bat", ".yml", ".yaml"}:
        content = path.read_text(encoding="utf-8-sig")
        if "Simulating build" in content:
            raise AssertionError(f"placeholder build remains in {path}")

print("Aegis11 repository compile checks: OK")
