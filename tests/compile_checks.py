from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(path: str, text: str) -> None:
    content = (ROOT / path).read_text(encoding="utf-8-sig")
    if text not in content:
        raise AssertionError(f"{path} does not contain required marker: {text}")

require("CMakeLists.txt", 'project(Aegis11 VERSION 0.1.2 LANGUAGES CXX RC)')
require("include/Core/PolicyEngine.hpp", '#define AEGIS_ENGINE_VERSION "0.1.2"')
require("include/Core/PolicyEngine.hpp", 'case RegType::QWORD: winType = REG_QWORD; break;')
require("include/Core/PolicyEngine.hpp", 'case RegType::MULTI_SZ: winType = REG_MULTI_SZ; break;')
require("CMakeLists.txt", 'add_executable(aegis11\n')
require("include/Core/Logger.hpp", 'EscapeJsonString')
require("include/Modules/NetworkWfp.hpp", 'FwpmFilterAdd0')
require("include/Core/PolicyEngine.hpp", 'written == padded_size')
require("include/Core/PolicyEngine.hpp", 'const size_t crcSeparator = payloadStart + payloadSize;')
require("include/Core/PolicyEngine.hpp", 'currentType != tx.targetType || currentSize != tx.targetData.size()')
require("include/Core/PolicyEngine.hpp", 'Do not overwrite a value that changed after this transaction.')
require("include/Core/PolicyEngine.hpp", 'RegDeleteKeyW(root, path.c_str())')
require("include/Core/PolicyEngine.hpp", 'tx.state = recovered ? TxState::RECOVERY_APPLIED : TxState::FAILED;')
require("include/Core/PolicyEngine.hpp", 'latestById')
require("include/Core/PolicyEngine.hpp", 'tx-" + std::to_string(tx.sequence_number)')
require("include/Core/PolicyEngine.hpp", 'Unable to persist the failed commit recovery result.')
require("include/Core/PolicyEngine.hpp", 'Unable to persist the registry write failure result.')
require("include/Core/PolicyEngine.hpp", 'journal.back().state = TxState::PARTIAL_APPLY;')
require("include/Core/PolicyEngine.hpp", 'journal.back().state = TxState::FAILED;')
require("include/Core/PolicyEngine.hpp", 'the WAL was retained for another recovery attempt.')
require("include/Core/PolicyEngine.hpp", 'the WAL could not be removed.')
require("include/Core/StateEngine.hpp", 'SysInfo::GetCapabilities')
require("include/Core/StateEngine.hpp", 'MOVEFILE_WRITE_THROUGH')
require("include/Modules/TaskManager.hpp", 'Core::Utils::VerifyDigitalSignature(exePath)')
require("src/main.cpp", '"[!] --apply is disabled: service mutations are not journaled with rollback parity yet.')
require("include/UI/InteractiveShell.hpp", '"[!] Balanced is disabled: service, task and Appx mutations do not yet share a journaled rollback plan.')
require("include/UI/InteractiveShell.hpp", '"[!] Aggressive is disabled: it includes non-journaled and potentially irreversible operations.')
if 'svc.EnforcePolicy(false)' in (ROOT / "include/UI/InteractiveShell.hpp").read_text(encoding="utf-8-sig"):
    raise AssertionError("interactive profiles must not mutate services outside the journal")
if 'tasks.DisableTelemetryTasks()' in (ROOT / "include/UI/InteractiveShell.hpp").read_text(encoding="utf-8-sig"):
    raise AssertionError("interactive profiles must not mutate tasks outside the journal")
if 'authorMatch || sigMatch' in (ROOT / "include/Modules/TaskManager.hpp").read_text(encoding="utf-8-sig"):
    raise AssertionError("task trust must not accept author metadata without signature verification")
if 'Windows 11 (Dynamic)' in (ROOT / "include/Core/StateEngine.hpp").read_text(encoding="utf-8-sig"):
    raise AssertionError("snapshot must not contain a hardcoded operating-system version")

for path in ROOT.rglob("*"):
    if path.is_file() and path.suffix in {".cpp", ".hpp", ".h", ".bat", ".yml", ".yaml"}:
        content = path.read_text(encoding="utf-8-sig")
        if "Simulating build" in content:
            raise AssertionError(f"placeholder build remains in {path}")

print("Aegis11 repository compile checks: OK")
