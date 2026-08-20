from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(path: str, text: str) -> None:
    content = (ROOT / path).read_text(encoding="utf-8-sig")
    if text not in content:
        raise AssertionError(f"{path} does not contain required marker: {text}")


require("CMakeLists.txt", 'project(Aegis11 VERSION 1.0.0 LANGUAGES CXX RC)')
require("CMakeLists.txt", 'add_executable(aegis11 WIN32')
require("include/Core/Logger.hpp", 'EscapeJsonString')
require("include/Modules/NetworkWfp.hpp", 'FwpmFilterAdd0')
require("include/Core/PolicyEngine.hpp", 'written == padded_size')

for path in ROOT.rglob("*"):
    if path.is_file() and path.suffix in {".cpp", ".hpp", ".h", ".bat", ".yml", ".yaml"}:
        content = path.read_text(encoding="utf-8-sig")
        if "Simulating build" in content:
            raise AssertionError(f"placeholder build remains in {path}")

print("Aegis11 repository compile checks: OK")
