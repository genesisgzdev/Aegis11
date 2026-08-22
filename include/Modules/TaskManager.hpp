#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Utils.hpp"
#include "../Core/State.hpp"
#include <taskschd.h>
#include <comdef.h>
#include <string>

namespace Aegis::Modules {
    class TaskManager {
        Core::Logger& log;
        Core::ComPtr<ITaskService> pService;

    public:
        explicit TaskManager(Core::Logger& logger) : log(logger) {
            CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)pService.ReleaseAndGetAddressOf());
            if (pService) pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        }

        void Snapshot(Core::SystemSnapshot& snapshot) {
            if (!pService) return;
            Core::ComPtr<ITaskFolder> root;
            if (FAILED(pService->GetFolder(_bstr_t(L"\\"), root.ReleaseAndGetAddressOf()))) return;
            const wchar_t* knownTasks[] = {
                L"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
                L"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater"
            };
            for (const auto* path : knownTasks) {
                Core::ComPtr<IRegisteredTask> task;
                const std::string key = Core::Utils::ws2s(path);
                if (FAILED(root->GetTask(_bstr_t(path), task.ReleaseAndGetAddressOf()))) {
                    snapshot.tasks[key] = Core::TaskState{key, false, false};
                    continue;
                }
                VARIANT_BOOL enabled = VARIANT_FALSE;
                if (SUCCEEDED(task->get_Enabled(&enabled))) {
                    Core::TaskState state{key, enabled == VARIANT_TRUE, true, ""};
                    BSTR xml = nullptr;
                    if (SUCCEEDED(task->get_Xml(&xml)) && xml != nullptr) {
                        state.xml = Core::Utils::ws2s(std::wstring(xml, SysStringLen(xml)));
                        SysFreeString(xml);
                    }
                    snapshot.tasks[key] = std::move(state);
                }
            }
        }

        void DisableTelemetryTasks() {
            log.Log(Core::LogLevel::INFO, "TASK", 100, "Validating task executable path and Authenticode signature...");
            if (!pService) return;

            Core::ComPtr<ITaskFolder> pRootFolder;
            if (FAILED(pService->GetFolder(_bstr_t(L"\\"), pRootFolder.ReleaseAndGetAddressOf()))) return;

            const wchar_t* knownTasks[] = {
                L"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
                L"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater"
            };

            for (const auto& path : knownTasks) {
                Core::ComPtr<IRegisteredTask> pTask;
                if (SUCCEEDED(pRootFolder->GetTask(_bstr_t(path), pTask.ReleaseAndGetAddressOf()))) {
                    Core::ComPtr<ITaskDefinition> pDef;
                    if (SUCCEEDED(pTask->get_Definition(pDef.ReleaseAndGetAddressOf()))) {
                        
                        // Extract Execution Path
                        Core::ComPtr<IActionCollection> pActions;
                        Core::ComPtr<IAction> pAction;
                        std::wstring exePath = L"";
                        if (SUCCEEDED(pDef->get_Actions(pActions.ReleaseAndGetAddressOf()))) {
                            if (SUCCEEDED(pActions->get_Item(1, pAction.ReleaseAndGetAddressOf()))) {
                                Core::ComPtr<IExecAction> pExecAction;
                                if (SUCCEEDED(pAction->QueryInterface(IID_IExecAction, (void**)pExecAction.ReleaseAndGetAddressOf()))) {
                                    BSTR bstrPath = NULL;
                                    if (SUCCEEDED(pExecAction->get_Path(&bstrPath)) && bstrPath != NULL) {
                                        exePath = std::wstring(bstrPath, SysStringLen(bstrPath));
                                        SysFreeString(bstrPath);
                                    }
                                }
                            }
                        }

                        // A task author is metadata supplied by the task XML;
                        // a substring such as "Microsoft" is not an identity.
                        // Require a real executable under System32 and a valid
                        // Authenticode signature before changing task state.
                        wchar_t windir[MAX_PATH] = {};
                        ExpandEnvironmentStringsW(L"%WINDIR%\\System32", windir, MAX_PATH);
                        const std::wstring system32(windir);
                        const bool pathTrust = !exePath.empty()
                            && exePath.size() > system32.size()
                            && _wcsnicmp(exePath.c_str(), system32.c_str(), system32.size()) == 0
                            && (exePath[system32.size()] == L'\\' || exePath[system32.size()] == L'/');
                        const bool sigMatch = pathTrust && Core::Utils::VerifyDigitalSignature(exePath);

                        if (sigMatch) {
                            pTask->put_Enabled(VARIANT_FALSE);
                            log.Log(Core::LogLevel::INFO, "TASK", 200, "Disabled verified task: " + Core::Utils::ws2s(path));
                        } else {
                            log.Log(Core::LogLevel::WARN, "TASK", 400, "Skipped task (Failed Trust Validation): " + Core::Utils::ws2s(path));
                        }
                    }
                }
            }
        }
    };
}
