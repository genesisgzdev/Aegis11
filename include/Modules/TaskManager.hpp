#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Utils.hpp"
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

        void DisableTelemetryTasks() {
            log.Log(Core::LogLevel::INFO, "TASK", 100, "Validating tasks via WinVerifyTrust & Author...");
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

                        // Validate Author
                        Core::ComPtr<IRegistrationInfo> pRegInfo;
                        if (SUCCEEDED(pDef->get_RegistrationInfo(pRegInfo.ReleaseAndGetAddressOf()))) {
                            BSTR bstrAuthor = NULL;
                            if (SUCCEEDED(pRegInfo->get_Author(&bstrAuthor)) && bstrAuthor != NULL) {
                                std::wstring author(bstrAuthor, SysStringLen(bstrAuthor));
                                SysFreeString(bstrAuthor);
                                
                                bool authorMatch = (author.find(L"Microsoft") != std::wstring::npos);
                                
                                // Canonical Directory Trust: Enforce that the executable path is shielded by the OS
                                wchar_t windir[MAX_PATH]; ExpandEnvironmentStringsW(L"%WINDIR%\\System32", windir, MAX_PATH);
                                bool pathTrust = (exePath.find(windir) == 0) || (exePath.find(L"\"%WINDIR%\\System32") == 0);

                                bool sigMatch = (!exePath.empty() && pathTrust && Core::Utils::VerifyDigitalSignature(exePath));

                                if (authorMatch || sigMatch) {
                                    pTask->put_Enabled(VARIANT_FALSE);
                                    log.Log(Core::LogLevel::INFO, "TASK", 200, "Disabled verified task: " + Core::Utils::ws2s(path));
                                } else {
                                    log.Log(Core::LogLevel::WARN, "TASK", 400, "Skipped task (Failed Trust Validation): " + Core::Utils::ws2s(path));
                                }
                            }
                        }
                    }
                }
            }
        }
    };
}
