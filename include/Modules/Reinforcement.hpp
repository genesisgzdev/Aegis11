#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include <windows.h>
#include <taskschd.h>
#include <comdef.h>

namespace Aegis::Modules {
    class Reinforcement {
        Core::Logger& log;
    public:
        explicit Reinforcement(Core::Logger& logger) : log(logger) {}

        void RegisterSelfHealingTask() {
            log.Log(Core::LogLevel::INFO, "SYS", 100, "Registering Aegis Self-Healing Scheduled Task (Post-Update Resilience)...");
            
            Core::ComPtr<ITaskService> pService;
            if (FAILED(CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)pService.ReleaseAndGetAddressOf()))) return;
            pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

            Core::ComPtr<ITaskDefinition> pTask;
            pService->NewTask(0, pTask.ReleaseAndGetAddressOf());

            Core::ComPtr<IRegistrationInfo> pRegInfo;
            pTask->get_RegistrationInfo(pRegInfo.ReleaseAndGetAddressOf());
            pRegInfo->put_Author(_bstr_t(L"Aegis11"));
            pRegInfo->put_Description(_bstr_t(L"Aegis11 State Reconciliation Hook (Anti-Drift)"));

            Core::ComPtr<ITaskSettings> pSettings;
            pTask->get_Settings(pSettings.ReleaseAndGetAddressOf());
            pSettings->put_StartWhenAvailable(VARIANT_TRUE);
            pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // No limit

            Core::ComPtr<ITriggerCollection> pTriggers;
            pTask->get_Triggers(pTriggers.ReleaseAndGetAddressOf());
            
            // Advanced persistence: Trigger via System Event (Windows Update / Servicing Installation) instead of a legacy Logon trigger
            Core::ComPtr<ITrigger> pEventTrigger;
            pTriggers->Create(TASK_TRIGGER_EVENT, pEventTrigger.ReleaseAndGetAddressOf());
            Core::ComPtr<IEventTrigger> pEvent;
            pEventTrigger->QueryInterface(IID_IEventTrigger, (void**)pEvent.ReleaseAndGetAddressOf());
            pEvent->put_Subscription(_bstr_t(L"<QueryList><Query Id=\"0\" Path=\"Setup\"><Select Path=\"Setup\">*[System[Provider[@Name='Microsoft-Windows-Servicing'] and (EventID=2 or EventID=3 or EventID=4)]]</Select></Query></QueryList>"));

            Core::ComPtr<IActionCollection> pActions;
            pTask->get_Actions(pActions.ReleaseAndGetAddressOf());
            Core::ComPtr<IAction> pAction;
            pActions->Create(TASK_ACTION_EXEC, pAction.ReleaseAndGetAddressOf());
            Core::ComPtr<IExecAction> pExec;
            pAction->QueryInterface(IID_IExecAction, (void**)pExec.ReleaseAndGetAddressOf());

            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            pExec->put_Path(_bstr_t(exePath));
            pExec->put_Arguments(_bstr_t(L"--reconcile"));

            Core::ComPtr<ITaskFolder> pRoot;
            pService->GetFolder(_bstr_t(L"\\"), pRoot.ReleaseAndGetAddressOf());
            pRoot->RegisterTaskDefinition(_bstr_t(L"Aegis11_SelfHealing"), pTask.get(), TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(), NULL);
            
            log.Log(Core::LogLevel::INFO, "DONE", 200, "Self-healing task registered at Logon.");
        }
    };
}
