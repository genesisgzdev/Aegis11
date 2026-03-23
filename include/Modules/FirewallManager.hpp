#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include <netfw.h>
#include <comdef.h>
#include <vector>
#include <string>

namespace Aegis::Modules {
    class FirewallManager {
        Core::Logger& log;

        void CleanupOldAegisRules(INetFwRules* pRules, const std::wstring& targetExe) {
            Core::ComPtr<IUnknown> pEnumerator;
            if (SUCCEEDED(pRules->get__NewEnum(pEnumerator.ReleaseAndGetAddressOf()))) {
                Core::ComPtr<IEnumVARIANT> pVariantEnum;
                if (SUCCEEDED(pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)pVariantEnum.ReleaseAndGetAddressOf()))) {
                    VARIANT var; VariantInit(&var);
                    while (pVariantEnum->Next(1, &var, NULL) == S_OK) {
                        Core::ComPtr<INetFwRule> pRule;
                        if (SUCCEEDED(var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)pRule.ReleaseAndGetAddressOf()))) {
                            
                            BSTR bstrGroup = NULL, bstrApp = NULL;
                            NET_FW_ACTION action; NET_FW_RULE_DIRECTION dir;

                            pRule->get_Grouping(&bstrGroup);
                            pRule->get_ApplicationName(&bstrApp);
                            pRule->get_Action(&action);
                            pRule->get_Direction(&dir);

                            std::wstring group = (bstrGroup) ? std::wstring(bstrGroup, SysStringLen(bstrGroup)) : L"";
                            std::wstring app = (bstrApp) ? std::wstring(bstrApp, SysStringLen(bstrApp)) : L"";
                            
                            if (bstrGroup) SysFreeString(bstrGroup);
                            if (bstrApp) SysFreeString(bstrApp);

                            // Strict Fingerprint Validation
                            if (group == L"@Aegis11_Group" && app == targetExe && action == NET_FW_ACTION_BLOCK && dir == NET_FW_RULE_DIR_OUT) {
                                BSTR bstrName;
                                if (SUCCEEDED(pRule->get_Name(&bstrName))) {
                                    pRules->Remove(bstrName);
                                    SysFreeString(bstrName);
                                }
                            }
                        }
                        VariantClear(&var);
                    }
                }
            }
        }

    public:
        explicit FirewallManager(Core::Logger& logger) : log(logger) {}

        void EnforceBlockRules(bool dryRun) {
            log.Log(Core::LogLevel::INFO, "FW", 100, "Initializing COM Firewall Engine...");
            if (dryRun) return;
            
            Core::ComPtr<INetFwPolicy2> pNetFwPolicy2;
            if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)pNetFwPolicy2.ReleaseAndGetAddressOf()))) return;

            Core::ComPtr<INetFwRules> pFwRules;
            if (FAILED(pNetFwPolicy2->get_Rules(pFwRules.ReleaseAndGetAddressOf()))) return;

            std::vector<std::wstring> executables = { L"%WINDIR%\\System32\\CompatTelRunner.exe", L"%WINDIR%\\System32\\DeviceCensus.exe" };

            for (const auto& exe : executables) {
                CleanupOldAegisRules(pFwRules.get(), exe);

                Core::ComPtr<INetFwRule> pFwRule;
                if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)pFwRule.ReleaseAndGetAddressOf()))) {
                    std::wstring ruleName = L"Aegis_Block_" + exe.substr(exe.find_last_of(L"\\") + 1);
                    pFwRule->put_Name(_bstr_t(ruleName.c_str()));
                    pFwRule->put_Grouping(_bstr_t(L"@Aegis11_Group"));
                    pFwRule->put_ApplicationName(_bstr_t(exe.c_str()));
                    pFwRule->put_Action(NET_FW_ACTION_BLOCK);
                    pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
                    pFwRule->put_Enabled(VARIANT_TRUE);
                    pFwRules->Add(pFwRule.get());
                }
            }
        }
    };
}
