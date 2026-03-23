#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <roapi.h>
#include <wrl/client.h>
#include <wrl/wrappers/corewrappers.h>
#include <windows.management.deployment.h>
#include <string>
#include <vector>

#pragma comment(lib, "runtimeobject.lib")

namespace Aegis::Modules {
    class AppxManager {
        Core::Logger& log;

        bool RemovePackageNative(const std::wstring& appName) {
            using namespace Microsoft::WRL;
            using namespace Microsoft::WRL::Wrappers;
            using namespace ABI::Windows::Management::Deployment;
            using namespace ABI::Windows::Foundation;

            ComPtr<IPackageManager> packageManager;
            HRESULT hr = RoActivateInstance(HStringReference(RuntimeClass_Windows_Management_Deployment_PackageManager).Get(), &packageManager);
            if (FAILED(hr)) return false;

            // Query packages by publisher and exact name
            ComPtr<ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::ApplicationModel::Package*>> packages;
            hr = packageManager->FindPackagesByNamePublisher(HStringReference(appName.c_str()).Get(), nullptr, &packages);
            if (FAILED(hr)) return false;

            ComPtr<ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::ApplicationModel::Package*>> iterator;
            packages->First(&iterator);

            boolean hasCurrent = false;
            iterator->get_HasCurrent(&hasCurrent);
            
            bool eradicated = false;
            while (hasCurrent) {
                ComPtr<ABI::Windows::ApplicationModel::IPackage> package;
                iterator->get_Current(&package);
                
                ComPtr<ABI::Windows::ApplicationModel::IPackageId> packageId;
                package->get_Id(&packageId);
                
                HString fullName;
                packageId->get_FullName(fullName.GetAddressOf());

                // Asynchronous native package removal operation
                ComPtr<IAsyncOperationWithProgress<DeploymentResult*, DeploymentProgress>> removalOperation;
                hr = packageManager->RemovePackageAsync(fullName.Get(), &removalOperation);
                
                if (SUCCEEDED(hr)) eradicated = true;
                iterator->MoveNext(&hasCurrent);
            }
            return eradicated;
        }

        void KillProcessNative(const wchar_t* processName) {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe;
                pe.dwSize = sizeof(PROCESSENTRY32W);
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        if (_wcsicmp(pe.szExeFile, processName) == 0) {
                            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (hProc) {
                                TerminateProcess(hProc, 1);
                                CloseHandle(hProc);
                            }
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
        }

        void ExecuteSilent(const std::wstring& cmd) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {};
            std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end()); cmdBuf.push_back(0);
            if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 60000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        }

    public:
        explicit AppxManager(Core::Logger& logger) : log(logger) {}

        void RemoveBloatware(bool aggressive) {
            log.Log(Core::LogLevel::INFO, "APPX", 201, "Invoking Native WinRT COM for Appx removal (Zero-PowerShell)...");
            std::vector<std::wstring> targets = { L"Microsoft.BingNews", L"Microsoft.BingWeather", L"Microsoft.WindowsFeedbackHub" };
            if (aggressive) targets.push_back(L"Microsoft.XboxApp");

            for (const auto& app : targets) {
                if (RemovePackageNative(app)) {
                    log.Log(Core::LogLevel::INFO, "APPX", 200, "Successfully removed: " + std::string(app.begin(), app.end()));
                } else {
                    log.Log(Core::LogLevel::WARN, "APPX", 401, "Package not found or locked: " + std::string(app.begin(), app.end()));
                }
            }
        }

        void RemoveEdgeAndOneDrive() {
            log.Log(Core::LogLevel::INFO, "SYS", 202, "Executing native OneDrive process termination and uninstallation...");
            KillProcessNative(L"OneDrive.exe");
            wchar_t sysDir[MAX_PATH];
            GetEnvironmentVariableW(L"SystemRoot", sysDir, MAX_PATH);
            std::wstring uninstallCmd = std::wstring(sysDir) + L"\\SysWOW64\\OneDriveSetup.exe /uninstall";
            ExecuteSilent(uninstallCmd);
        }
    };
}
