#pragma once
#include <windows.h>
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <vector>
#include <evntprov.h>
#include <winmeta.h>

#pragma comment(lib, "advapi32.lib")

namespace Aegis::Core {
    enum class LogLevel { TRACE, DEBUG, INFO, WARN, ERR, FATAL };

    // Aegis Custom ETW Provider GUID: {A1B2C3D4-E5F6-7A8B-9C0D-1E2F3A4B5C6D}
    static const GUID AEGIS_ETW_PROVIDER_GUID = { 0xa1b2c3d4, 0xe5f6, 0x7a8b, { 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d } };

    class Logger {
        std::mutex mtx;
        std::string logBaseName = "aegis_audit";
        std::string logExt = ".json";
        std::string currentLogPath;
        const uintmax_t MAX_LOG_SIZE = 5 * 1024 * 1024; // 5 MB
        const int MAX_ARCHIVES = 3;
        std::string currentTraceId;
        std::string sessionId;
        REGHANDLE etwHandle = NULL;

        std::string GetTimestamp() {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            std::tm tm_buf; localtime_s(&tm_buf, &time);
            std::ostringstream oss;
            oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
            return oss.str();
        }

        std::string LevelToStr(LogLevel level) {
            switch (level) {
                case LogLevel::TRACE: return "TRACE";
                case LogLevel::DEBUG: return "DEBUG";
                case LogLevel::INFO:  return "INFO";
                case LogLevel::WARN:  return "WARN";
                case LogLevel::ERR:   return "ERROR";
                case LogLevel::FATAL: return "FATAL";
                default: return "UNKNOWN";
            }
        }

        void RotateLogIfNeeded() {
            std::error_code ec;
            if (std::filesystem::exists(currentLogPath, ec) && std::filesystem::file_size(currentLogPath, ec) > MAX_LOG_SIZE) {
                // Shift historical files
                for (int i = MAX_ARCHIVES - 1; i > 0; --i) {
                    std::string oldF = logBaseName + "." + std::to_string(i) + logExt;
                    std::string newF = logBaseName + "." + std::to_string(i + 1) + logExt;
                    if (std::filesystem::exists(oldF, ec)) {
                        std::filesystem::rename(oldF, newF, ec);
                    }
                }
                std::string arch1 = logBaseName + ".1" + logExt;
                std::filesystem::rename(currentLogPath, arch1, ec);
            }
        }

    public:
        Logger() {
            currentLogPath = logBaseName + logExt;
            SetTraceId("BOOTSTRAP");
            
            // Deterministic Session ID based on process start time tick count
            sessionId = std::to_string(GetTickCount64());
            
            // Register Provider with Event Tracing for Windows (ETW) Subsystem
            EventRegister(&AEGIS_ETW_PROVIDER_GUID, NULL, NULL, &etwHandle);
        }

        ~Logger() {
            if (etwHandle) EventUnregister(etwHandle);
        }

        void SetTraceId(const std::string& traceId) {
            std::lock_guard<std::mutex> lock(mtx);
            currentTraceId = traceId;
        }

        void Log(LogLevel level, const std::string& category, int eventId, const std::string& message, uint32_t latencyMs = 0) {
            std::lock_guard<std::mutex> lock(mtx);
            RotateLogIfNeeded();

            // Persistent JSON payload enriched with telemetry metadata
            std::string payload = "{\"ts\":\"" + GetTimestamp() + "\",\"sid\":\"" + sessionId + 
                                 "\",\"trace\":\"" + currentTraceId + "\",\"lvl\":\"" + LevelToStr(level) + 
                                 "\",\"cat\":\"" + category + "\",\"evt\":" + std::to_string(eventId) + 
                                 ",\"lat\":" + std::to_string(latencyMs) + ",\"msg\":\"" + message + "\"}";

            std::ofstream file(currentLogPath, std::ios::app);
            if (file.is_open()) {
                file << payload << "\n";
                file.flush();
            }
            
            // ETW Dispatch: Enables high-performance querying via Event Viewer or SIEM integration.
            if (etwHandle) {
                std::wstring wPayload(payload.begin(), payload.end());
                EventWriteString(etwHandle, level <= LogLevel::INFO ? WINEVENT_LEVEL_INFO : WINEVENT_LEVEL_ERROR, 0, wPayload.c_str());
            }
        }

        std::string GetLastErrorString() {
            DWORD error = GetLastError();
            if (error == 0) return "No error";
            LPSTR buf = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                         NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
            std::string message(buf, size);
            LocalFree(buf);
            while(!message.empty() && (message.back() == '\n' || message.back() == '\r')) message.pop_back();
            return message + " (Code: " + std::to_string(error) + ")";
        }
    };
}
