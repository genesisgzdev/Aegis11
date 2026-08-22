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

    // Stable ETW provider identifier owned by Aegis11.
    static const GUID AEGIS_ETW_PROVIDER_GUID = { 0x9928b3e2, 0xd719, 0x4307, { 0x96, 0x3c, 0x3f, 0xa0, 0x0e, 0x5a, 0x93, 0xf3 } };

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

        static std::string EscapeJsonString(const std::string& value) {
            std::ostringstream escaped;
            escaped << std::hex << std::setfill('0');
            for (unsigned char ch : value) {
                switch (ch) {
                    case '"': escaped << "\\\""; break;
                    case '\\': escaped << "\\\\"; break;
                    case '\b': escaped << "\\b"; break;
                    case '\f': escaped << "\\f"; break;
                    case '\n': escaped << "\\n"; break;
                    case '\r': escaped << "\\r"; break;
                    case '\t': escaped << "\\t"; break;
                    default:
                        if (ch < 0x20) {
                            escaped << "\\u" << std::setw(4) << static_cast<unsigned int>(ch);
                        } else {
                            escaped << static_cast<char>(ch);
                        }
                }
            }
            return escaped.str();
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

        // Keep the short form used by legacy modules while preserving the
        // structured event id in the canonical logger path.
        void Log(LogLevel level, const std::string& category, const std::string& message) {
            Log(level, category, 0, message);
        }

        void Log(LogLevel level, const std::string& category, int eventId, const std::string& message, uint32_t latencyMs = 0) {
            std::lock_guard<std::mutex> lock(mtx);
            RotateLogIfNeeded();

            // Persistent JSON payload enriched with telemetry metadata
            std::string payload = "{\"ts\":\"" + EscapeJsonString(GetTimestamp()) + "\",\"sid\":\"" + EscapeJsonString(sessionId) +
                                 "\",\"trace\":\"" + EscapeJsonString(currentTraceId) + "\",\"lvl\":\"" + EscapeJsonString(LevelToStr(level)) +
                                 "\",\"cat\":\"" + EscapeJsonString(category) + "\",\"evt\":" + std::to_string(eventId) +
                                 ",\"lat\":" + std::to_string(latencyMs) + ",\"msg\":\"" + EscapeJsonString(message) + "\"}";

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
