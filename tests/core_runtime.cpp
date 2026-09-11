#include "Core/RAII.hpp"
#include "Core/Utils.hpp"
#include <iostream>
#include <stdexcept>

using Aegis::Core::KernelHandle;
using Aegis::Core::Utils;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

int main() {
    try {
        const std::wstring label = L"Pol\u00edtica \u65e5\u672c\u8a9e \U0001f512";
        const std::string utf8 = "Pol\xc3\xad" "tica \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e \xf0\x9f\x94\x92";
        require(Utils::ws2s(label) == utf8, "wide text was not encoded as UTF-8");
        require(Utils::s2ws(utf8) == label, "UTF-8 round trip lost characters");
        require(Utils::ws2s(L"").empty(), "empty conversion failed");

        auto event = KernelHandle::From(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        require(static_cast<bool>(event), "create event failed");
        const HANDLE raw = event.get();
        auto moved = std::move(event);
        require(!event && event.get() == nullptr, "move must leave canonical empty handle");
        event.reset();
        require(SetEvent(moved.get()) != FALSE, "reset of moved-from handle closed the event");
        require(moved.release() == raw, "release returned another handle");
        require(!moved && moved.get() == nullptr, "release must leave canonical empty handle");
        require(WaitForSingleObject(raw, 0) == WAIT_OBJECT_0, "release closed the event");
        event = KernelHandle::From(raw);
        event.reset();
        DWORD flags = 0;
        SetLastError(ERROR_SUCCESS);
        require(GetHandleInformation(raw, &flags) == FALSE && GetLastError() == ERROR_INVALID_HANDLE,
                "reset did not close the event");
        std::cout << "Native handle ownership and Unicode tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
