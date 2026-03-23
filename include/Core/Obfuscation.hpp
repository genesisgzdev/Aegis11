#pragma once
#include <string>
#include <windows.h>

namespace Aegis::Core {
    template<size_t N>
    struct XorStr {
        char data[N];
        constexpr XorStr(const char* str, char key) : data{} {
            for(size_t i = 0; i < N; ++i) data[i] = str[i] ^ key;
        }
        std::string get() const {
            std::string res(N, '\0');
            for(size_t i = 0; i < N; ++i) res[i] = data[i] ^ 0x4B;
            return res;
        }
        std::wstring getW() const {
            std::string s = get();
            if (s.empty()) return std::wstring();
            int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
            std::wstring ws(sz, 0);
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], sz);
            return ws;
        }
    };
}
#define _X(str) []{ constexpr Aegis::Core::XorStr<sizeof(str)-1> xs(str, 0x4B); return xs; }().getW()
#define _XA(str) []{ constexpr Aegis::Core::XorStr<sizeof(str)-1> xs(str, 0x4B); return xs; }().get()
