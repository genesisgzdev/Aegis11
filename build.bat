@echo off
echo Building aegis11 v1 (Architect Refactor)...
windres resources\aegis.rc -O coff -o resources\aegis.res
g++ -std=c++20 -O3 -flto -s -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,--dynamicbase -Wl,--nxcompat -mwindows src\main.cpp resources\aegis.res -o aegis11.exe -Iinclude -ladvapi32 -lshell32 -luser32 -lole32 -loleaut32 -ltaskschd -lfwpuclnt -lrpcrt4 -lcrypt32 -lwintrust -lws2_32 -static -static-libgcc -static-libstdc++ -lssp
if %ERRORLEVEL% NEQ 0 ( echo [ERROR] Build failed. ) else ( echo [SUCCESS] aegis11.exe successfully compiled. )
pause
