@echo off
setlocal
echo Configuring Aegis11 with CMake and the Visual Studio 2022 x64 toolchain...
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
cmake --build build --config Release --parallel
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
echo [SUCCESS] build\Release\aegis11.exe successfully compiled.
