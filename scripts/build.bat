@echo off
REM SiktirGitDPI build helper.
REM   build.bat              -> CMake + MSVC, Release x64
REM   build.bat Debug        -> CMake + MSVC, Debug
REM   build.bat Release vs   -> Visual Studio 17 2022 generator (vs Ninja)
REM   build.bat mingw        -> Static MinGW build (no Visual Studio needed)

setlocal EnableDelayedExpansion

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release

set GEN=%2

cd /d "%~dp0\.."

if /i "%CONFIG%"=="mingw" (
    REM MinGW path: delegate to bash script.
    bash scripts/build-mingw.sh
    exit /b !errorlevel!
)

if not exist "third_party\windivert\include\windivert.h" (
    echo [..] WinDivert SDK missing, fetching...
    powershell -ExecutionPolicy Bypass -File "scripts\get-windivert.ps1"
    if errorlevel 1 (
        echo [!!] WinDivert fetch failed.
        exit /b 1
    )
)

if not exist build mkdir build

if /i "%GEN%"=="vs" (
    cmake -S . -B build -G "Visual Studio 17 2022" -A x64
) else (
    cmake -S . -B build -A x64
)
if errorlevel 1 exit /b 1

cmake --build build --config %CONFIG% --parallel
if errorlevel 1 exit /b 1

echo.
echo [ok] Build complete: build\%CONFIG%\sgdpi.exe
echo [..] Run unit tests:
echo        ctest --test-dir build -C %CONFIG%
echo [..] Run as admin:
echo        build\%CONFIG%\sgdpi.exe --preset tt --stats
endlocal
