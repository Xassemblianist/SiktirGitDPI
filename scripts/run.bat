@echo off
REM Run sgdpi with default settings, requesting admin rights via UAC.

setlocal
cd /d "%~dp0\.."

set EXE=build\Release\sgdpi.exe
if not exist "%EXE%" set EXE=build\Debug\sgdpi.exe
if not exist "%EXE%" (
    echo [!!] sgdpi.exe not found. Run scripts\build.bat first.
    exit /b 1
)

REM Forward all args.
"%EXE%" %*
endlocal
