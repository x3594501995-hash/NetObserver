@echo off
setlocal

set "ROOT=%~dp0"

call "%ROOT%scripts\build-vs-cmake.cmd"
if errorlevel 1 (
    echo.
    echo Build failed. Review the compiler output above.
    pause
    exit /b 1
)

start "" "%ROOT%build\vs\Debug\NetObserver.exe"
exit /b 0

