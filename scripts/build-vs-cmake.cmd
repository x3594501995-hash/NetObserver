@echo off
setlocal EnableExtensions

set "ROOT=%~dp0.."
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSPATH="
set "CMAKE="
set "CTEST="

if not exist "%VSWHERE%" (
    echo Visual Studio Installer was not found.
    exit /b 1
)

for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%I"
if not defined VSPATH (
    echo Visual Studio C++ build tools were not found.
    exit /b 1
)

set "VSDEV=%VSPATH%\Common7\Tools\VsDevCmd.bat"
if exist "%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
    set "CMAKE=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    set "CTEST=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
)

if not defined CMAKE (
    for /f "delims=" %%I in ('where cmake 2^>nul') do if not defined CMAKE set "CMAKE=%%I"
    if defined CMAKE (
        for %%I in ("%CMAKE%") do set "CTEST=%%~dpIctest.exe"
    )
)

if not exist "%VSDEV%" (
    echo Visual Studio developer command prompt script was not found.
    exit /b 1
)

if not defined CMAKE (
    echo CMake was not found.
    exit /b 1
)

if not exist "%CTEST%" (
    echo CTest was not found.
    exit /b 1
)

call "%VSDEV%" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1

pushd "%ROOT%"

"%CMAKE%" -S . -B build\vs ^
    -G "Visual Studio 17 2022" -A x64 ^
    -DNPCAP_ROOT="%ROOT%\third_party\npcap-sdk"
if errorlevel 1 (
    popd
    exit /b 1
)

"%CMAKE%" --build build\vs --config Debug
if errorlevel 1 (
    popd
    exit /b 1
)

"%CTEST%" --test-dir build\vs -C Debug --output-on-failure
set "TEST_RESULT=%ERRORLEVEL%"

popd
exit /b %TEST_RESULT%

