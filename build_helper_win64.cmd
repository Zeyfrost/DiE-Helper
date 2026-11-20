@echo off
rem DiE Helper fork: incremental Windows x64 build (MSVC 2022 + Qt 6 + Ninja).
rem Same cmake flags as upstream build_win_generic_qt6.cmd, but the build directory (_build) is kept,
rem so only changed files are recompiled. Output: release\die_win64_qt6\die.exe
rem Override Qt with:  set QT_PREFIX_PATH=C:\Qt\6.x.y\msvc2022_64
setlocal
set "SRC=%~dp0"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"
set "BLD=%SRC%\_build"
set "INST=%SRC%\release\die_win64_qt6"
if not defined QT_PREFIX_PATH set "QT_PREFIX_PATH=C:\Qt\6.8.3\msvc2022_64"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR ( echo Visual Studio not found & exit /b 1 )
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

if not exist "%BLD%\build.ninja" (
    cmake -S "%SRC%" -B "%BLD%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DWITH_PEID=OFF -DCMAKE_PREFIX_PATH="%QT_PREFIX_PATH%" || exit /b 1
)
cmake --build "%BLD%" || exit /b 1
cmake --install "%BLD%" --prefix "%INST%" || exit /b 1

rem Data folders, as upstream's script copies them (db_extra subfolders are merged into db\)
xcopy "%SRC%\dep\Detect-It-Easy\db" "%INST%\db\" /E /I /Y /Q >nul
for /D %%D in ("%SRC%\dep\Detect-It-Easy\db_extra\*") do xcopy "%%D" "%INST%\db\%%~nxD\" /E /I /Y /Q >nul
xcopy "%SRC%\dep\XStyles\qss" "%INST%\qss\" /E /I /Y /Q >nul
xcopy "%SRC%\dep\XInfoDB\info" "%INST%\info\" /E /I /Y /Q >nul
xcopy "%SRC%\dep\XYara\yara_rules" "%INST%\yara_rules\" /E /I /Y /Q >nul
if exist "%INST%\yara_rules\peid.yar" del /Q "%INST%\yara_rules\peid.yar"
xcopy "%SRC%\images" "%INST%\images\" /E /I /Y /Q >nul
if exist "%SRC%\dep\signatures\crypto.db" (
    mkdir "%INST%\signatures" 2>nul
    copy /Y "%SRC%\dep\signatures\crypto.db" "%INST%\signatures\" >nul
)
if exist "%INST%\api-ms-win-crt-*.dll" del /f /q "%INST%\api-ms-win-crt-*.dll"

echo BUILD_OK: %INST%\die.exe
endlocal
