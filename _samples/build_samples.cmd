@echo off
rem Builds the Helper test samples with MSVC (x86 + x64) and packs copies with UPX.
rem The samples are only ever SCANNED by DiE - never run or loaded them.
setlocal
cd /d "%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSDIR=%%i"
set "VCB=%VSDIR%\VC\Auxiliary\Build"

setlocal
call "%VCB%\vcvars32.bat" >nul || exit /b 1
cl /nologo /O1 /MT src\hello.c /Fo:hello32.obj /Fe:hello32.exe || exit /b 1
cl /nologo /O1 /MT /LD src\hello_dll.c /Fo:hello_dll32.obj /Fe:hello_dll32.dll || exit /b 1
endlocal
setlocal
call "%VCB%\vcvars64.bat" >nul || exit /b 1
cl /nologo /O1 /MT src\hello.c /Fo:hello64.obj /Fe:hello64.exe || exit /b 1
cl /nologo /O1 /MT /LD src\hello_dll.c /Fo:hello_dll64.obj /Fe:hello_dll64.dll || exit /b 1
cl /nologo /O1 /MT src\obfusc_native.c /Fo:obfusc_native64.obj /Fe:obfusc_native64.exe || exit /b 1
cl /nologo /O1 /MT src\strings_hash.c /Fo:strings_hash64.obj /Fe:strings_hash64.exe || exit /b 1
endlocal
rem .NET sample (Framework csc ships with Windows)
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /out:hello_net.exe src\hello_net.cs || exit /b 1
del /q *.obj *.lib *.exp 2>nul

for %%F in (hello32.exe hello64.exe hello_dll32.dll hello_dll64.dll) do (
    if exist "%%~nF_upx%%~xF" del /q "%%~nF_upx%%~xF"
    upx -q -9 -o "%%~nF_upx%%~xF" "%%F" >nul || exit /b 1
)
rem renamed-section / scrambled UPX variants (byte patching only)
python -I "%~dp0patch_samples.py" "%~dp0." || exit /b 1
echo SAMPLES_OK
dir /b *.exe *.dll
endlocal
