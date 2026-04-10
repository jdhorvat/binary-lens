@echo off
setlocal

echo ============================================================
echo  BinaryLens -- Build Script
echo ============================================================
echo.

:: Check for dotnet
where dotnet >nul 2>&1
if errorlevel 1 (
    echo ERROR: .NET SDK not found on PATH.
    echo Download from https://dotnet.microsoft.com/download
    pause
    exit /b 1
)

:: Safety: ensure we only build the main project, not reference projects
:: The .csproj already excludes "reference projects\**" from compilation,
:: but we also verify we're in the right directory.
if not exist "BinaryLens.csproj" (
    echo ERROR: BinaryLens.csproj not found in current directory.
    echo Please run this script from the BinaryLens project root.
    pause
    exit /b 1
)

echo .NET SDK found:
dotnet --version
echo.

:: Restore NuGet packages
echo [1/3] Restoring NuGet packages...
dotnet restore BinaryLens.csproj -r win-x64
if errorlevel 1 ( echo RESTORE FAILED & pause & exit /b 1 )

:: Build Release
echo.
echo [2/3] Building Release x64...
dotnet build BinaryLens.csproj -c Release -r win-x64 --no-restore
if errorlevel 1 ( echo BUILD FAILED & pause & exit /b 1 )

:: Publish self-contained single EXE
echo.
echo [3/3] Publishing self-contained EXE...
dotnet publish BinaryLens.csproj -c Release -r win-x64 ^
    --self-contained true ^
    --no-restore ^
    -p:PublishSingleFile=true ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    -o publish\
if errorlevel 1 ( echo PUBLISH FAILED & pause & exit /b 1 )

:: Clean satellite assembly language folders (de, fr, ja, etc.)
echo.
echo [Cleanup] Removing satellite language folders...
for /d %%D in (publish\*) do (
    if exist "%%D\*.resources.dll" (
        echo   Removing %%D
        rd /s /q "%%D"
    )
)

echo.
echo ============================================================
echo  Done.  Output: publish\BinaryLens.exe
echo ============================================================
echo.
start "" "publish\"
pause

