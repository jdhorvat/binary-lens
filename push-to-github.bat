@echo off
echo === BinaryLens GitHub Upload ===
echo.
echo Prerequisites: git and gh (GitHub CLI)
echo   Install git:  winget install Git.Git
echo   Install gh:   winget install GitHub.cli
echo   Then run:     gh auth login
echo.
pause

cd /d "%~dp0"

:: Check for git
where git >nul 2>nul
if errorlevel 1 (
    echo ERROR: git not found. Install it with: winget install Git.Git
    echo Then close and reopen this terminal.
    pause
    exit /b 1
)

:: Check for gh
where gh >nul 2>nul
if errorlevel 1 (
    echo ERROR: gh not found. Install it with: winget install GitHub.cli
    pause
    exit /b 1
)

:: Clean up broken .git from previous failed run
if exist .git (
    echo Removing broken .git folder from previous attempt...
    rmdir /s /q .git
)

:: Init and add source files
git init
if errorlevel 1 (
    echo ERROR: git init failed. Try deleting the .git folder manually and retry.
    pause
    exit /b 1
)
git checkout -b main
git add README.md LICENSE .gitignore BinaryLens.csproj build.bat push-to-github.bat
git add App.xaml App.xaml.cs MainWindow.xaml MainWindow.xaml.cs
git add Analysis\*.cs Models\*.cs Export\*.cs
git commit -m "Initial commit: BinaryLens binary analysis workbench"

:: Push to existing repo (already created on GitHub)
git remote add origin https://github.com/jdhorvat/binary-lens.git
git push -u origin main --force

echo.
echo Source code pushed! Now creating release with binaries...
echo.

:: Zip the publish folder for release
if exist publish\ (
    powershell -Command "Compress-Archive -Path 'publish\*' -DestinationPath 'BinaryLens-win-x64.zip' -Force"
    gh release delete v1.0 --repo jdhorvat/binary-lens --yes 2>nul
    gh release create v1.0 BinaryLens-win-x64.zip --repo jdhorvat/binary-lens --title "BinaryLens v1.0" --notes "Pre-built Windows x64 binary. Extract and run BinaryLens.exe."
    del BinaryLens-win-x64.zip
    echo Release created with binaries!
) else (
    echo No publish folder found. Build first with: dotnet publish -c Release -r win-x64
)

echo.
echo Done!
pause
