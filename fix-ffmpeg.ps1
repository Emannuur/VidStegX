# ============================================================================
# FFmpeg Fix Script for VidStegX
# ============================================================================
# This script downloads FFmpeg 7.x binaries including ffmpeg.exe
# Run this script from the project directory
# ============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FFmpeg Fix Script for VidStegX" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get project directory
$projectDir = $PSScriptRoot
$ffmpegDir = Join-Path $projectDir "ffmpeg"
$markerFile = Join-Path $ffmpegDir ".downloaded"

Write-Host "Project Directory: $projectDir" -ForegroundColor Yellow
Write-Host "FFmpeg Directory: $ffmpegDir" -ForegroundColor Yellow
Write-Host ""

# Step 1: Clean up old ffmpeg directory if it exists
if (Test-Path $ffmpegDir) {
    Write-Host "[1/5] Removing old FFmpeg directory..." -ForegroundColor Green
    try {
        Remove-Item -Path $ffmpegDir -Recurse -Force -ErrorAction Stop
        Write-Host "      ? Old directory removed" -ForegroundColor Gray
    }
    catch {
        Write-Host "      ? Could not remove old directory: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "      Please manually delete the 'ffmpeg' folder and run this script again." -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "[1/5] No old FFmpeg directory found (OK)" -ForegroundColor Green
}

# Step 2: Create fresh ffmpeg directory
Write-Host "[2/5] Creating FFmpeg directory..." -ForegroundColor Green
try {
    New-Item -ItemType Directory -Path $ffmpegDir -Force | Out-Null
    Write-Host "      ? Directory created: $ffmpegDir" -ForegroundColor Gray
}
catch {
    Write-Host "      ? Failed to create directory: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 3: Download FFmpeg
Write-Host "[3/5] Downloading FFmpeg 7.1 from GitHub..." -ForegroundColor Green
$ffmpegUrl = "https://github.com/GyanD/codexffmpeg/releases/download/7.1/ffmpeg-7.1-full_build-shared.zip"
$zipFile = Join-Path $projectDir "ffmpeg-temp.zip"
$extractPath = Join-Path $projectDir "ffmpeg-temp"

try {
    Write-Host "      URL: $ffmpegUrl" -ForegroundColor Gray
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $ffmpegUrl -OutFile $zipFile -UseBasicParsing -TimeoutSec 300
    $ProgressPreference = 'Continue'
    
    $zipSize = (Get-Item $zipFile).Length / 1MB
    Write-Host "      ? Downloaded: $([math]::Round($zipSize, 2)) MB" -ForegroundColor Gray
}
catch {
    Write-Host "      ? Download failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "      Please check your internet connection and try again." -ForegroundColor Red
    exit 1
}

# Step 4: Extract and copy files
Write-Host "[4/5] Extracting FFmpeg binaries..." -ForegroundColor Green
try {
    # Extract the zip file
    Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force
    Write-Host "      ? Extracted to temp directory" -ForegroundColor Gray
    
    # Find the bin directory
    $binDir = Get-ChildItem -Path $extractPath -Directory | Where-Object { $_.Name -like "ffmpeg-*" } | Select-Object -First 1
    
    if (-not $binDir) {
        throw "Could not find FFmpeg directory in extracted files"
    }
    
    $binPath = Join-Path $binDir.FullName "bin"
    
    if (-not (Test-Path $binPath)) {
        throw "Could not find 'bin' directory in: $($binDir.FullName)"
    }
    
    Write-Host "      ? Found bin directory: $binPath" -ForegroundColor Gray
    
    # Copy DLL files
    Write-Host "      Copying DLL files..." -ForegroundColor Gray
    $dlls = Get-ChildItem -Path $binPath -Filter "*.dll"
    foreach ($dll in $dlls) {
        Copy-Item $dll.FullName -Destination $ffmpegDir -Force
        Write-Host "        - $($dll.Name)" -ForegroundColor DarkGray
    }
    Write-Host "      ? Copied $($dlls.Count) DLL files" -ForegroundColor Gray
    
    # Copy EXE files (CRITICAL: ffmpeg.exe, ffprobe.exe, ffplay.exe)
    Write-Host "      Copying EXE files..." -ForegroundColor Gray
    $exes = Get-ChildItem -Path $binPath -Filter "*.exe"
    foreach ($exe in $exes) {
        Copy-Item $exe.FullName -Destination $ffmpegDir -Force
        Write-Host "        - $($exe.Name)" -ForegroundColor DarkGray
    }
    Write-Host "      ? Copied $($exes.Count) EXE files" -ForegroundColor Gray
    
    # Create marker file
    New-Item -ItemType File -Path $markerFile -Force | Out-Null
    Write-Host "      ? Created marker file" -ForegroundColor Gray
}
catch {
    Write-Host "      ? Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    # Cleanup temp files
    if (Test-Path $zipFile) {
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $extractPath) {
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Step 5: Verify installation
Write-Host "[5/5] Verifying installation..." -ForegroundColor Green

$ffmpegExe = Join-Path $ffmpegDir "ffmpeg.exe"
$ffprobeExe = Join-Path $ffmpegDir "ffprobe.exe"

$allGood = $true

if (Test-Path $ffmpegExe) {
    Write-Host "      ? ffmpeg.exe found" -ForegroundColor Gray
    
    # Test ffmpeg version
    try {
        $versionInfo = & $ffmpegExe -version 2>&1 | Select-Object -First 1
        Write-Host "      ? $versionInfo" -ForegroundColor Gray
    }
    catch {
        Write-Host "      ? ffmpeg.exe found but could not execute" -ForegroundColor Yellow
    }
}
else {
    Write-Host "      ? ffmpeg.exe NOT found at: $ffmpegExe" -ForegroundColor Red
    $allGood = $false
}

if (Test-Path $ffprobeExe) {
    Write-Host "      ? ffprobe.exe found" -ForegroundColor Gray
}
else {
    Write-Host "      ? ffprobe.exe NOT found (optional)" -ForegroundColor Yellow
}

# Count files
$dllCount = (Get-ChildItem -Path $ffmpegDir -Filter "*.dll").Count
$exeCount = (Get-ChildItem -Path $ffmpegDir -Filter "*.exe").Count

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  - DLL files: $dllCount" -ForegroundColor White
Write-Host "  - EXE files: $exeCount" -ForegroundColor White
Write-Host "  - Location: $ffmpegDir" -ForegroundColor White

Write-Host ""
if ($allGood) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "? SUCCESS!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "FFmpeg is now properly installed." -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Rebuild your project in Visual Studio (Ctrl+Shift+B)" -ForegroundColor White
    Write-Host "  2. Run the application (F5)" -ForegroundColor White
    Write-Host "  3. Try embedding a message in a video" -ForegroundColor White
    Write-Host ""
}
else {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "? INSTALLATION INCOMPLETE" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Please run this script again or check for errors above." -ForegroundColor Red
    Write-Host ""
    exit 1
}
