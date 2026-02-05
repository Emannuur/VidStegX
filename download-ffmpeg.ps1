# PowerShell script to download FFmpeg 7.x binaries for FFMediaToolkit
$ffmpegDir = Join-Path $PSScriptRoot "ffmpeg"
$markerFile = Join-Path $ffmpegDir ".downloaded"

# Check if FFmpeg is already downloaded
if (Test-Path $markerFile) {
    Write-Host "FFmpeg binaries already exist. Skipping download."
    exit 0
}

Write-Host "Downloading FFmpeg 7.x binaries..."

# Create ffmpeg directory if it doesn't exist
if (!(Test-Path $ffmpegDir)) {
    New-Item -ItemType Directory -Path $ffmpegDir | Out-Null
}

# Use a mirror that provides stable FFmpeg 7.x builds
$ffmpegUrl = "https://github.com/GyanD/codexffmpeg/releases/download/7.1/ffmpeg-7.1-full_build-shared.zip"
$zipFile = Join-Path $PSScriptRoot "ffmpeg-temp.zip"
$extractPath = Join-Path $PSScriptRoot "ffmpeg-temp"

try {
    # Download FFmpeg
    Write-Host "Downloading from GitHub (Gyan Dev)..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ffmpegUrl -OutFile $zipFile -UseBasicParsing
    
    # Extract the zip file
    Write-Host "Extracting FFmpeg binaries..."
    Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force
    
    # Find the bin directory in the extracted files
    $binDir = Get-ChildItem -Path $extractPath -Directory | Where-Object { $_.Name -like "ffmpeg-*" } | Select-Object -First 1
    $binPath = Join-Path $binDir.FullName "bin"
    
    # Copy DLL files AND executables to ffmpeg directory
    if (Test-Path $binPath) {
        Write-Host "Copying FFmpeg DLLs and executables..."
        
        # Copy DLL files
        Get-ChildItem -Path $binPath -Filter "*.dll" | ForEach-Object {
            Copy-Item $_.FullName -Destination $ffmpegDir -Force
            Write-Host "  Copied: $($_.Name)"
        }
        
        # Copy EXE files (ffmpeg.exe, ffprobe.exe, ffplay.exe)
        Get-ChildItem -Path $binPath -Filter "*.exe" | ForEach-Object {
            Copy-Item $_.FullName -Destination $ffmpegDir -Force
            Write-Host "  Copied: $($_.Name)"
        }
        
        # Create marker file to indicate successful download
        New-Item -ItemType File -Path $markerFile -Force | Out-Null
        Write-Host "FFmpeg binaries downloaded successfully!"
        Write-Host "Total DLLs: $(( Get-ChildItem -Path $ffmpegDir -Filter '*.dll').Count)"
        Write-Host "Total EXEs: $(( Get-ChildItem -Path $ffmpegDir -Filter '*.exe').Count)"
    } else {
        Write-Error "Could not find bin directory in extracted files"
        exit 1
    }
}
catch {
    Write-Error "Failed to download FFmpeg: $_"
    Write-Error "Error details: $($_.Exception.Message)"
    exit 1
}
finally {
    # Cleanup
    if (Test-Path $zipFile) {
        Remove-Item $zipFile -Force
    }
    if (Test-Path $extractPath) {
        Remove-Item $extractPath -Recurse -Force
    }
}
