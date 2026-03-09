#!/usr/bin/env pwsh
param(
  [string]$Version = $env:HANDSHAKER_VERSION,
  [switch]$UseSource
)

$ErrorActionPreference = 'Stop'
$repo = 'gbiagomba/WeakSSL'
$bin = 'handshaker'

function Say($msg) { Write-Host "[install] $msg" }
function Err($msg) { Write-Error "[install][error] $msg" }

function Detect-Target {
  $os = 'windows'
  $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToUpper()
  switch ($arch) {
    'X64' { $arch = 'X64' }
    'ARM64' { $arch = 'ARM64' }
    default { Err "Unsupported arch: $arch"; exit 1 }
  }
  return "$os-$arch"
}

function Install-FromBinary {
  $target = Detect-Target
  $asset = "$bin-$target.exe"
  if (-not $Version) {
    try {
      $latest = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$repo/releases/latest"
      $Version = $latest.tag_name
    } catch {
      Err "Could not determine latest version"; return $false
    }
  }
  $url = "https://github.com/$repo/releases/download/$Version/$asset"
  $tmp = New-TemporaryFile
  Say "Downloading $url"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp
  } catch {
    Remove-Item -Force $tmp -ErrorAction SilentlyContinue
    return $false
  }
  $dest = Join-Path $env:ProgramFiles "${bin}.exe"
  if (-not (Test-Path (Split-Path $dest -Parent))) { New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null }
  Copy-Item -Force $tmp $dest
  Remove-Item -Force $tmp
  Say "Installed $bin to $dest"
  $destDir = Split-Path $dest -Parent
  if ($env:PATH -notlike "*${destDir}*") {
    [Environment]::SetEnvironmentVariable('PATH', "$($env:PATH);$destDir", 'Machine')
    Say "Added $destDir to PATH"
  }
  return $true
}

function Install-FromSource {
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Err 'cargo is required for source install'; exit 1 }
  Say 'Building from source (release)'
  & cargo build --release
  $src = "target/release/${bin}.exe"
  if (-not (Test-Path $src)) { Err "Build failed: $src not found"; exit 1 }
  $dest = Join-Path $env:ProgramFiles "${bin}.exe"
  Copy-Item -Force $src $dest
  Say "Installed $bin to $dest"
}

if ($UseSource) {
  Install-FromSource
} else {
  if (-not (Install-FromBinary)) {
    Say 'Falling back to source build'
    Install-FromSource
  }
}
