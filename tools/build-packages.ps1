# Build only declared release files. No deployment or device access.
# Use -LiteOnly when the separately reviewed full runtime is unavailable.
param(
  [switch]$LiteOnly,
  [string]$RuntimeDir = ''
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$releaseBase = Split-Path -Parent $PSScriptRoot
$releaseOut = Join-Path $releaseBase 'dist'
$moduleSource = Join-Path $releaseBase 'module'
if (-not $RuntimeDir) { $RuntimeDir = Join-Path $releaseBase 'nrtp' }
$moduleFiles = @(
  'adapt-probe.mjs', 'adapt-probe.sh', 'common.sh', 'customize.sh',
  'deploy.sh', 'gencert.mjs', 'META-INF/com/google/android/update-binary',
  'module.prop', 'proxy.mjs', 'proxy.version', 'RELEASE.md', 'resolve4.mjs',
  'service.sh', 'tanke-proxy.sh', 'targets.env', 'uninstall.sh', 'VERSION_COMPAT.md'
)
$licenseFiles = @('LICENSE', 'THIRD-PARTY-NOTICES.txt')
$runtimeFiles = @(
  'bin/node', 'lib/libc++_shared.so', 'lib/libcares.so', 'lib/libcrypto.so.3',
  'lib/libffi.so', 'lib/libicudata.so.79', 'lib/libicui18n.so.79',
  'lib/libicuuc.so.79', 'lib/libsqlite3.so', 'lib/libssl.so.3', 'lib/libz.so.1'
)
$executables = @(
  'service.sh', 'uninstall.sh', 'common.sh', 'deploy.sh', 'tanke-proxy.sh',
  'adapt-probe.sh', 'customize.sh', 'META-INF/com/google/android/update-binary', 'bin/node'
)

function Relative-Path([string]$root, [string]$file) {
  $prefix = [System.IO.Path]::GetFullPath($root).TrimEnd([char]92, [char]47)
  return $file.Substring($prefix.Length + 1).Replace([char]92, [char]47)
}

function Require-File([string]$file) {
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
    throw "Missing required release input: $file"
  }
  if ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Release inputs must not be symlinks/reparse points: $file"
  }
}

function Copy-Exact([string]$source, [string]$destination) {
  Require-File $source
  New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
  Copy-Item -LiteralPath $source -Destination $destination -Force
}

function Check-ModuleInputs {
  foreach ($name in $moduleFiles) { Require-File (Join-Path $moduleSource $name) }
  foreach ($name in $licenseFiles) { Require-File (Join-Path $releaseBase $name) }
  $allowed = $moduleFiles + $licenseFiles
  foreach ($item in (Get-ChildItem -LiteralPath $moduleSource -Recurse -Force)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw 'Module input contains a symlink/reparse point.'
    }
    if (-not $item.PSIsContainer) {
      $relative = Relative-Path $moduleSource $item.FullName
      if ($allowed -cnotcontains $relative) {
        throw "Unexpected module file; review it before changing the allowlist: $relative"
      }
    }
  }
}

function Copy-Module([string]$destination) {
  foreach ($name in $moduleFiles) {
    Copy-Exact (Join-Path $moduleSource $name) (Join-Path $destination $name)
  }
  # Always use the repository's current license, including in the installation ZIP.
  foreach ($name in $licenseFiles) {
    Copy-Exact (Join-Path $releaseBase $name) (Join-Path $destination $name)
  }
}

function Normalize-LF([string]$directory) {
  foreach ($file in (Get-ChildItem -LiteralPath $directory -Recurse -File)) {
    if ($file.Extension -in @('.sh', '.mjs', '.md', '.prop', '.env', '.txt') -or
        $file.Name -in @('update-binary', 'proxy.version', 'LICENSE')) {
      $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
      if ($bytes -contains 13) {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        $text = $text.Replace(([string][char]13 + [char]10), [string][char]10)
        [System.IO.File]::WriteAllText($file.FullName, $text, (New-Object System.Text.UTF8Encoding($false)))
      }
    }
  }
}

function New-ReleaseZip([string]$directory, [string]$zipPath) {
  if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
  $stream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
  $archive = $null
  try {
    $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    foreach ($file in (Get-ChildItem -LiteralPath $directory -Recurse -File | Sort-Object FullName)) {
      $relative = Relative-Path $directory $file.FullName
      $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
      # Fixed non-personal timestamp; entries carry no source path or extra fields.
      $entry.LastWriteTime = [DateTimeOffset]::new(2026, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
      $unixMode = if ($executables -contains $relative) { 0x81ED } else { 0x81A4 }
      $entry.ExternalAttributes = $unixMode -shl 16
      $entryStream = $entry.Open()
      try {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $entryStream.Write($bytes, 0, $bytes.Length)
      } finally {
        $entryStream.Dispose()
      }
    }
  } finally {
    if ($archive) { $archive.Dispose() }
    $stream.Dispose()
  }
}

Check-ModuleInputs
$runtimeLicenseFiles = @()
if (-not $LiteOnly) {
  foreach ($name in $runtimeFiles) { Require-File (Join-Path $RuntimeDir $name) }
  Require-File (Join-Path $RuntimeDir 'THIRD-PARTY-NOTICES.txt')
  $licenseRoot = Join-Path $RuntimeDir 'licenses'
  if (-not (Test-Path -LiteralPath $licenseRoot -PathType Container)) {
    throw 'Full builds require reviewed upstream license texts in nrtp/licenses/.'
  }
  foreach ($item in (Get-ChildItem -LiteralPath $licenseRoot -Recurse -Force)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw 'Runtime licenses must not contain symlinks/reparse points.'
    }
  }
  $runtimeLicenseFiles = @(Get-ChildItem -LiteralPath $licenseRoot -Recurse -File -Force)
  if (-not $runtimeLicenseFiles.Count) { throw 'Full builds require actual upstream license texts.' }
  foreach ($file in $runtimeLicenseFiles) {
    if ($file.Extension -notin @('.txt', '.md') -and $file.Name -notin @('LICENSE', 'COPYING', 'NOTICE')) {
      throw 'Unexpected runtime license file type; review before packaging.'
    }
  }
  # Presence checks do not establish legal compliance: review actual upstream versions.
}

New-Item -ItemType Directory -Path $releaseOut -Force | Out-Null
$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('tanke-release-' + [Guid]::NewGuid().ToString('N'))
$built = @()
try {
  $liteStage = Join-Path $stageRoot 'lite'
  Copy-Module $liteStage
  Normalize-LF $liteStage
  $litePath = Join-Path $releaseOut 'tanke-proxy-lite.zip'
  New-ReleaseZip $liteStage $litePath
  $built += $litePath
  if (-not $LiteOnly) {
    $fullStage = Join-Path $stageRoot 'full'
    Copy-Module $fullStage
    foreach ($name in $runtimeFiles) {
      Copy-Exact (Join-Path $RuntimeDir $name) (Join-Path $fullStage $name)
    }
    $runtimeNoticeDestination = Join-Path $fullStage 'third_party/runtime/THIRD-PARTY-NOTICES.txt'
    Copy-Exact (Join-Path $RuntimeDir 'THIRD-PARTY-NOTICES.txt') $runtimeNoticeDestination
    foreach ($file in $runtimeLicenseFiles) {
      $relative = Relative-Path $licenseRoot $file.FullName
      Copy-Exact $file.FullName (Join-Path $fullStage ('third_party/runtime/licenses/' + $relative))
    }
    Normalize-LF $fullStage
    $fullPath = Join-Path $releaseOut 'tanke-proxy-full.zip'
    New-ReleaseZip $fullStage $fullPath
    $built += $fullPath
  }
} finally {
  if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
}

foreach ($file in $built) {
  $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
  $read = [System.IO.Compression.ZipFile]::OpenRead($file)
  try { $count = $read.Entries.Count } finally { $read.Dispose() }
  Write-Output ("{0} bytes={1} entries={2} sha256={3}" -f
    (Split-Path -Leaf $file), (Get-Item -LiteralPath $file).Length, $count, $hash)
}
