param(
    [switch]$Demo,
    [switch]$Rebuild,
    [ValidateRange(1,65535)][int]$Port = 8080,
    [string]$MsysRoot = 'C:\msys64'
)
$ErrorActionPreference = 'Stop'
$toolchain = Join-Path $MsysRoot 'ucrt64\bin'
$gcc = Join-Path $toolchain 'gcc.exe'
if (-not (Test-Path $gcc)) {
    throw 'Install MSYS2 and the three UCRT64 packages listed in README.md.'
}
$env:Path = "$toolchain;$env:Path"
Push-Location $PSScriptRoot
try {
    $exe = Join-Path $PSScriptRoot 'campusfind.exe'
    $sources = Get-Item server.c,dsa.c,dsa.h,sqlite_api.h
    $old = Test-Path $exe
    if ($old) {
        $modified = (Get-Item $exe).LastWriteTimeUtc
        $old = -not ($sources | Where-Object { $_.LastWriteTimeUtc -gt $modified })
    }
    if ($Rebuild -or -not $old) {
        & $gcc -std=c17 -Wall -Wextra -O2 server.c dsa.c -o $exe -lsqlite3 -lcrypto -lws2_32
        if ($LASTEXITCODE -ne 0) { throw 'CampusFind compilation failed.' }
    }
    $arguments = @('--port', "$Port")
    if ($Demo) { $arguments += '--demo' }
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw 'CampusFind stopped with an error.' }
} finally {
    Pop-Location
}
