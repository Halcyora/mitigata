$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wheelhouse = Join-Path $repoRoot "targets\vulnerable_flask\wheelhouse"
$staging = Join-Path $env:TEMP ("mitigata-flask-wheels-" + [guid]::NewGuid().ToString())

New-Item -ItemType Directory -Force $staging | Out-Null
try {
    & python -m pip download `
        --disable-pip-version-check `
        --only-binary=:all: `
        --platform manylinux2014_x86_64 `
        --python-version 3.11 `
        --implementation cp `
        --abi cp311 `
        --dest $staging `
        -r (Join-Path $repoRoot "targets\vulnerable_flask\requirements.txt")

    if ($LASTEXITCODE -ne 0) {
        throw "Could not download the pinned Flask runtime wheels."
    }

    New-Item -ItemType Directory -Force $wheelhouse | Out-Null
    Copy-Item (Join-Path $staging "*.whl") $wheelhouse -Force
    Write-Host "Prepared Linux/Python 3.11 wheels in $wheelhouse."
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}
