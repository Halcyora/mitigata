$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$targets = @(
    @{
        Name = "Vulnerable-Flask-App"
        Url = "https://github.com/we45/Vulnerable-Flask-App.git"
        Path = Join-Path $repoRoot "targets\vulnerable_flask\source"
        Revision = "b6a4f97afd466e83e1f60781494252dec1c37039"
    },
    @{
        Name = "OWASP Juice Shop"
        Url = "https://github.com/juice-shop/juice-shop.git"
        Path = Join-Path $repoRoot "targets\juice-shop\source"
        Revision = "f189f521266f42c6bd05884468292000cee852ed"
    }
)

foreach ($target in $targets) {
    if (Test-Path (Join-Path $target.Path ".git")) {
        $actualRevision = (& git -C $target.Path rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "Could not read the Git revision for $($target.Name)."
        }

        if ($actualRevision -eq $target.Revision) {
            Write-Host "$($target.Name) is already at $($target.Revision)."
            continue
        }

        $changes = & git -C $target.Path status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Could not check the working tree for $($target.Name)."
        }
        if ($changes) {
            throw "$($target.Name) has local changes; refusing to change its revision."
        }

        & git -C $target.Path fetch --depth 1 origin $target.Revision
        if ($LASTEXITCODE -ne 0) {
            throw "Could not fetch the pinned revision for $($target.Name)."
        }
        & git -C $target.Path checkout --detach $target.Revision
        if ($LASTEXITCODE -ne 0) {
            throw "Could not check out the pinned revision for $($target.Name)."
        }
        continue
    }

    if (Test-Path $target.Path) {
        throw "Target directory already exists but is not a Git checkout: $($target.Path)"
    }

    New-Item -ItemType Directory -Force (Split-Path $target.Path) | Out-Null
    & git clone --no-checkout $target.Url $target.Path
    if ($LASTEXITCODE -ne 0) {
        throw "Could not clone $($target.Name)."
    }
    & git -C $target.Path fetch --depth 1 origin $target.Revision
    if ($LASTEXITCODE -ne 0) {
        throw "Could not fetch the pinned revision for $($target.Name)."
    }
    & git -C $target.Path checkout --detach $target.Revision
    if ($LASTEXITCODE -ne 0) {
        throw "Could not check out the pinned revision for $($target.Name)."
    }
}
