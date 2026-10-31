$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot

Push-Location $projectRoot
try {
    Write-Host "Stopping any Compose engine/frontend containers that occupy local ports..."
    docker compose stop engine frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Could not stop the Compose engine/frontend services."
    }

    Write-Host "Starting only the isolated target applications..."
    docker compose up -d target-flask target-juice-shop
    if ($LASTEXITCODE -ne 0) {
        throw "Could not start the target applications. Fetch the target sources and Flask wheelhouse first."
    }

    $flaskBinding = docker compose port target-flask 5050
    if ($LASTEXITCODE -ne 0) { throw "Could not determine the Flask target's loopback port." }
    $juiceShopBinding = docker compose port target-juice-shop 3000
    if ($LASTEXITCODE -ne 0) { throw "Could not determine the Juice Shop target's loopback port." }
    $flaskPort = ($flaskBinding | Select-Object -Last 1).Trim().Split(':')[-1]
    $juiceShopPort = ($juiceShopBinding | Select-Object -Last 1).Trim().Split(':')[-1]

    $venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        $python = $venvPython
    }
    else {
        $python = "python"
    }

    $env:MITIGATA_TARGET_URL_FLASK_DEMO = "http://127.0.0.1:$flaskPort"
    $env:MITIGATA_TARGET_URL_JUICE_SHOP = "http://127.0.0.1:$juiceShopPort"
    $env:GRAPHCODEBERT_MODE = "ON"

    Write-Host "Starting the API locally. GraphCodeBERT weights load on first planner request if uncached."
    & $python -m uvicorn engine.api.main:app --host 127.0.0.1 --port 8000
    if ($LASTEXITCODE -ne 0) {
        throw "The local API exited with an error."
    }
}
finally {
    Pop-Location
}
