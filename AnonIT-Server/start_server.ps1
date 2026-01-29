# AnonIT Server Startup Script (PowerShell)
# Run with: powershell -ExecutionPolicy Bypass -File start_server.ps1

$Host.UI.RawUI.WindowTitle = "AnonIT Server"

Write-Host "========================================"
Write-Host "     AnonIT Secure Messenger Server"
Write-Host "========================================"
Write-Host ""

# Check if venv exists
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
    
    Write-Host "Installing dependencies..."
    & "venv\Scripts\Activate.ps1"
    pip install -r requirements.txt
} else {
    & "venv\Scripts\Activate.ps1"
}

Write-Host ""
Write-Host "Starting server on port 8765..."
Write-Host "Press Ctrl+C to stop"
Write-Host ""

# Auto-restart loop
while ($true) {
    try {
        python server.py
    } catch {
        Write-Host "Error: $_"
    }
    
    Write-Host ""
    Write-Host "Server stopped. Restarting in 5 seconds..."
    Write-Host "Press Ctrl+C again to exit completely"
    Start-Sleep -Seconds 5
}
