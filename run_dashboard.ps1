Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Starting Adaptive Cyber Defense Framework Dashboard" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n[1/2] Starting Backend on http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\backend'; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

Start-Sleep -Seconds 2

Write-Host "[2/2] Starting Frontend on http://localhost:5173 ..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\frontend'; npm run dev"

Start-Sleep -Seconds 3

Write-Host "`nOpening browser at http://localhost:5173 ..." -ForegroundColor Yellow
Start-Process "http://localhost:5173"

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "Dashboard is LIVE!" -ForegroundColor Green
Write-Host "Frontend URL:  http://localhost:5173" -ForegroundColor White
Write-Host "Backend API:   http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "Login Email:   soc_admin@defense.com" -ForegroundColor White
Write-Host "Password:      AdminPassword123!" -ForegroundColor White
Write-Host "===================================================" -ForegroundColor Cyan
