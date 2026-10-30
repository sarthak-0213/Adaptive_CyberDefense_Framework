@echo off
title Adaptive Cyber Defense - Launcher
echo ===================================================
echo Starting Adaptive Cyber Defense Framework Dashboard
echo ===================================================

cd /d "%~dp0"

echo [1/2] Starting Backend on http://127.0.0.1:8000 ...
start "ACDF-Backend" cmd /k "cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

ping 127.0.0.1 -n 3 >nul

echo [2/2] Starting Frontend on http://localhost:5173 ...
start "ACDF-Frontend" cmd /k "cd frontend && npm run dev"

ping 127.0.0.1 -n 4 >nul

echo Opening browser...
start http://localhost:5173

echo.
echo ===================================================
echo Dashboard is running!
echo Frontend: http://localhost:5173
echo Backend:  http://127.0.0.1:8000/docs
echo Admin Login: soc_admin@defense.com / AdminPassword123!
echo ===================================================
