@echo off
setlocal

cd /d "%~dp0"

echo [1/4] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
  echo Python was not found on PATH.
  echo Install Python 3.8+ and rerun this file.
  exit /b 1
)

echo [2/4] Installing requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed.
  exit /b 1
)

if not exist "data\model_artifact.pkl" (
  echo [3/4] Training sample model...
  python -m phishing_detector.training --data data/sample_urls.csv --artifact data/model_artifact.pkl
  if errorlevel 1 (
    echo Training failed.
    exit /b 1
  )
) else (
  echo [3/4] Existing model artifact found. Skipping sample training.
)

echo [4/4] Starting Flask app...
echo Open http://127.0.0.1:5000 in your browser.
python app.py
