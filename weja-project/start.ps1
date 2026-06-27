Write-Host "Starting WEJÀ WAF Sandbox Environment..." -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$aiEnginePort = if ($env:AI_ENGINE_PORT) { $env:AI_ENGINE_PORT } else { '5000' }
$targetPort = if ($env:TARGET_PORT) { $env:TARGET_PORT } else { '4000' }
$wafPort = if ($env:WAF_PORT) { $env:WAF_PORT } else { '3000' }

# Start AI Engine
Write-Host "Starting AI Engine..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k set AI_ENGINE_PORT=$aiEnginePort && cd ai-engine && venv\Scripts\activate && python app.py" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Dummy Target
Write-Host "Starting Dummy Target..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k set TARGET_PORT=$targetPort && cd dummy-target && node server.js" -WindowStyle Normal
Start-Sleep -Seconds 1

# Start WAF Gateway
Write-Host "Starting WAF Gateway..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k set PORT=$wafPort && set AI_ENGINE_PORT=$aiEnginePort && set TARGET_PORT=$targetPort && cd waf-proxy && npm start" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Dashboard
Write-Host "Starting Dashboard..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd client-dashboard && npm run dev" -WindowStyle Normal
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "================================" -ForegroundColor Green
Write-Host "All services started in separate windows!" -ForegroundColor Green
Write-Host ""
Write-Host "📡 AI Engine:    http://localhost:$aiEnginePort"
Write-Host "🎯 Target:       http://localhost:$targetPort"
Write-Host "🛡️  WAF Gateway:  http://localhost:$wafPort"
Write-Host "📊 Dashboard:    http://localhost:5173"
Write-Host ""
Write-Host "To test: node test_traffic.js"
Write-Host ""
