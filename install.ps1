$Version = "v1.0.0"
$Url = "https://github.com/Omkar443/leakhunterx-agent/releases/download/$Version/lhx-agent-windows-x64.exe"

$Dest = "$env:ProgramFiles\lhx-agent.exe"

Invoke-WebRequest -Uri $Url -OutFile $Dest

Write-Host "LeakHunterX Agent installed."
Write-Host "Run: lhx-agent.exe pair"
