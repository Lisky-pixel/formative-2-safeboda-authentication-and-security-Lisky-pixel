$ErrorActionPreference = 'Stop'

$base = 'http://127.0.0.1:8000'
$u = 'oluchi' + (Get-Random -Maximum 100000)
$pwd = 'Password123!'

# Register
$regBody = @{ 
  username = $u
  email = "$u@example.com"
  phone_number = '+250788000111'
  password = $pwd
  password_confirm = $pwd
  first_name = 'Oluchi'
  last_name = 'Okafor'
} | ConvertTo-Json
$regRes = Invoke-RestMethod -Method Post -Uri "$base/api/auth/register/" -ContentType 'application/json' -Body $regBody

# Session login
$loginBody = @{ 
  username = $u
  password = $pwd
  remember_me = $false
} | ConvertTo-Json
$loginRes = Invoke-RestMethod -Method Post -Uri "$base/api/auth/session/login/" -ContentType 'application/json' -Body $loginBody -SessionVariable sess

# JWT token
$tokenBody = @{ 
  username = $u
  password = $pwd
} | ConvertTo-Json
$tokRes = Invoke-RestMethod -Method Post -Uri "$base/api/auth/jwt-token/" -ContentType 'application/json' -Body $tokenBody
$access = $tokRes.access
$refresh = $tokRes.refresh

# Verify token
$verifyRes = Invoke-RestMethod -Method Post -Uri "$base/api/auth/jwt/verify/" -Headers @{ Authorization = "Bearer $access" }

# Privacy data export (protected)
$exportRes = Invoke-RestMethod -Method Get -Uri "$base/api/privacy/data-export/" -Headers @{ Authorization = "Bearer $access" }

Write-Host "USER=$u"
Write-Host "SESSION_LOGIN=OK"
Write-Host "ACCESS_LEN=$($access.Length)"
Write-Host "VERIFY_OK"
Write-Host "EXPORT_KEYS=$($exportRes | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue | Out-String)"
