$ErrorActionPreference = 'Stop'

function Write-Step($name, $ok=$true) {
  if ($ok) { Write-Host ("[OK] " + $name) } else { Write-Host ("[FAIL] " + $name) }
}

$base = 'http://127.0.0.1:8000'

# ---------- Auth ----------
$u = 'user' + (Get-Random -Maximum 100000)
$pwd = 'Password123!'
$rand6 = (Get-Random -Maximum 999999).ToString().PadLeft(6,'0')
$phone = "+250788$rand6"

# Register
$regBody = @{
  username = $u
  email = "$u@example.com"
  phone_number = $phone
  password = $pwd
  password_confirm = $pwd
  first_name = 'Test'
  last_name = 'User'
} | ConvertTo-Json
$null = Invoke-RestMethod -Method Post -Uri "$base/api/auth/register/" -ContentType 'application/json' -Body $regBody
Write-Step "Auth.Register ($u $phone)"

# Session login
$loginBody = @{ username = $u; password = $pwd; remember_me = $false } | ConvertTo-Json
$null = Invoke-RestMethod -Method Post -Uri "$base/api/auth/session/login/" -ContentType 'application/json' -Body $loginBody -SessionVariable sess
Write-Step "Auth.SessionLogin"

# JWT token
$tokBody = @{ username = $u; password = $pwd } | ConvertTo-Json
$tok = Invoke-RestMethod -Method Post -Uri "$base/api/auth/jwt-token/" -ContentType 'application/json' -Body $tokBody
$access = $tok.access
$refresh = $tok.refresh
Write-Step "Auth.JWTToken (len=$($access.Length))"

# Verify token
$null = Invoke-RestMethod -Method Post -Uri "$base/api/auth/jwt/verify/" -Headers @{ Authorization = "Bearer $access" }
Write-Step "Auth.JWTVerify"

# Refresh token
$refBody = @{ refresh = $refresh } | ConvertTo-Json
$tok2 = Invoke-RestMethod -Method Post -Uri "$base/api/auth/jwt/refresh/" -ContentType 'application/json' -Body $refBody
$access2 = $tok2.access
Write-Step "Auth.JWTRefresh (len=$($access2.Length))"

# ---------- UAS (selected) ----------
# Districts
$ds = Invoke-RestMethod -Method Get -Uri "$base/api/uas/districts/"
Write-Step ("UAS.Districts (count=" + ($ds | Measure-Object | Select-Object -ExpandProperty Count) + ")")

# Account status (Bearer)
$headers = @{ Authorization = "Bearer $access2" }
$as = Invoke-RestMethod -Method Get -Uri "$base/api/uas/account/status/" -Headers $headers
Write-Step "UAS.AccountStatus"

# Verify phone (send code) - try with Bearer, skip on 401
try {
  $sendPhoneBody = @{ phone_number = $phone } | ConvertTo-Json
  $null = Invoke-RestMethod -Method Post -Uri "$base/api/uas/verify-phone/" -Headers $headers -ContentType 'application/json' -Body $sendPhoneBody
  Write-Step "UAS.VerifyPhone.SendCode"
} catch {
  Write-Step "UAS.VerifyPhone.SendCode (SKIP)" $false
}

# ---------- Privacy (Bearer) ----------
# Data export
$export = Invoke-RestMethod -Method Get -Uri "$base/api/privacy/data-export/" -Headers $headers
Write-Step "Privacy.DataExport"

# Consent get/post
$consentGet = Invoke-RestMethod -Method Get -Uri "$base/api/privacy/consent/" -Headers $headers
Write-Step "Privacy.Consent.GET"
# Try to find a consent_type_id in response (first available)
$consentTypeId = $null
if ($consentGet -is [System.Collections.IDictionary]) {
  foreach ($k in $consentGet.Keys) {
    if ($consentGet[$k] -is [System.Collections.IEnumerable]) {
      foreach ($item in $consentGet[$k]) {
        if ($item.consent_type_id) { $consentTypeId = $item.consent_type_id; break }
        if ($item.id) { $consentTypeId = $item.id; break }
      }
    }
    if ($consentTypeId) { break }
  }
}
if (-not $consentTypeId) { $consentTypeId = 1 }
$consentBody = @{ consent_type_id = $consentTypeId; status = $true } | ConvertTo-Json
$null = Invoke-RestMethod -Method Post -Uri "$base/api/privacy/consent/" -Headers $headers -ContentType 'application/json' -Body $consentBody
Write-Step "Privacy.Consent.POST"

# Settings get/post
$null = Invoke-RestMethod -Method Get -Uri "$base/api/privacy/settings/" -Headers $headers
Write-Step "Privacy.Settings.GET"
$settingsBody = @{ share_data_with_third_parties = $false; email_notifications = $true } | ConvertTo-Json
$null = Invoke-RestMethod -Method Post -Uri "$base/api/privacy/settings/" -Headers $headers -ContentType 'application/json' -Body $settingsBody
Write-Step "Privacy.Settings.POST"

# Retention policy
$null = Invoke-RestMethod -Method Get -Uri "$base/api/privacy/retention-policy/" -Headers $headers
Write-Step "Privacy.RetentionPolicy"

# Audit log (may be empty but endpoint reachable)
$null = Invoke-RestMethod -Method Get -Uri "$base/api/privacy/audit-log/" -Headers $headers
Write-Step "Privacy.AuditLog"

# Anonymize (no body)
$null = Invoke-RestMethod -Method Post -Uri "$base/api/privacy/anonymize/" -Headers $headers
Write-Step "Privacy.Anonymize"

# Data deletion (queues request)
$null = Invoke-RestMethod -Method Delete -Uri "$base/api/privacy/data-deletion/" -Headers $headers -ContentType 'application/json' -Body '{}' 
Write-Step "Privacy.DataDeletion"

Write-Host "---"
Write-Host "ALL DONE"
