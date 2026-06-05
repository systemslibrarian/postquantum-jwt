param(
    [string]$IssuerUrl = "http://localhost:5180",
    [string]$OrdersUrl = "http://localhost:5190"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $ScriptDir "docker-compose.yml"

$PassCount = 0

function Pass($Message) {
    $script:PassCount++
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Fail($Message) {
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    throw $Message
}

function Wait-ForHealth($Name, $Url) {
    for ($i = 0; $i -lt 90; $i++) {
        try {
            Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 3 | Out-Null
            Pass "$Name health check"
            return
        }
        catch {
            Start-Sleep -Seconds 2
        }
    }

    Fail "$Name did not become healthy at $Url"
}

function New-Token($Path, $Body) {
    $json = $Body | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri "$IssuerUrl$Path" -Method Post -ContentType "application/json" -Body $json
}

function Get-TokenPartCount($Token) {
    return ($Token -split '\.').Count
}

function Invoke-Orders($Token) {
    try {
        Invoke-WebRequest -Uri "$OrdersUrl/orders/123" -Method Get -Headers @{ Authorization = "Bearer $Token" } -UseBasicParsing
    }
    catch {
        return $_.Exception.Response
    }
}

function Expect-Status($Label, [int]$Expected, $Token) {
    $response = Invoke-Orders $Token
    $status = [int]$response.StatusCode

    if ($status -eq $Expected) {
        Pass $Label
    }
    else {
        Fail "$Label expected HTTP $Expected but got $status"
    }
}

Write-Host "Starting ProductionDeploymentDemo stack..."
docker compose -f $ComposeFile up --build -d

Wait-ForHealth "issuer" "$IssuerUrl/health"
Wait-ForHealth "orders-api" "$OrdersUrl/health"

$encrypted = New-Token "/token" @{
    subject = "alice"
    role = "reader"
    scope = "orders.read"
    encrypted = $true
}
$encryptedToken = $encrypted.access_token
$encryptedParts = Get-TokenPartCount $encryptedToken

if ($encryptedParts -eq 5) {
    Pass "encrypted token issued as 5-part compact token"
}
else {
    Fail "encrypted token should have 5 parts but had $encryptedParts"
}

Expect-Status "encrypted token accepted by orders-api" 200 $encryptedToken

$signed = New-Token "/token" @{
    subject = "bob"
    role = "reader"
    scope = "orders.read"
    encrypted = $false
}
$signedToken = $signed.access_token
$signedParts = Get-TokenPartCount $signedToken

if ($signedParts -eq 3) {
    Expect-Status "signed-only token accepted by orders-api" 200 $signedToken
}
else {
    Fail "signed-only token should have 3 parts but had $signedParts"
}

$replay = New-Token "/token" @{
    subject = "carol"
    role = "reader"
    scope = "orders.read"
    encrypted = $true
}
$replayToken = $replay.access_token

Expect-Status "first use of replay-test token accepted" 200 $replayToken
Expect-Status "replayed token rejected" 401 $replayToken

Expect-Status "tampered token rejected" 401 "$encryptedToken`A"

$wrongAudience = New-Token "/token/wrong-audience" @{
    subject = "dana"
    role = "reader"
    scope = "orders.read"
    encrypted = $true
}
Expect-Status "wrong-audience token rejected" 401 $wrongAudience.access_token

$expired = New-Token "/token/expired" @{
    subject = "erin"
    role = "reader"
    scope = "orders.read"
    encrypted = $true
}
Expect-Status "expired token rejected" 401 $expired.access_token

$old1 = New-Token "/token" @{
    subject = "frank"
    role = "reader"
    scope = "orders.read"
    encrypted = $true
}
$old2 = New-Token "/token" @{
    subject = "grace"
    role = "reader"
    scope = "orders.read"
    encrypted = $true
}

$rotate = Invoke-RestMethod -Uri "$IssuerUrl/keys/rotate" -Method Post -ContentType "application/json" -Body "{}"
if ([int]$rotate.publishedKeyCount -eq 2) {
    Pass "key rotation publishes active + previous keys"
}
else {
    Fail "key rotation should publish 2 keys but published $($rotate.publishedKeyCount)"
}

Start-Sleep -Seconds 3
Expect-Status "old-key token accepted during overlap" 200 $old1.access_token

$retire = Invoke-RestMethod -Uri "$IssuerUrl/keys/retire-previous" -Method Post -ContentType "application/json" -Body "{}"
if ([int]$retire.publishedKeyCount -eq 1) {
    Pass "previous key retired"
}
else {
    Fail "retirement should publish 1 key but published $($retire.publishedKeyCount)"
}

Start-Sleep -Seconds 3
Expect-Status "old-key token rejected after retirement" 401 $old2.access_token

Write-Host ""
Write-Host "ProductionDeploymentDemo complete: $PassCount/14 checks passed." -ForegroundColor Cyan
