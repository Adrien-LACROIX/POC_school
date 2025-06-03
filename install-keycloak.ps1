[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Configuration
$KeycloakHost = "http://localhost:8081"
$AdminUser = "admin"
$AdminPassword = "admin"

$RealmName = "myrealm"
$ClientId = "myapp"

$TestUsername = "testuser"
$TestEmail = "test@example.com"
$TestPassword = "secret123"

Write-Host "Connexion à Keycloak..."
$TokenResponse = Invoke-RestMethod -Method Post -Uri "$KeycloakHost/realms/master/protocol/openid-connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{
    username = $AdminUser
    password = $AdminPassword
    grant_type = "password"
    client_id = "admin-cli"
}

$AccessToken = $TokenResponse.access_token

# === Realm ===
try {
    $RealmCheck = Invoke-RestMethod -Method Get -Uri "$KeycloakHost/admin/realms/$RealmName" -Headers @{ Authorization = "Bearer $AccessToken" }
    Write-Host "Le realm '$RealmName' existe déjà."
} catch {
    Write-Host "Création du realm '$RealmName'..."
    $RealmPayload = @{
        realm = $RealmName
        enabled = $true
    } | ConvertTo-Json -Depth 10

    Invoke-RestMethod -Method Post -Uri "$KeycloakHost/admin/realms" -Headers @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    } -Body $RealmPayload
    Write-Host "Realm '$RealmName' créé avec succès."
}

# === Client ===
$Clients = Invoke-RestMethod -Method Get -Uri "$KeycloakHost/admin/realms/$RealmName/clients?clientId=$ClientId" -Headers @{ Authorization = "Bearer $AccessToken" }

if ($Clients.Count -eq 0) {
    Write-Host "Création du client '$ClientId'..."
    $ClientPayload = @{
        clientId = $ClientId
        enabled = $true
        protocol = "openid-connect"
        publicClient = $true
        redirectUris = @("http://localhost:8080/*")
        webOrigins = @("http://localhost:8080")
        directAccessGrantsEnabled = $true
        standardFlowEnabled = $true
    } | ConvertTo-Json -Depth 10

    Invoke-RestMethod -Method Post -Uri "$KeycloakHost/admin/realms/$RealmName/clients" -Headers @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    } -Body $ClientPayload
    Write-Host "Le client '$ClientId' créé avec succès."
} else {
    Write-Host "Le client '$ClientId' existe déjà."
}

# === Utilisateur ===
Write-Host "Création de l'utilisateur '$TestUsername'..."
$UserPayload = @{
    username = $TestUsername
    email = $TestEmail
    enabled = $true
    emailVerified = $true
    credentials = @(@{
        type = "password"
        value = $TestPassword
        temporary = $false
    })
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Post -Uri "$KeycloakHost/admin/realms/$RealmName/users" -Headers @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
} -Body $UserPayload

Write-Host "Utilisateur '$TestUsername' ajouté au realm '$RealmName'."
