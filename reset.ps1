Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
Write-Host "Lancement de Docker Desktop..."
Start-Sleep -Seconds 10

Write-Host "Arrêt et suppression des conteneurs + volumes..."
docker-compose down -v

Write-Host "Reconstruction et démarrage des conteneurs..."
docker-compose up --build -d

##Write-Host "Attente du démarrage de Keycloak (30s)..."
##Start-Sleep -Seconds 30

Write-Host 'Initialisation de Keycloak (realm, client, user)...'
.\install-keycloak.ps1

Write-Host "Ouverture de l application dans le navigateur..."
cd app/
go run ./main.go
Start-Process "http://localhost:8080"

Write-Host "Environnement pret à l emploi avec interface ouverte..."