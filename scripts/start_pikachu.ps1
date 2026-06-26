$ErrorActionPreference = "Stop"

$containerName = "quirky_heyrovsky"

docker start $containerName | Out-Null
docker exec $containerName sh -lc "rm -f /var/run/apache2/apache2.pid && apache2ctl start"

Write-Host "Pikachu should now be available at http://127.0.0.1:8765/"
