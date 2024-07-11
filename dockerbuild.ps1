$version = get-date -Format yyyyMMddHHmmss
$image = "inventory-updater"

docker login keppel.eu-de-1.cloud.sap
docker build . -t keppel.eu-de-1.cloud.sap/ccloud/${image}:$version -t keppel.eu-de-1.cloud.sap/ccloud/${image}:latest
docker push keppel.eu-de-1.cloud.sap/ccloud/${image}:$version
