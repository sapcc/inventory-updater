
param (
    $region = "eu-de-2"
)

$ProgressPreference = "SilentlyContinue"

#$netbox = "https://netbox.global.cloud.sap"
$netbox = "https://netbox-dev.netbox.c.eu-de-2.cloud.sap"

$request = Invoke-WebRequest -Uri "${netbox}/api/dcim/regions/?q=${region}"
$content = $request.content|ConvertFrom-Json
$region = $content.results

$uri = "https://netbox.global.cloud.sap/api/dcim/devices/?role_id=8&region_id=$($region.id)&tenant_id=1&exclude=config_context&limit=100&tag__n=no-redfish&status=active"
do {
    $serverlist = @()
    $request = Invoke-WebRequest -Uri $uri
    $content = $request.content|ConvertFrom-Json
    foreach ($server in $content.results) {$serverlist += "$($server.name).cc.$($server.site.slug.substring(0,7)).cloud.sap"}
    $serverlist|Out-File -Append "serverlist_$($region.slug).txt" -Encoding ascii
    $uri = $content.next
} while ($content.next)

