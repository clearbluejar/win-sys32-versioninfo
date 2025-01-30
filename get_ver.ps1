#$ver = [System.Environment]::OSVersion.Version -join '.'
# $ver = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object -ExpandProperty LCUVer
$ver = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
if ($ver.LCUVer) {
    $ver = $ver.LCUVer
} elseif ($ver.ReleaseId) {
    $ver = "$($ver.CurrentMajorVersionNumber).$($ver.CurrentMinorVersionNumber).$($ver.CurrentBuild).$(($ver.UBR))"
} else {
    $ver = "Property not found"
}

Write-Host $ver