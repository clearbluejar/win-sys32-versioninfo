$runner=$args[0]
$ver = .\get_ver.ps1
$com_json_path = "${runner}-${ver}-com.json"
Get-CimInstance -ClassName Win32_COMSetting | ? {$_.InprocServer32 -or $_.LocalServer32 } | ConvertTo-Json | Out-File $com_json_path