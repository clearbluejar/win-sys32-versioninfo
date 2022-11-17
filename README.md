# win-sys32-versioninfo
A simple repo to generate version info for System32

Leverages powershell to collect FileVersion information from the file system.

```powershell
   $ver = [System.Environment]::OSVersion.Version -join '.'
         $bin_types = "*.exe","*.dll","*.sys","*.winmd","*.cpl","*.ax","*.node","*.ocx","*.efi","*.acm","*.scr","*.tsp","*.drv"
         $allrecurse = "${ver}-versioninfo-system32-winprogiles-recurse.json"
         $allpaths_to_scan = "C:\Program*\Mi*","C:\Program*\Win*", "C:\Windows\System32\", "C:\Program*\Common*"
         Get-ChildItem $allpaths_to_scan -Include $bin_types -Recurse -ErrorAction SilentlyContinue | select  Name,VersionInfo | ConvertTo-Json -depth 100 -Compress | Out-File $allrecurse
```

The workflow runs on the Github [win2022-server image runner](https://github.com/actions/runner-images/blob/main/images/win/Windows2022-Readme.md) and generates the corresponding json. 

Sample output:
```json


   {
        "Name": "EmbeddedBrowserWebView.dll",
        "VersionInfo": {
            "Comments": "",
            "CompanyName": "Microsoft Corporation",
            "FileBuildPart": 1418,
            "FileDescription": "Microsoft Edge Embedded Browser WebView Client",
            "FileMajorPart": 107,
            "FileMinorPart": 0,
            "FileName": "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\107.0.1418.35\\EBWebView\\x86\\EmbeddedBrowserWebView.dll",
            "FilePrivatePart": 35,
            "FileVersion": "107.0.1418.35",
            "InternalName": "EmbeddedBrowserWebView.dll",
            "IsDebug": false,
            "IsPatched": false,
            "IsPrivateBuild": false,
            "IsPreRelease": false,
            "IsSpecialBuild": false,
            "Language": "English (United States)",
            "LegalCopyright": "Copyright Microsoft Corporation. All rights reserved.",
            "LegalTrademarks": "",
            "OriginalFilename": "EmbeddedBrowserWebView.dll",
            "PrivateBuild": "",
            "ProductBuildPart": 1418,
            "ProductMajorPart": 107,
            "ProductMinorPart": 0,
            "ProductName": "Microsoft Edge Embedded Browser WebView Client",
            "ProductPrivatePart": 35,
            "ProductVersion": "107.0.1418.35",
            "SpecialBuild": "",
            "FileVersionRaw": {
                "Major": 107,
                "Minor": 0,
                "Build": 1418,
                "Revision": 35,
                "MajorRevision": 0,
                "MinorRevision": 35
            },
            "ProductVersionRaw": {
                "Major": 107,
                "Minor": 0,
                "Build": 1418,
                "Revision": 35,
                "MajorRevision": 0,
                "MinorRevision": 35
            }
        }
    },
    {
        "Name": "setup.exe",
        "VersionInfo": {
            "Comments": "",
            "CompanyName": "Microsoft Corporation",
            "FileBuildPart": 1418,
            "FileDescription": "Microsoft Edge Installer",
            "FileMajorPart": 107,
            "FileMinorPart": 0,
            "FileName": "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\107.0.1418.35\\Installer\\setup.exe",
            "FilePrivatePart": 35,
            "FileVersion": "107.0.1418.35",
            "InternalName": "setup_exe",
            "IsDebug": false,
            "IsPatched": false,
            "IsPrivateBuild": false,
            "IsPreRelease": false,
            "IsSpecialBuild": false,
            "Language": "English (United States)",
            "LegalCopyright": "Copyright Microsoft Corporation. All rights reserved.",
            "LegalTrademarks": "",
            "OriginalFilename": "setup.exe",
            "PrivateBuild": "",
            "ProductBuildPart": 1418,
            "ProductMajorPart": 107,
            "ProductMinorPart": 0,
            "ProductName": "Microsoft Edge Installer",
            "ProductPrivatePart": 35,
            "ProductVersion": "107.0.1418.35",
            "SpecialBuild": "",
            "FileVersionRaw": {
                "Major": 107,
                "Minor": 0,
                "Build": 1418,
                "Revision": 35,
                "MajorRevision": 0,
                "MinorRevision": 35
            },
            "ProductVersionRaw": {
                "Major": 107,
                "Minor": 0,
                "Build": 1418,
                "Revision": 35,
                "MajorRevision": 0,
                "MinorRevision": 35
            }
        }
    },
    
  ```
