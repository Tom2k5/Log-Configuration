1) **By examining the logs located in the `"C:\Logs\DLLHijack"` directory, determine the process responsible for executing a DLL hijacking attack. Enter the process name as your answer. Answer format: `_.exe`**
- Event ID 7
- Unsigned DLL
```
Get-WinEvent -Path "C:\Logs\DLLHijack\*.evtx" |
Where-Object {
    $_.Id -eq 7 -and
    $_.Message -match "dll" -and
    $_.Message -match "Signed:\s+false"
} |
ForEach-Object {
    Write-Host "===== Event ====="
    Write-Host "Time: $($_.TimeCreated)"
    Write-Host "Event ID: $($_.Id)"
    Write-Host "Provider: $($_.ProviderName)"
    Write-Host "Message:`n$($_.Message)"
    Write-Host "`n"
}
```

```
Image: C:\Windows\System32\rundll32.exe
ImageLoaded: C:\ProgramData\DismCore.dll
FileVersion: 0.0.0.0
Description: FILEDESCRIPTIONGOESHERE
Product: PRODUCTNAMEGOESHERE
Company: -
OriginalFileName: ORIGINALFILENAMEGOESHERE
Hashes: SHA1=524945EE2CC863CDB57C7CCCD89607B9CD6E0524,MD5=9B5056E10FCF5959F70637553E5C1577,SHA256=6AB9D94E6888FB808E7FBBE93F8F60A0D7A021D6080923A1D8596C3C8CD6B7F7,IMPHASH=5393B78894398013B4127419F1A93894
Signed: false
Signature: -
SignatureStatus: Unavailable


Image: C:\ProgramData\Dism.exe
ImageLoaded: C:\ProgramData\DismCore.dll
FileVersion: 0.0.0.0
Description: FILEDESCRIPTIONGOESHERE
Product: PRODUCTNAMEGOESHERE
Company: -
OriginalFileName: ORIGINALFILENAMEGOESHERE
Hashes: SHA1=524945EE2CC863CDB57C7CCCD89607B9CD6E0524,MD5=9B5056E10FCF5959F70637553E5C1577,SHA256=6AB9D94E6888FB808E7FBBE93F8F60A0D7A021D6080923A1D8596C3C8CD6B7F7,IMPHASH=5393B78894398013B4127419F1A93894
Signed: false
Signature: -
SignatureStatus: Unavailable
```

=> **Dism.exe** 

2) **By examining the logs located in the `"C:\Logs\PowershellExec"` directory, determine the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: `_.exe`**

- Event ID 7
- **ImageLoaded** : clr.dll and clrjit.dll

```
Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" |
Where-Object {
    $_.Id -eq 7 -and
    ($_.Message -match "clr.dll" -or $_.Message -match "clrjit.dll")
} |
ForEach-Object {
    Write-Host "===== Event ====="
    Write-Host "Time: $($_.TimeCreated)"
    Write-Host "Event ID: $($_.Id)"
    Write-Host "Provider: $($_.ProviderName)"
    Write-Host "Message:`n$($_.Message)"
    Write-Host "`n"
}
```

```
===== Event =====
Time: 04/27/2022 18:59:42
Event ID: 7
Provider: Microsoft-Windows-Sysmon
Message:
Image loaded:
RuleName: -
UtcTime: 2022-04-28 01:59:42.249
ProcessGuid: {67e39d39-f4cc-6269-3203-000000000300}
ProcessId: 3776
Image: C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
ImageLoaded: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll
FileVersion: 4.8.4470.0 built by: NET48REL1LAST_C
Description: Microsoft .NET Runtime Just-In-Time Compiler
Product: Microsoft® .NET Framework
Company: Microsoft Corporation
OriginalFileName: clrjit.dll
Hashes: SHA1=078C7D64CF4D522E39CE9C1B3BC0333689DF3F40,MD5=61FDA7DD133D894630C2902900538647,SHA256=D8BB3F91EE89E3E4D6A418E7266DBCA1A354343226942C1E0A2E108F44DBCE5E,IMPHASH=9F2B44B648DE13A18C1ABC07250B85C2
Signed: true
Signature: Microsoft Corporation
SignatureStatus: Valid
User: DESKTOP-R4PEEIF\waldo


===== Event =====
Time: 04/27/2022 18:59:42
Event ID: 7
Provider: Microsoft-Windows-Sysmon
Message:
Image loaded:
RuleName: -
UtcTime: 2022-04-28 01:59:42.194
ProcessGuid: {67e39d39-f4cc-6269-3203-000000000300}
ProcessId: 3776
Image: C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
ImageLoaded: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
FileVersion: 4.8.4470.0 built by: NET48REL1LAST_C
Description: Microsoft .NET Runtime Common Language Runtime - WorkStation
Product: Microsoft® .NET Framework
Company: Microsoft Corporation
OriginalFileName: clr.dll
Hashes: SHA1=C5A99CE7425E1A2245A4C0FAC6FFD725508A6897,MD5=3C242B76E36DAB6C0B1E300AE7BC3D2E,SHA256=99ED3CC3A8CA5938783C0CAA052AC72A104FB6C7777A56D3AD7D6BBA32D52969,IMPHASH=6851068577998FF473E5933122867348
Signed: true
Signature: Microsoft Corporation
SignatureStatus: Valid
User: DESKTOP-R4PEEIF\waldo
```

**=> Calculator.exe**

3)  **By examining the logs located in the `"C:\Logs\PowershellExec"` directory, determine the process that injected into the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: `_.exe`**

- **TargetImage**: Calculator.exe => **SourceImage**: rundll32.exe

```
Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" |
Where-Object {
    $_.Message -match "TargetImage:\s+C:\\Program Files\\WindowsApps\\Microsoft\.WindowsCalculator_10\.1906\.55\.0_x64__8wekyb3d8bbwe\\Calculator\.exe"
} |
ForEach-Object {
    Write-Host "===== Event ====="
    Write-Host "Time: $($_.TimeCreated)"
    Write-Host "Event ID: $($_.Id)"
    Write-Host "Provider: $($_.ProviderName)"
    Write-Host "Message:`n$($_.Message)"
    Write-Host "`n"
}
```

```
===== Event =====
Time: 04/27/2022 19:00:13
Event ID: 8
Provider: Microsoft-Windows-Sysmon
Message:
CreateRemoteThread detected:
RuleName: -
UtcTime: 2022-04-28 02:00:13.593
SourceProcessGuid: {67e39d39-f0f6-6269-b601-000000000300}
SourceProcessId: 8364
SourceImage: C:\Windows\System32\rundll32.exe
TargetProcessGuid: {67e39d39-f4cc-6269-3203-000000000300}
TargetProcessId: 3776
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
NewThreadId: 4816
StartAddress: 0x00000253B2180000
StartModule: -
StartFunction: -
SourceUser: DESKTOP-R4PEEIF\waldo
TargetUser: DESKTOP-R4PEEIF\waldo
```

4) By examining the logs located in the `"C:\Logs\Dump"` directory, determine the process that performed an LSASS dump. Enter the process name as your answer. Answer format: `_.exe`
- Event ID 10 (ProcessAccess)
- **TargetImage** : lsass.exe
=>  svchost.exe
=>  ProcessHacker.exe
=>  2022-04-28 02:08:47.827 (The last time access to lsass.exe)

```
Get-WinEvent -Path "C:\Logs\Dump\*.evtx" |
Where-Object {
    $_.Id -eq 10 -and
    $_.Message -match "TargetImage:\s+C:\\Windows\\system32\\lsass\.exe"
} |
ForEach-Object {
    Write-Host "===== Event ====="
    Write-Host "Time: $($_.TimeCreated)"
    Write-Host "Event ID: $($_.Id)"
    Write-Host "Provider: $($_.ProviderName)"
    Write-Host "Message:`n$($_.Message)"
    Write-Host "`n"
}
```

```
===== Event =====
Time: 04/27/2022 19:08:47
Event ID: 10
Provider: Microsoft-Windows-Sysmon
Message:
Process accessed:
RuleName: -
UtcTime: 2022-04-28 02:08:47.827
SourceProcessGUID: {67e39d39-f72f-6269-6203-000000000300}
SourceProcessId: 5560
SourceThreadId: 3936
SourceImage: C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe
TargetProcessGUID: {67e39d39-ecd9-6269-0c00-000000000300}
TargetProcessId: 696
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1400
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9d234|C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe+9373b|C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe+95a1b|C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe+175751|C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe+10952b|C:\Windows\System32\KERNEL32.DLL+17034|C:\Windows\SYSTEM32\ntdll.dll+52651
SourceUser: DESKTOP-R4PEEIF\waldo
TargetUser: NT AUTHORITY\SYSTEM
```

5) By examining the logs located in the `"C:\Logs\Dump"` directory, determine if an ill-intended login took place after the LSASS dump. Answer format: Yes or No

- 2022-04-28 02:08:47.827 (The last time access to lsass.exe) (above)

```
Get-WinEvent -Path "C:\Logs\Dump\*.evtx" |
Where-Object {
	$_.Id -eq 4624 -and
    $_.TimeCreated -gt (Get-Date "2022-04-28 02:08:47.827") -and
    $_.Message -match "*"
} |
Select-Object TimeCreated, Message
```

```
$dumpTime = Get-Date "2022-04-28 02:08:47.827"
$events = Get-WinEvent -Path "C:\Logs\Dump\*.evtx" | Where-Object {
    $_.Id -eq 4624 -and $_.TimeCreated -gt $dumpTime
}
foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    Write-Host "`n==== Event ===="
    $xml.Event.EventData.Data | ForEach-Object {
        "$($_.Name): $($_.'#text')"
    }
}
```

=> No

6) By examining the logs located in the `"C:\Logs\StrangePPID"` directory, determine a process that was used to temporarily execute code based on a strange parent-child relationship. Enter the process name as your answer. Answer format: `_.exe`

- Event ID 1 (ProcessCreation)
- Cause it returns too much results => Terminal gets crash => Use XML-based query.

=> **WerFault.exe** (only `powershell.exe` spawns `cmd.exe`)

```
Get-WinEvent -Path "C:\Logs\StrangePPID\*.evtx" |
Where-Object { $_.Id -eq 1 } |  # Event ID 1 = Process creation (Sysmon)
ForEach-Object {
    [xml]$xml = $_.ToXml()
    $parentImage = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentImage" }
    $image = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }
    Write-Host "`n=== Strange PPID Detected ==="
    Write-Host "Time: $($_.TimeCreated)"
    Write-Host "Parent: $($parentImage.'#text')"
    Write-Host "Child:  $($image.'#text')"
}
```

```
=== Strange PPID Detected ===
Time: 04/27/2022 19:18:06
Parent: C:\Windows\System32\cmd.exe
Child:  C:\Windows\System32\whoami.exe

=== Strange PPID Detected ===
Time: 04/27/2022 19:18:06
Parent: C:\Windows\System32\cmd.exe
Child:  C:\Windows\System32\conhost.exe

=== Strange PPID Detected ===
Time: 04/27/2022 19:18:06
Parent: C:\Windows\System32\WerFault.exe
Child:  C:\Windows\System32\cmd.exe

=== Strange PPID Detected ===
Time: 04/27/2022 19:17:25
Parent: C:\Windows\explorer.exe
Child:  C:\Windows\System32\WerFault.exe
```

- Comparison for finding strange process can be based on the image below.

![](../6.%20Image/EJbSAt9WsAAE7Z4.jpg)

