 Utilize the **Get-WinEvent** cmdlet to traverse all event logs located within the `"C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement"` directory and determine when the `\\*\PRINT` share was added. Enter the time of the identified event in the format HH:MM:SS as your answer.

```
Get-WinEvent -Path "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement\*.evtx" |
Where-Object { $_.Id -eq 5142 -and $_.Message -like "*\\*\PRINT*" } |
Select-Object TimeCreated, Message
```

![](../6.%20Image/Pasted%20image%2020250519002332.png)
