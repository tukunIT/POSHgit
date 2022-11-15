#Run Powershell as admin

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# Your script here

$Notisblokk = Get-StartApps -Name *Application*
If ($Notisblokk -eq $null)
    {
        Try {
                Write-Host "Failed to locate program"
                }   
        Catch
        {
            Throw "Failed to start $PSCOMMANDPATH"
        }
    }
else 
    {
    If (!(Test-Path HKLM:\SOFTWARE\NORDR))
	            {
	                New-Item HKLM:\SOFTWARE\*YourValueHere* -Force
	            }
                    New-ItemProperty -Path HKLM:\SOFTWARE\*YourValueHere*\ -Name "HP Bloatware Removal" -PropertyType string -Value "999" -Force
    }
pause
