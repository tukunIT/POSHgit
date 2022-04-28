#Code to open PowerShell as 64-bit if Intune has launched it in the 32-bit host 

#Prepend this to Intune script deployments to ensure everything runs like it is supposed to. 
     If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") 
 { 
     Try { 
                &"$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $PSCOMMANDPATH 
            } 
     Catch  
{ 
                Throw "Failed to start $PSCOMMANDPATH" 
            } 
            Exit 
            } 
 
#Create Detection Key 
If (!(Test-Path HKLM:\SOFTWARE\KUNDENAVN)) 
{ 
    New-Item HKLM:\SOFTWARE\KUNDENAVN -Force 
} 
New-ItemProperty -Path HKLM:\SOFTWARE\KUNDENAVN\ -Name "APPLIKASJON" -PropertyType string -Value "999" -Force 