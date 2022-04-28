#TC Managed Cloud Client Script 00005

#Script to configure SCEP using NDES for Intune. 

#!!!!!!!!!!!!!!!Select the relevant section and run with F8!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!Select the relevant section and run with F8!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!Select the relevant section and run with F8!!!!!!!!!!!!!!!

#v1.0
#Version History
#0.1 Initial release 06.09.2017
#0.2 Added Try Catch
#0.3 Added CA Management group updating. The NDES service account should be added to this group.
#0.4 21.09.2017 Added Silverlight install, needed for registering the Intune connector.
#0.5 07.11.2017 Changed the Web Server Template name for N13.
#0.6 20.04.2018 Improved and simplified operation, removed redundant sections. Added logging into same directory that script is opended from.
#0.7 23.05.2018 Added friendly name to the NDES cert, changed export of root and intermediate certs.
#0.8 23.05.2018 Added TCS information for CA Certs
#0.9 27.03.2019 Added Register App Proxy Connector with token, can be used with or wothout MFA. Changed the certificate template to a variable
#1.0 24.04.2020 Added SPN for service account
#1.1 15.05.2020 Changed the CertTemplate name
#1.2 13.10.2020 Forced Tls [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 when using Install-Module etc

#Jon Young
#The Intune templates for SCEP client enrollment and Web Server should exist in the CA before running this script.
#
#The N10 Intune IIS template name is WebServer-NDES-SSL
#The N10 Intune User template name is Intune-User. The group N10\N10-Intune-SCEP-CA has read/enroll access to the template
#The N10 CA Name is N10OS2SCA001.N10.tconet.net\TeleComputing N10 Issuing CA
#
#The N13 Intune IIS template name is WebServer-NDES-SSL
#The N13 Intune User template name is Intune-User. The group N13\N13-Intune-SCEP-CA has read/enroll access to the template
#The N13 CA Name is N13OS2SCA001.N13.tconet.net\TeleComputing N13 Issuing CA

#If configuring for other zones the CA template will require configuring. Templates should be created for the Intune certificate connector server
#and User template for use with SCEP. A group should be created and added to the template security ACL with read and enroll permissions. The service account that is created in
#this script will be added to the group.

###############################
#Safeguard to prevent running script outside of ISE
If ($PSIse){
}

else {
Write-Host "Script must run from ISE!!" -ForegroundColor Yellow -BackgroundColor Red
Exit
}
###############################

###############################
#Variables
$CustomerNo="105150"
$Password=ConvertTo-SecureString -AsPlainText "VMG((fRXQA7" -Force
$NDESGroup="-Intune-User-CA" #The domain Netbios name will be pre-pended to this automatically e.g. N10-Intune-SCEP
$CAManagementGroup="-CA-Management" #The domain Netbios name will be pre-pended to this automatically. e.g. N10-CA-Management
$CertTemplate="NDES-SSL"
$CertTemplateUser="Intune-SCEP" #The name of the certificate template used to issue certificate to user
$NDESConnectorDownloadURL="http://download.microsoft.com/download/E/C/6/EC6E36B8-3377-4D3A-BC17-4754F42FFC1C/NDESConnectorSetup.exe"
$AADAppProxyDownloadURL="https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/Download"
$NDESConnectorUICommand="C:\Program Files\Microsoft Intune\NDESConnectorUI\NDESConnectorUI.exe"
$AppProxyInstallPath="C:\Program Files\Microsoft AAD App Proxy Connector"
$RootCASubject="*CN=TeleComputing Root Premium CA*"
#The SecondTierCASubject and ThirdTierCASubject will be changed to the correct value if the variable $BRenameCertSubject=$True and the zone is Nxx or Zxx
$SecondTierCASubject="*CN=TeleComputing COUNTRY Root Premium CA*"
$ThirdTierCASubject="*CN=TeleComputing ZONE Issuing CA*"
$NumberOfCATiers="3"
$BRenameCertSubject=$True
$NDESCertFriendlyName="Intune-NDES"
$BUseTokenToRegAppProxyConn=$True
###############################
#Do not modify below this line

###############################
#Functions
Function Launch-IE($url){
$IE = New-Object -com internetexplorer.application;
$IE.visible = $true; 
$IE.navigate($url); 
}
###############################

###############################
function Log-Message([string]$message,$File,$MessageType){
$date=Get-Date

If ($MessageType -eq "INFO"){Write-Host $Date $message -ForegroundColor Green}
ElseIf ($MessageType -eq "WARN"){Write-Host $Date $message -ForegroundColor Yellow}
ElseIf ($MessageType -eq "ERROR"){Write-Host $Date $message -ForegroundColor Yellow -BackgroundColor Red}

"" + $date + " " + $message | Add-Content -Encoding Ascii $File
}
###############################


###############################
#0.0 Create Log
$Date=(Get-Date -UFormat %d%m%Y_%T) -replace ":",""
$ScriptLogDir=Split-Path -Path $PSIse.CurrentFile.FullPath
$LogFile=$ScriptLogDir+"\"+((Split-Path -Path $PSIse.CurrentFile.FullPath -Leaf)-replace ".ps1","")+"-"+$Date+".txt"

$Tmp="Log "+$LogFile
Log-Message $Tmp $LogFile "INFO"

$Tmp="Starting "+$PSIse.CurrentFile.FullPath
Log-Message $Tmp $LogFile "INFO"
###############################

###############################
#0.1 Create Temp and Install RSAT-AD-PowerShell
$Tmp="Setting up..."
Log-Message $Tmp $LogFile "INFO"

Try {
Add-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop

$TempDir=$env:SystemDrive+"\Temp"
If (!(Test-Path $TempDir)){
$Tmp=New-Item $TempDir -ItemType Directory -ErrorAction Stop
}

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#1.0 Create the NDES Service Account. Add to CA template security and management groups. Adjust the password.
Import-Module ActiveDirectory

$DomainInfo=Get-ADDomain
$NDESGroup=$DomainInfo.NetBIOSName+$NDESGroup
$CAManagementGroup=$DomainInfo.NetBIOSName+$CAManagementGroup

$LDAPFilter="(name="+$CustomerNo+")"
$OU=Get-ADOrganizationalUnit -LDAPFilter $LDAPFilter

$Tmp="Domain is "+$DomainInfo.DNSRoot+ ". LDAP filter "+$LDAPFilter
Log-Message $Tmp $LogFile "INFO"

If ($OU){

$Tmp="Found OU for customer number "+$CustomerNo+" DN is "+$OU.DistinguishedName
Log-Message $Tmp $LogFile "INFO"

If (!($OU.Count)){

$OUSplit=$OU -split ("OU=ASP")
$OUSplit2=$OUSplit -split ("OU=")
$OSL=$OUSplit2[$OUSplit2.GetUpperBound(0)-1] -replace ",",""
$DCInfo=Get-ADDomainController
$StrDomain=$DCInfo.Domain
$StrDC=$DCInfo.HostName
$StrOU="OU=Resources,"+$OU.DistinguishedName
$StrSvcAccount="__"+$CustomerNo+"-intune-ndes"
$StrUPN=$StrSvcAccount+"@"+$DCInfo.Domain
$Description="Service Account for Intune SCEP"

$Tmp="Creating service account "+$StrSvcAccount
Log-Message $Tmp $LogFile "INFO"

Try{
New-ADUser -Name $StrSvcAccount -Server $StrDC -Path $StrOU -AccountPassword $Password -Enabled $True -PasswordNeverExpires $True -CannotChangePassword $True -Description $Description -UserPrincipalName $StrUPN -OtherAttributes @{'extensionAttribute1'=$CustomerNo;'extensionAttribute2'=$OSL;'extensionAttribute12'="0"} -ErrorAction Stop

Add-ADGroupMember -Server $StrDC $NDESGroup $StrSvcAccount -ErrorAction Stop
Add-ADGroupMember -Server $StrDC $CAManagementGroup $StrSvcAccount -ErrorAction Stop

$Spn="http/"+$env:COMPUTERNAME+"."+$DomainInfo.DNSRoot
Set-ADUser -Identity $StrSvcAccount -ServicePrincipalNames @{Add=$Spn} -ErrorAction Stop

$Tmp="Service account created successfully..."
Log-Message $Tmp $LogFile "INFO"

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}

}

Else {
$Tmp="More than one OU found for customer number "+$CustomerNo+", cannot continue"
Log-Message $Tmp $LogFile "ERROR"
}

}

Else {
$Tmp="Failed to find OU for customer number "+$CustomerNo
Log-Message $Tmp $LogFile "ERROR"
}
###############################

###############################
#1.1 Get the CA Name.
#https://technet.microsoft.com/en-us/library/hh848374(v=wps.630).aspx
#Get the CA Name first, this is required to request a certificate for IIS.
#
###########
#Get the CA Name, in the output copy the contents of the Config: field and strip out the CA Name into the $CAName variable
<#Entry 0:
  Name:                   	`em-TCSERVER1-CA'
  Organizational Unit:    	`'
  Organization:           	`'
  Locality:               	`'
  State:                  	`'
  Country/region:         	`'
  --> This value --> Config:                 	`TCSERVER1.em.local\em-TCSERVER1-CA'
  Exchange Certificate:   	`'
  Signature Certificate:  	`'
  Description:            	`'
  Server:                 	`TCSERVER1.em.local'
  Authority:              	`em-TCSERVER1-CA'
  Sanitized Name:         	`em-TCSERVER1-CA'
  Short Name:             	`em-TCSERVER1-CA'
  Sanitized Short Name:   	`em-TCSERVER1-CA'
  Flags:                  	`1'
  Web Enrollment Servers: 	`'
CertUtil: -dump command completed successfully.

#>

#e.g. $CAName="TCSERVER1.em.local\em-TCSERVER1-CA"

$CA=certutil
$CAConfig=$CA | Select-String -Pattern "Config:"
$CAConfigSplit=$CAConfig -split ":"
$CAConfigTemp=$CAConfigSplit[1].Trim()
$CAName=$CAConfigTemp.Substring(1,($CAConfigTemp.Length-2))

$Tmp="Certificate Authority Name is "+$CAName
Log-Message $Tmp $LogFile "INFO"
###############################

###############################
#2.0 Request a certificate for the NDES Web Server.
$CertDNSName=$env:COMPUTERNAME+"."+$StrDomain
$CertSubjectName="CN="+$CertDNSName
$CertLocation="Cert:\LocalMachine\My"

Try{
$Tmp="Requesting certificate"
Log-Message $Tmp $LogFile "INFO"

$Cert=Get-Certificate -Template $CertTemplate -Url ldap:///CN=$CAName -DnsName $CertDNSName -CertStoreLocation $CertLocation -SubjectName $CertSubjectName -ErrorAction Stop
$Thumbprint=$Cert.Certificate.Thumbprint

$Cert=Get-ChildItem -Path $CertLocation\$Thumbprint
$Cert.FriendlyName=$NDESCertFriendlyName

$Tmp="Success... Thumbprint is "+$Thumbprint+". Friendly Name is "+$NDESCertFriendlyName
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}

###############################

###############################
#3.0 Install NDES
Try{
$Tmp="Installing features"
Log-Message $Tmp $LogFile "INFO"

Add-WindowsFeature -Name @("ADCS-Device-Enrollment","Web-Server","Web-WebServer","Web-Common-Http","Web-Default-Doc",
"Web-Dir-Browsing","Web-Http-Errors","Web-Static-Content","Web-Http-Redirect","Web-Health","Web-Http-Logging",
"Web-Log-Libraries","Web-Request-Monitor","Web-Http-Tracing","Web-Performance","Web-Stat-Compression",
"Web-Security","Web-Filtering","Web-Windows-Auth","Web-App-Dev","Web-Net-Ext","Web-Net-Ext45",
"Web-Asp-Net","Web-Asp-Net45","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Mgmt-Tools","Web-Mgmt-Console",
"Web-Mgmt-Compat","Web-Metabase","Web-WMI","NET-Framework-Features","NET-Framework-Core","NET-HTTP-Activation",
"NET-Framework-45-Features","NET-Framework-45-Core","NET-Framework-45-ASPNET","NET-WCF-Services45","NET-WCF-HTTP-Activation45",
"NET-WCF-TCP-PortSharing45","RSAT-ADCS-Mgmt","WAS","WAS-Process-Model","WAS-NET-Environment","WAS-Config-APIs") -ErrorAction Stop

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#4.0 Add NDES service account to IIS_IUSRS group
Try {

$Tmp="Adding NDES service account to IIS_IUSRS group"
Log-Message $Tmp $LogFile "INFO"

$group = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/IIS_IUSRS,group")
$group.add("WinNT://$StrDomain/$StrSvcAccount,user")

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#5.0 Configure NDES.
$StrSvcAccount2=$StrDomain+"\"+$StrSvcAccount

$Tmp="Installing NDES Service"
Log-Message $Tmp $LogFile "INFO"

Try{
Install-AdcsNetworkDeviceEnrollmentService -CAConfig $CAName -ServiceAccountName $StrSvcAccount2 -ServiceAccountPassword $Password -SigningProviderName "Microsoft Strong Cryptographic Provider" -SigningKeyLength "2048" -EncryptionProviderName "Microsoft Strong Cryptographic Provider" -EncryptionKeyLength "2048" -Confirm:$False -ErrorAction Stop

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}

###############################


###############################
#6.0 Update registry so SCEP has the correct template information
Try {

$Tmp="Updating registry with SCEP template names"
Log-Message $Tmp $LogFile "INFO"

Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP -Name EncryptionTemplate -Value $CertTemplateUser -ErrorAction Stop
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP -Name GeneralPurposeTemplate -Value $CertTemplateUser -ErrorAction Stop
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP -Name SignatureTemplate -Value $CertTemplateUser -ErrorAction Stop

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#7.0 Launch IE to check operation with HTTP
$UrlToPass="http://"+$env:COMPUTERNAME+"."+$StrDomain+"/certsrv/mscep/mscep.dll"

$Tmp="Launching IE to check HTTP operation of "+$UrlToPass
Log-Message $Tmp $LogFile "INFO"

Launch-IE $UrlToPass
###############################

###############################
#8.0 Add SSL binding with certificate requested earlier
#https://docs.microsoft.com/en-us/iis/manage/powershell/powershell-snap-in-configuring-ssl-with-the-iis-powershell-snap-in
Try{
$Tmp="Adding IIS SSL binding, certificate is "+$Thumbprint
Log-Message $Tmp $LogFile "INFO"

New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https -ErrorAction Stop
CD IIS:\SslBindings -ErrorAction Stop
get-item Cert:\LocalMachine\MY\$Thumbprint | New-Item 0.0.0.0!443 -ErrorAction Stop
Start-Sleep 10
cd C:\

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#9.0 Launch IE to check operation with HTTPS
$UrlToPass="https://"+$env:COMPUTERNAME+"."+$StrDomain+"/certsrv/mscep/mscep.dll"

$Tmp="Launching IE to check HTTPS operation of "+$UrlToPass
Log-Message $Tmp $LogFile "INFO"

Launch-IE $UrlToPass
###############################

###############################
#10.0 Modify request filtering
$Tmp="Setting request filtering registry entries "
Log-Message $Tmp $LogFile "INFO"

$CMDOutput=C:\Windows\System32\inetsrv\appcmd set config /section:requestfiltering /requestlimits.maxurl:65534
If ($CMDOutput -like "*Applied configuration changes*"){

$Tmp="Set MaxUrl successfully..."
Log-Message $Tmp $LogFile "INFO"

}

Else {
$Tmp="Failed to set value"
Log-Message $Tmp $LogFile "ERROR"

Write-Host "Failed to set value" -ForegroundColor Yellow -BackgroundColor Red
}

$CMDOutput=C:\Windows\System32\inetsrv\appcmd set config /section:requestfiltering /requestlimits.maxquerystring:65534
If ($CMDOutput -like "*Applied configuration changes*"){

$Tmp="Set MaxQueryString successfully..."
Log-Message $Tmp $LogFile "INFO"

}

Else {
$Tmp="Failed to set value"
Log-Message $Tmp $LogFile "ERROR"
}

###############################

###############################
#11.0 Update registry
Try{

$Tmp="Updating HTTP registry entries"
Log-Message $Tmp $LogFile "INFO"

New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength -PropertyType DWORD -Value 65534 -ErrorAction Stop
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes -PropertyType DWORD -Value 65534 -ErrorAction Stop

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}

###############################

###############################
#12.0 Install the Intune Certificate Connector. Downloadable from the Intune admin portal https://portal.azure.com
#Microsoft Intune-Device configuration-Certification Authority
#OR http://download.microsoft.com/download/E/C/6/EC6E36B8-3377-4D3A-BC17-4754F42FFC1C/NDESConnectorSetup.exe

$Tmp="Downloading Intune Certificate Connector"
Log-Message $Tmp $LogFile "INFO"

Invoke-WebRequest -Uri $NDESConnectorDownloadURL -OutFile $TempDir\NDESConnectorSetup.exe

$Tmp="Installing Intune Certificate Connector"
Log-Message $Tmp $LogFile "INFO"

$StrCommand=$TempDir+"\ndesconnectorsetup.exe"
$StrParams="EULAAGREE=1 SELECTEDCERT="+$Thumbprint.ToLower()+" /QR"
$StrParamsSplit=$StrParams.Split(" ")

& "$StrCommand" $StrParamsSplit
###############################

###############################
#12.01 Check the Application Log for installation message. EventID 1033

$Tmp="Checking if Intune Certificate Connector installed successfully"
Log-Message $Tmp $LogFile "INFO"

Get-EventLog -LogName Application -Source MsiInstaller -InstanceId 1033 -Newest 1 | Where {$_.Message -like "*Intune Connector*"} | ForEach {

Write-Host $_.Message

If ($_.Message.Contains("Installation success or error status: 0")){

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Else {
$Tmp="Failed to install..."
Log-Message $Tmp $LogFile "ERROR"
}

}
###############################

###############################
#12.1 Configure the Intune Certificate Connector. 
#Sign in with a global administrator account admin@tenant.onmicrosoft.com.
#The user account registering must have a valid intune licence assigned. if the account is not licenced it will probably get the error, 'user is not recognized'
#In advanced enter the service account created in this script in the $StrSvcAccount variable in the format DOMAIN\User
$Tmp="Launching Intune Connector Config Tool"
Log-Message $Tmp $LogFile "INFO"

$Tmp="Account for entering into the 'Advanced-CA Account' tab is "+$DomainInfo.NetBIOSName+"\"+$StrSvcAccount
Log-Message $Tmp $LogFile "INFO"

& "$NDESConnectorUICommand"
###############################

###############################
#13.0 Download and install the Azure application proxy connector
#https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/Download
#!!!There is no visible output from the installation process

##################
#13.1 Download the installer
$Tmp="Dowload the Azure Application Proxy from "+$AADAppProxyDownloadURL
Log-Message $Tmp $LogFile "INFO"

Launch-IE $AADAppProxyDownloadURL
##################

##################
#13.2 Install
$Tmp="Installing the Azure Application proxy"
Log-Message $Tmp $LogFile "INFO"

$StrCommand=$env:USERPROFILE +"\Downloads\AADApplicationProxyConnectorInstaller.exe"
$StrParams="REGISTERCONNECTOR=false /Q"
$StrParamsSplit=$StrParams.Split(" ")

& "$StrCommand" $StrParamsSplit

Start-Sleep 20
##################
###############################

###############################
#13.01 Check the Application Log for installation message. EventID 1033
#There are two log entries, one for the connector, one for the updater
$Tmp="Checking if Azure Application Proxy installed successfully"
Log-Message $Tmp $LogFile "INFO"

Get-EventLog -LogName Application -Source MsiInstaller -InstanceId 1033 -Newest 2 | Where {$_.Message -like "*Microsoft Azure AD Application Proxy Connector*"} | ForEach {

Write-Host $_.Message

If ($_.Message.Contains("Installation success or error status: 0")){

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Else {

$Tmp="Failed to install..."
Log-Message $Tmp $LogFile "INFO"

}

}
###############################

###############################
#13.2 Register the application proxy connector.
#https://docs.microsoft.com/en-us/azure/active-directory/active-directory-application-proxy-silent-installation
#Enter AzureAD global admin creds.
$Tmp="Registering Azure Application Proxy"
Log-Message $Tmp $LogFile "INFO"

If ($BUseTokenToRegAppProxyConn){
#token

#The following is to enable the registration of the app proxy connector using a token where MFA is enforced.
#https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/application-proxy-register-connector-powershell
# Locate AzureAD PowerShell Module
# Change Name of Module to AzureAD after what you have installed

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

 $AADPoshPath = (Get-InstalledModule -Name AzureAD).InstalledLocation
 
 If ($AADPoshPath){
 $Tmp="AzureAD module installed"
 Log-Message $Tmp $LogFile "INFO"
 }

 Else {
 $Tmp="AzureAD module not installed, installing"
 Log-Message $Tmp $LogFile "INFO"

 $NuGetVer="2.8.5.201"
 Install-PackageProvider -Name NuGet -MinimumVersion $NuGetVer -Force
 Install-Module AzureAD -Force
 $AADPoshPath = (Get-InstalledModule -Name AzureAD).InstalledLocation
 }

  # Set Location for ADAL Helper Library
 $ADALPath = $(Get-ChildItem -Path $($AADPoshPath) -Filter Microsoft.IdentityModel.Clients.ActiveDirectory.dll -Recurse ).FullName | Select-Object -Last 1

 # Add ADAL Helper Library
 Add-Type -Path $ADALPath

 #region constants

 # The AAD authentication endpoint uri
 [uri]$AadAuthenticationEndpoint = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0/" 

 # The application ID of the connector in AAD
 [string]$ConnectorAppId = "55747057-9b5d-4bd4-b387-abf52a8bd489"

 # The reply address of the connector application in AAD
 [uri]$ConnectorRedirectAddress = "urn:ietf:wg:oauth:2.0:oob" 

 # The AppIdUri of the registration service in AAD
 [uri]$RegistrationServiceAppIdUri = "https://proxy.cloudwebappproxy.net/registerapp"

 #endregion

 #region GetAuthenticationToken

 # Set AuthN context
 $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $AadAuthenticationEndpoint

 # Build platform parameters
 $promptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
 $platformParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $promptBehavior

 # Do AuthN and get token
 $authResult = $authContext.AcquireTokenAsync($RegistrationServiceAppIdUri.AbsoluteUri, $ConnectorAppId, $ConnectorRedirectAddress, $platformParam).Result

 # Check AuthN result
 If (($authResult) -and ($authResult.AccessToken) -and ($authResult.TenantId) ) {
 $token = $authResult.AccessToken
 $tenantId = $authResult.TenantId
 
 $SecureToken = $Token | ConvertTo-SecureString -AsPlainText -Force

 $Tmp="Token obtained"
 Log-Message $Tmp $LogFile "INFO"

 cd $AppProxyInstallPath

 .\RegisterConnector.ps1 -modulePath "C:\Program Files\Microsoft AAD App Proxy Connector\Modules\" -moduleName "AppProxyPSModule" -Authenticationmode Token -Token $SecureToken -TenantId $tenantId -Feature ApplicationProxy

 }

 Else {
 $Tmp="Authentication result, token or tenant id returned are null"
 Log-Message $Tmp $LogFile "ERROR"
 }

}

Else {
#user, no mfa

$cred = Get-Credential

cd $AppProxyInstallPath

.\RegisterConnector.ps1 -modulePath "C:\Program Files\Microsoft AAD App Proxy Connector\Modules\" -moduleName "AppProxyPSModule" -Authenticationmode Credentials -Usercredentials $cred -Feature ApplicationProxy
}
###############################

###############################
#14.0 Export Certificates from CA. We need the entire chain. They are needed to create certificate deployment in Intune.
#For example:
#TeleComputing Root Premium CA
#TeleComputing Norway Root Premium CA
#TeleComputing N10 Issuing CA

#Cert store paths:
#CA = Intermediate Certification Authorities
#Root = Trusted Root Certification Authorities
#My = Personal

#Adjust the subject of the certificates as required, the first two certs should be OK for all TCN zones.

#Certificate chain for TC. Export all to file. These files are required for the Intune policies.

If ($BRenameCertSubject){

$Tmp="Domain Netbios name:"+$DomainInfo.NetBIOSName
Log-Message $Tmp $LogFile "INFO"

$Tmp="Domain FQDN:"+$DCInfo.Domain
Log-Message $Tmp $LogFile "INFO"

$SecondTierCASubjectTemp=$SecondTierCASubject
$ThirdTierCASubjectTemp=$ThirdTierCASubject

If ( ($DomainInfo.NetBIOSName.Substring(0,1).ToLower() -eq "n") -and ($DCInfo.Domain.ToLower().Contains(".tconet.net")) -or ($DCInfo.Domain.ToLower().Contains(".no.tconet.net")))
{
$SecondTierCASubject=$SecondTierCASubject -replace "COUNTRY","Norway"
$Tmp="Country is Norway"
Log-Message $Tmp $LogFile "INFO"
}

If ( ($DomainInfo.NetBIOSName.Substring(0,1).ToLower() -eq "s") -and ($DCInfo.Domain.ToLower().Contains(".tconet.net")) -or ($DCInfo.Domain.ToLower().Contains(".se.tconet.net")))
{
$SecondTierCASubject=$SecondTierCASubject -replace "COUNTRY","Sweden"
$Tmp="Country is Sweden"
Log-Message $Tmp $LogFile "INFO"
}

$ThirdTierCASubject=$ThirdTierCASubject -replace "ZONE", $DomainInfo.NetBIOSName

}

If ($SecondTierCASubjectTemp -ne $SecondTierCASubject){

Try {
$Tmp="Exporting CA certificates"
Log-Message $Tmp $LogFile "INFO"

#Root
If ($NumberOfCATiers -ge 1){Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where {$_.Subject -like $RootCASubject} | Sort-Object -Property NotAfter | Select-Object -Last 1 | Export-Certificate -FilePath $TempDir\TCRootPremiumCA.cer -ErrorAction Stop}
#TCNorwayOrSweden
If ($NumberOfCATiers -ge 2){Get-ChildItem -Path Cert:\LocalMachine\CA\ | Where {$_.Subject -like $SecondTierCASubject} | Sort-Object -Property NotAfter | Select-Object -First 1 | Export-Certificate -FilePath $TempDir\TCSecondTierRootPremiumCA.cer -ErrorAction Stop}
#TCDomain Issuing
If ($NumberOfCATiers -ge 3){Get-ChildItem -Path Cert:\LocalMachine\CA\ | Where {$_.Subject -like $ThirdTierCASubject} | Sort-Object -Property NotAfter | Select-Object -First 1 | Export-Certificate -FilePath $TempDir\TCDomainIssuingCA.cer -ErrorAction Stop}

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception" -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
}

Else {
$Tmp="Failed to find correct CA certificate subject names, not exporting."
Log-Message $Tmp $LogFile "ERROR"
}
###############################

###############################
#15.0 Restart
$Tmp="Restarting computer"
Log-Message $Tmp $LogFile "INFO"

Restart-Computer -Force
###############################

###############################
#End
