#TC Managed Cloud Client Script 00007

#Script to install and configure RRAS VPN

#!!!!!!!!!!!!!!!Select the relevant section and run with F8!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!Select the relevant section and run with F8!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!Select the relevant section and run with F8!!!!!!!!!!!!!!!

#The standard configuration used in TC for Microsoft based VPN is to have a Netscaler front end load balancer set to use two back end servers with Microsoft RRAS VPN.
#The two VPN servers will use the same certificate issued from the relevant zone CA. The name of the VPN should follow the standard of zone-vpn.tchost.no
#For example n13-vpn.tchost.no or n10-vpn.tchost.no
#
#The certificate issued should be used for the Netscaler and both VPN servers. The request should only be made from one server (node 1), the certificate
#is exported and imported to node 2 as part of this script. Section 2.0 is the certificate request, only performed on node 1, section 2.2 is the import, only
#perform on node 2.
#
#Copy this script to each node to be built, set the parameters below and run each section at a time.

#To do:
#Disable the PPTP and L2TP ports use

#v0.8
#Version History
#0.1 Initial release 25.01.2018
#0.2 Added additional logging 14.02.2018
#0.3 Changed to standard logging 31.05.2018
#0.4 Added a query of all file and print servers in the domain so they can be submitted as a firewall request to allow VPN client subnet communication
#0.5 Added extra information into firewall request
#0.6 Fixed issue with installing ActiveDirectory PS module
#0.7 Fixed path to .pfx file on second node 11.04.2019
#0.8 Added a check for IPv6. IPv6 is required.

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
#Parameters-modify as required
$TempDir=$env:SystemDrive+"\Temp"
$CertTemplate="WebServerZ67"
$RRASFqdn="z67-vpn2.tchost.no"
#If using only one VPN server set the line below as $RRASNode2=""
$RRASNode2="z67os2npx006"
$RRASNode2CopyPath="\\"+$RRASNode2+"\c$\Temp"
$IPAddressRangeStart="10.10.10.1"
$IPAddressRangeEnd="10.10.10.253"
$RadiusServer1="10.65.207.138"
#If using only one radius server set the line below as $RadiusServer2=""
$RadiusServer2="10.65.207.139"
#If using more than one server set the line below as $NPSServers="server1","server2"
$NPSServers="z67os2sac005","z67os2sac006"
$bRestartNPSService=$True
#LDAP below filter to include all SPR and CFI servers, exclude Win10 and Mac OS. Can't guarantee that NetApp Filer computer object has correct operatingSystem tag so exclude Win10 and Mac OS.
$FWReqLDAPFilter="(&(objectclass=computer)(|(samaccountname=*fi*)(samaccountname=*pr*)(samaccountname=*sdc*)(samaccountname=*scd*)(samaccountname=*sic*)(samaccountname=*sca*)(samaccountname=*sac*))(!(|(operatingSystem=*Windows 10*)(operatingSystem=*Mac OS*))))"
$FWSourceName="TCMCC-VPN"
$FWSourceIPAddress="10.29.13.0/24"
$CitrixNSExitIP="10.78.215.102"
$SstpPorts="253"
$Ikev2Ports="253"
###############################
###############################
#Parameters-no need to modify 
$RadiusTimeOut="5"
$RadiusScore="30"
$RadiusPort="1812"
$SharedSecret=([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 | sort {Get-Random})[0..10] -join ''
###############################

#Functions
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
#0.0 **** BOTH NODES **** Create Log
$Date=(Get-Date -UFormat %d%m%Y_%T) -replace ":",""
$ScriptLogDir=Split-Path -Path $PSIse.CurrentFile.FullPath
$LogFile=$ScriptLogDir+"\"+((Split-Path -Path $PSIse.CurrentFile.FullPath -Leaf)-replace ".ps1","")+"-"+$Date+".txt"

$Tmp="Log "+$LogFile
Log-Message $Tmp $LogFile "INFO"

$Tmp="Starting "+$PSIse.CurrentFile.FullPath
Log-Message $Tmp $LogFile "INFO"
###############################

###############################
#0.1 **** BOTH NODES **** Check if IPv6 is disabled
$Tmp="Ipv6 check."
Log-Message $Tmp $LogFile "INFO"

$RegValue=Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -Name DisabledComponents -ErrorAction SilentlyContinue
If ($RegValue.DisabledComponents -gt 0){

$Tmp="Ipv6 is disabled, this is required for RRAS-VPN to function." 
Log-Message $Tmp $LogFile "ERROR"

$Tmp="Check HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents"
Log-Message $Tmp $LogFile "ERROR"

$Tmp="Ipv6 can be re-enabled by preventing the GPO that is disabling. Please check the GPOs applied."
Log-Message $Tmp $LogFile "ERROR"

}

Else {

$Tmp="Ipv6 not disabled."
Log-Message $Tmp $LogFile "INFO"

}
###############################

###############################
#1.0 **** BOTH NODES ****
If (!(Test-Path $TempDir)){New-Item $TempDir -ItemType Directory

$Tmp="Creating temp dir "+$TempDir
Log-Message $Tmp $LogFile "INFO"
}
###############################

###############################
#1.1 ****NODE 1 ONLY **** Get the CA Name.
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
#2.0 **** NODE 1 ONLY **** Request a certificate for the RRAS Server. Update the CA name from the step above.
#Using certreq
$Tmp="Certificate request"
Log-Message $Tmp $LogFile "INFO"

$Tmp="CA Name:"+$CAName
Log-Message $Tmp $LogFile "INFO"

$CertSubject='Subject = "CN='+$RRASFqdn+'"'
$RequestInf=$TempDir+"\Request.inf"
$CertRequestFile=$TempDir+"\CertRequest.req"
$CertIssuedFile=$TempDir+"\CertIssued.cer"
$CertIssuedRSPFile=$TempDir+"\CertIssued.rsp"
$ThumbprintFile=$TempDir+"\Thumbprint.txt"

"[NewRequest]" | Set-Content $RequestInf
$CertSubject | Add-Content $RequestInf
"Exportable = TRUE" | Add-Content $RequestInf
"KeyLength = 2048"| Add-Content $RequestInf
"KeySpec = 1" | Add-Content $RequestInf
"KeyUsage = 0xf0"| Add-Content $RequestInf
"MachineKeySet = TRUE"| Add-Content $RequestInf
"[RequestAttributes]"| Add-Content $RequestInf
'CertificateTemplate = "'+$CertTemplate+'"'| Add-Content $RequestInf

If (Test-Path $CertRequestFile){Remove-Item $CertRequestFile}
If (Test-Path $CertIssuedFile){Remove-Item $CertIssuedFile}
If (Test-Path $CertIssuedRSPFile){Remove-Item $CertIssuedRSPFile}

$CertNew=certreq -new $RequestInf $CertRequestFile

If ($CertNew -like "*Request Created*"){
$Tmp="Certificate requested successfully"
Log-Message $Tmp $LogFile "INFO"

$CertSubmit=certreq -submit -config $CAName $CertRequestFile $CertIssuedFile

If ($CertSubmit -like "*Certificate retrieved(Issued)*"){

$Tmp="Certificate issued successfully"
Log-Message $Tmp $LogFile "INFO"

$CertAccept=certreq -accept $CertIssuedFile

$Cert=Get-ChildItem -Path cert:\localMachine\MY\ | Where {$_.Subject -like "*$RRASFqdn*"} | Sort-Object -Property NotBefore | Select -Last 1
$Thumbprint=$Cert.Thumbprint

$Tmp="Certificate thumbprint:"+$Thumbprint
Log-Message $Tmp $LogFile "INFO"

}

Else {
$Tmp="Certificate issue failed"
Log-Message $Tmp $LogFile "ERROR"
}

}

Else {
$Tmp="Certificate create failed"
Log-Message $Tmp $LogFile "ERROR"
}

###############################

###############################
#2.1 **** NODE 1 ONLY **** Export the certificate, use to configure additional nodes.
#$CertPath=$ScriptLogDir+"\"+$env:COMPUTERNAME+"-RRAS.pfx"

$CertPath=$TempDir+"\"+$RRASFqdn+"-RRAS.pfx"

$Tmp="Export certificate to pfx"
Log-Message $Tmp $LogFile "INFO"

$CertCopyPath=$RRASNode2CopyPath

Try{
$Password=Read-Host "Enter password for pfx export" -AsSecureString -ErrorAction Stop
Get-ChildItem -Path cert:\localMachine\MY\$Thumbprint | Export-PfxCertificate -FilePath $CertPath -Password $Password -ErrorAction Stop

If ($RRASNode2){

If (!(Test-Path $CertCopyPath)){
New-Item $CertCopyPath -ItemType Directory -ErrorAction Stop
}

$Tmp="Copying pfx to node "+$RRASNode2
Log-Message $Tmp $LogFile "INFO"

Copy-Item $CertPath $CertCopyPath -ErrorAction Stop

}

Else {
$Tmp="No second node, skipping copy."
Log-Message $Tmp $LogFile "INFO"
}

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#2.2 **** NODE 2 ONLY **** Import the certificate that was exported from the 1st node.
$Tmp="Import certificate from pfx"
Log-Message $Tmp $LogFile "INFO"

$CertPath=$TempDir+"\"+$RRASFqdn+"-RRAS.pfx"

Try{
$Password=Read-Host "Enter password for pfx import" -AsSecureString -ErrorAction Stop
Import-PfxCertificate –FilePath $CertPath Cert:\LocalMachine\My -Password $Password -Exportable -ErrorAction Stop

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#3.0 **** BOTH NODES **** Add-WindowsFeature RRAS
$Tmp="Add DirectAccess-VPN feature"
Log-Message $Tmp $LogFile "INFO"

Try{
Add-WindowsFeature -Name @("DirectAccess-VPN") -IncludeManagementTools -ErrorAction Stop
$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#4.0 **** BOTH NODES **** Install VPN
$Tmp="Install and configure Remote-Access"
Log-Message $Tmp $LogFile "INFO"

Try{
Install-RemoteAccess -VpnType VPN -Legacy -IPAddressRange @($IPAddressRangeStart,$IPAddressRangeEnd) -RadiusServer $RadiusServer1 -SharedSecret $SharedSecret -RadiusTimeout $RadiusTimeOut -RadiusScore $RadiusScore -RadiusPort $RadiusPort -MsgAuthenticator 'Disabled' -ErrorAction Stop

If ($RadiusServer2){Add-RemoteAccessRadius -ServerName $RadiusServer2 -SharedSecret $SharedSecret -Timeout $RadiusTimeOut -Score $RadiusScore -Port $RadiusPort -MsgAuthenticator 'Disabled' -Purpose Authentication -ErrorAction Stop}

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"

$Tmp="Shared secret:"+$SharedSecret
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#5.0 **** BOTH NODES **** Configure RRAS to use cert
$Tmp="Configure Remote-Access to use certificate"
Log-Message $Tmp $LogFile "INFO"

$RRASCert=Get-ChildItem -Path cert:\localMachine\MY\ | Where {$_.Subject -like "*$RRASFqdn*"} | Sort-Object -Property NotBefore | Select -Last 1
$Thumbprint=$RRASCert.Thumbprint

$Tmp="Thumbprint:"+$Thumbprint
Log-Message $Tmp $LogFile "INFO"

Try{
Set-RemoteAccess -SslCertificate $RRASCert -ErrorAction Stop
Restart-Service RemoteAccess -ErrorAction Stop

$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#6.0 **** BOTH NODES **** Configure NPS to add radius client. **The NPS service will be restarted**.
#******If there are multiple NICs in the server disable the front facing adapter whilst running this section******

$Tmp="Configure NPS"
Log-Message $Tmp $LogFile "INFO"

$Tmp="Stopping Routing and Remote Access"
Log-Message $Tmp $LogFile "INFO"

Stop-Service "Routing and Remote Access"

$NetIPConfig=Get-NetIPConfiguration
If ($NetIPConfig.IPv4Address.Count -eq 1){

$Tmp="We have one IP address reported, continuing."
Log-Message $Tmp $LogFile "INFO"

$NPSRadiusClient=$NetIPConfig.IPv4Address.IPAddress
$NPSRadiusClientName=$env:COMPUTERNAME
$NPSRadiusClientSecret=$SharedSecret

$NPSServers | ForEach {

$NPSServer=$_

$Tmp="Processing NPS server "+$NPSServer
Log-Message $Tmp $LogFile "INFO"

Try{
$RemoteSession=New-PSSession -ComputerName $NPSServer -ErrorAction Stop

$Tmp="Created remote PSSession with "+$NPSServer
Log-Message $Tmp $LogFile "INFO"

Invoke-Command -Session $RemoteSession -ScriptBlock {Import-Module Nps} -ErrorAction Stop

$Tmp="Importing PSSession"
Log-Message $Tmp $LogFile "INFO"

Import-PSSession $RemoteSession -Prefix S0 -ErrorAction SilentlyContinue

$Tmp="Creating Radius client"
Log-Message $Tmp $LogFile "INFO"

$RadiusClient=New-S0NpsRadiusClient -Address $NPSRadiusClient -Name $NPSRadiusClientName -SharedSecret $NPSRadiusClientSecret -ErrorAction Stop

If ($RadiusClient){
$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"


If ($bRestartNPSService){
$Tmp="Restarting NPS Service"
Log-Message $Tmp $LogFile "INFO"

Restart-S0Service "Network Policy Server"
}

Else {
$Tmp="The NPS Service must be restarted for the changes to take effect."
Log-Message $Tmp $LogFile "INFO"
}

}

Else {
$Tmp="Failed to create Radius client"
Log-Message $Tmp $LogFile "ERROR"
}

Remove-PSSession -Id $RemoteSession.Id -ErrorAction Stop

}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}

}

$Tmp="Starting Routing and Remote Access"
Log-Message $Tmp $LogFile "INFO"

}

Else {
$Tmp="There is more than one IP Address reported, cannot continue. If there are multiple NICs in the server disable the front facing adapter and retry."+$NPSServer
Log-Message $Tmp $LogFile "WARN"
}

Start-Service "Routing and Remote Access"
###############################

###############################
#7.0 **** BOTH NODES **** Configure VPN Ports. Needs a reboot to take effect.
$Tmp="Configure ports"
Log-Message $Tmp $LogFile "INFO"

$Tmp="SSTP:"+$SstpPorts+" IKEv2:"+$Ikev2Ports
Log-Message $Tmp $LogFile "INFO"

Try{
Set-VpnServerConfiguration -SstpPorts $SstpPorts -Ikev2Ports $Ikev2Ports -L2tpPorts 0 -ErrorAction Stop
$Tmp="Success..."
Log-Message $Tmp $LogFile "INFO"
}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}
###############################

###############################
#7.1 **** NODE 1 ONLY **** Query the local domain for all file and print servers and output to a firewall request file.
$CompCount=0
$FWReqFile=$ScriptLogDir+"\FWReqFile.txt"
$NetIPConfig=Get-NetIPConfiguration

"SourceName"+[Char]9+"SourceIPAddress"+[Char]9+"TargetProtocol"+[Char]9+"TargetPort"+[Char]9+"TargetName"+[Char]9+"TargetIPAddress"+[Char]9+"Comment" | Set-Content -Path $FWReqFile -Encoding UTF8

$Tmp="Querying domain for all file and print servers, output to "+$FWReqFile
Log-Message $Tmp $LogFile "INFO"

$Tmp="LDAP filter:"+$FWReqLDAPFilter
Log-Message $Tmp $LogFile "INFO"

Try{

$ADMod=Get-Module ActiveDirectory -ErrorAction Stop

If (!($ADmod)){
Add-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
}

$DomainInfo=Get-ADDomain
$ServerFQDN=$env:COMPUTERNAME+"."+$DomainInfo.DNSRoot

Get-ADComputer -LDAPFilter $FWReqLDAPFilter | Sort-Object -Property Name | ForEach {

$CompCount++

$Computer=$_

$Tmp="Processing "+$Computer.Name
Log-Message $Tmp $LogFile "INFO"

If ($Computer.DNSHostName){

$DNSEntry=Resolve-DnsName -DnsOnly $Computer.DNSHostName -Type A -ErrorAction SilentlyContinue

If ($DNSEntry.Name){

$Tmp="Adding "+$Computer.DNSHostName+" "+$DNSEntry.IPAddress
Log-Message $Tmp $LogFile "INFO"

If ($DNSEntry.Name.ToLower() -like "*sdc*"){
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"389"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"389"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"636"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"3268"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"3269"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"53"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"53"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"88"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"88"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"464"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"464"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"445"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"137"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"138"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"139"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController"| Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"123"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"DomainController" | Add-Content -Path $FWReqFile -Encoding UTF8
}


If ($DNSEntry.Name.ToLower() -like "*cfi*"){
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"137"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"FileServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"138"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"FileServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"139"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"FileServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"445"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"FileServer" | Add-Content -Path $FWReqFile -Encoding UTF8
}

If ($DNSEntry.Name.ToLower() -like "*spr*"){
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"137"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"PrintServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"UDP"+[Char]9+"138"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"PrintServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"139"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"PrintServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"445"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"PrintServer" | Add-Content -Path $FWReqFile -Encoding UTF8
}

If ($DNSEntry.Name.ToLower() -like "*scd*"){
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"80"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"CitrixDataCollector" | Add-Content -Path $FWReqFile -Encoding UTF8
}

If ($DNSEntry.Name.ToLower() -like "*sic*"){
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"1494"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"CitrixServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"2598"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"CitrixServer" | Add-Content -Path $FWReqFile -Encoding UTF8
}

If ($DNSEntry.Name.ToLower() -like "*sca*"){
$env:COMPUTERNAME+[Char]9+$NetIPConfig.IPv4Address+[Char]9+"TCP"+[Char]9+"135"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"CertificateAuthority" | Add-Content -Path $FWReqFile -Encoding UTF8
$env:COMPUTERNAME+[Char]9+$NetIPConfig.IPv4Address+[Char]9+"TCP"+[Char]9+"49152-65535"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"CertificateAuthority" | Add-Content -Path $FWReqFile -Encoding UTF8
}

If ($DNSEntry.Name.ToLower() -like "*sac*"){
$env:COMPUTERNAME+[Char]9+$NetIPConfig.IPv4Address+[Char]9+"UDP"+[Char]9+"1812"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"NetworkPolicyServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$env:COMPUTERNAME+[Char]9+$NetIPConfig.IPv4Address+[Char]9+"UDP"+[Char]9+"1813"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"NetworkPolicyServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$env:COMPUTERNAME+[Char]9+$NetIPConfig.IPv4Address+[Char]9+"UDP"+[Char]9+"1645"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"NetworkPolicyServer" | Add-Content -Path $FWReqFile -Encoding UTF8
$env:COMPUTERNAME+[Char]9+$NetIPConfig.IPv4Address+[Char]9+"UDP"+[Char]9+"1646"+[Char]9+$Computer.Name+[Char]9+$DNSEntry.IPAddress+[Char]9+"NetworkPolicyServer" | Add-Content -Path $FWReqFile -Encoding UTF8
}

}

Else {
$Tmp="Cannot resolve "+$Computer.DNSHostName+" in DNS. Check entry."
Log-Message $Tmp $LogFile "ERROR"
}

}

Else {
$Tmp="Missing DNSHostName in DNS query for "+$Computer.Name+". Check entry."
Log-Message $Tmp $LogFile "ERROR"
}

}

$Tmp=""+$CompCount+" objects found"
Log-Message $Tmp $LogFile "INFO"

#Get the Citrix storefront URL
$CitrixStorefrontURL=$DomainInfo.NetBIOSName+"-storefront."+$DomainInfo.DNSRoot

$DNSEntry=Resolve-DnsName -DnsOnly $CitrixStorefrontURL -Type A -ErrorAction SilentlyContinue

If ($DNSEntry.Name){
$Tmp="Adding Citrix Storefront "+$CitrixStorefrontURL+" "+$DNSEntry.IPAddress
Log-Message $Tmp $LogFile "INFO"

$FWSourceName+[Char]9+$FWSourceIPAddress+[Char]9+"TCP"+[Char]9+"443"+[Char]9+$CitrixStorefrontURL+[Char]9+$DNSEntry.IPAddress+[Char]9+"CitrixStoreFront" | Add-Content -Path $FWReqFile -Encoding UTF8
}

Else {
$Tmp="Cannot resolve "+$Computer.DNSHostName+" in DNS. Check entry."
Log-Message $Tmp $LogFile "ERROR"
}

#Citrix NS to VPN traffic#Get the Citrix storefront URL
$DNSEntry=Resolve-DnsName -DnsOnly $ServerFQDN -Type A -ErrorAction SilentlyContinue

If ($DNSEntry.Name){
$Tmp="Adding Citrix NS "+$CitrixNSExitIP+" to VPN backend"
Log-Message $Tmp $LogFile "INFO"

"CitrixNS"+[Char]9+$CitrixNSExitIP+[Char]9+"UDP"+[Char]9+"500"+[Char]9+$env:COMPUTERNAME+[Char]9+$DNSEntry.IPAddress+[Char]9+"CitrixNSToVPNBackend" | Add-Content -Path $FWReqFile -Encoding UTF8
"CitrixNS"+[Char]9+$CitrixNSExitIP+[Char]9+"UDP"+[Char]9+"4500"+[Char]9+$env:COMPUTERNAME+[Char]9+$DNSEntry.IPAddress+[Char]9+"CitrixNSToVPNBackend" | Add-Content -Path $FWReqFile -Encoding UTF8
"CitrixNS"+[Char]9+$CitrixNSExitIP+[Char]9+"TCP"+[Char]9+"443"+[Char]9+$env:COMPUTERNAME+[Char]9+$DNSEntry.IPAddress+[Char]9+"CitrixNSToVPNBackend" | Add-Content -Path $FWReqFile -Encoding UTF8
}

Else {
$Tmp="Cannot resolve "+$ServerFQDN+" in DNS. Check entry."
Log-Message $Tmp $LogFile "ERROR"
}


}

Catch {
$Tmp="Exception..."
Log-Message $Tmp $LogFile "ERROR"
write-host "Exception Type: $($_.Exception.GetType().FullName)"  -ForegroundColor Yellow -BackgroundColor Red
write-host "Exception Message: $($_.Exception.Message)"  -ForegroundColor Yellow -BackgroundColor Red
}

$Tmp="Submit the firewall request using "+$FWReqFile+". Add any addtional services required."
Log-Message $Tmp $LogFile "INFO"
###############################

###############################
#8.0 **** BOTH NODES **** Restart
$Tmp="Restarting"
Log-Message $Tmp $LogFile "INFO"

$Tmp="Ending..."
Log-Message $Tmp $LogFile "INFO"

Restart-Computer -Force
#############################
