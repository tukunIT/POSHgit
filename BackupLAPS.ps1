import-module activedirectory 
$Computer = (Get-ADComputer -Filter 'ObjectClass -eq "computer"' -SearchBase "OU=Computers,OU=104180,OU=Customers,OU=TCNOSL,OU=ASP,DC=N10,DC=tconet,DC=net"-prop ms-Mcs-AdmPwd) | get-admpwdpassword | FT ComputerName, Password
$Computer | out-file C:\LAPSpw.txt 