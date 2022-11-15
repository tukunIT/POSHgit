import-module activedirectory 
$Computer = (Get-ADComputer -Filter 'ObjectClass -eq "computer"' -SearchBase "OU PATH"-prop ms-Mcs-AdmPwd) | get-admpwdpassword | FT ComputerName, Password
$Computer | out-file C:\LAPSpw.txt 
