$Output= @() 
$names = Get-content "C:\Temp\Computerlist.txt" 
foreach ($name in $names){ 
  if (Test-Connection -ComputerName $name -Count 1 -ErrorAction SilentlyContinue){ 
   $Output+= "$name,up" 
   Write-Host "$Name,up" 
  }
  else{ 
    $Output+= "$name,down" 
    Write-Host "$Name,down" 
  } 
} 
$Output | Out-file "C:\Temp\Computerlist_result.csv" 