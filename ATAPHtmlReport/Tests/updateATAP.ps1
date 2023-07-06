#set the directory where you are programming
$dev_directory = "$PSScriptRoot\..\.."

#deletes the old modules, if they exist
if(Test-Path "C:\Program Files\WindowsPowerShell\Modules\ATAPAuditor") {
        Remove-Item -Path "C:\Program Files\WindowsPowerShell\Modules\ATAPAuditor" -recurse
}
if(Test-Path "C:\Program Files\WindowsPowerShell\Modules\ATAPHtmlReport") {
        Remove-Item -Path "C:\Program Files\WindowsPowerShell\Modules\ATAPHtmlReport" -recurse
}
#copys the new modules to the module path of powershell
Copy-Item ($dev_directory + "\ATAPAuditor") -Destination "C:\Program Files\WindowsPowerShell\Modules" -recurse
Copy-Item ($dev_directory + "\ATAPHtmlReport") -Destination "C:\Program Files\WindowsPowerShell\Modules" -recurse
#imports ATAPAuditor and ATAPHtmlReport
Import-Module ATAPAuditor -Force
Import-Module ATAPHtmlReport -Force