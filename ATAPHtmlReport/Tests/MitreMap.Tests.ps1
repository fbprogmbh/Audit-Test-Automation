
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"


InModuleScope ATAPHtmlReport {
    Describe 'Testing MitreMap' {
        It 'tests Constructot' {
            $mitreMap = [MitreMap]::new()
            $mitreMap.Print()
        }
    }
}