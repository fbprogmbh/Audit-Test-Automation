#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'Testing Get-MitreTacticName' {
        It 'tests with example Values' {
            Get-MitreTacticName -TacticId 'TA0042' | Should -Be "Resource Development"
            Get-MitreTacticName -TacticId 'TA0004' | Should -Be "Privilege Escalation"
            Get-MitreTacticName -TacticId 'TA0008' | Should -Be "Lateral Movement"
        }
    }
}