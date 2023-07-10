
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"


InModuleScope ATAPHtmlReport {
    Describe 'Testing get-MitreLink' {
        It 'tests for tactics' {
            get-MitreLink -tactic -id 'TA0001' | Should -Be 'https://attack.mitre.org/tactics/TA0001/'
            get-MitreLink -tactic -id 'TA0008' | Should -Be 'https://attack.mitre.org/tactics/TA0008/'
        }
        It 'tests for techniques' {
            get-MitreLink -technique -id 'T1548' | Should -Be 'https://attack.mitre.org/techniques/T1548/'
            get-MitreLink -technique -id 'T1119' | Should -Be 'https://attack.mitre.org/techniques/T1119/'
        }
    }
}