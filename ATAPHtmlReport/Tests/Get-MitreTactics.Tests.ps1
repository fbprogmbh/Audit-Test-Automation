#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'Testing Get-MitreTactics' {
        It 'tests with example Values' {

            Get-MitreTactics -TechniqueID "T1591" | Should -Be 'TA0043'

            Get-MitreTactics -TechniqueID "T1056" | Should -Be 'TA0009', 'TA0006'
        }
    }
}