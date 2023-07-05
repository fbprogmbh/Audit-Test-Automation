#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe "Testing Get-ColorValue" {
            It "Should return true" {
                $result = Get-ColorValue -FirstValue 4 -SecondValue 4
                $result | Should -Be 1
            }
        }

        Context "When comparing different integers" {
            It "Should return false" {
                $result = Get-ColorValue -FirstValue 3 -SecondValue 7
                $result | Should -Be 0
            }
        }
}
