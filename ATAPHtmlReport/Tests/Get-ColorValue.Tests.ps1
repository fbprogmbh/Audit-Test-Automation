#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe "Testing Get-ColorValue" {
            It "Should return hundred" {
                $result = Get-ColorValue -FirstValue 10 -SecondValue 10
                $result | Should -Be "hundred"
            }
            It "Should return ninety" {
                $result = Get-ColorValue -FirstValue 9 -SecondValue 10
                $result | Should -Be "ninety"
            }
            It "Should return eighty" {
                $result = Get-ColorValue -FirstValue 8 -SecondValue 10
                $result | Should -Be "eighty"
            }
            It "Should return seventy" {
                $result = Get-ColorValue -FirstValue 7 -SecondValue 10
                $result | Should -Be "seventy"
            }
            It "Should return sixty" {
                $result = Get-ColorValue -FirstValue 6 -SecondValue 10
                $result | Should -Be "sixty"
            }
            It "Should return fifty" {
                $result = Get-ColorValue -FirstValue 5 -SecondValue 10
                $result | Should -Be "fifty"
            }
            It "Should return fourty" {
                $result = Get-ColorValue -FirstValue 4 -SecondValue 10
                $result | Should -Be "fourty"
            }
            It "Should return thirty" {
                $result = Get-ColorValue -FirstValue 3 -SecondValue 10
                $result | Should -Be "thirty"
            }
            It "Should return twenty" {
                $result = Get-ColorValue -FirstValue 2 -SecondValue 10
                $result | Should -Be "twenty"
            }
            It "Should return ten" {
                $result = Get-ColorValue -FirstValue 1 -SecondValue 10
                $result | Should -Be "ten"
            }
            It "Should return zero" {
                $result = Get-ColorValue -FirstValue 0 -SecondValue 10
                $result | Should -Be "zero"
            }
            It "Should return empty" {
                $result = Get-ColorValue -FirstValue 0 -SecondValue 0
                $result | Should -Be "empty"
            }
    }
}
