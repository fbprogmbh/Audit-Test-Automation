<#
BSD 3-Clause License

Copyright (c) 2019, FB Pro GmbH
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>


using module ATAPHtmlReport

function Test-Windows10_GDPR_MS_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableRootAutoUpdate' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '1'
                Task = "Turn off Automatic Root Certificates Update"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '1'
                Task = "Turn off Automatic Root Certificates Update"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '1'
            Task = "Turn off Automatic Root Certificates Update"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '1'
        Task = "Turn off Automatic Root Certificates Update"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_2_1_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowCortana' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '2.1.1'
                Task = "Disable Allow Cortana"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '2.1.1'
                Task = "Disable Allow Cortana"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '2.1.1'
            Task = "Disable Allow Cortana"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '2.1.1'
        Task = "Disable Allow Cortana"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_2_1_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowSearchToUseLocation' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '2.1.2'
                Task = "Disable Allow search and Cortana to use location"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '2.1.2'
                Task = "Disable Allow search and Cortana to use location"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '2.1.2'
            Task = "Disable Allow search and Cortana to use location"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '2.1.2'
        Task = "Disable Allow search and Cortana to use location"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_2_1_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableWebSearch' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '2.1.3'
                Task = "Do not allow web search"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '2.1.3'
                Task = "Do not allow web search"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '2.1.3'
            Task = "Do not allow web search"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '2.1.3'
        Task = "Do not allow web search"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_2_1_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ErrorAction Stop | Select-Object -ExpandProperty 'ConnectedSearchUseWeb' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '2.1.4'
                Task = "Don't search the web or display web results in Search"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '2.1.4'
                Task = "Don't search the web or display web results in Search"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '2.1.4'
            Task = "Don't search the web or display web results in Search"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '2.1.4'
        Task = "Don't search the web or display web results in Search"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_2_1_5 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ErrorAction Stop | Select-Object -ExpandProperty 'ConnectedSearchPrivacy' -ErrorAction Stop
        if ($regValue -eq '3') {
            return [AuditInfo] @{
                Id = '2.1.5'
                Task = "Set Set what information is shared in Search to Anonymous info"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '2.1.5'
                Task = "Set Set what information is shared in Search to Anonymous info"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '2.1.5'
            Task = "Set Set what information is shared in Search to Anonymous info"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '2.1.5'
        Task = "Set Set what information is shared in Search to Anonymous info"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_3_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop | Select-Object -ExpandProperty 'Type' -ErrorAction Stop
        if ($regValue -eq 'NoSync') {
            return [AuditInfo] @{
                Id = '3.1'
                Task = "Prevent Windows from setting the time automatically"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '3.1'
                Task = "Prevent Windows from setting the time automatically"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '3.1'
            Task = "Prevent Windows from setting the time automatically"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '3.1'
        Task = "Prevent Windows from setting the time automatically"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_3_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient' -ErrorAction Stop | Select-Object -ExpandProperty 'Enabled' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '3.2'
                Task = "Disable Windows NTP Client"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '3.2'
                Task = "Disable Windows NTP Client"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '3.2'
            Task = "Disable Windows NTP Client"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '3.2'
        Task = "Disable Windows NTP Client"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -ErrorAction Stop | Select-Object -ExpandProperty 'PreventDeviceMetadataFromNetwork' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '4'
                Task = "Prevent Windows from retrieving device metadata from the Internet"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '4'
                Task = "Prevent Windows from retrieving device metadata from the Internet"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '4'
            Task = "Prevent Windows from retrieving device metadata from the Internet"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '4'
        Task = "Prevent Windows from retrieving device metadata from the Internet"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_5 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowFindMyDevice' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '5'
                Task = "Turn off Find My Device"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '5'
                Task = "Turn off Find My Device"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '5'
            Task = "Turn off Find My Device"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '5'
        Task = "Turn off Find My Device"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_6 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction Stop | Select-Object -ExpandProperty 'EnableFontProviders' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '6'
                Task = "Disable Font Providers"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '6'
                Task = "Disable Font Providers"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '6'
            Task = "Disable Font Providers"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '6'
        Task = "Disable Font Providers"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_7 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowBuildPreview' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '7'
                Task = "Turn off Insider Preview builds for Windows 10"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '7'
                Task = "Turn off Insider Preview builds for Windows 10"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '7'
            Task = "Turn off Insider Preview builds for Windows 10"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '7'
        Task = "Turn off Insider Preview builds for Windows 10"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites' -ErrorAction Stop | Select-Object -ExpandProperty 'Enabled' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.0.1'
                Task = "Disable Suggested Sites"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.1'
                Task = "Disable Suggested Sites"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.1'
            Task = "Disable Suggested Sites"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.1'
        Task = "Disable Suggested Sites"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowServicePoweredQSA' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.0.2'
                Task = "Disable Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.2'
                Task = "Disable Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.2'
            Task = "Disable Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.2'
        Task = "Disable Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete' -ErrorAction Stop | Select-Object -ExpandProperty 'AutoSuggest' -ErrorAction Stop
        if ($regValue -eq 'No') {
            return [AuditInfo] @{
                Id = '8.0.3'
                Task = "Turn off the auto-complete feature for web addresses"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.3'
                Task = "Turn off the auto-complete feature for web addresses"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.3'
            Task = "Turn off the auto-complete feature for web addresses"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.3'
        Task = "Turn off the auto-complete feature for web addresses"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation' -ErrorAction Stop | Select-Object -ExpandProperty 'PolicyDisableGeolocation' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '8.0.4'
                Task = "Turn off browser geolocation"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.4'
                Task = "Turn off browser geolocation"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.4'
            Task = "Turn off browser geolocation"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.4'
        Task = "Turn off browser geolocation"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_5 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter' -ErrorAction Stop | Select-Object -ExpandProperty 'EnabledV9' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.0.5'
                Task = "Prevent managing SmartScreen filter"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.5'
                Task = "Prevent managing SmartScreen filter"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.5'
            Task = "Prevent managing SmartScreen filter"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.5'
        Task = "Prevent managing SmartScreen filter"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_6 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableSiteListEditing' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '8.0.6'
                Task = "Turn off Compatibility View."
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.6'
                Task = "Turn off Compatibility View."
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.6'
            Task = "Turn off Compatibility View."
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.6'
        Task = "Turn off Compatibility View."
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_7 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead' -ErrorAction Stop | Select-Object -ExpandProperty 'Enabled' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.0.7'
                Task = "Turn off the flip ahead with page prediction feature"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.7'
                Task = "Turn off the flip ahead with page prediction feature"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.7'
            Task = "Turn off the flip ahead with page prediction feature"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.7'
        Task = "Turn off the flip ahead with page prediction feature"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_8 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -ErrorAction Stop | Select-Object -ExpandProperty 'BackgroundSyncStatus' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.0.8'
                Task = "Turn off background synchronization for feeds and Web Slices"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.8'
                Task = "Turn off background synchronization for feeds and Web Slices"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.8'
            Task = "Turn off background synchronization for feeds and Web Slices"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.8'
        Task = "Turn off background synchronization for feeds and Web Slices"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_9 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowOnlineTips' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.0.9'
                Task = "Disable Allow Online Tips"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.9'
                Task = "Disable Allow Online Tips"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.9'
            Task = "Disable Allow Online Tips"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.9'
        Task = "Disable Allow Online Tips"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_10 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -ErrorAction Stop | Select-Object -ExpandProperty 'Start Page' -ErrorAction Stop
        if ($regValue -eq 'about:blank') {
            return [AuditInfo] @{
                Id = '8.0.10'
                Task = "Set home page blank"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.10'
                Task = "Set home page blank"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.10'
            Task = "Set home page blank"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.10'
        Task = "Set home page blank"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_11 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel' -ErrorAction Stop | Select-Object -ExpandProperty 'HomePage' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '8.0.11'
                Task = "Disable changing home page settings"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.11'
                Task = "Disable changing home page settings"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.11'
            Task = "Disable changing home page settings"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.11'
        Task = "Disable changing home page settings"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_12 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableFirstRunCustomize and set it to Go directly to home page' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '8.0.12'
                Task = "Prevent running First Run wizard"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.12'
                Task = "Prevent running First Run wizard"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.12'
            Task = "Prevent running First Run wizard"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.12'
        Task = "Prevent running First Run wizard"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_0_13 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing' -ErrorAction Stop | Select-Object -ExpandProperty 'NewTabPageShow' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.0.13'
                Task = "Specify default behavior for a new tab"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.0.13'
                Task = "Specify default behavior for a new tab"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.0.13'
            Task = "Specify default behavior for a new tab"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.0.13'
        Task = "Specify default behavior for a new tab"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_8_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\VersionManager' -ErrorAction Stop | Select-Object -ExpandProperty 'DownloadVersionList' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '8.1'
                Task = "Turn off Automatic download of the ActiveX VersionList"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '8.1'
                Task = "Turn off Automatic download of the ActiveX VersionList"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '8.1'
            Task = "Turn off Automatic download of the ActiveX VersionList"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '8.1'
        Task = "Turn off Automatic download of the ActiveX VersionList"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_9 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LicenseManager' -ErrorAction Stop | Select-Object -ExpandProperty 'Start' -ErrorAction Stop
        if ($regValue -eq '4') {
            return [AuditInfo] @{
                Id = '9'
                Task = "Turn off License Manager related traffic"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '9'
                Task = "Turn off License Manager related traffic"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '9'
            Task = "Turn off License Manager related traffic"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '9'
        Task = "Turn off License Manager related traffic"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_10 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -ErrorAction Stop | Select-Object -ExpandProperty 'NoCloudApplicationNotification' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '10'
                Task = "Turn Off notifications network usage"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '10'
                Task = "Turn Off notifications network usage"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '10'
            Task = "Turn Off notifications network usage"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '10'
        Task = "Turn Off notifications network usage"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_11 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail' -ErrorAction Stop | Select-Object -ExpandProperty 'ManualLaunchAllowed' -ErrorAction Stop
        if ($regValue -eq '4') {
            return [AuditInfo] @{
                Id = '11'
                Task = "Turn off mail synchronization for Microsoft Accounts that are configured on the device"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '11'
                Task = "Turn off mail synchronization for Microsoft Accounts that are configured on the device"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '11'
            Task = "Turn off mail synchronization for Microsoft Accounts that are configured on the device"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '11'
        Task = "Turn off mail synchronization for Microsoft Accounts that are configured on the device"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_12 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\wlidsvc' -ErrorAction Stop | Select-Object -ExpandProperty 'Start' -ErrorAction Stop
        if ($regValue -eq '4') {
            return [AuditInfo] @{
                Id = '12'
                Task = "Disable the Microsoft Account Sign-In Assistant"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '12'
                Task = "Disable the Microsoft Account Sign-In Assistant"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '12'
            Task = "Disable the Microsoft Account Sign-In Assistant"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '12'
        Task = "Disable the Microsoft Account Sign-In Assistant"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI' -ErrorAction Stop | Select-Object -ExpandProperty 'ShowOneBox' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '13.1'
                Task = "Disable Allow Address Bar drop-down list suggestions"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.1'
                Task = "Disable Allow Address Bar drop-down list suggestions"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.1'
            Task = "Disable Allow Address Bar drop-down list suggestions"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.1'
        Task = "Disable Allow Address Bar drop-down list suggestions"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowConfigurationUpdateForBooksLibrary' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '13.2'
                Task = "Disable Allow configuration updates for the Books Library"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.2'
                Task = "Disable Allow configuration updates for the Books Library"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.2'
            Task = "Disable Allow configuration updates for the Books Library"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.2'
        Task = "Disable Allow configuration updates for the Books Library"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ErrorAction Stop | Select-Object -ExpandProperty 'Use FormSuggest' -ErrorAction Stop
        if ($regValue -eq 'No') {
            return [AuditInfo] @{
                Id = '13.3'
                Task = "Disable Configure Autofill"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.3'
                Task = "Disable Configure Autofill"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.3'
            Task = "Disable Configure Autofill"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.3'
        Task = "Disable Configure Autofill"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ErrorAction Stop | Select-Object -ExpandProperty 'DoNotTrack' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '13.4'
                Task = "Configure Do Not Track"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.4'
                Task = "Configure Do Not Track"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.4'
            Task = "Configure Do Not Track"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.4'
        Task = "Configure Do Not Track"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_5 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ErrorAction Stop | Select-Object -ExpandProperty 'FormSuggest Passwords' -ErrorAction Stop
        if ($regValue -eq 'No') {
            return [AuditInfo] @{
                Id = '13.5'
                Task = "Disable Configure Password Manager"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.5'
                Task = "Disable Configure Password Manager"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.5'
            Task = "Disable Configure Password Manager"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.5'
        Task = "Disable Configure Password Manager"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_6 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes' -ErrorAction Stop | Select-Object -ExpandProperty 'ShowSearchSuggestionsGlobal' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '13.6'
                Task = "Disable Configure search suggestions in Address Bar"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.6'
                Task = "Disable Configure search suggestions in Address Bar"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.6'
            Task = "Disable Configure search suggestions in Address Bar"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.6'
        Task = "Disable Configure search suggestions in Address Bar"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_7 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -ErrorAction Stop | Select-Object -ExpandProperty 'EnabledV9' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '13.7'
                Task = "Disable Configure Windows Defender SmartScreen Filter (Windows 10, version 1703)"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.7'
                Task = "Disable Configure Windows Defender SmartScreen Filter (Windows 10, version 1703)"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.7'
            Task = "Disable Configure Windows Defender SmartScreen Filter (Windows 10, version 1703)"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.7'
        Task = "Disable Configure Windows Defender SmartScreen Filter (Windows 10, version 1703)"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_8 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowWebContentOnNewTabPage' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '13.8'
                Task = "Disable Allow web content on New Tab page"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.8'
                Task = "Disable Allow web content on New Tab page"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.8'
            Task = "Disable Allow web content on New Tab page"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.8'
        Task = "Disable Allow web content on New Tab page"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_9 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -ErrorAction Stop | Select-Object -ExpandProperty 'ProvisionedHomePages' -ErrorAction Stop
        if ($regValue -eq 'about:blank') {
            return [AuditInfo] @{
                Id = '13.9'
                Task = "Configure corporate Home pages"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.9'
                Task = "Configure corporate Home pages"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.9'
            Task = "Configure corporate Home pages"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.9'
        Task = "Configure corporate Home pages"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_10 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -ErrorAction Stop | Select-Object -ExpandProperty 'PreventFirstRunPage' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '13.10'
                Task = "Prevent the First Run webpage from opening on Microsoft Edge"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.10'
                Task = "Prevent the First Run webpage from opening on Microsoft Edge"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.10'
            Task = "Prevent the First Run webpage from opening on Microsoft Edge"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.10'
        Task = "Prevent the First Run webpage from opening on Microsoft Edge"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_13_11 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BrowserEmulation' -ErrorAction Stop | Select-Object -ExpandProperty 'MSCompatibilityMode' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '13.11'
                Task = "Disable Compatibility View."
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '13.11'
                Task = "Disable Compatibility View."
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '13.11'
            Task = "Disable Compatibility View."
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '13.11'
        Task = "Disable Compatibility View."
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_14 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' -ErrorAction Stop | Select-Object -ExpandProperty 'NoActiveProbe' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '14'
                Task = "Turn off Windows Network Connectivity Status Indicator active tests"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '14'
                Task = "Turn off Windows Network Connectivity Status Indicator active tests"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '14'
            Task = "Turn off Windows Network Connectivity Status Indicator active tests"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '14'
        Task = "Turn off Windows Network Connectivity Status Indicator active tests"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_15_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -ErrorAction Stop | Select-Object -ExpandProperty 'AutoDownloadAndUpdateMapData' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '15.1'
                Task = "Turn off Automatic Download and Update of Map Data"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '15.1'
                Task = "Turn off Automatic Download and Update of Map Data"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '15.1'
            Task = "Turn off Automatic Download and Update of Map Data"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '15.1'
        Task = "Turn off Automatic Download and Update of Map Data"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_15_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowUntriggeredNetworkTrafficOnSettingsPage' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '15.2'
                Task = "Turn off unsolicited network traffic on the Offline Maps settings page"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '15.2'
                Task = "Turn off unsolicited network traffic on the Offline Maps settings page"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '15.2'
            Task = "Turn off unsolicited network traffic on the Offline Maps settings page"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '15.2'
        Task = "Turn off unsolicited network traffic on the Offline Maps settings page"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_16_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableFileSyncNGSC' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '16.1'
                Task = "Prevent the usage of OneDrive for file storage"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '16.1'
                Task = "Prevent the usage of OneDrive for file storage"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '16.1'
            Task = "Prevent the usage of OneDrive for file storage"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '16.1'
        Task = "Prevent the usage of OneDrive for file storage"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_16_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\OneDrive' -ErrorAction Stop | Select-Object -ExpandProperty 'PreventNetworkTrafficPreUserSignIn' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '16.2'
                Task = "Prevent OneDrive from generating network traffic until the user signs in to OneDrive (Enable)"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '16.2'
                Task = "Prevent OneDrive from generating network traffic until the user signs in to OneDrive (Enable)"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '16.2'
            Task = "Prevent OneDrive from generating network traffic until the user signs in to OneDrive (Enable)"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '16.2'
        Task = "Prevent OneDrive from generating network traffic until the user signs in to OneDrive (Enable)"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_1_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -ErrorAction Stop | Select-Object -ExpandProperty 'Enabled' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.1.1'
                Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.1.1'
                Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.1.1'
            Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.1.1'
        Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_1_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -ErrorAction Stop | Select-Object -ExpandProperty 'DisabledByGroupPolicy' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.1.2'
                Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.1.2'
                Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.1.2'
            Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.1.2'
        Task = "Turn off Let apps use advertising ID to make ads more interesting to you based on your app usage (turning this off will reset your ID)"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_1_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -ErrorAction Stop | Select-Object -ExpandProperty 'HttpAcceptLanguageOptOut' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.1.3'
                Task = "Turn off Let websites provide locally relevant content by accessing my language list"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.1.3'
                Task = "Turn off Let websites provide locally relevant content by accessing my language list"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.1.3'
            Task = "Turn off Let websites provide locally relevant content by accessing my language list"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.1.3'
        Task = "Turn off Let websites provide locally relevant content by accessing my language list"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_1_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ErrorAction Stop | Select-Object -ExpandProperty 'Start_TrackProgs' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.1.4'
                Task = "Turn off Let Windows track app launches to improve Start and search results"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.1.4'
                Task = "Turn off Let Windows track app launches to improve Start and search results"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.1.4'
            Task = "Turn off Let Windows track app launches to improve Start and search results"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.1.4'
        Task = "Turn off Let Windows track app launches to improve Start and search results"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_2_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessLocation' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.2.1'
                Task = "Turn off Location for this device"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.2.1'
                Task = "Turn off Location for this device"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.2.1'
            Task = "Turn off Location for this device"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.2.1'
        Task = "Turn off Location for this device"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_2_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableLocation' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.2.2'
                Task = "Turn off Location"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.2.2'
                Task = "Turn off Location"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.2.2'
            Task = "Turn off Location"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.2.2'
        Task = "Turn off Location"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_3_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessCamera' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.3.1'
                Task = "Turn off Let apps use my camera"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.3.1'
                Task = "Turn off Let apps use my camera"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.3.1'
            Task = "Turn off Let apps use my camera"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.3.1'
        Task = "Turn off Let apps use my camera"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_4_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessMicrophone' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.4.1'
                Task = "Turn off Let apps use my microphone"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.4.1'
                Task = "Turn off Let apps use my microphone"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.4.1'
            Task = "Turn off Let apps use my microphone"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.4.1'
        Task = "Turn off Let apps use my microphone"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_5_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -ErrorAction Stop | Select-Object -ExpandProperty 'NoCloudApplicationNotification' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.5.1'
                Task = "Turn off notifications network usage"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.5.1'
                Task = "Turn off notifications network usage"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.5.1'
            Task = "Turn off notifications network usage"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.5.1'
        Task = "Turn off notifications network usage"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_5_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessNotifications' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.5.2'
                Task = "Turn off Let apps access my notifications"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.5.2'
                Task = "Turn off Let apps access my notifications"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.5.2'
            Task = "Turn off Let apps access my notifications"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.5.2'
        Task = "Turn off Let apps access my notifications"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_6_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'HasAccepted' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.6.1'
                Task = "Turn off dictation of your voice, speaking to Cortana and other apps, and to prevent sending your voice input to Microsoft Speech services"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.6.1'
                Task = "Turn off dictation of your voice, speaking to Cortana and other apps, and to prevent sending your voice input to Microsoft Speech services"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.6.1'
            Task = "Turn off dictation of your voice, speaking to Cortana and other apps, and to prevent sending your voice input to Microsoft Speech services"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.6.1'
        Task = "Turn off dictation of your voice, speaking to Cortana and other apps, and to prevent sending your voice input to Microsoft Speech services"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_6_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Speech' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowSpeechModelUpdate' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.6.2'
                Task = "Turn off updates to the speech recognition and speech synthesis models"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.6.2'
                Task = "Turn off updates to the speech recognition and speech synthesis models"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.6.2'
            Task = "Turn off updates to the speech recognition and speech synthesis models"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.6.2'
        Task = "Turn off updates to the speech recognition and speech synthesis models"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_7_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessAccountInfo' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.7.1'
                Task = "Turn off Let apps access my name, picture, and other account info"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.7.1'
                Task = "Turn off Let apps access my name, picture, and other account info"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.7.1'
            Task = "Turn off Let apps access my name, picture, and other account info"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.7.1'
        Task = "Turn off Let apps access my name, picture, and other account info"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_8 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessContacts' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.8'
                Task = "Turn off Choose apps that can access contacts"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.8'
                Task = "Turn off Choose apps that can access contacts"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.8'
            Task = "Turn off Choose apps that can access contacts"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.8'
        Task = "Turn off Choose apps that can access contacts"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_9_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessCalendar' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.9.1'
                Task = "Turn off Let apps access my calendar"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.9.1'
                Task = "Turn off Let apps access my calendar"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.9.1'
            Task = "Turn off Let apps access my calendar"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.9.1'
        Task = "Turn off Let apps access my calendar"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_10 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessCallHistory' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.10'
                Task = "Turn off Let apps access my call history"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.10'
                Task = "Turn off Let apps access my call history"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.10'
            Task = "Turn off Let apps access my call history"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.10'
        Task = "Turn off Let apps access my call history"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_11 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessEmail' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.11'
                Task = "Turn off Let apps access and send email"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.11'
                Task = "Turn off Let apps access and send email"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.11'
            Task = "Turn off Let apps access and send email"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.11'
        Task = "Turn off Let apps access and send email"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_12_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessMessaging' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.12.1'
                Task = "Turn off Let apps read or send messages (text or MMS)"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.12.1'
                Task = "Turn off Let apps read or send messages (text or MMS)"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.12.1'
            Task = "Turn off Let apps read or send messages (text or MMS)"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.12.1'
        Task = "Turn off Let apps read or send messages (text or MMS)"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_12_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Messaging' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowMessageSync' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.12.3'
                Task = "Turn off Message Sync"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.12.3'
                Task = "Turn off Message Sync"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.12.3'
            Task = "Turn off Message Sync"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.12.3'
        Task = "Turn off Message Sync"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_13_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessPhone' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.13.1'
                Task = "Turn off Let apps make phone calls"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.13.1'
                Task = "Turn off Let apps make phone calls"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.13.1'
            Task = "Turn off Let apps make phone calls"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.13.1'
        Task = "Turn off Let apps make phone calls"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_14_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessRadios' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.14.1'
                Task = "Turn off Let apps control radios"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.14.1'
                Task = "Turn off Let apps control radios"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.14.1'
            Task = "Turn off Let apps control radios"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.14.1'
        Task = "Turn off Let apps control radios"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_15_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsSyncWithDevices' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.15.1'
                Task = "Turn off Let apps automatically share and sync info with wireless devices that do not explicitly pair with your PC, tablet, or phone"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.15.1'
                Task = "Turn off Let apps automatically share and sync info with wireless devices that do not explicitly pair with your PC, tablet, or phone"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.15.1'
            Task = "Turn off Let apps automatically share and sync info with wireless devices that do not explicitly pair with your PC, tablet, or phone"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.15.1'
        Task = "Turn off Let apps automatically share and sync info with wireless devices that do not explicitly pair with your PC, tablet, or phone"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_15_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessTrustedDevices' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.15.2'
                Task = "Turn off Let your apps use your trusted devices (hardware you've already connected, or comes with your PC, tablet, or phone)"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.15.2'
                Task = "Turn off Let your apps use your trusted devices (hardware you've already connected, or comes with your PC, tablet, or phone)"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.15.2'
            Task = "Turn off Let your apps use your trusted devices (hardware you've already connected, or comes with your PC, tablet, or phone)"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.15.2'
        Task = "Turn off Let your apps use your trusted devices (hardware you've already connected, or comes with your PC, tablet, or phone)"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_16_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection' -ErrorAction Stop | Select-Object -ExpandProperty 'DoNotShowFeedbackNotifications' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.16.1'
                Task = "Do not show feedback notificationsk"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.16.1'
                Task = "Do not show feedback notificationsk"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.16.1'
            Task = "Do not show feedback notificationsk"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.16.1'
        Task = "Do not show feedback notificationsk"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_16_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowTelemetry' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.16.2'
                Task = "Set Send your device data to Microsoft to Basic"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.16.2'
                Task = "Set Send your device data to Microsoft to Basic"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.16.2'
            Task = "Set Send your device data to Microsoft to Basic"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.16.2'
        Task = "Set Send your device data to Microsoft to Basic"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_16_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableWindowsConsumerFeatures' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.16.3'
                Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.16.3'
                Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.16.3'
            Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.16.3'
        Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_16_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableTailoredExperiencesWithDiagnosticData' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.16.4'
                Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.16.4'
                Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.16.4'
            Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.16.4'
        Task = "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_17 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsRunInBackground' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.17'
                Task = "Turn off Let apps run in the background"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.17'
                Task = "Turn off Let apps run in the background"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.17'
            Task = "Turn off Let apps run in the background"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.17'
        Task = "Turn off Let apps run in the background"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_18 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessMotion' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.18'
                Task = "Turn off Let Windows and your apps use your motion data and collect motion history"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.18'
                Task = "Turn off Let Windows and your apps use your motion data and collect motion history"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.18'
            Task = "Turn off Let Windows and your apps use your motion data and collect motion history"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.18'
        Task = "Turn off Let Windows and your apps use your motion data and collect motion history"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_19 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsAccessTasks' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.19'
                Task = "Set Let Windows apps access Tasks to Force Deny"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.19'
                Task = "Set Let Windows apps access Tasks to Force Deny"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.19'
            Task = "Set Let Windows apps access Tasks to Force Deny"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.19'
        Task = "Set Let Windows apps access Tasks to Force Deny"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_20 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsGetDiagnosticInfo' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '18.20'
                Task = "Let Windows apps access diagnostic information about other apps"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.20'
                Task = "Let Windows apps access diagnostic information about other apps"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.20'
            Task = "Let Windows apps access diagnostic information about other apps"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.20'
        Task = "Let Windows apps access diagnostic information about other apps"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_21 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\InputPersonalization' -ErrorAction Stop | Select-Object -ExpandProperty 'RestrictImplicitTextCollection' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '18.21'
                Task = "Turn off Inking & Typing data collection"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.21'
                Task = "Turn off Inking & Typing data collection"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.21'
            Task = "Turn off Inking & Typing data collection"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.21'
        Task = "Turn off Inking & Typing data collection"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_22_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -ErrorAction Stop | Select-Object -ExpandProperty 'EnableActivityFeed' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.22.1'
                Task = "Disable Activity Feed"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.22.1'
                Task = "Disable Activity Feed"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.22.1'
            Task = "Disable Activity Feed"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.22.1'
        Task = "Disable Activity Feed"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_22_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -ErrorAction Stop | Select-Object -ExpandProperty 'PublishUserActivities' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.22.2'
                Task = "Disable Allow publishing of User Activities"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.22.2'
                Task = "Disable Allow publishing of User Activities"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.22.2'
            Task = "Disable Allow publishing of User Activities"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.22.2'
        Task = "Disable Allow publishing of User Activities"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_22_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -ErrorAction Stop | Select-Object -ExpandProperty 'UploadUserActivities' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.22.3'
                Task = "Disable Allow upload of User Activities"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.22.3'
                Task = "Disable Allow upload of User Activities"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.22.3'
            Task = "Disable Allow upload of User Activities"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.22.3'
        Task = "Disable Allow upload of User Activities"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_23_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'LetAppsActivateWithVoice' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.23.1'
                Task = "Disable Let Windows apps activate with voice"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.23.1'
                Task = "Disable Let Windows apps activate with voice"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.23.1'
            Task = "Disable Let Windows apps activate with voice"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.23.1'
        Task = "Disable Let Windows apps activate with voice"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_18_23_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy' -ErrorAction Stop | Select-Object -ExpandProperty 'PublishUserActivities' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '18.23.2'
                Task = "Disable Allow publishing of User Activities"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '18.23.2'
                Task = "Disable Allow publishing of User Activities"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '18.23.2'
            Task = "Disable Allow publishing of User Activities"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '18.23.2'
        Task = "Disable Allow publishing of User Activities"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_19 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -ErrorAction Stop | Select-Object -ExpandProperty 'NoGenTicket' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '19'
                Task = "Turn off KMS Client Online AVS Validation"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '19'
                Task = "Turn off KMS Client Online AVS Validation"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '19'
            Task = "Turn off KMS Client Online AVS Validation"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '19'
        Task = "Turn off KMS Client Online AVS Validation"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_20 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\StorageHealth' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowDiskHealthModelUpdates' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '20'
                Task = "Disable Allow downloading updates to the Disk Failure Prediction Model"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '20'
                Task = "Disable Allow downloading updates to the Disk Failure Prediction Model"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '20'
            Task = "Disable Allow downloading updates to the Disk Failure Prediction Model"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '20'
        Task = "Disable Allow downloading updates to the Disk Failure Prediction Model"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_21_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\SettingSync' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableSettingSync' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '21.1'
                Task = "Enable Do not sync"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '21.1'
                Task = "Enable Do not sync"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '21.1'
            Task = "Enable Do not sync"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '21.1'
        Task = "Enable Do not sync"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_21_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\SettingSync' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableSettingSyncUserOverride' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '21.2'
                Task = "Disable Allow users to turn syncing on"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '21.2'
                Task = "Disable Allow users to turn syncing on"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '21.2'
            Task = "Disable Allow users to turn syncing on"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '21.2'
        Task = "Disable Allow users to turn syncing on"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_21_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Messaging' -ErrorAction Stop | Select-Object -ExpandProperty 'CloudServiceSyncEnabled' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '21.3'
                Task = "Turn off Messaging cloud sync"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '21.3'
                Task = "Turn off Messaging cloud sync"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '21.3'
            Task = "Turn off Messaging cloud sync"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '21.3'
        Task = "Turn off Messaging cloud sync"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_22 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' -ErrorAction Stop | Select-Object -ExpandProperty 'Teredo_State' -ErrorAction Stop
        if ($regValue -eq 'Disabled') {
            return [AuditInfo] @{
                Id = '22'
                Task = "Set Teredo State to disabled state"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '22'
                Task = "Set Teredo State to disabled state"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '22'
            Task = "Set Teredo State to disabled state"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '22'
        Task = "Set Teredo State to disabled state"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_23 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -ErrorAction Stop | Select-Object -ExpandProperty 'AutoConnectAllowedOEM' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '23'
                Task = "Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '23'
                Task = "Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '23'
            Task = "Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '23'
        Task = "Turn off Connect to suggested open hotspots and Connect to networks shared by my contacts"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_0_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet' -ErrorAction Stop | Select-Object -ExpandProperty 'SpyNetReporting' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '24.0.1'
                Task = "Disable Join Microsoft MAPS"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.0.1'
                Task = "Disable Join Microsoft MAPS"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.0.1'
            Task = "Disable Join Microsoft MAPS"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.0.1'
        Task = "Disable Join Microsoft MAPS"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_0_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet' -ErrorAction Stop | Select-Object -ExpandProperty 'SubmitSamplesConsent' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '24.0.3'
                Task = "Set Send file samples when further analysis is required to Never Send"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.0.3'
                Task = "Set Send file samples when further analysis is required to Never Send"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.0.3'
            Task = "Set Send file samples when further analysis is required to Never Send"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.0.3'
        Task = "Set Send file samples when further analysis is required to Never Send"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_0_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates' -ErrorAction Stop | Select-Object -ExpandProperty 'FallbackOrder' -ErrorAction Stop
        if ($regValue -eq 'FileShares') {
            return [AuditInfo] @{
                Id = '24.0.4'
                Task = "Set Define the order of sources for downloading definition updates to FileShares"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.0.4'
                Task = "Set Define the order of sources for downloading definition updates to FileShares"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.0.4'
            Task = "Set Define the order of sources for downloading definition updates to FileShares"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.0.4'
        Task = "Set Define the order of sources for downloading definition updates to FileShares"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_0_5 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates' -ErrorAction Stop | Select-Object -ExpandProperty 'DefinitionUpdateFileSharesSources' -ErrorAction Stop
        if ($null -eq $regValue) {
            return [AuditInfo] @{
                Id = '24.0.5'
                Task = "Define Define file shares for downloading definition updates to Nothing"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.0.5'
                Task = "Define Define file shares for downloading definition updates to Nothing"
                Message = 'Registry value found'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.0.5'
            Task = "Define Define file shares for downloading definition updates to Nothing"
            Message = 'Compliant. Registry key or value not found'
            Audit = [AuditStatus]::True
        }
    }

    return [AuditInfo] @{
        Id = '24.0.5'
        Task = "Define Define file shares for downloading definition updates to Nothing"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_0_6 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\MRT' -ErrorAction Stop | Select-Object -ExpandProperty 'DontReportInfectionInformation' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '24.0.6'
                Task = "Turn off Malicious Software Reporting Tool diagnostic data"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.0.6'
                Task = "Turn off Malicious Software Reporting Tool diagnostic data"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.0.6'
            Task = "Turn off Malicious Software Reporting Tool diagnostic data"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.0.6'
        Task = "Turn off Malicious Software Reporting Tool diagnostic data"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_0_7 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableEnhancedNotifications' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '24.0.7'
                Task = "Turn off Enhanced Notifications as follows"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.0.7'
                Task = "Turn off Enhanced Notifications as follows"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.0.7'
            Task = "Turn off Enhanced Notifications as follows"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.0.7'
        Task = "Turn off Enhanced Notifications as follows"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_1_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -ErrorAction Stop | Select-Object -ExpandProperty 'EnableSmartScreen' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '24.1.1'
                Task = "Disable Windows Defender Smartscreen"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.1.1'
                Task = "Disable Windows Defender Smartscreen"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.1.1'
            Task = "Disable Windows Defender Smartscreen"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.1.1'
        Task = "Disable Windows Defender Smartscreen"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_1_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen' -ErrorAction Stop | Select-Object -ExpandProperty 'ConfigureAppInstallControlEnabled' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '24.1.2'
                Task = "Disable Windows Defender Smartscreen"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.1.2'
                Task = "Disable Windows Defender Smartscreen"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.1.2'
            Task = "Disable Windows Defender Smartscreen"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.1.2'
        Task = "Disable Windows Defender Smartscreen"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_24_1_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen' -ErrorAction Stop | Select-Object -ExpandProperty 'ConfigureAppInstallControl' -ErrorAction Stop
        if ($regValue -eq 'Anywhere') {
            return [AuditInfo] @{
                Id = '24.1.3'
                Task = "Disable Windows Defender Smartscreen"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '24.1.3'
                Task = "Disable Windows Defender Smartscreen"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '24.1.3'
            Task = "Disable Windows Defender Smartscreen"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '24.1.3'
        Task = "Disable Windows Defender Smartscreen"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_25_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableWindowsSpotlightFeatures' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '25.1'
                Task = "Turn off all Windows spotlight features"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '25.1'
                Task = "Turn off all Windows spotlight features"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '25.1'
            Task = "Turn off all Windows spotlight features"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '25.1'
        Task = "Turn off all Windows spotlight features"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_25_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ErrorAction Stop | Select-Object -ExpandProperty 'NoLockScreen' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '25.2'
                Task = "Do not display the Lock Screen"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '25.2'
                Task = "Do not display the Lock Screen"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '25.2'
            Task = "Do not display the Lock Screen"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '25.2'
        Task = "Do not display the Lock Screen"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_25_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ErrorAction Stop | Select-Object -ExpandProperty 'LockScreenImage' -ErrorAction Stop
        if ($regValue -eq 'C:\windows\web\screen\lockscreen.jpg') {
            return [AuditInfo] @{
                Id = '25.3'
                Task = "Force a specific default lock screen image and logon image"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '25.3'
                Task = "Force a specific default lock screen image and logon image"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '25.3'
            Task = "Force a specific default lock screen image and logon image"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '25.3'
        Task = "Force a specific default lock screen image and logon image"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_25_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ErrorAction Stop | Select-Object -ExpandProperty 'LockScreenOverlaysDisabled' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '25.4'
                Task = "Turn off fun facts, tips, tricks, and more on lock screen"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '25.4'
                Task = "Turn off fun facts, tips, tricks, and more on lock screen"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '25.4'
            Task = "Turn off fun facts, tips, tricks, and more on lock screen"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '25.4'
        Task = "Turn off fun facts, tips, tricks, and more on lock screen"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_25_5 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableSoftLanding' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '25.5'
                Task = "Do not show Windows tips"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '25.5'
                Task = "Do not show Windows tips"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '25.5'
            Task = "Do not show Windows tips"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '25.5'
        Task = "Do not show Windows tips"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_25_6 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableWindowsConsumerFeatures' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '25.6'
                Task = "Turn off Microsoft consumer experiences"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '25.6'
                Task = "Turn off Microsoft consumer experiences"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '25.6'
            Task = "Turn off Microsoft consumer experiences"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '25.6'
        Task = "Turn off Microsoft consumer experiences"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_26_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableStoreApps' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '26.1'
                Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '26.1'
                Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '26.1'
            Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '26.1'
        Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_26_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction Stop | Select-Object -ExpandProperty 'AutoDownload' -ErrorAction Stop
        if ($regValue -eq '2') {
            return [AuditInfo] @{
                Id = '26.2'
                Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '26.2'
                Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '26.2'
            Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '26.2'
        Task = "Turn off the ability to launch apps from the Microsoft Store that were preinstalled or downloaded"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_27 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction Stop | Select-Object -ExpandProperty 'EnableAppUriHandlers' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '27'
                Task = "Turn off apps for websites, preventing customers who visit websites that are registered with their associated app from directly launching the app"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '27'
                Task = "Turn off apps for websites, preventing customers who visit websites that are registered with their associated app from directly launching the app"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '27'
            Task = "Turn off apps for websites, preventing customers who visit websites that are registered with their associated app from directly launching the app"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '27'
        Task = "Turn off apps for websites, preventing customers who visit websites that are registered with their associated app from directly launching the app"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_28_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -ErrorAction Stop | Select-Object -ExpandProperty 'DODownloadMode' -ErrorAction Stop
        if ($regValue -eq '100') {
            return [AuditInfo] @{
                Id = '28.3'
                Task = "Enable the Download Mode and set the Download Mode to `"Bypass`" to prevent traffic"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '28.3'
                Task = "Enable the Download Mode and set the Download Mode to `"Bypass`" to prevent traffic"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '28.3'
            Task = "Enable the Download Mode and set the Download Mode to `"Bypass`" to prevent traffic"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '28.3'
        Task = "Enable the Download Mode and set the Download Mode to `"Bypass`" to prevent traffic"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_29_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop | Select-Object -ExpandProperty 'DoNotConnectToWindowsUpdateInternetLocations' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '29.1'
                Task = "Turn off Windows Update"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '29.1'
                Task = "Turn off Windows Update"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '29.1'
            Task = "Turn off Windows Update"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '29.1'
        Task = "Turn off Windows Update"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_29_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop | Select-Object -ExpandProperty 'DisableWindowsUpdateAccess' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '29.2'
                Task = "Turn off Windows Update"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '29.2'
                Task = "Turn off Windows Update"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '29.2'
            Task = "Turn off Windows Update"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '29.2'
        Task = "Turn off Windows Update"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_29_3 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop | Select-Object -ExpandProperty 'WUServer' -ErrorAction Stop
        if ($regValue -eq '') {
            return [AuditInfo] @{
                Id = '29.3'
                Task = "Turn off Windows Update"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '29.3'
                Task = "Turn off Windows Update"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '29.3'
            Task = "Turn off Windows Update"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '29.3'
        Task = "Turn off Windows Update"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_29_4 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop | Select-Object -ExpandProperty 'WUStatusServer' -ErrorAction Stop
        if ($regValue -eq '') {
            return [AuditInfo] @{
                Id = '29.4'
                Task = "Turn off Windows Update"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '29.4'
                Task = "Turn off Windows Update"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '29.4'
            Task = "Turn off Windows Update"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '29.4'
        Task = "Turn off Windows Update"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_29_5 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop | Select-Object -ExpandProperty 'UpdateServiceUrlAlternate' -ErrorAction Stop
        if ($regValue -eq '') {
            return [AuditInfo] @{
                Id = '29.5'
                Task = "Turn off Windows Update"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '29.5'
                Task = "Turn off Windows Update"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '29.5'
            Task = "Turn off Windows Update"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '29.5'
        Task = "Turn off Windows Update"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_MS_29_6 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction Stop | Select-Object -ExpandProperty 'UseWUServer' -ErrorAction Stop
        if ($regValue -eq '1') {
            return [AuditInfo] @{
                Id = '29.6'
                Task = "Turn off Windows Update"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '29.6'
                Task = "Turn off Windows Update"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '29.6'
            Task = "Turn off Windows Update"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '29.6'
        Task = "Turn off Windows Update"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_BSI_3_1_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -ErrorAction Stop | Select-Object -ExpandProperty 'AllowTelemetry' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '3.1.1'
                Task = "Configuration of the lowest telemetry-level"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '3.1.1'
                Task = "Configuration of the lowest telemetry-level"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '3.1.1'
            Task = "Configuration of the lowest telemetry-level"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '3.1.1'
        Task = "Configuration of the lowest telemetry-level"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_BSI_3_1_2_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack' -ErrorAction Stop | Select-Object -ExpandProperty 'Start' -ErrorAction Stop
        if ($regValue -eq '4') {
            return [AuditInfo] @{
                Id = '3.1.2.1'
                Task = "Deactivation of the telemetry-service and etw-sessions - DiagTrack"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '3.1.2.1'
                Task = "Deactivation of the telemetry-service and etw-sessions - DiagTrack"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '3.1.2.1'
            Task = "Deactivation of the telemetry-service and etw-sessions - DiagTrack"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '3.1.2.1'
        Task = "Deactivation of the telemetry-service and etw-sessions - DiagTrack"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_BSI_3_1_2_2 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' -ErrorAction Stop | Select-Object -ExpandProperty 'Start' -ErrorAction Stop
        if ($regValue -eq '0') {
            return [AuditInfo] @{
                Id = '3.1.2.2'
                Task = "Deactivation of the telemetry-service and etw-sessions - Autologger-Diatrack-Listener"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '3.1.2.2'
                Task = "Deactivation of the telemetry-service and etw-sessions - Autologger-Diatrack-Listener"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '3.1.2.2'
            Task = "Deactivation of the telemetry-service and etw-sessions - Autologger-Diatrack-Listener"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '3.1.2.2'
        Task = "Deactivation of the telemetry-service and etw-sessions - Autologger-Diatrack-Listener"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Test-Windows10_GDPR_BSI_3_1_3_1 {
    try {
        $regValue = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' -ErrorAction Stop | Select-Object -ExpandProperty 'Start' -ErrorAction Stop
        if ($regValue -eq '4') {
            return [AuditInfo] @{
                Id = '3.1.3.1'
                Task = "Deactivation of telemetry according to Microsoft recommendation"
                Message = 'Compliant'
                Audit = [AuditStatus]::True
            }
        }
        else {
            return [AuditInfo] @{
                Id = '3.1.3.1'
                Task = "Deactivation of telemetry according to Microsoft recommendation"
                Message = 'Registry value is wrong'
                Audit = [AuditStatus]::False
            }
        }
    }
    catch [System.Management.Automation.PSArgumentException], [System.Management.Automation.ItemNotFoundException] {
        return [AuditInfo] @{
            Id = '3.1.3.1'
            Task = "Deactivation of telemetry according to Microsoft recommendation"
            Message = 'Registry key or value not found'
            Audit = [AuditStatus]::False
        }
    }

    return [AuditInfo] @{
        Id = '3.1.3.1'
        Task = "Deactivation of telemetry according to Microsoft recommendation"
        Message = 'An error occured.'
        Audit = [AuditStatus]::False
    }
}

function Get-Windows10GDPRHtmlReport {
    <#
    .Synopsis
        Generates an audit report in an html file.
    .Description
        The Get-Windows10GDPRHtmlReport cmdlet collects by default data from the current machine to generate an audit report.
    .Parameter Path
        Specifies the relative path to the file in which the report will be stored.
    .Example
        C:\PS> Get-Windows10GDPRHtmlReport -Path "MyReport.html"
    #>

    [CmdletBinding()]
    param (
        [string] $Path = "$($env:HOMEPATH)\Documents\$(Get-Date -UFormat %Y%m%d_%H%M)_auditreport.html",

        [switch] $DarkMode
    )

    $args = @{
        Path = $Path
        Title = 'Windows 10 GDPR Audit Report'
        ModuleName = 'Windows10GDPRAudit'
        BasedOn = 'GDPR settings by Microsoft', 'Bundesamt für Sicherheit in der Informationstechnik (BSI)'
        Sections = @(
            @{
                Title = 'GDPR settings by Microsoft'
                AuditInfos = @(
                    Test-Windows10_GDPR_MS_1
                    Test-Windows10_GDPR_MS_2_1_1
                    Test-Windows10_GDPR_MS_2_1_2
                    Test-Windows10_GDPR_MS_2_1_3
                    Test-Windows10_GDPR_MS_2_1_4
                    Test-Windows10_GDPR_MS_2_1_5
                    Test-Windows10_GDPR_MS_3_1
                    Test-Windows10_GDPR_MS_3_2
                    Test-Windows10_GDPR_MS_4
                    Test-Windows10_GDPR_MS_5
                    Test-Windows10_GDPR_MS_6
                    Test-Windows10_GDPR_MS_7
                    Test-Windows10_GDPR_MS_8_0_1
                    Test-Windows10_GDPR_MS_8_0_2
                    Test-Windows10_GDPR_MS_8_0_3
                    Test-Windows10_GDPR_MS_8_0_4
                    Test-Windows10_GDPR_MS_8_0_5
                    Test-Windows10_GDPR_MS_8_0_6
                    Test-Windows10_GDPR_MS_8_0_7
                    Test-Windows10_GDPR_MS_8_0_8
                    Test-Windows10_GDPR_MS_8_0_9
                    Test-Windows10_GDPR_MS_8_0_10
                    Test-Windows10_GDPR_MS_8_0_11
                    Test-Windows10_GDPR_MS_8_0_12
                    Test-Windows10_GDPR_MS_8_0_13
                    Test-Windows10_GDPR_MS_8_1
                    Test-Windows10_GDPR_MS_9
                    Test-Windows10_GDPR_MS_10
                    Test-Windows10_GDPR_MS_11
                    Test-Windows10_GDPR_MS_12
                    Test-Windows10_GDPR_MS_13_1
                    Test-Windows10_GDPR_MS_13_2
                    Test-Windows10_GDPR_MS_13_3
                    Test-Windows10_GDPR_MS_13_4
                    Test-Windows10_GDPR_MS_13_5
                    Test-Windows10_GDPR_MS_13_6
                    Test-Windows10_GDPR_MS_13_7
                    Test-Windows10_GDPR_MS_13_8
                    Test-Windows10_GDPR_MS_13_9
                    Test-Windows10_GDPR_MS_13_10
                    Test-Windows10_GDPR_MS_13_11
                    Test-Windows10_GDPR_MS_14
                    Test-Windows10_GDPR_MS_15_1
                    Test-Windows10_GDPR_MS_15_2
                    Test-Windows10_GDPR_MS_16_1
                    Test-Windows10_GDPR_MS_16_2
                    Test-Windows10_GDPR_MS_18_1_1
                    Test-Windows10_GDPR_MS_18_1_2
                    Test-Windows10_GDPR_MS_18_1_3
                    Test-Windows10_GDPR_MS_18_1_4
                    Test-Windows10_GDPR_MS_18_2_1
                    Test-Windows10_GDPR_MS_18_2_2
                    Test-Windows10_GDPR_MS_18_3_1
                    Test-Windows10_GDPR_MS_18_4_1
                    Test-Windows10_GDPR_MS_18_5_1
                    Test-Windows10_GDPR_MS_18_5_2
                    Test-Windows10_GDPR_MS_18_6_1
                    Test-Windows10_GDPR_MS_18_6_2
                    Test-Windows10_GDPR_MS_18_7_1
                    Test-Windows10_GDPR_MS_18_8
                    Test-Windows10_GDPR_MS_18_9_1
                    Test-Windows10_GDPR_MS_18_10
                    Test-Windows10_GDPR_MS_18_11
                    Test-Windows10_GDPR_MS_18_12_1
                    Test-Windows10_GDPR_MS_18_12_3
                    Test-Windows10_GDPR_MS_18_13_1
                    Test-Windows10_GDPR_MS_18_14_1
                    Test-Windows10_GDPR_MS_18_15_1
                    Test-Windows10_GDPR_MS_18_15_2
                    Test-Windows10_GDPR_MS_18_16_1
                    Test-Windows10_GDPR_MS_18_16_2
                    Test-Windows10_GDPR_MS_18_16_3
                    Test-Windows10_GDPR_MS_18_16_4
                    Test-Windows10_GDPR_MS_18_17
                    Test-Windows10_GDPR_MS_18_18
                    Test-Windows10_GDPR_MS_18_19
                    Test-Windows10_GDPR_MS_18_20
                    Test-Windows10_GDPR_MS_18_21
                    Test-Windows10_GDPR_MS_18_22_1
                    Test-Windows10_GDPR_MS_18_22_2
                    Test-Windows10_GDPR_MS_18_22_3
                    Test-Windows10_GDPR_MS_18_23_1
                    Test-Windows10_GDPR_MS_18_23_2
                    Test-Windows10_GDPR_MS_19
                    Test-Windows10_GDPR_MS_20
                    Test-Windows10_GDPR_MS_21_1
                    Test-Windows10_GDPR_MS_21_2
                    Test-Windows10_GDPR_MS_21_3
                    Test-Windows10_GDPR_MS_22
                    Test-Windows10_GDPR_MS_23
                    Test-Windows10_GDPR_MS_24_0_1
                    Test-Windows10_GDPR_MS_24_0_3
                    Test-Windows10_GDPR_MS_24_0_4
                    Test-Windows10_GDPR_MS_24_0_5
                    Test-Windows10_GDPR_MS_24_0_6
                    Test-Windows10_GDPR_MS_24_0_7
                    Test-Windows10_GDPR_MS_24_1_1
                    Test-Windows10_GDPR_MS_24_1_2
                    Test-Windows10_GDPR_MS_24_1_3
                    Test-Windows10_GDPR_MS_25_1
                    Test-Windows10_GDPR_MS_25_2
                    Test-Windows10_GDPR_MS_25_3
                    Test-Windows10_GDPR_MS_25_4
                    Test-Windows10_GDPR_MS_25_5
                    Test-Windows10_GDPR_MS_25_6
                    Test-Windows10_GDPR_MS_26_1
                    Test-Windows10_GDPR_MS_26_2
                    Test-Windows10_GDPR_MS_27
                    Test-Windows10_GDPR_MS_28_3
                    Test-Windows10_GDPR_MS_29_1
                    Test-Windows10_GDPR_MS_29_2
                    Test-Windows10_GDPR_MS_29_3
                    Test-Windows10_GDPR_MS_29_4
                    Test-Windows10_GDPR_MS_29_5
                    Test-Windows10_GDPR_MS_29_6

                )
            }
            @{
                Title = 'Bundesamt für Sicherheit in der Informationstechnik (BSI)'
                AuditInfos = @(
                    Test-Windows10_GDPR_BSI_3_1_1
                    Test-Windows10_GDPR_BSI_3_1_2_1
                    Test-Windows10_GDPR_BSI_3_1_2_2
                    Test-Windows10_GDPR_BSI_3_1_3_1

                )
            }

        )
        DarkMode = $DarkMode
    }

    Get-ATAPHtmlReport @args
}

