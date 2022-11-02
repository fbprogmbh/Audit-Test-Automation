<#
BSD 3-Clause License
Copyright (c) 2018, FB Pro GmbH
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

$ScriptRoot = Split-Path -Parent $PSCommandPath

$Settings = Import-PowerShellDataFile -Path "$ScriptRoot\Settings.psd1"
$ModuleVersion = (Import-PowerShellDataFile -Path "$ScriptRoot\ATAPHtmlReport.psd1").ModuleVersion

$StatusValues = 'True', 'False', 'Warning', 'None', 'Error'
$AuditProperties = @{ Name = 'Id' }, @{ Name = 'Task' }, @{ Name = 'Message' }, @{ Name = 'Status' }

function Join-ATAPReportStatus {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory = $true)]
		[string[]]
		$Statuses
	)

	if ($Statuses -contains 'False') {
		return 'False'
	}
	elseif ($Statuses -contains 'Error') {
		return 'Warning'
	}
	elseif ($Statuses -contains 'Warning') {
		return 'Warning'
	}
	elseif ($Statuses -contains 'True') {
		return 'True'
	}
	else {
		return 'None'
	}
}

function htmlElement {
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]
		$ElementName,

		[Parameter(Mandatory = $true, Position = 1)]
		[hashtable]
		$Attributes,

		[Parameter(Mandatory = $true, Position = 2)]
		[scriptblock]
		$Children
	)

	$htmlAttributes = @()
	foreach ($attribute in $Attributes.GetEnumerator()) {
		$htmlAttributes += '{0}="{1}"' -f $attribute.Name, $attribute.Value
	}

	[string[]]$htmlChildren = & $Children

	return '<{0} {1}>{2}</{0}>' -f $ElementName, ($htmlAttributes -join ' '), ($htmlChildren -join '')
}

function Get-SectionStatus {
	param(
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[Alias('AuditInfos')]
		[array]
		$ConfigAudits,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Subsections
	)

	process {
		$allStatuses = @()
		if ($null -ne $ConfigAudits) {
			$allStatuses += $ConfigAudits.Status
		}
		if ($null -ne $Subsections) {
			foreach ($subsection in $Subsections) {
				$allStatuses += $subsection | Get-SectionStatus
			}
		}
		return Join-ATAPReportStatus $allStatuses
	}
}

function Get-HtmlClassFromStatus {
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$Status
	)

	process {
		switch ($Status) {
			'True' { 'passed' }
			'False' { 'failed' }
			'Warning' { 'warning' }
			Default { "" }
		}
	}
}

function Convert-SectionTitleToHtmlId {
	param(
		[Parameter(Mandatory = $true)]
		[string] $Title
	)

	$charMap = {
		switch ($_) {
			' ' { "-" }
			'-' { "--" }
			Default { $_ }
		}
	}

	return ([char[]]$Title | ForEach-Object $charMap) -join ''
}

function CreateToc{
	param(
		[Parameter(Mandatory = $true)]
		$title
	)
	htmlElement 'li' @{} {
		htmlElement 'a' @{ href = "#$($title)" } {"$($title)" }
	}
}

function CreateReportContent{
	param(
		[Parameter(Mandatory = $true)]
		$tests,
		[Parameter(Mandatory = $true)]
		$title
	)
	$amountOfFailedTests = 0
	foreach($test in $tests){
		if($test.Status -eq 'False'){
			$amountOfFailedTests ++
		}
	}
	#if at least one test is failed
	if($amountOfFailedTests -gt 0){
		htmlElement 'h2' @{ id="$($title)"; style="padding: 5px 10px; border-radius: 8px; color:white; background-color: #cc0000; display: inline;"}{"$($title)"}
	}
	else{
		htmlElement 'h2' @{ id="$($title)"; style="padding: 5px 10px; border-radius: 8px; color:white; background-color: #33cca6; display: inline;"}{"$($title)"}
	}
	htmlElement 'table' @{class = 'audit-info'; style = 'margin-bottom: 50px; margin-top: 20px;'} {
		htmlElement 'tbody' @{}{
			htmlElement 'tr' @{}{
				htmlElement 'th' @{} {"Id"}
				htmlElement 'th' @{} {"Task"}
				htmlElement 'th' @{} {"Message"}
				htmlElement 'th' @{} {"Status"}
			}
			foreach($test in $tests){
				htmlElement 'tr' @{}{
					htmlElement 'td' @{} { "$($test.Id)"}
					htmlElement 'td' @{} { "$($test.Task)"}
					htmlElement 'td' @{} { "$($test.Message)"}
					htmlElement 'td' @{} { 
						if($test.Status -eq 'False'){
							htmlElement 'span' @{class="severityResultFalse"}{
								"$($test.Status)"
							}
						}
						elseif($test.Status -eq 'True'){
							htmlElement 'span' @{class="severityResultTrue"}{
								"$($test.Status)"
							}
						}
						elseif($test.Status -eq 'None'){
							htmlElement 'span' @{class="severityResultNone"}{
								"$($test.Status)"
							}
						}
						elseif($test.Status -eq 'Warning'){
							htmlElement 'span' @{class="severityResultWarning"}{
								"$($test.Status)"
							}
						}
						elseif($test.Status -eq 'Error'){
							htmlElement 'span' @{class="severityResultError"}{
								"$($test.Status)"
							}
						}
					}
				}
			}
		}
	}
}


function Get-HtmlTableRow {
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		$Audit
	)

	process {
		# $properties = $Audit | Get-Member -MemberType Property

		htmlElement 'tr' @{} {
			foreach ($property in $AuditProperties) {
				$value = $Audit | Select-Object -ExpandProperty $property.Name
				if ($Property.Name -eq 'Status') {
					$class = Get-HtmlClassFromStatus $Audit.Status
					$value = htmlElement 'span' @{ class = "auditstatus $class" } { $value }
				}
				htmlElement 'td' @{} { $value }
			}
		}
	}
}

function Get-HtmlToc {
	param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Subsections,

		[string]
		$Prefix = ''
	)

	process {
		$id = Convert-SectionTitleToHtmlId -Title ($Prefix + $Title)
		htmlElement 'li' @{} {
			htmlElement 'a' @{ href = "#$id" } { $Title }
			if ($null -ne $Subsections) {
				htmlElement 'ul' @{} {
					foreach ($subsection in $Subsections) {
						$subsection | Get-HtmlToc -Prefix ($Prefix + $Title)
					}
				}
			}
		}
	}
}

function Get-HtmlReportSection {
	param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Description,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[alias('AuditInfos')]
		[array]
		$ConfigAudits,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[alias('Sections')]
		[array]
		$Subsections,

		[Parameter(Mandatory = $false)]
		[string]
		$Prefix
	)

	process {
		$id = Convert-SectionTitleToHtmlId -Title ($Prefix + $Title)
		$sectionStatus = Get-SectionStatus -ConfigAudits $ConfigAudits -Subsections $Subsections
		$class = Get-HtmlClassFromStatus $sectionStatus

		htmlElement 'section' @{} {
			htmlElement 'h1' @{ id = $id } {
				htmlElement 'span' @{ class = $class } { $Title }
				htmlElement 'span' @{ class = 'sectionAction collapseButton' } { '-' }
				htmlElement 'a' @{ href = '#toc'; class = 'sectionAction' } {
					htmlElement 'span' @{ style = "font-size: 75%;" } { '&uarr;' }
				}
			}

			if ($null -ne $Description) {
				htmlElement 'p' @{} { $Description }
			}
			# if ($null -ne $ConfigAudits){
			# 	htmlElement 'p' @{} {$ConfigAudits.Count + ' tests have been executed in this section'}
			# }
			if ($null -ne $ConfigAudits) {
				htmlElement 'table' @{ class = 'audit-info' } {
					htmlElement 'tbody' @{} {
						htmlElement 'tr' @{} {
							foreach ($columnName in $AuditProperties.Name) {
								htmlElement 'th' @{} { $columnName }
							}
						}
						foreach ($configAudit in $ConfigAudits) {
							$configAudit | Get-HtmlTableRow
						}
					}
				}
			}
			if ($null -ne $Subsections) {
				foreach ($subsection in $Subsections) {
					$subsection | Get-HtmlReportSection -Prefix ($Prefix + $Title)
				}
			}
		}
	}
}

function Get-ATAPHostInformation {
	$unixOS = [System.Environment]::OSVersion.Platform -eq 'Unix' # returns 'Unix' on Linux and MacOS and 'Win32NT' on Windows, PS v6+ has builtin environment variable for this
	if ($unixOS) {
		return @{
			"Hostname"                  = hostname
			"Domain role"               = $role
			"Operating System"          = (Get-Content /etc/os-release | Select-String -Pattern '^PRETTY_NAME=\"(.*)\"$').Matches.Groups[1].Value
			"Installation Language"     = (($(locale) | Where-Object { $_ -match "LANG=" }) -split '=')[1]
			"Kernel Version"            = uname -r
			"Free physical memory (GB)" = "{0:N1}" -f (( -split (Get-Content /proc/meminfo | Where-Object { $_ -match 'MemFree:' }))[1] / 1MB)
			"Free disk space (GB)"      = "{0:N1}" -f ((Get-PSDrive | Where-Object { $_.Name -eq '/' }).Free / 1GB)
		}
	}
 else {
		$infos = Get-CimInstance Win32_OperatingSystem
		$disk = Get-CimInstance Win32_LogicalDisk | Where-Object -Property DeviceID -eq "C:"
		$role = Switch ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole) {
			"0"	{ "Standalone Workstation" }
			"1"	{ "Member Workstation" }
			"2"	{ "Standalone Server" }
			"3"	{ "Member Server" }
			"4"	{ "Backup Domain Controller" }
			"5"	{ "Primary Domain Controller" }
		}
		$freeMemory = ($infos.FreePhysicalMemory /1024) / 1024;
		$totalMemory = ($infos.TotalVirtualMemorySize /1024) /1024;
		
		return @{
			"Hostname"                  = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
			"Domain role"               = $role
			"Operating System"          = $infos.Caption
			"Build Number"              = $infos.BuildNumber
			"Installation Language"     = ((Get-UICulture).DisplayName)
			"Free disk space (GB)"      = "{0:N1}" -f ($disk.FreeSpace / 1GB)
			"Free physical memory (GB)" = "{0:N3}" -f "$([math]::Round(($freeMemory/$totalMemory)*100,1))%  ($([math]::Round($freeMemory,1)) GB / $([math]::Round($totalMemory,1)) GB)" 
		} 
	}
}

function Get-CompletionStatus {
	param(
		[string[]]
		$Statuses,

		[array]$Sections
	)

	$totalCount = $Statuses.Count
	$status = @{
		TotalCount = $totalCount
	}

	#Total completion status
	foreach ($value in $StatusValues) {
		$count = ($Statuses | Where-Object { $_ -eq $value }).Count
		$status[$value] = @{
			Count   = $count
			Percent = (100 * ($count / $totalCount)).ToString("0.00", [cultureinfo]::InvariantCulture)
		}
	}

	#Section Total Count
	$sectionTotalCountHash = @{}
	foreach ($section in $Sections) {
		$sectionResult = $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status'
		$totalSectionCount = 0
		foreach ($value in $StatusValues) {
			$count = ($sectionResult | Where-Object { $_ -eq $value }).Count
			$totalSectionCount += $count
		}
		$sectionTotalCountHash.Add($section.Title, $totalSectionCount)
	}
	#Counts the completion status for each section and each value. Also calculates the percentage.
	$sectionCountHash = @{}
	foreach ($section in $Sections) {
		$sectionResult = $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status'
		foreach ($value in $StatusValues) {
			$count = ($sectionResult | Where-Object { $_ -eq $value }).Count
			$sectionCountHash.Add($section.Title + $value + "Count", $count)
			$percent = (100 * ($count / $sectionTotalCountHash[$section.Title])).ToString("0.00", [cultureinfo]::InvariantCulture)
			$sectionCountHash.Add($section.Title + $value + "Percent", $percent)
		}
	}
	return $status, $sectionTotalCountHash, $sectionCountHash
}

function Get-OverallComplianceCSS {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		$completionStatus
	)

	$css = ""
	$percent = $completionStatus['True'].Percent / 1

	if ($percent -gt 50) {
		$degree = 180 + ((($percent - 50) / 1) * 3.6)
		$css += ".donut-chart.chart .slice.one {clip: rect(0 200px 100px 0); -webkit-transform: rotate(90deg); transform: rotate(90deg);}"
		$css += ".donut-chart.chart .slice.two {clip: rect(0 100px 200px 0); -webkit-transform: rotate($($degree)deg); transform: rotate($($degree)deg);}"
	}
	else {
		$degree = 90 + ($percent * 3.6)
		$css += ".donut-chart.chart .slice.one {clip: rect(0 200px 100px 0); -webkit-transform: rotate($($degree)deg); transform: rotate($($degree)deg);}"
		$css += ".donut-chart.chart .slice.two {clip: rect(0 100px 200px 0); -webkit-transform: rotate(0deg); transform: rotate(0deg);}"
	}

	$css += ".donut-chart.chart .chart-center span:after {content: `"$percent %`";}"

	return $css
}

function Select-ConfigAudit {
	param(
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[Alias('AuditInfos')]
		[array]
		$ConfigAudits,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Subsections
	)

	process {
		$results = @()
		if ($null -ne $ConfigAudits) {
			$results += $ConfigAudits
		}
		if ($null -ne $Subsections) {
			foreach ($subsection in $Subsections) {
				$results += $subsection | Select-ConfigAudit
			}
		}
		return $results
	}
}

function Get-ATAPHtmlReport {
	<#
	.Synopsis
		Generates an audit report in an html file.
	.Description
		The `Get-ATAPHtmlReport` cmdlet collects data from the current machine to generate an audit report.
	.Parameter Path
		Specifies the relative path to the file in which the report will be stored.
	.Example
		C:\PS> Get-ATAPHtmlReport -Path "MyReport.html"
	#>

	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		[Parameter(Mandatory = $false)]
		[hashtable]
		$HostInformation = (Get-ATAPHostInformation),

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ModuleName,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$AuditorVersion,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$BasedOn,

		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Sections,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[RSFullReport[]]
		$RSReport,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[FoundationReport]
		$FoundationReport,

		[switch] $DarkMode,

		[switch] $ComplianceStatus
	)

	process {
		$allConfigResults = foreach ($section in $Sections) { $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status' }
		$completionStatus, $sectionTotalCountHash, $sectionCountHash = Get-CompletionStatus -Statuses $allConfigResults -sections $Sections

		# HTML <head> markup
		$head = htmlElement 'head' @{} {
			htmlElement 'meta' @{ charset = 'UTF-8' } { }
			htmlElement 'meta' @{ name = 'viewport'; content = 'width=device-width, initial-scale=1.0' } { }
			htmlElement 'meta' @{ 'http-equiv' = 'X-UA-Compatible'; content = 'ie=edge' } { }
			htmlElement 'title' @{} { "$Title [$(Get-Date)]" }
			htmlElement 'style' @{} {
				$cssEnding = ''
				if ($DarkMode) { $cssEnding = '.dark' }
				$cssPath = $ScriptRoot | Join-path -ChildPath "/report$($cssEnding).css"
				Get-Content $cssPath
				Get-OverallComplianceCSS $completionStatus
			}
			htmlElement 'script' @{} {
				$jsPath = $ScriptRoot | Join-path -ChildPath "/report.js"
				Get-Content $jsPath
			}
		}
		$body = htmlElement 'body' @{onload = "startConditions()" } {
			# Header
			htmlElement 'div' @{ class = 'header content' } {
				$Settings.LogoSvg
				htmlElement 'h1' @{} { $Title }
				# htmlElement 'p' @{} {
				# 	"Generated by the <i>$ModuleName</i> Module Version <i>$AuditorVersion</i> by FB Pro GmbH. Get it in the <a href=`"$($Settings.PackageLink)`">Audit Test Automation Package</a>. Are you seeing a lot of red sections? Check out our <a href=`"$($Settings.SolutionsLink)`">hardening solutions</a>."
				# }
				# htmlElement 'p' @{} {
				# 	"Based on:"
				# 	htmlElement 'ul' @{} {
				# 		foreach ($item in $BasedOn) {
				# 			htmlElement 'li' @{} { $item }
				# 		}
				# 	}
				# 	htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
				# }
			}
			# Main section
			htmlElement 'div' @{ class = 'main content' } {
				htmlElement 'div' @{ class = 'host-information' } {
					# htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
					# # Host information
					# htmlElement 'table' @{} {
					# 	htmlElement 'tbody' @{} {
					# 		foreach ($hostDatum in $HostInformation.GetEnumerator()) {
					# 			htmlElement 'tr' @{} {
					# 				htmlElement 'th' @{ scope = 'row' } { $hostDatum.Name }
					# 				htmlElement 'td' @{} { $hostDatum.Value }
					# 			}
					# 		}

					# 	}
					# }
					# Show compliance status
					if ($ComplianceStatus) {
						$sliceColorClass = Get-HtmlClassFromStatus 'True'
						htmlElement 'div' @{ class = 'card' } {
							htmlElement 'h2' @{} { 'Compliance status' }
							htmlElement 'div' @{ class = 'donut-chart chart' } {
								htmlElement 'div' @{ class = "slice one $sliceColorClass" } { }
								htmlElement 'div' @{ class = "slice two $sliceColorClass" } { }
								htmlElement 'div' @{ class = 'chart-center' } { htmlElement 'span' @{} { } }
							}
						}
					}

					$os = [System.Environment]::OSVersion.Platform

					###  Risk Checks ###
					# Quantity
					$TotalAmountOfRules = $completionStatus.TotalCount;
					$AmountOfCompliantRules = 0;
					$AmountOfNonCompliantRules = 0;
					foreach ($value in $StatusValues) {
						if($value -eq 'True'){
							$AmountOfCompliantRules = $completionStatus[$value].Count
						}
						if($value -eq 'False'){
							$AmountOfNonCompliantRules = $completionStatus[$value].Count
						}
					}

					if($os -match "Win32NT" -and $Title -match "Win"){
						# percentage of compliance quantity
						$QuantityCompliance = [math]::round(($AmountOfCompliantRules / $TotalAmountOfRules) * 100,2);	
	
						# Variables, which will be evaluated in report.js
						htmlElement 'div' @{id="AmountOfNonCompliantRules"} {"$($AmountOfNonCompliantRules)"}
						htmlElement 'div' @{id="AmountOfCompliantRules"} {"$($AmountOfCompliantRules)"}
						htmlElement 'div' @{id="TotalAmountOfRules"} {"$($TotalAmountOfRules)"}
						htmlElement 'div' @{id="QuantityCompliance"} {"$($QuantityCompliance)"}
	
						# Severity
						htmlElement 'div' @{id="TotalAmountOfSeverityRules"} {"$($RSReport.RSSeverityReport.AuditInfos.Length)"}
						$AmountOfFailedSeverityRules = 0;
						foreach($rule in $RSReport.RSSeverityReport.AuditInfos){
							if($rule.Status -eq "False"){
								$AmountOfFailedSeverityRules ++;
							}
						}
						htmlElement 'div' @{id="AmountOfFailedSeverityRules"} {"$($AmountOfFailedSeverityRules)"}
					}


					htmlElement 'div' @{id = 'navigationButtons' } {
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'summaryBtn'; onclick = "clickButton('1')" } { "Benchmark Compliance" }
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'foundationDataBtn'; onclick = "clickButton('5')" } { "Foundation Data" }
						if($os -match "Win32NT" -and $Title -match "Win"){
							htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'riskScoreBtn'; onclick = "clickButton('2')" } { "Risk Score" }
						}
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'settingsOverviewBtn'; onclick = "clickButton('4')" } { "Hardening Settings" }
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'referenceBtn'; onclick = "clickButton('3')" } { "About Us" }
					}

					htmlElement 'div' @{class = 'tabContent'; id = 'settingsOverview'} {
						# Table of Contents
						htmlElement 'h1' @{ id = 'toc' } { 'Hardening Settings' }
						htmlElement 'h2' @{} {"Table Of Contents"}
						htmlElement 'p' @{} { 'Click the link(s) below for quick access to a report section.' }
						htmlElement 'ul' @{} {
							foreach ($section in $Sections) { $section | Get-HtmlToc }
						}
						htmlElement 'h2' @{} {"Benchmark Details"}
						# Report Sections
						foreach ($section in $Sections) { $section | Get-HtmlReportSection }
					}


					#This div hides/reveals the whole summary section
					htmlElement 'div' @{class = 'tabContent'; id = 'summary' } {
						# htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
						# Host information
						htmlElement 'h1' @{} { 'Benchmark Compliance' }
						htmlElement 'div' @{style="float: left;"} {
							htmlElement 'p' @{} {
								"Generated by the <i>$ModuleName</i> Module Version <i>$AuditorVersion</i> by FB Pro GmbH. Get it in the <a href=`"$($Settings.PackageLink)`">Audit Test Automation Package</a>."
							}
							htmlElement 'p' @{}{
								"Does your system show low benchmark compliance? Check out our <a href=`"$($Settings.SolutionsLink)`">hardening solutions</a>."
							}
							htmlElement 'p' @{} {
								"Based on:"
								htmlElement 'ul' @{} {
									foreach ($item in $BasedOn) {
										htmlElement 'li' @{} { $item }
									}
								}
								htmlElement 'p' @{} { "This report was generated on $((Get-Date)) on $($HostInformation.Hostname) with ATAPHtmlReport version $ModuleVersion." }
							}
						}
						
						htmlElement 'div' @{id='riskMatrixSummaryArea'}{
							if($os -match "Win32NT" -and $Title -match "Win"){
								htmlElement 'h2' @{id = 'CurrentRiskScore'} {"Current Risk Score on tested System: "}
								htmlElement 'h3' @{} {'For further information, please head to the tab "Risk Score".'}
								htmlElement 'div' @{id ='riskMatrixSummary'}{
									htmlElement 'div' @{id='dotSummaryTab'}{}
									htmlElement 'div' @{id ='severity'} {
										htmlElement 'p' @{id = 'severityArea'}{'Severity'}
									}
									htmlElement 'div' @{id ='quantity'} {
										htmlElement 'p' @{id = 'quantityArea'}{'Quantity'}
									}
									htmlElement 'div' @{id ='severityCritical'}{"Critical"}
									htmlElement 'div' @{id ='severityHigh'}{"High"}
									htmlElement 'div' @{id ='severityMedium'}{"Medium"}
									htmlElement 'div' @{id ='severityLow'}{"Low"}
		
									htmlElement 'div' @{id ='quantityCritical'}{"Critical"}
									htmlElement 'div' @{id ='quantityHigh'}{"High"}
									htmlElement 'div' @{id ='quantityMedium'}{"Medium"}
									htmlElement 'div' @{id ='quantityLow'}{"Low"}
		
									#colored areas
									htmlElement 'div' @{id ='critical_low'}{}
									htmlElement 'div' @{id ='high_low'}{}
									htmlElement 'div' @{id ='medium_low'}{}
									htmlElement 'div' @{id ='low_low'}{}
		
									htmlElement 'div' @{id ='critical_medium'}{}
									htmlElement 'div' @{id ='high_medium'}{}
									htmlElement 'div' @{id ='medium_medium'}{}
									htmlElement 'div' @{id ='low_medium'}{}
		
									htmlElement 'div' @{id ='critical_high'}{}
									htmlElement 'div' @{id ='high_high'}{}
									htmlElement 'div' @{id ='medium_high'}{}
									htmlElement 'div' @{id ='low_high'}{}
		
									htmlElement 'div' @{id ='critical_critical'}{}
									htmlElement 'div' @{id ='high_critical'}{}
									htmlElement 'div' @{id ='medium_critical'}{}
									htmlElement 'div' @{id ='low_critical'}{}
								}
							}
							else{
								htmlElement 'h2' @{id = 'CurrentRiskScore'} {"Current Risk Score on tested System:"}
								htmlElement 'h2' @{id = 'invalidOS'} {"N/A"}
								htmlElement 'h3' @{} {'Risk Score calculation implemented for Microsoft Windows OS for now.'}
								htmlElement 'div' @{id ='riskMatrixSummary'}{
									htmlElement 'div' @{id ='severity'} {
										htmlElement 'p' @{id = 'severityArea'}{'Severity'}
									}
									htmlElement 'div' @{id ='quantity'} {
										htmlElement 'p' @{id = 'quantityArea'}{'Quantity'}
									}
									htmlElement 'div' @{id ='severityCritical'}{"Critical"}
									htmlElement 'div' @{id ='severityHigh'}{"High"}
									htmlElement 'div' @{id ='severityMedium'}{"Medium"}
									htmlElement 'div' @{id ='severityLow'}{"Low"}
		
									htmlElement 'div' @{id ='quantityCritical'}{"Critical"}
									htmlElement 'div' @{id ='quantityHigh'}{"High"}
									htmlElement 'div' @{id ='quantityMedium'}{"Medium"}
									htmlElement 'div' @{id ='quantityLow'}{"Low"}
		
									#colored areas
									htmlElement 'div' @{id ='critical_low'}{}
									htmlElement 'div' @{id ='high_low'}{}
									htmlElement 'div' @{id ='medium_low'}{}
									htmlElement 'div' @{id ='low_low'}{}
		
									htmlElement 'div' @{id ='critical_medium'}{}
									htmlElement 'div' @{id ='high_medium'}{}
									htmlElement 'div' @{id ='medium_medium'}{}
									htmlElement 'div' @{id ='low_medium'}{}
		
									htmlElement 'div' @{id ='critical_high'}{}
									htmlElement 'div' @{id ='high_high'}{}
									htmlElement 'div' @{id ='medium_high'}{}
									htmlElement 'div' @{id ='low_high'}{}
		
									htmlElement 'div' @{id ='critical_critical'}{}
									htmlElement 'div' @{id ='high_critical'}{}
									htmlElement 'div' @{id ='medium_critical'}{}
									htmlElement 'div' @{id ='low_critical'}{}
								}
							}
						}
						# Benchmark compliance
						htmlElement 'h1' @{ style = 'clear:both;' } {}
						htmlElement 'p' @{} {
							'A total of {0} tests have been executed.' -f @(
								$completionStatus.TotalCount
							)
						}

						# Status percentage gauge
						htmlElement 'div' @{ class = 'gauge' } {
							foreach ($value in $StatusValues) {
								$count = $completionStatus[$value].Count
								$htmlClass = Get-HtmlClassFromStatus $value
								$percent = $completionStatus[$value].Percent

								htmlElement 'div' @{
									class = "gauge-meter $htmlClass"
									style = "width: $($percent)%"
									title = "$value $count test(s), $($percent)%"
								} { }
							}
						}
						htmlElement 'ol' @{ class = 'gauge-info' } {
							foreach ($value in $StatusValues) {
								$count = $completionStatus[$value].Count
								$htmlClass = Get-HtmlClassFromStatus $value
								$percent = $completionStatus[$value].Percent

								htmlElement 'li' @{ class = 'gauge-info-item' } {
									htmlElement 'span' @{ class = "auditstatus $htmlClass" } { $value }
									" $count test(s) &#x2259; $($percent)%"
								}
							}

						}
						# Sections
						foreach ($section in $Sections) {
							htmlElement 'h2' @{ style = 'clear:both; margin-top: 0;' } { $section.Title }
							htmlElement 'p' @{} {
								'A total of {0} tests have been executed in section {1}.' -f @(
									$sectionTotalCountHash[$section.Title]
									$section.Title
								)
							}

							# Status percentage gauge for sections
							htmlElement 'div' @{ class = 'gauge' } {
								foreach ($value in $StatusValues) {
									$count = $sectionCountHash[$section.Title + $value + "Count"]
									$htmlClass = Get-HtmlClassFromStatus $value
									$percent = $sectionCountHash[$section.Title + $value + "Percent"]

									htmlElement 'div' @{
										class = "gauge-meter $htmlClass"
										style = "width: $($percent)%"
										title = "$value $count test(s), $($percent)%"
									} { }
								}
							}
							htmlElement 'ol' @{ class = 'gauge-info' } {
								foreach ($value in $StatusValues) {
									$count = $sectionCountHash[$section.Title + $value + "Count"]
									$htmlClass = Get-HtmlClassFromStatus $value
									$percent = $sectionCountHash[$section.Title + $value + "Percent"]

									htmlElement 'li' @{ class = 'gauge-info-item' } {
										htmlElement 'span' @{ class = "auditstatus $htmlClass" } { $value }
										" $count test(s) &#x2259; $($percent)%"
									}
								}
							}
						}
					}

					#Tab: Foundation Data
					$Sections = $FoundationReport.Sections
					htmlElement 'div' @{class = 'tabContent'; id = 'foundationData'}{
						htmlElement 'h1' @{} {"Foundation Data"}
						htmlElement 'div' @{id="systemData"} {
							htmlElement 'h2' @{style="margin-top: 0px;"} {'System information'}
							htmlElement 'table' @{id='summaryTable'} {
								htmlElement 'tbody' @{} {
									$hostInformation = Get-ATAPHostInformation;
									#Hostname
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[4] }
										htmlElement 'td' @{} { $($hostInformation.Values)[4] }
									}
									#Domain Role
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[2] }
										htmlElement 'td' @{} { $($hostInformation.Values)[2] }
									}
									#Operating System
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[3] }
										htmlElement 'td' @{} { $($hostInformation.Values)[3] }
									}
									#Build Number
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[5] }
										htmlElement 'td' @{} { $($hostInformation.Values)[5] }
									}
									#Installation Language
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[1] }
										htmlElement 'td' @{} { $($hostInformation.Values)[1] }
									}
									#Free disk space (GB)
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[0] }
										htmlElement 'td' @{} { $($hostInformation.Values)[0] }
									}
									#Free physical memory (GB)
									htmlElement 'tr' @{} {
										htmlElement 'th' @{ scope = 'row' } { $($hostInformation.Keys)[6] }
										htmlElement 'td' @{} { $($hostInformation.Values)[6] }
									}
								}
							}
						}
						htmlElement 'h2' @{} {"Table Of Contents"}
						htmlElement 'p' @{} { 'Click the link(s) below for quick access to a report section.' }
						htmlElement 'ul' @{} {
							foreach ($section in $Sections) { $section | Get-HtmlToc }
						}
						htmlElement 'h2' @{} {"Security Base Data Details"}
						# Report Sections
						foreach ($section in $Sections) { $section | Get-HtmlReportSection }
					}
					
					
					htmlElement 'div' @{class = 'tabContent'; id = 'riskScore' } {
						htmlElement 'h1'@{} {"Risk Score"}
						htmlElement 'p'@{} {'To get a quick overview of how risky the tested system is, the Risk Score is used. This is made up of the areas "Severity" and "Quantity". The higher risk is used as the overall risk.'}
						htmlElement 'h2' @{id = 'CurrentRiskScoreRS'} {"Current Risk Score on tested System: "}

						htmlElement 'div' @{id ='riskMatrixContainer'}{
							htmlElement 'div' @{id='dotRiskScoreTab'}{}
							htmlElement 'div' @{id ='severity'} {
								htmlElement 'p' @{id = 'severityArea'}{'Severity'}
							}
							htmlElement 'div' @{id ='quantity'} {
								htmlElement 'p' @{id = 'quantityArea'}{'Quantity'}
							}
							htmlElement 'div' @{id ='severityCritical'}{"Critical"}
							htmlElement 'div' @{id ='severityHigh'}{"High"}
							htmlElement 'div' @{id ='severityMedium'}{"Medium"}
							htmlElement 'div' @{id ='severityLow'}{"Low"}

							htmlElement 'div' @{id ='quantityCritical'}{"Critical"}
							htmlElement 'div' @{id ='quantityHigh'}{"High"}
							htmlElement 'div' @{id ='quantityMedium'}{"Medium"}
							htmlElement 'div' @{id ='quantityLow'}{"Low"}

							#colored areas
							htmlElement 'div' @{id ='critical_low'}{}
							htmlElement 'div' @{id ='high_low'}{}
							htmlElement 'div' @{id ='medium_low'}{}
							htmlElement 'div' @{id ='low_low'}{}

							htmlElement 'div' @{id ='critical_medium'}{}
							htmlElement 'div' @{id ='high_medium'}{}
							htmlElement 'div' @{id ='medium_medium'}{}
							htmlElement 'div' @{id ='low_medium'}{}

							htmlElement 'div' @{id ='critical_high'}{}
							htmlElement 'div' @{id ='high_high'}{}
							htmlElement 'div' @{id ='medium_high'}{}
							htmlElement 'div' @{id ='low_high'}{}

							htmlElement 'div' @{id ='critical_critical'}{}
							htmlElement 'div' @{id ='high_critical'}{}
							htmlElement 'div' @{id ='medium_critical'}{}
							htmlElement 'div' @{id ='low_critical'}{}
						}

						htmlElement 'div' @{id='calculationTables'} {
							htmlElement 'h3' @{class = 'calculationTablesText'} {"Risk Score Calculation"}
							htmlElement 'p' @{class = 'calculationTablesText'} {"The calculation of the Risk Score is based on the set of compliant rules at the quantity level and also at the severity level."}
							htmlElement 'table' @{id='quantityTable'}{
								htmlElement 'tr' @{}{
									htmlElement 'th' @{}{'Compliance to Benchmarks (Quantity)'}
									htmlElement 'th' @{}{'Risk Assessment'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'More than 80%'}
									htmlElement 'td' @{}{'Low'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'Between 65% and 80%'}
									htmlElement 'td' @{}{'Medium'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'Between 50% and 65%'}
									htmlElement 'td' @{}{'High'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'Less than 50%'}
									htmlElement 'td' @{}{'Critical'}
								}
							}
	
							htmlElement 'table' @{id='severityTable'}{
								htmlElement 'tr' @{}{
									htmlElement 'th' @{}{'Compliance to Benchmarks (Severity)'}
									htmlElement 'th' @{}{'Risk Assessment'}
								}
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'All critical settings compliant'}
									htmlElement 'td' @{}{'Low'}
								}
								# htmlElement 'tr' @{}{
								# 	htmlElement 'td' @{}{'70% < X < 85%'}
								# 	htmlElement 'td' @{}{'Medium'}
								# }
								# htmlElement 'tr' @{}{
								# 	htmlElement 'td' @{}{'55% < X < 70%'}
								# 	htmlElement 'td' @{}{'High'}
								# }
								htmlElement 'tr' @{}{
									htmlElement 'td' @{}{'1 or more incompliant setting(s)'}
									htmlElement 'td' @{}{'Critical'}
								}
							}
						}


						htmlElement 'div' @{id ="severityCompliance"} {
							htmlElement 'p' @{id="complianceStatus"}{'Table Of Severity Rules'}
							htmlElement 'span' @{class="sectionAction collapseButton"; id="severityComplianceCollapse"} {"-"}
							htmlElement 'table' @{id = 'severityDetails'}{
								htmlElement 'tr' @{}{
									htmlElement 'th' @{}{'Id'}
									htmlElement 'th' @{}{'Task'}
									htmlElement 'th' @{}{'Status'}
									htmlElement 'th' @{}{'Severity'}
								}
								foreach($info in $RSReport.RSSeverityReport.AuditInfos){
									htmlElement 'tr' @{}{
										htmlElement 'td' @{} {"$($info.Id)"}
										htmlElement 'td' @{} {"$($info.Task)"}
										htmlElement 'td' @{} {
											if($info.Status -eq 'False'){
												htmlElement 'span' @{class="severityResultFalse"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'True'){
												htmlElement 'span' @{class="severityResultTrue"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'None'){
												htmlElement 'span' @{class="severityResultNone"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'Warning'){
												htmlElement 'span' @{class="severityResultWarning"}{
													"$($info.Status)"
												}
											}
											elseif($info.Status -eq 'Error'){
												htmlElement 'span' @{class="severityResultError"}{
													"$($info.Status)"
												}
											}
										}
										htmlElement 'td' @{} {
											htmlElement 'p' @{style="margin: 5px auto;"}{"Critical"}
										}
									}
								}
							}
						}

						


						# htmlElement 'h2' @{} {'Number of Successes: ' + $RSReport.RSSeverityReport.ResultTable.Success }
						# htmlElement 'h2' @{} {'Number of Failed: ' + $RSReport.RSSeverityReport.ResultTable.Failed }
						# htmlElement 'h2' @{} {'Endresult of Quality: ' + $RSReport.RSSeverityReport.Endresult }

						# 'Test for AuditInfo: ' + $RSReport.RSSeverityReport.TestTable
					}

					htmlElement 'div' @{class = 'tabContent'; id = 'references'}{
						htmlElement 'h1' @{} {"About us"}
						htmlElement 'h2' @{} {"What makes FB Pro GmbH different"}
						htmlElement 'h3' @{} {"What do we want?"}
						htmlElement 'p' @{} {"Protect our customers' data and information - and thus implicitly contribute to the safe use of the Internet."}
						htmlElement 'h3' @{} {"How do we achieve this? "}
						htmlElement 'p' @{} {"We implement in-depth IT security for our customers. And we always do so in a state-of-the-art, efficient and automated manner."}
						htmlElement 'div'@{id="referencesContainer"}{
							htmlElement 'div'@{}{
								htmlElement 'h2' @{} {"Check out our hardening solution"}
								htmlElement 'a' @{href="https://www.fb-pro.com/enforce-administrator-product/"}{
									htmlElement 'img' @{height="200px"; width="125px"; src=$Settings.EA}{}
								}

							}

							htmlElement 'div'@{}{
								htmlElement 'h2' @{} {"Check out our Audit Report Tool here"}
								htmlElement 'a' @{href="https://www.fb-pro.com/audit-tap-product-information/"}{
									htmlElement 'img' @{height="200px"; width="125px"; src=$Settings.ATAP}{}		
								}
							}				
						}
						htmlElement 'footer' @{} {
							htmlElement 'h3' @{} {"Contact us:"}
							htmlElement 'p' @{} {"FB Pro GmbH"}
							htmlElement 'p' @{} {"Fon: +49 6727 7559039"}
							htmlElement 'p' @{} {"Web: ";htmlElement 'a' @{href="https://www.fb-pro.com/"} {"https://www.fb-pro.com/"}}
							htmlElement 'p' @{} {"Mail: "; htmlElement 'a' @{href="mailto:info@fb-pro.com"} {"info@fb-pro.com"}}

							htmlElement 'h3' @{} {"Can we help you? "}
							htmlElement 'p' @{} {"Do you need support with system hardening?"}
							htmlElement 'p' @{} {"Our team of system hardening experts will be happy to provide you with advice and support."}
							htmlElement 'p' @{} {"Contact us for a no-obligation inquiry!"}
							htmlElement 'a' @{href="mailto:info@fb-pro.com"} {
								htmlElement 'button' @{id="contactUsButton"} {"CONTACT US!"}
							}
						}
					}


				}
			}
			htmlElement 'script' @{ type = 'text/javascript' } { @"
						function collapseHandler(e) {
							var targetSection = e.target.parentElement.parentElement;
							if (targetSection.classList.toggle('collapsed')) {
								e.target.innerText = '+';
							} else {
								e.target.innerText = '-';
							}
						}
						var collapseButtons = document.getElementsByClassName("collapseButton");
						for (var i = 0; i < collapseButtons.length; i++) {
							collapseButtons[i].addEventListener('click', collapseHandler);
						}
"@
			}
		}

		$html = "<!DOCTYPE html><html lang=`"en`">$($head)$($body)</body></html> "

		$head = "
		<head>
			<title>A Meaningful Page Title</title>
			<style>
				body{
					font-family: Cambria, Georgia, serif;
				}
				.header {
					background-color: #c6c9cc;
				}
				.green{
					height: 160px; width: 160px;background-color:#33cca6;
				}
				.red{
					height: 160px; width: 160px;background-color:#cc0000;
				}
				td{
					text-align: center;
				}
				table{
					margin-left: auto;
    				margin-right: auto;
				}
				.riskMatrix{
					margin: auto;
					width: 50%;
				}
				h1{
					text-align: center;
					margin-bottom: 25px;
				}
				h1 p{
					text-align: center;
				}
				td {
					border: 1px solid black;
				}
			</style>
		</head>
		"


		if (Test-Path -Path $path) {
			Write-Warning "$path already exists. $path will be overridden!"
		}

		#Create Report file
		New-Item $path -ItemType File -Force
		$html | Out-File -FilePath $path -Encoding utf8
	}
}