<#
BSD 3-Clause License
Copyright (c) 2023, FB Pro GmbH
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

$webIcon = @"
<svg width='20' height='20' viewBox='0 0 25 25'><path d='M10.4425 2.44429C10.0752 3.64002 9.32073 6.25569 8.89915 8.83258C9.99331 9.00921 11.0621 9.12209 12 9.12209C12.9379 9.12209 14.0067 9.00921 15.1009 8.83258C14.6793 6.25569 13.9248 3.64002 13.5575 2.44429C13.0509 2.3624 12.5307 2.31977 12 2.31977C11.4693 2.31977 10.9491 2.3624 10.4425 2.44429ZM15.3337 2.90893C15.737 4.305 16.2958 6.42828 16.6448 8.54737C18.1513 8.23703 19.5727 7.85824 20.605 7.56109C19.4986 5.42102 17.6172 3.74662 15.3337 2.90893ZM21.2129 9.01933C20.1222 9.33683 18.5423 9.76328 16.8594 10.1057C16.9295 10.7564 16.9709 11.3958 16.9709 12C16.9709 12.8816 16.8827 13.8411 16.7445 14.8058C18.759 14.3858 20.6068 13.849 21.5557 13.5575C21.6376 13.0509 21.6802 12.5307 21.6802 12C21.6802 10.959 21.5162 9.95751 21.2129 9.01933ZM21.0911 15.3337C19.9166 15.6729 18.229 16.1219 16.4634 16.4634C16.1219 18.229 15.6729 19.9166 15.3337 21.0911C17.9978 20.1138 20.1138 17.9978 21.0911 15.3337ZM13.5576 21.5557C13.849 20.6068 14.3858 18.759 14.8058 16.7445C13.8411 16.8827 12.8816 16.9709 12 16.9709C11.1184 16.9709 10.1589 16.8827 9.19423 16.7445C9.61421 18.759 10.151 20.6068 10.4425 21.5557C10.9491 21.6376 11.4693 21.6802 12 21.6802C12.5307 21.6802 13.0509 21.6376 13.5576 21.5557ZM8.66629 21.0911C8.32707 19.9166 7.8781 18.229 7.53658 16.4634C5.77099 16.1219 4.08335 15.6729 2.90891 15.3337C3.88622 17.9978 6.00216 20.1138 8.66629 21.0911ZM2.44429 13.5575C3.39316 13.849 5.24101 14.3858 7.25548 14.8058C7.1173 13.8411 7.02907 12.8816 7.02907 12C7.02907 11.3958 7.07048 10.7564 7.14056 10.1057C5.45769 9.76328 3.87779 9.33683 2.78712 9.01933C2.48383 9.95751 2.31977 10.959 2.31977 12C2.31977 12.5307 2.3624 13.0509 2.44429 13.5575ZM3.39504 7.56109C4.42731 7.85824 5.84865 8.23703 7.35522 8.54737C7.70416 6.42827 8.26303 4.305 8.66626 2.90893C6.38282 3.74662 4.50139 5.42102 3.39504 7.56109ZM8.68924 10.3888C8.63137 10.9544 8.59884 11.4968 8.59884 12C8.59884 12.9399 8.71224 14.012 8.88985 15.1102C9.98798 15.2878 11.0601 15.4012 12 15.4012C12.9399 15.4012 14.012 15.2878 15.1102 15.1102C15.2878 14.012 15.4012 12.9399 15.4012 12C15.4012 11.4968 15.3686 10.9544 15.3108 10.3888C14.1776 10.5703 13.0348 10.6919 12 10.6919C10.9652 10.6919 9.82236 10.5703 8.68924 10.3888ZM9.67273 0.991173C10.4243 0.833026 11.2029 0.75 12 0.75C12.7971 0.75 13.5757 0.833026 14.3273 0.991174C18.0108 1.76627 21.0281 4.34097 22.42 7.75174C22.9554 9.06356 23.25 10.4983 23.25 12C23.25 12.7971 23.167 13.5757 23.0088 14.3273C22.0943 18.6736 18.6736 22.0943 14.3273 23.0088C13.5757 23.167 12.7971 23.25 12 23.25C11.2029 23.25 10.4243 23.167 9.67273 23.0088C5.32644 22.0943 1.90572 18.6736 0.991173 14.3273C0.833026 13.5757 0.75 12.7971 0.75 12C0.75 10.4972 1.04509 9.06132 1.58123 7.74866C2.97369 4.33943 5.99026 1.76604 9.67273 0.991173Z' fill='#000000'></path></svg>
"@

$mailIcon = @"
<svg width='20' height='20' viewBox='0 0 25 25'><path fill-rule='evenodd' clip-rule='evenodd' d='M2.54433 5.16792C3.0468 4.46923 3.86451 4 4.8 4H19.2C20.1355 4 20.9532 4.46923 21.4557 5.16792C21.7993 5.64567 22 6.235 22 6.86667V17.1333C22 18.682 20.7804 20 19.2 20H4.8C3.21964 20 2 18.682 2 17.1333V6.86667C2 6.23499 2.20074 5.64567 2.54433 5.16792ZM4.9327 6L11.2598 12.9647C11.6566 13.4015 12.3434 13.4015 12.7402 12.9647L19.0673 6H4.9327ZM20 7.94766L14.2205 14.3096C13.0301 15.6199 10.9699 15.6199 9.77948 14.3096L4 7.94766V17.1333C4 17.6466 4.39214 18 4.8 18H19.2C19.6079 18 20 17.6466 20 17.1333V7.94766Z' fill='#000000'></path></svg>
"@

$phoneIcon = @"
<svg width='20' height='20' viewBox='0 0 25 25'><path d='M16.5562 12.9062L16.1007 13.359C16.1007 13.359 15.0181 14.4355 12.0631 11.4972C9.10812 8.55901 10.1907 7.48257 10.1907 7.48257L10.4775 7.19738C11.1841 6.49484 11.2507 5.36691 10.6342 4.54348L9.37326 2.85908C8.61028 1.83992 7.13596 1.70529 6.26145 2.57483L4.69185 4.13552C4.25823 4.56668 3.96765 5.12559 4.00289 5.74561C4.09304 7.33182 4.81071 10.7447 8.81536 14.7266C13.0621 18.9492 17.0468 19.117 18.6763 18.9651C19.1917 18.9171 19.6399 18.6546 20.0011 18.2954L21.4217 16.883C22.3806 15.9295 22.1102 14.2949 20.8833 13.628L18.9728 12.5894C18.1672 12.1515 17.1858 12.2801 16.5562 12.9062Z' fill='#000000'></path></svg>
"@
<#
icons from https://www.svgrepo.com/

#>
enum AuditInfoStatus {
	True
	False
	Warning
	None
	Error
}

$ScriptRoot = Split-Path -Parent $PSCommandPath

$Settings = Import-PowerShellDataFile -Path "$ScriptRoot\Settings.psd1"
$ModuleVersion = (Import-PowerShellDataFile -Path "$ScriptRoot\ATAPHtmlReport.psd1").ModuleVersion

$StatusValues = 'True', 'False', 'Warning', 'None', 'Error'
$AuditProperties = @{ Name = 'Id' }, @{ Name = 'Task' }, @{ Name = 'Message' }, @{ Name = 'Status' }

#read in all information needed for Mitre Attack Mapping from json file
$global:CISToAttackMappingData = Get-Content -Raw "$PSScriptRoot\resources\CISToAttackMappingData.json" | ConvertFrom-Json

function Get-MitreMappingMetaData {
	<#
	.SYNOPSIS
		Returns the specified metadata to the mapping data 
	.EXAMPLE
		Get-MitreMappingMetaData -Get BasedOn
		Get-MitreMappingMetaData BasedOn
	#>
	param(
		[Parameter(Mandatory)][ValidateSet('Version', 'BasedOn', 'Compatible')]
		[string]$Get
	)
	return $CISToAttackMappingData.'MappingMetaData'.$Get
}

function Get-MitreTacticName {
	<#
	.SYNOPSIS
		Returns the corresponding name for a given Mitre Tactic Id

	.EXAMPLE
		Get-MitreTacticName TacticId 'TA0043'
	#>
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$TacticId
	)

	# $CISToAttackMappingData[AttackTactics][$tacticId] cannot be used because CISToAttackMappingData is a customObject and not a map
	return $CISToAttackMappingData.'AttackTactics'.$tacticId
}

function Get-MitreTactics {
	<#
	.SYNOPSIS
		Returns a List of Mitre Tactic IDs for a given Mitre Technique Id

	.EXAMPLE
		Get-MitreTactics -TechniqueID 'T1133'
	#>
	param(
		[Parameter(Mandatory = $true)]
		$TechniqueID
	)
	return $CISToAttackMappingData.'TechniquesToTactis'.$TechniqueID
}

function Get-MitreTechniqueName {
	<#
	.SYNOPSIS
		Returns the name of a Mitre technique for a given Mitre Technique Id

	.EXAMPLE
		Get-MitreTechniqueName -TechniqueID 'T1133'
	#>
	param(
		[Parameter(Mandatory = $true)]
		$TechniqueID
	)
	return $CISToAttackMappingData.'AttackTechniques'.$TechniqueID.'name'
}

function Test-CompatibleMitreReport {
	<#
	.SYNOPSIS
		Returns if the report is compatible with the current mitre heatmap

	.EXAMPLE
		Test-CompatibleMitreReport -Title "Windows 10 Report" -os "Win32NT"
	#>
	param(
		[Parameter(Mandatory = $true)]
		$Title,
		[Parameter(Mandatory = $true)]
		$os
	)
	if (($Title -eq "Windows 10 Report" -or $Title -eq "Windows 11 Report" -or $Title -eq "Windows Server 2019 Audit Report" -or $Title -eq "Windows Server 2022 Audit Report") -and $os -match "Win32NT") {
		return $true
	}
	else {
		return $false
	}
}

function Get-MitreTechniqueCategories {
	<#
	.SYNOPSIS
		Returns the categories of a Mitre technique in order to apply filters to the report.
		Will return a string that provides all categories stored in the JSON file.

	.EXAMPLE
		Get-MitreTechniqueCategories -TechniqueID 'T1133'
	#>
	param(
		[Parameter(Mandatory = $true)]
		$TechniqueID
	)
	return $CISToAttackMappingData.'AttackTechniques'.$TechniqueID.'categories'
}


class MitreMap {
	[System.Collections.Generic.Dictionary[string, [System.Collections.Generic.Dictionary[string, [System.Collections.Generic.Dictionary[string, AuditInfoStatus]]]]]] $Map

	MitreMap() {
		$this.Map = @{}

		#read in techniques from json-file
		$techniques = $global:CISToAttackMappingData.'AttackTechniques'
		$tactics = $global:CISToAttackMappingData.'AttackTactics'

		foreach ($tacitc in $tactics.psobject.properties.name) {
			$this.Map[$tacitc] = @{}
		}

		#add all techniques and tactics to map
		foreach ($technique in $techniques.psobject.properties.name) {
			$tactics = Get-MitreTactics -TechniqueID $techniques.$technique.'ID'
			foreach ($tactic in $tactics) {
				if ($null -eq $this.Map[$tactic][$techniques.$technique.'ID']) {
					$this.Map[$tactic][$techniques.$technique.'ID'] = @{}
				}
			}
		}
	}

	[void] Add($tactic, $technique, $id, $value) {
		if ($tactic -and $technique -and $id -and $null -ne $value -and $tactic.GetType().Name -eq 'String' -and $technique.GetType().Name -eq 'String' -and $id.GetType().Name -eq 'String' -and $value.GetType().Name -eq 'AuditInfoStatus') {
			if ($null -eq $this.Map[$tactic]) {
				$this.Map[$tactic] = @{}
			}
			if ($null -eq $this.Map[$tactic][$technique]) {
				$this.Map[$tactic][$technique] = @{}
			}
			$this.Map[$tactic][$technique][$id] = $value
		}
		else {
			if (!$tactic) {
				Write-Error -Message 'Could not add value to Map. $tactic is $null or empty' -Category InvalidType
			}
			elseif (!$technique) {
				Write-Error -Message 'Could not add value to Map. $technique is $null or empty' -Category InvalidType
			}
			elseif (!$id) {
				Write-Error -Message 'Could not add value to Map. $id is $null or empty' -Category InvalidType
			}
			elseif ($null -eq $value) {
				Write-Error -Message 'Could not add value to Map. $value is $null' -Category InvalidType
			}
			else {
				Write-Error -Message 'Could not add value to Map' -Category InvalidType
			}
		}
	}

	[void] Print() {
		foreach ($tactic in $this.Map.Keys) {
			Write-Host "$tactic = "
			foreach ($technique in $this.Map[$tactic].Keys) {
				Write-Host "    $technique = "
				foreach ($id in $this.Map[$tactic][$technique].Keys) {
					Write-Host "        $id = $($this.Map[$tactic][$technique][$id])"
				}
			}
		}
	}
}

function get-MitreLink {
	<#
	.SYNOPSIS
		Creates a url which points to the documentation of mitre for a given tactic or technique

    .PARAMETER id
        id of the tactic or technique
		
    .PARAMETER type
		one of 'tactic', 'technique' or 'mitigations'

	.EXAMPLE
		get-MitreLink -type technique -id 'T1548' | Should -Be 'https://attack.mitre.org/techniques/T1548/'
	#>

	param(
		[string] $id,
		[Parameter(Mandatory)][ValidateSet('tactics', 'techniques', 'mitigations')]
		[string]$type
	)

	$url = 'https://attack.mitre.org/'
	$url += "$type/$id/"
	return $url
}

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

function CreateHashTable {
	htmlElement 'div'@{id = "hashTableDiv" } {
		htmlElement 'h2' @{style = "margin-top: 0;" } { "Overall integrity" }
		htmlElement 'p' @{} { "This table outlines integrity checksums for each hardening recommendation. This allows for a quick comparison between reports by simply comparing provided hash values." }
		htmlElement 'table'@{ id = "hashTable" } {
			htmlElement 'thead' @{} {
				htmlElement 'tr' @{} {
					htmlElement 'th'  @{style = "border: 1px solid #d2d2d2; border-collapse: collapse; background-color: lightgray;" } { "Integrity Check for following scopes" }
					htmlElement 'th'  @{style = "border: 1px solid #d2d2d2; border-collapse: collapse; background-color: lightgray;" } { "Checksum (SHA-256)" }
				}
			}
			htmlElement 'tbody' @{id = "hashTableBody" } {
				htmlElement 'tr' @{} {
					#Scope
					htmlElement 'td' @{style = "border: 1px solid #d2d2d2; border-collapse: collapse;vertical-align: middle; " } { "Overall integrity check" }
					#Checksum
					htmlElement 'td' @{style = "border: 1px solid #d2d2d2; border-collapse: collapse; " } {
						htmlElement 'p' @{style = "padding-right: 20px;" } { "$($hashtable_sha256.Get_Item($Title))" }
					}
				}

				$index = 0
				foreach ($section in $Sections) {
					$trColorSwitch += 1
					$background = ""
					if ($index%2 -eq 0) {
						$background = "background-color: #efefef;"
					}else{
						$background = ""
					}
					htmlElement 'tr'  @{style = "border: 1px solid #d2d2d2; border-collapse: collapse;$($background)" } {
						#Scope
						htmlElement 'td'  @{style = "border: 1px solid #d2d2d2; border-collapse:; vertical-align: middle; " } { "$($section.Title)" }
						#Checksum
						htmlElement 'td'  @{style = "border: 1px solid #d2d2d2; border-collapse: collapse; " } {
							htmlElement 'p' @{style = "padding-right: 20px;" } { "$($hashtable_sha256.Get_Item($section.Title))" }
						}
					}
					$index += 1
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

function Merge-CisAuditsToMitreMap {
	<#
	.Synopsis
		Merges the stati of multiple AuditInfos into a 2 dimensional map which can be indexd by the corresponding Mitre tactics an techniques. 
		This allows to simply find out how many Audits where succesfull for a given Mitre technique.
		The result is a MitreMap Object.

    .PARAMETER Audit
        An AuditTest Object containing the Audit results. Multiple can be passed from a pipeline
		
	.EXAMPLE
		$mitreMap = $Sections | 
			Where-Object { $_.Title -eq "CIS Benchmarks" } | 
			ForEach-Object { return $_.SubSections } | 
			ForEach-Object { return $_.AuditInfos } | 
			Merge-CisAuditsToMitreMap
		$mitreMap.Print()
	#>
    
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		$Audit
	)
	Begin {
		$json = $global:CISToAttackMappingData.'CISAttackMapping'
		$mitreMap = [MitreMap]::new()
	}
        
	Process {
		$id = $Audit.Id
		$technique1 = $json.$id.'Technique1'
		$technique2 = $json.$id.'Technique2'

		if ($technique1) {
			foreach ($tactic in Get-MitreTactics -TechniqueID $technique1) {
				if ($tactic) {
					$mitreMap.Add($tactic, $technique1, $id, $Audit.Status)
				}
			}
		}

		if ($technique2) {
			foreach ($tactic in Get-MitreTactics -TechniqueID $technique2) {
				if ($tactic) {
					$mitreMap.Add($tactic, $technique2, $id, $Audit.Status)
				}
			}
		}
	}

	End {
		return [MitreMap] $mitreMap
	}
}

function Get-MitigationsFromFailedTests {
	<#
	.Synopsis
		Returns a map with a array with all Techniques which had a failed test and the Mitigation.

    .PARAMETER Mappings
        Is a mitre Mapping from Get-MitigationsFromFailedTests
		
	.EXAMPLE
		$CISAMitigations = $Mappings.Map | Get-MitigationsFromFailedTests
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		$Mappings
	)
	Begin {
		$json = $global:CISToAttackMappingData.'CISAttackMapping'
		#mapping with Mitigation IDs as keys
		#array with all techniques where the mititgation is in the cisa paper and a tests failed
		#mitigation from the cisa paper
		$CISAMitigationsFromPaper = [ordered]@{
			'M1017' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spear-phishing and social engineering.'
			}
			'M1018' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Manage the creation, modification, use, and permissions associated to user accounts.'
			}
			'M1021' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Restrict or block certain websites.'
			}
			'M1027' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Set and enforce secure password policies for accounts.'
			}
			'M1028' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques.'
			}
			'M1030' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to sensitive systems and information.'
			}
			'M1031' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Configure Network Intrusion Prevention systems to block malicious file signatures and file types at the network boundary.'
			}
			'M1038' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Block execution of code on a system.'
			}
			'M1041' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Use strong encryption mechanisms to protect sensitive data.'
			}
			'M1042' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.'
			}
			'M1057' = @{
				'MitreTechniqueIDs' = @()
				'Mitigation'        = 'Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personally identifiable information (PII), and restrict exfiltration of sensitive data.'
			}
		}
		$CISAMitigations = @()
		$KeysToRemove = @()
	}

	Process {
		foreach ($tactic in $Mappings.Keys) {
			foreach ($technique in $Mappings[$tactic].Keys) {
				$Mappings[$tactic][$technique].Keys | 
				#checks for each technique if there is a failed test
				Where-Object { $Mappings[$tactic][$technique][$_] -eq [AuditInfoStatus]::False } | 
				ForEach-Object {
					#if the mitigation from the failed test is in ihe mitigation from the cisa paper
					if ($null -ne $json.$_.'Mitigation1' -and $CISAMitigationsFromPaper.Keys -contains $json.$_.'Mitigation1') {
						#put the technique in the mapping (no doubles)
						if ($CISAMitigationsFromPaper[$json.$_.'Mitigation1']['MitreTechniqueIDs'] -notcontains $technique) {
							$CISAMitigationsFromPaper[$json.$_.'Mitigation1']['MitreTechniqueIDs'] += $technique
						}
						#put the mitigation in a separate array (no doubles)
						if ($CISAMitigations -notcontains $json.$_.'Mitigation1') {
							$CISAMitigations += $json.$_.'Mitigation1'
						}
					}
					#if the mitigation from the failed test is in ihe mitigation from the cisa paper
					if ($null -ne $json.$_.'Mitigation2' -and $CISAMitigationsFromPaper.Keys -contains $json.$_.'Mitigation2') {
						#put the technique in the mapping (no doubles)
						if ($CISAMitigationsFromPaper[$json.$_.'Mitigation2']['MitreTechniqueIDs'] -notcontains $technique) {
							$CISAMitigationsFromPaper[$json.$_.'Mitigation2']['MitreTechniqueIDs'] += $technique
						}
						#put the mitigation in a separate array (no doubles)
						if ($CISAMitigations -notcontains $json.$_.'Mitigation2') {
							$CISAMitigations += $json.$_.'Mitigation2'
						}
					}
				}
			}
		}
		#write keys which where not in the sperat mitigation array in $KeysToRemove beacause you can't delete in a foreach over the object you want to delete from
		$CISAMitigationsFromPaper.Keys | Where-Object { $CISAMitigations -notcontains $_ } | ForEach-Object { $KeysToRemove += $_ }
		#delete the keys from $CISAMitigation from paper which were not in the sperate mitigation array
		$KeysToRemove | ForEach-Object { $CISAMitigationsFromPaper.Remove($_) }
	}
	End {
		return $CISAMitigationsFromPaper
	}
}

function ConvertTo-HtmlTable {
	<#
	.Synopsis 
		Generates a html table using the mapping keys of the tactics and techniques
		It also adds the links to the table using the function "get-MitreLink"
		and colours the cells
	.Example
		ConvertTo-HtmlTable $Mappings.map

	#>
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		$Mappings
	)

	htmlElement 'table' @{id = 'MITRETable' } {
		htmlElement 'thead' @{id = 'MITREthead' } {
			htmlElement 'tr' @{} {
				foreach ($tactic in $Mappings.Keys) {
					$url = get-MitreLink -type tactics -id $tactic
					$TacticCount = Get-TacticCounter $tactic $Mappings
					htmlElement 'td' @{} {
						$tacticName = Get-MitreTacticName -TacticId $tactic
						$link = htmlElement 'a' @{href = $url; target = "_blank" } { "$tacticName" }
						htmlElement 'p' @{} { $link + "`n" + "$TacticCount/" + $Mappings[$tactic].Count }
					}
				}
			}
		}
		htmlElement 'tbody' @{id = 'MITREtbody' } {
			htmlElement 'tr' @{} {
				foreach ($tactic in $Mappings.Keys) {
					htmlElement 'td' @{} {
						foreach ($technique in $Mappings[$tactic].Keys) {
							$successCounter = 0
							foreach ($id in $Mappings[$tactic][$technique].Keys) {
								if ($Mappings[$tactic][$technique][$id] -eq [AuditInfoStatus]::True) {
									$successCounter++
								}
							}
							$url = get-MitreLink -type techniques -id $technique
							$color = Get-ColorValue $successCounter $Mappings[$tactic][$technique].Count
							$categories = Get-MitreTechniqueCategories -TechniqueID $technique
							htmlElement 'div' @{class = "MITRETechnique $categories"; style = "background-color: $color; background-clip: border-box" } {
								htmlElement 'a' @{href = $url; target = "_blank"; class = "tooltip" } { "$technique" 
									htmlElement 'span' @{class = "tooltiptext" } { Get-MitreTechniqueName -TechniqueID $technique }
								} 
								htmlElement 'span' @{} { ": $successCounter/" + $Mappings[$tactic][$technique].Count }
							}
						}
					}
				}
			}
		}
	}
}

function ConvertTo-HtmlCISA {
	<#
	.Synopsis 
		Generates a html table using the CISA Mitigation, Mitre Mitigation id and failed techniques
	.Example
		ConvertTo-HtmlCISA $CISAMitigations
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		$CISAMitigations
	)
	#create CISA table
	htmlElement 'table' @{id = 'CISATable' } {
		#create table head with the column CISA Mitigation, MITRE Mitigation ID, MITRE Technique IDs
		htmlElement 'thead' @{id = 'CISAthead' } {
			htmlElement 'tr' @{} {
				htmlElement 'th' @{class = 'CISAMitigationIDs' } {
					'ID'
				}
				htmlElement 'th' @{class = 'CISAMitigations' } {
					'Mitigation Description'
				}
				htmlElement 'th' @{class = 'CISAMitreTechniqueIDs' } {
					'caused Audit failures'
				}
			}
		}
		#fill the columns with the information from the $CISAMitigation map
		htmlElement 'tbody' @{id = 'CISAtbody' } {
			$KeyOrder = $CISAMitigations.GetEnumerator() | Sort-Object { $_.Value.MitreTechniqueIDs.Count } -Descending
			$KeyOrder | ForEach-Object {
				htmlElement 'tr' @{} {
					htmlElement 'td' @{class = 'CISAMitigationIDs' } {
						htmlElement 'a' @{href = $(get-MitreLink -type mitigations -id $_.Key); target = "_blank" } {
							$_.Key
						}
					}
					htmlElement 'td' @{class = 'CISAMitigations' } {
						htmlElement 'a' @{} {
							$CISAMitigations[$_.Key]['Mitigation']
						}	
					}
					htmlElement 'td' @{class = 'CISAMitreTechniqueIDs' } {
						$mitigationsList = $CISAMitigations[$_.Key]['MitreTechniqueIDs']
						for ($i = 0; $i -lt $mitigationsList.Length; $i++) {
							htmlElement 'a' @{href = $(get-MitreLink -type techniques -id $mitigationsList[$i]); target = "_blank" } {
								$mitigationsList[$i]
							}
						}
					}
				}
			}
		}
	}
}

function Get-ColorValue {
	<#
	.Synopsis 
		Compares two Integer variables returns true if equal, false if not
	.Example 
		$colorValue = Get-ColorValue $successCounter $Mappings[$tactic][$technique].Count
	#>
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[int]$FirstValue,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[int]$SecondValue
	)

	if ($SecondValue -eq 0) {
		$result = '#a7a7a7'
	}
	else {
		$successPercentage = ($FirstValue / $SecondValue)

		switch ($successPercentage) {
			1 { $result = '#33cca6' }
			{ $_ -le 0.99 } { $result = '#52CC8F' }
			{ $_ -le 0.89 } { $result = '#70CC78' }
			{ $_ -le 0.79 } { $result = '#8FCC61' }
			{ $_ -le 0.69 } { $result = '#ADCC4A' }
			{ $_ -le 0.59 } { $result = '#CCCC33' }
			{ $_ -le 0.49 } { $result = '#CCA329' }
			{ $_ -le 0.39 } { $result = '#CC7A1F' }
			{ $_ -le 0.29 } { $result = '#CC5214' }
			{ $_ -le 0.19 } { $result = '#CC290A' }
			{ $_ -le 0.09 } { $result = '#cc0000' }
		}
	}

	return $result
}

function Get-TacticCounter {
	<#
	.Synopsis 
		Counts the amount of successful techniques per tactic
	.Example 
		$TacticCounter = Get-TacticCounter $tactic $Mappings
	#>
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[object]$tactic,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[object]$Mappings
	)
	$TacticCount = 0
	foreach ($technique in $Mappings[$tactic].Keys) {
		$successCounter = 0
		foreach ($id in $Mappings[$tactic][$technique].Keys) {
			if ($Mappings[$tactic][$technique][$id] -eq [AuditInfoStatus]::True) {
				$successCounter++
			}
			if ($successCounter -eq $Mappings[$tactic][$technique].Count -And $successCounter -gt 0) {
				$TacticCount++
			}
		}    
	}     
	return $TacticCount                      
}

#in the current state the function checks the cis version used for the mapping and used in the Save-ATAPHtmlReport
#but the versions don't match so the function prints the status in the HTML but doesn't block Merge-CisAuditsToMitreMap
function Compare-EqualCISVersions {
	<#
	.Synopsis 
		Returns a boolean, if the $ReportBasedOn and $MitreMappingCompatible Versions can be used together or not.
	.Parameter  $Title
		The Title of the Report
	.Parameter  $ReportBasedOn
		The BasedOn information from the report
	.Parameter  $MitreMappingCompatible
		The Compatible CIS versions of the mitre mapping
	.Example 
		Compare-EqualCISVersions -Title:$Title -ReportBasedOn:$ReportBasedOn -MitreMappingCompatible:$MitreMappingCompatible
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$ReportBasedOn,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$MitreMappingCompatible
	)
	$os = [System.Environment]::OSVersion.Platform

	if (Test-CompatibleMitreReport -Title $Title -os $os) {
		$ReportBasedOn = $ReportBasedOn | Where-Object { $_ -match 'CIS' }
		return $($null -ne $ReportBasedOn -and $null -ne $MitreMappingCompatible -and $($ReportBasedOn -in $MitreMappingCompatible))
	}
	return $false
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
		This function creates the HTML file
	.Parameter Path
		Specifies the relative path to the file in which the report will be stored.
	.Example
		C:\PS> Get-ATAPHtmlReport -Path "MyReport.html"
	#>

	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Output Path for the report
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		# Title of the Report
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Title,

		# Version of ATAPAuditor
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$AuditorVersion,

		# The benchmarks used to create the report
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$BasedOn,

		# Contains all of the selected benchmark audit test results
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[array]
		$Sections,

		# Table Of Severity Rules
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[RSFullReport[]]
		$RSReport,

		# Security Base Data audit test results
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[FoundationReport]
		$FoundationReport,

		# Boolean to enable/disable the Risk Score table
		[Parameter(Mandatory = $false)]
		[switch] $RiskScore,

		# # Unused
		# # This Parameter is commented out on the side of ATAPAuditor (which calls this function to generate the report) due to it being too outdated
		# [Parameter(Mandatory = $false)]
		# [switch] $MITRE,

		# Overall Integrity
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[hashtable]
		$hashtable_sha256,

		# Unused atm but has functionality
		# [switch] $ComplianceStatus,

		# Hardware and Software Information
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
		[SystemInformation]
		$SystemInformation
	)

	process {
		Write-Progress -Activity "Creating HTML report head" -Status "Progress:" -PercentComplete 0
		$allConfigResults = foreach ($section in $Sections) { $section | Select-ConfigAudit | Select-Object -ExpandProperty 'Status' }
		$completionStatus, $sectionTotalCountHash, $sectionCountHash = Get-CompletionStatus -Statuses $allConfigResults -sections $Sections

		# HTML <head> markup

		$head = htmlElement 'head' @{} {
			htmlElement 'meta' @{ charset = 'UTF-8' } { }
			htmlElement 'meta' @{ name = 'viewport'; content = 'width=device-width, initial-scale=1.0' } { }
			htmlElement 'meta' @{ 'http-equiv' = 'X-UA-Compatible'; content = 'ie=edge' } { }
			htmlElement 'title' @{} { "$Title [$(Get-Date)]" }
			htmlElement 'style' @{} {
				$cssPath = $ScriptRoot | Join-path -ChildPath "/report.css"
				Get-Content $cssPath
				Get-OverallComplianceCSS $completionStatus
			}
			htmlElement 'script' @{} {
				$jsPath = $ScriptRoot | Join-path -ChildPath "/report.js"
				Get-Content $jsPath
			}
		}
		#Handles Release Date from Releases; Compares Release with this ATAP Version
		Write-Progress -Activity "Creating HTML report body" -Status "Progress:" -PercentComplete 13
		$body = htmlElement 'body' @{onload = "startConditions()" } {
			# Header
			htmlElement 'div' @{ class = 'header content' } {
				htmlElement 'div' @{ id = "logo" } {
					htmlElement 'a' @{id = "companyLink"; href = "https://www.fb-pro.com/"; target = "_blank" } {
						htmlElement 'h1' @{id = "companyName" } { "FB PRO GMBH" }
						htmlElement 'p' @{id = "companySlogan" } { "System Hardening & Secure Configuration" }
					}
				}
				htmlElement 'div' @{ id = "reportInformation" } {
					htmlElement 'h1' @{} { $Title }
					$datum = "{0:d}. {1} {2} {3:D2}:{4:D2}" -f (Get-Date).Day, (Get-Date).ToString("MMMM"), (Get-Date).Year, (Get-Date).Hour, (Get-Date).Minute					
					htmlElement 'div' @{} { "Generated on $($datum)" }
				}
			}
			# Main section
			htmlElement 'div' @{ class = 'main content' } {
				htmlElement 'div' @{ class = 'host-information' } {
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
					if ($RiskScore) {
						# Quantity
						$TotalAmountOfRules = $completionStatus.TotalCount;
						$AmountOfCompliantRules = 0;
						$AmountOfNonCompliantRules = 0;
						$None_Rules = 0;
						foreach ($value in $StatusValues) {
							if ($value -eq 'True') {
								$AmountOfCompliantRules = $completionStatus[$value].Count
							}
							#exclude Rules, which are set to None, to make an independent calculation between Compliant and non Compliant
							if ($value -eq 'None') {
								$None_Rules = $completionStatus[$value].Count
							}
							if ($value -eq 'False') {
								$AmountOfNonCompliantRules = $completionStatus[$value].Count
							}
						}
						$TotalAmountOfRules = $TotalAmountOfRules - $None_Rules
						if ($os -match "Win32NT" -and $Title -match "Win") {
							# percentage of compliance quantity
							$QuantityCompliance = [math]::round(($AmountOfCompliantRules / $TotalAmountOfRules) * 100, 2);	
							# Variables, which will be evaluated in report.js
							htmlElement 'div' @{id = "AmountOfNonCompliantRules" } { "$($AmountOfNonCompliantRules)" }
							htmlElement 'div' @{id = "AmountOfCompliantRules" } { "$($AmountOfCompliantRules)" }
							htmlElement 'div' @{id = "TotalAmountOfRules" } { "$($TotalAmountOfRules)" }
							htmlElement 'div' @{id = "QuantityCompliance" } { "$($QuantityCompliance)" }
		
							# Severity
							htmlElement 'div' @{id = "TotalAmountOfSeverityRules" } { "$($RSReport.RSSeverityReport.AuditInfos.Length)" }
							$AmountOfFailedSeverityRules = 0;
							foreach ($rule in $RSReport.RSSeverityReport.AuditInfos) {
								if ($rule.Status -eq "False") {
									$AmountOfFailedSeverityRules ++;
								}
							}
							htmlElement 'div' @{id = "AmountOfFailedSeverityRules" } { "$($AmountOfFailedSeverityRules)" }
						}
					}

					htmlElement 'div' @{id = 'navigationButtons' } {
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'summaryBtn'; onclick = "clickButton('1')" } { "Benchmark Compliance" }
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'foundationDataBtn'; onclick = "clickButton('5')" } { "Security Base Data" }
						if ($RiskScore -and ($os -match "Win32NT" -and $Title -match "Win")) {
							htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'riskScoreBtn'; onclick = "clickButton('2')" } { "Risk Score" }
						}
						if ($MITRE) {
							if (Test-CompatibleMitreReport -Title $Title -os $os) {
								htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'MITREBtn'; onclick = "clickButton('6')" } { "MITRE ATT&CK" }
								htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'CISABtn'; onclick = "clickButton('7')" } { "CISA Recommendations" }
							}
						}
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'settingsOverviewBtn'; onclick = "clickButton('4')" } { "Hardening Settings" }
						htmlElement 'button' @{type = 'button'; class = 'navButton'; id = 'referenceBtn'; onclick = "clickButton('3')" } { "About Us" }
					}

					Write-Progress -Activity "Creating settings overview page" -Status "Progress:" -PercentComplete 25
					htmlElement 'div' @{class = 'tabContent'; id = 'settingsOverview' } {
						# Table of Contents
						htmlElement 'h1' @{ id = 'toc' } { 'Hardening Settings' }
						CreateHashTable
						htmlElement 'h2' @{} { "Table Of Contents" }
						htmlElement 'p' @{} { 'Click the link(s) below for quick access to a report section.' }
						htmlElement 'ul' @{} {
							foreach ($section in $Sections) { $section | Get-HtmlToc }
						}
						htmlElement 'h2' @{} { "Benchmark Details" }

						# Report Sections for hardening settings
						foreach ($section in $Sections) {
							$section | Get-HtmlReportSection
						}
					}

					Write-Progress -Activity "Creating summary page" -Status "Progress:" -PercentComplete 38
					#This div hides/reveals the whole summary section
					htmlElement 'div' @{class = 'tabContent'; id = 'summary' } {
						# Host information
						htmlElement 'h1' @{} { 'Benchmark Compliance' }
						htmlElement 'div' @{style = "float: left;" } {
							htmlElement 'p' @{} {
								"Modules:"
								htmlElement 'ul' @{} {
									htmlElement 'div' @{} { "ATAPAuditor version $AuditorVersion" }
									htmlElement 'div' @{} { "ATAPHtmlReport version $ModuleVersion" }
								}
							}
							htmlElement 'p' @{} {
								"Test baseline:"
								htmlElement 'ul' @{} {
									foreach ($item in $BasedOn) {
										htmlElement 'li' @{} { $item }
									}
								}
								htmlElement 'div' @{} {
									"Does your system show low benchmark compliance? Check out our <a href=`"$($Settings.SolutionsLink)`"target=`"_blank`">hardening solutions</a>."
								}
							}
						}
						htmlElement 'div' @{id = 'riskMatrixSummaryArea' } {
							if ($RiskScore -and ($os -match "Win32NT" -and $Title -match "Win")) {
								htmlElement 'h2' @{id = 'CurrentRiskScore' } { "Current Risk Score of tested System: " }
								htmlElement 'h3' @{} { 'For further information, please head to the tab "Risk Score".' }
								htmlElement 'div' @{id = 'riskMatrixSummary' } {
									htmlElement 'div' @{id = 'dotSummaryTab' } {}
									htmlElement 'div' @{id = 'severity' } {
										htmlElement 'p' @{id = 'severityArea' } { 'Severity' }
									}
									htmlElement 'div' @{id = 'quantity' } {
										htmlElement 'p' @{id = 'quantityArea' } { 'Quantity' }
									}
									htmlElement 'div' @{id = 'severityCritical' } { "Critical" }
									htmlElement 'div' @{id = 'severityHigh' } { "High" }
									htmlElement 'div' @{id = 'severityMedium' } { "Medium" }
									htmlElement 'div' @{id = 'severityLow' } { "Low" }
		
									htmlElement 'div' @{id = 'quantityCritical' } { "Critical" }
									htmlElement 'div' @{id = 'quantityHigh' } { "High" }
									htmlElement 'div' @{id = 'quantityMedium' } { "Medium" }
									htmlElement 'div' @{id = 'quantityLow' } { "Low" }
		
									#colored areas
									htmlElement 'div' @{id = 'critical_low' } {}
									htmlElement 'div' @{id = 'high_low' } {}
									htmlElement 'div' @{id = 'medium_low' } {}
									htmlElement 'div' @{id = 'low_low' } {}
		
									htmlElement 'div' @{id = 'critical_medium' } {}
									htmlElement 'div' @{id = 'high_medium' } {}
									htmlElement 'div' @{id = 'medium_medium' } {}
									htmlElement 'div' @{id = 'low_medium' } {}
		
									htmlElement 'div' @{id = 'critical_high' } {}
									htmlElement 'div' @{id = 'high_high' } {}
									htmlElement 'div' @{id = 'medium_high' } {}
									htmlElement 'div' @{id = 'low_high' } {}
		
									htmlElement 'div' @{id = 'critical_critical' } {}
									htmlElement 'div' @{id = 'high_critical' } {}
									htmlElement 'div' @{id = 'medium_critical' } {}
									htmlElement 'div' @{id = 'low_critical' } {}
								}
							}
							else {
								if ($RiskScore) {
									htmlElement 'h2' @{id = 'CurrentRiskScore' } { "Current Risk Score of tested System:" }
									htmlElement 'h2' @{id = 'invalidOS' } { "N/A" }
									htmlElement 'h3' @{} { 'Risk Score calculation implemented for Microsoft Windows OS for now.' }
									htmlElement 'div' @{id = 'riskMatrixSummary' } {
										htmlElement 'div' @{id = 'severity' } {
											htmlElement 'p' @{id = 'severityArea' } { 'Severity' }
										}
										htmlElement 'div' @{id = 'quantity' } {
											htmlElement 'p' @{id = 'quantityArea' } { 'Quantity' }
										}
										htmlElement 'div' @{id = 'severityCritical' } { "Critical" }
										htmlElement 'div' @{id = 'severityHigh' } { "High" }
										htmlElement 'div' @{id = 'severityMedium' } { "Medium" }
										htmlElement 'div' @{id = 'severityLow' } { "Low" }
			
										htmlElement 'div' @{id = 'quantityCritical' } { "Critical" }
										htmlElement 'div' @{id = 'quantityHigh' } { "High" }
										htmlElement 'div' @{id = 'quantityMedium' } { "Medium" }
										htmlElement 'div' @{id = 'quantityLow' } { "Low" }
			
										#colored areas
										htmlElement 'div' @{id = 'critical_low' } {}
										htmlElement 'div' @{id = 'high_low' } {}
										htmlElement 'div' @{id = 'medium_low' } {}
										htmlElement 'div' @{id = 'low_low' } {}
			
										htmlElement 'div' @{id = 'critical_medium' } {}
										htmlElement 'div' @{id = 'high_medium' } {}
										htmlElement 'div' @{id = 'medium_medium' } {}
										htmlElement 'div' @{id = 'low_medium' } {}
			
										htmlElement 'div' @{id = 'critical_high' } {}
										htmlElement 'div' @{id = 'high_high' } {}
										htmlElement 'div' @{id = 'medium_high' } {}
										htmlElement 'div' @{id = 'low_high' } {}
			
										htmlElement 'div' @{id = 'critical_critical' } {}
										htmlElement 'div' @{id = 'high_critical' } {}
										htmlElement 'div' @{id = 'medium_critical' } {}
										htmlElement 'div' @{id = 'low_critical' } {}
									}
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

					Write-Progress -Activity "Creating foundation data page" -Status "Progress:" -PercentComplete 50
					htmlElement 'div' @{class = 'tabContent'; id = 'foundationData' } {
						#Tab: Foundation Data (Only works for Windows OS!)
						htmlElement 'h1' @{} { "Security Base Data" }
						htmlElement 'div' @{id = "testGrid" } {
							htmlElement 'div' @{style = "grid-column-start: 1; grid-column-end: 2; grid-row-start: 1; grid-row-end: 2; font-size: 23px; font-weight: bold; border: 0; padding-top: 0px;" } { "System Information" }
							htmlElement 'div' @{style = "grid-column-start: 1; grid-column-end: 3; grid-row-start: 2; grid-row-end: 3; font-weight: bold; background-color: lightgray;" } { "Software Information" }
							htmlElement 'div' @{style = "grid-column-start: 4; grid-column-end: 6; grid-row-start: 2; grid-row-end: 3; font-weight: bold; background-color: lightgray;" } { "Hardware Information" }

							$systeminfo_array = @(
								@{  colStart = 1; rowstart = 3;
									name =  "Hostname"
									value = $($SystemInformation.SoftwareInformation.Hostname)}
								@{  colStart = 1; rowstart = 4;
									name =  "System Uptime"
									value = $($SystemInformation.SoftwareInformation.SystemUptime)}
								@{  colStart = 1; rowstart = 5;
									name =  "Operating System"
									value = $($SystemInformation.SoftwareInformation.OperatingSystem)}
								@{  colStart = 1; rowstart = 6;
									name =  "Build Number"
									value = $($SystemInformation.SoftwareInformation.BuildNumber)}
								@{  colStart = 1; rowstart = 7;
									name =  "OS Architecture"
									value = $($SystemInformation.SoftwareInformation.OSArchitecture)}
								@{  colStart = 1; rowstart = 8;
									name =  "License Status"
									value = $($SystemInformation.SoftwareInformation.LicenseStatus)}
								@{  colStart = 1; rowstart = 9;
									name =  "Installation Language"
									value = $($SystemInformation.SoftwareInformation.InstallationLanguage)}
								@{  colStart = 1; rowstart = 10;
									name =  "Domain role"
									value = $($SystemInformation.SoftwareInformation.DomainRole)}

								@{  colStart = 4; rowstart = 3;
									name =  "System Manufacturer"
									value = $($SystemInformation.HardwareInformation.SystemManufacturer)}
								@{  colStart = 4; rowstart = 4;
									name =  "System SKU"
									value = $($SystemInformation.HardwareInformation.SystemSKU) }
								@{  colStart = 4; rowstart = 5;
									name =  "System Model"
									value = $($SystemInformation.HardwareInformation.SystemModel)}
								@{  colStart = 4; rowstart = 6;
									name =  "System Serialnumber"
									value = $($SystemInformation.HardwareInformation.SystemSerialnumber)}
								@{  colStart = 4; rowstart = 7;
									name =  "BIOS Version"
									value = $($SystemInformation.HardwareInformation.BIOSVersion)}
								@{  colStart = 4; rowstart = 8;
									name =  "Free disk space (C:)"
									value = $($SystemInformation.HardwareInformation.FreeDiskSpace)}
								@{  colStart = 4; rowstart = 9;
									name =  "Free physical memory"
									value = $($SystemInformation.HardwareInformation.FreePhysicalMemory)}
							)

							for ($i = 0; $i -lt $systeminfo_array.Length; $i++) {
								$grayBackground = ""
								if($i%2 -eq 0){
									$grayBackground =  "background-color: #efefef;" 
								}
								htmlElement 'div' @{style = "grid-column-start: $($systeminfo_array[$i].colStart+0); grid-column-end: $($systeminfo_array[$i].colStart+1); grid-row-start: $($systeminfo_array[$i].rowStart); grid-row-end: $($systeminfo_array[$i].rowStart+1); $($grayBackground) font-weight: bold;" } { "$($systeminfo_array[$i].name)" }
								htmlElement 'div' @{style = "grid-column-start: $($systeminfo_array[$i].colStart+1); grid-column-end: $($systeminfo_array[$i].colStart+2); grid-row-start: $($systeminfo_array[$i].rowStart); grid-row-end: $($systeminfo_array[$i].rowStart+1); $($grayBackground)" } { "$($systeminfo_array[$i].value)" }
							}
						}
						# htmlElement 'div' @{id="systemData"} {
						# }
						if ([System.Environment]::OSVersion.Platform -ne 'Unix') {
							htmlElement 'h2' @{} { "Table Of Contents" }
							htmlElement 'p' @{} { 'Use below links to jump to a specific report section.' }
							htmlElement 'ul' @{} {
								foreach ($section in $FoundationReport.Sections) { $section | Get-HtmlToc }
							}
							htmlElement 'h2' @{} { "Details" }
							# Report Sections
							foreach ($section in $FoundationReport.Sections) { $section | Get-HtmlReportSection }
						}
					}
					
					if ($RiskScore) {
						Write-Progress -Activity "Creating risk score  page" -Status "Progress:" -PercentComplete 63
						htmlElement 'div' @{class = 'tabContent'; id = 'riskScore' } {
							htmlElement 'h1'@{} { "Risk Score" }
							htmlElement 'p'@{} { "The risk score provides a quick overview of how secure the system is configured. This is made up of the areas `"Severity`" and `"Quantity`". The higher risk is used as the overall risk." }
							htmlElement 'h2' @{id = 'CurrentRiskScoreRS' } { "Current Risk Score of tested System: " }
	
							htmlElement 'div' @{id = 'riskMatrixContainer' } {
								htmlElement 'div' @{id = 'dotRiskScoreTab' } {}
								htmlElement 'div' @{id = 'severity' } {
									htmlElement 'p' @{id = 'severityArea' } { 'Severity' }
								}
								htmlElement 'div' @{id = 'quantity' } {
									htmlElement 'p' @{id = 'quantityArea' } { 'Quantity' }
								}
								htmlElement 'div' @{id = 'severityCritical' } { "Critical" }
								htmlElement 'div' @{id = 'severityHigh' } { "High" }
								htmlElement 'div' @{id = 'severityMedium' } { "Medium" }
								htmlElement 'div' @{id = 'severityLow' } { "Low" }
	
								htmlElement 'div' @{id = 'quantityCritical' } { "Critical" }
								htmlElement 'div' @{id = 'quantityHigh' } { "High" }
								htmlElement 'div' @{id = 'quantityMedium' } { "Medium" }
								htmlElement 'div' @{id = 'quantityLow' } { "Low" }
	
								#colored areas
								htmlElement 'div' @{id = 'critical_low' } {}
								htmlElement 'div' @{id = 'high_low' } {}
								htmlElement 'div' @{id = 'medium_low' } {}
								htmlElement 'div' @{id = 'low_low' } {}
	
								htmlElement 'div' @{id = 'critical_medium' } {}
								htmlElement 'div' @{id = 'high_medium' } {}
								htmlElement 'div' @{id = 'medium_medium' } {}
								htmlElement 'div' @{id = 'low_medium' } {}
	
								htmlElement 'div' @{id = 'critical_high' } {}
								htmlElement 'div' @{id = 'high_high' } {}
								htmlElement 'div' @{id = 'medium_high' } {}
								htmlElement 'div' @{id = 'low_high' } {}
	
								htmlElement 'div' @{id = 'critical_critical' } {}
								htmlElement 'div' @{id = 'high_critical' } {}
								htmlElement 'div' @{id = 'medium_critical' } {}
								htmlElement 'div' @{id = 'low_critical' } {}
							}
	
							htmlElement 'div' @{id = 'calculationTables' } {
								htmlElement 'h3' @{class = 'calculationTablesText' } { "Risk Score Calculation" }
								htmlElement 'p' @{class = 'calculationTablesText' } { "Risk Score calculation is based on the quantitative amount of compliant rules and the severity of incompliant checks." }
								htmlElement 'p' @{class = 'calculationTablesText' } { "Note: Quantity is calculated by dividing all compliant rules with the total number (minus none-compliant) of checks." }
								htmlElement 'table' @{id = 'quantityTable' } {
									htmlElement 'tr' @{} {
										htmlElement 'th' @{} { 'Compliance to Benchmarks (Quantity)' }
										htmlElement 'th' @{} { 'Risk Assessment' }
									}
									htmlElement 'tr' @{} {
										htmlElement 'td' @{} { 'More than 80%' }
										htmlElement 'td' @{} { 'Low' }
									}
									htmlElement 'tr' @{} {
										htmlElement 'td' @{} { 'Between 65% and 80%' }
										htmlElement 'td' @{} { 'Medium' }
									}
									htmlElement 'tr' @{} {
										htmlElement 'td' @{} { 'Between 50% and 65%' }
										htmlElement 'td' @{} { 'High' }
									}
									htmlElement 'tr' @{} {
										htmlElement 'td' @{} { 'Less than 50%' }
										htmlElement 'td' @{} { 'Critical' }
									}
								}
		
								htmlElement 'table' @{id = 'severityTable' } {
									htmlElement 'tr' @{} {
										htmlElement 'th' @{} { 'Compliance to Benchmarks (Severity)' }
										htmlElement 'th' @{} { 'Risk Assessment' }
									}
									htmlElement 'tr' @{} {
										htmlElement 'td' @{} { 'All critical settings compliant' }
										htmlElement 'td' @{} { 'Low' }
									}
									htmlElement 'tr' @{} {
										htmlElement 'td' @{} { '1 or more incompliant setting(s)' }
										htmlElement 'td' @{} { 'Critical' }
									}
								}
							}
	
	
							htmlElement 'div' @{id = "severityCompliance" } {
								htmlElement 'h2' @{} { 'Details' }
								htmlElement 'p' @{id = "complianceStatus" } { 'Table Of Severity Rules' }
								htmlElement 'span' @{class = "sectionAction collapseButton"; id = "severityComplianceCollapse" } { "-" }
								htmlElement 'table' @{id = 'severityDetails' } {
									htmlElement 'tr' @{} {
										htmlElement 'th' @{} { 'Id' }
										htmlElement 'th' @{} { 'Task' }
										htmlElement 'th' @{} { 'Status' }
										htmlElement 'th' @{} { 'Severity' }
									}
									foreach ($info in $RSReport.RSSeverityReport.AuditInfos) {
										htmlElement 'tr' @{} {
											htmlElement 'td' @{} { "$($info.Id)" }
											htmlElement 'td' @{} { "$($info.Task)" }
											htmlElement 'td' @{} {
												if ($info.Status -eq 'False') {
													htmlElement 'span' @{class = "severityResultFalse" } {
														"$($info.Status)"
													}
												}
												elseif ($info.Status -eq 'True') {
													htmlElement 'span' @{class = "severityResultTrue" } {
														"$($info.Status)"
													}
												}
												elseif ($info.Status -eq 'None') {
													htmlElement 'span' @{class = "severityResultNone" } {
														"$($info.Status)"
													}
												}
												elseif ($info.Status -eq 'Warning') {
													htmlElement 'span' @{class = "severityResultWarning" } {
														"$($info.Status)"
													}
												}
												elseif ($info.Status -eq 'Error') {
													htmlElement 'span' @{class = "severityResultError" } {
														"$($info.Status)"
													}
												}
											}
											htmlElement 'td' @{} {
												htmlElement 'p' @{style = "margin: 5px auto;" } { "Critical" }
											}
										}
									}
								}
							}
							# 'Test for AuditInfo: ' + $RSReport.RSSeverityReport.TestTable
						}
					}

					if ($MITRE) {
						if (Test-CompatibleMitreReport -Title $Title -os $os) {
							Write-Progress -Activity "Creating mitre heatmap page" -Status "Progress:" -PercentComplete 75
							
							$Mappings = $Sections | 
							Where-Object { $_.Title -eq "CIS Benchmarks" -or $_.Title -eq "CIS Stand-alone Benchmarks" } | 
							ForEach-Object { return $_.SubSections } | 
							ForEach-Object { return $_.AuditInfos } | 
							Merge-CisAuditsToMitreMap
							
							htmlElement 'div' @{class = 'tabContent'; id = 'MITRE' } {
								htmlElement 'h1'@{} { "MITRE ATT&CK" }
								htmlElement 'p'@{} { 'To get a quick overview of how good your system is hardened in terms of the MITRE ATT&CK Framework we made a heatmap.' }
								htmlElement 'p' @{id = 'Tip' } { 'Tip: Hover over the MITRE IDs to get a quick information to each Technique' }
								htmlElement 'h2'@{} { "Version of CIS in MITRE Mapping and tests" }
								htmlElement 'p'@{} { $(Get-MitreMappingMetaData Version) + "." }
								htmlElement 'p'@{} { "Based on: " + $(Get-MitreMappingMetaData BasedOn) + "." }
								$MitreMappingCompatible = Get-MitreMappingMetaData Compatible
								if (-not $(Compare-EqualCISVersions -Title:$Title -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible)) {
									Write-Warning "The CIS version used for the MITRE mapping doesn't match with the CIS version used for the tests. The Mitre heatmap will still be generated but might contain false information."
									htmlElement 'p'@{style = "font-size: 1.2em; color: red;" } { "The CIS version used for the MITRE mapping doesn't match with the CIS version used for the tests." }
								}
								htmlElement 'h2' @{} { 'Explanation of the cell colors' }

								htmlElement 'div' @{class = 'square-container' } {
									$color_S = Get-ColorValue 1 1
									htmlElement 'div' @{class = 'square'; style = "background: $color_S" } {} 
									htmlElement 'div'@{} { '= 100% of the tests were successful, the system is protected in the best possible way' }
								}
								
								htmlElement 'div' @{class = 'square-container' } {
									$color_F = Get-ColorValue 0 1
									htmlElement 'div' @{class = 'square'; style = "background: $color_F" } {}
									htmlElement 'div'@{} { '= 0% of the tests were successful, consider looking into possibilities to harden your system regarding this tactic / technique' }
								}
								
								htmlElement 'div' @{class = 'square-container' } {
									$color_S = Get-ColorValue 1 1
									$color_F = Get-ColorValue 0 1
									htmlElement 'div' @{class = 'square'; style = "background: linear-gradient($color_S,$color_F)" } {}
									htmlElement 'div'@{} { '= the color gradient moves in 10% steps. The greener the cell, the more tests were successful' }
								}
								
								htmlElement 'div' @{class = 'square-container' } {
									$color_E = Get-ColorValue 1 0
									htmlElement 'div' @{class = 'square'; style = "background: $color_E" } {}
									htmlElement 'div'@{} { '= No tests available yet' }
								}
								
								htmlElement 'h2' @{} { "Filters" }

								htmlElement 'label' @{} {
									"Hide techniques that are performed outside of enterprise defenses and controls:"
									htmlElement 'input' @{type = "checkbox"; id = "mitreFilterCheckbox"; onchange = "hideMitreTechniques(this, '.orgMeasure')" } {}
								}

								htmlElement 'p' @{} {
									htmlElement 'label' @{} {
										"Hide techniques that cannot be easily mitigated with preventive controls:"
										htmlElement 'input' @{type = "checkbox"; id = "noEasyMitigationCheckbox"; onchange = "hideMitreTechniques(this, '.noEasyMitigation')" } {}
									}
								}

								htmlElement 'p' @{} {
									htmlElement 'label' @{} {
										"Display only techniques related to the attack vector 'E-Mail'"
										htmlElement 'input' @{type = "checkbox"; id = "mailFilterCheckbox"; onchange = "hideMitreTechniques(this, '.MITRETechnique:not(.mailVector)')" } {}
									}
								}

								htmlElement 'h2' @{} { "Current ATT&CK heatmap on tested System" }

								ConvertTo-HtmlTable $Mappings.map
							}
							htmlElement 'div' @{class = 'tabContent'; id = 'CISA' } {
								htmlElement 'h1'@{} { "CISA Recommendations" }
								htmlElement 'p' @{} {
									"This table shows the top mitigations, that help against the most used attack techniques. 
									Implementing these mitigations has the biggest impact on the overall security of the system. 
									The table is based on the Information from CISAs " 
									htmlElement 'a' @{href = "https://www.cisa.gov/sites/default/files/publications/RVA_INFOGRAPHIC_508c.pdf"; target = "_blank" } {
										"Risk and Vulnerability Assessment (RVA) mapped to the MITRE ATT&CK Framework."
									}
									"Additionally, the table is sorted based on the number of audits that failed but could be prevented by a given mitigation."
								}
								htmlElement 'p'@{} { 'The table presents three columns: The first column lists the mitigations recommended by CISA, the second column contains the corresponding mitigation IDs from MITRE, and the third column shows the techniques that have at least one CISA-recommended mitigation and have experienced at least one test failure.' }
								htmlElement 'h1'@{} { 'Mitigation for top techniques' }

								$CISAMitigations = $Mappings.Map | Get-MitigationsFromFailedTests
								ConvertTo-HtmlCISA $CISAMitigations
							}
						}
						else {
							Write-Warning "Mitre Heatmap can only be used on a Windows System together with `"Microsoft Windows 10`", `"Microsoft Windows 10 Stand-alone`", `"Microsoft Windows 11`", `"Microsoft Windows 11 Stand-alone`", `"Microsoft Windows Server 2019`" or `"Microsoft Windows Server 2022`". The Mitre Heatmap will not be generated"
						}
					}

					Write-Progress -Activity "Creating references page" -Status "Progress:" -PercentComplete 83
					htmlElement 'div' @{class = 'tabContent'; id = 'references' } {

						
						htmlElement 'h1' @{} { "About us" }
						
						# Flex-Container
						htmlElement 'div' @{class = 'columns-container' } {
							
							# LEFT COLUMN
							htmlElement 'div' @{class = 'left-column' } {
								htmlElement 'h2' @{} { "What makes FB Pro GmbH different" }

								htmlElement 'h3' @{} { "What do we want?" }
								htmlElement 'p' @{} {
									"Protect our customers' data and information - and thus implicitly contribute to the safe use of the Internet."
								}

								htmlElement 'h3' @{} { "How do we achieve this?" }
								htmlElement 'p' @{} {
									"We implement in-depth IT security for our customers. Our approach always focuses on state-of-the-art technology that is highly efficient and automated."
								}

								htmlElement 'h3' @{} { "What is system hardening?" }
								htmlElement 'p' @{} { "The following video provides concise answers to questions such as:" }
								htmlElement 'ul' @{class = 'hardening-ul' } {
									htmlElement 'li' @{} { "What does System Hardening mean?" }
									htmlElement 'li' @{} { "How does System Hardening work?" }
									htmlElement 'li' @{} { "Why is System Hardening so important?" }
								}
								htmlElement 'p' @{style = 'font-style: italic;' } {
									"If you cannot see the video below, please check your browser settings to allow loading content from external sources.
									Alternatively, you can watch the video "
									htmlElement 'a' @{href = "https://www.youtube.com/watch?v=jbI19FwnBKY"; target = "_blank" } { "here"
									}
								}
									
								htmlElement 'div' @{class = 'video-wrapper' } {
									htmlElement 'iframe' @{
										src             = "https://www.youtube-nocookie.com/embed/jbI19FwnBKY?si=_p7JoaNAkxRB0HIL"
										title           = "YouTube video player"
										frameborder     = "0"
										allow           = "accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
										referrerpolicy  = "strict-origin-when-cross-origin"
										allowfullscreen = ""
									} {}
								}
							}

							# RIGHT COLUMN
							htmlElement 'div' @{class = 'right-column' } {

								htmlElement 'h2' @{} { "Check out our solutions" }
								# Flex-Container for the products
								htmlElement 'div' @{class = 'product-block' } {
									# Flex-Container for each product item (order in column and centered)
									htmlElement 'div' @{class = 'product-item ' } {
										htmlElement 'h3'@{} { "Enforce Administrator" }
										htmlElement 'a' @{href = "https://www.fb-pro.com/enforce-administrator-product/"; target = "_blank" } {
											htmlElement 'img' @{
												src   = $Settings.EA
												alt   = "Enforce Administrator"
												style = "width: 125px; height: 200px;"
											} {}
										}
									}
									htmlElement 'div' @{class = 'product-item ' } {
										htmlElement 'h3'@{} { "EnforceTAP" }
										htmlElement 'a' @{href = "https://www.fb-pro.com/enforce-suite/"; target = "_blank" } {
											htmlElement 'img' @{
												src   = $Settings.EnforceTAP
												alt   = "EnforceTAP"
												style = "width: 125px; height: 200px;"
											} {}
										}
									}
									htmlElement 'div' @{ class = 'product-item' } {
										htmlElement 'h3' @{} { " AuditTAP" }
										htmlElement 'a' @{href = "https://www.fb-pro.com/audit-tap-product-information/"; target = "_blank" } {
											htmlElement 'img' @{
												src   = $Settings.ATAP 
												alt   = "Audit Test Automation Package"
												style = "width: 125px; height: 200px;"
											} {}		
										}
									}		
								}

								htmlElement 'div' @{class = 'contact-block' } {
									htmlElement 'div' @{class = 'contact-flex' } {
										#Flex-Container for FB Pro Contact information (order in one column, centered)
										htmlElement 'div' @{ class = 'contact-item'; style = 'white-space: nowrap;' } {
											
											htmlElement 'h3' @{} { "Contact information" }
											htmlElement 'p' @{} { "FB Pro GmbH" }
											htmlElement 'p' @{} { htmlElement 'span' @{style = "display:inline-block; vertical-align:middle; position:relative; top:2px; margin-right:5px;" } { $phoneIcon }; "+49 6727 7559039" }
											htmlElement 'p' @{} {
												htmlElement 'span' @{style = "display:inline-block; vertical-align:middle; position:relative; top:2px; margin-right:5px;" } { $webIcon }; htmlElement 'a' @{href = "https://www.fb-pro.com/" ; target = "_blank" } { "https://www.fb-pro.com/" }
											}
											htmlElement 'p' @{} {
												htmlElement 'span' @{style = "display:inline-block; vertical-align:middle; position:relative; top:2px; margin-right:5px;" } { $mailIcon }; htmlElement 'a' @{href = "mailto:info@fb-pro.com" } { "info@fb-pro.com" }
											}
										}
										htmlElement 'div' @{class = 'contact-item' } {
											htmlElement 'h3' @{} { "Can we help you?" }
											htmlElement 'p' @{} { "Do you need support with system hardening?" }
											htmlElement 'p' @{} { "Our team of system hardening experts will be happy to assist you." }
											htmlElement 'p' @{} { " Contact us for a no-obligation inquiry!" }
										}
									}

									htmlElement 'div' @{ class = "contact-buttons" } {
										htmlElement 'a' @{href = "mailto:info@fb-pro.com" } {
											htmlElement 'button' @{id = "contactUsButton"; class = "button-base" } { "CONTACT US!" }
										}
										htmlElement 'a' @{href = "https://github.com/fbprogmbh/Hardening-Audit-Tool-AuditTAP-Audit-Test-Automation-Package"; target = "_blank" } {
											htmlElement 'button' @{id = "githubButton"; class = "button-base" } {
												"AuditTAP on GitHub"
											}
										}
									}
								}
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
	
		#If Path exists to a folder exists
		if ($Path -match ".html") {
			$name = Split-Path -Path $Path -Leaf
			$Path = Split-Path -Path $Path -Parent
			New-Item -Path $Path -Name $name -ItemType File -Value $html -Force 

		}
		else {
			$Title = $Title -replace " Audit Report", ""
			$auditReport += "$($Title)_$(Get-Date -UFormat %Y%m%d_%H%M%S).html"
			New-Item -Path $Path -Name $auditReport -ItemType File -Value $html -Force 
		}
		if ([System.Environment]::OSVersion.Platform -eq 'Unix') {
			# $shellPath = $Path"/"$name
			# bash -c "chmod o+r $($shellPath)"
			# Write-Host $shellPath
		}
		#Create Report file
		#$html | Out-File -FilePath $auditReport -Encoding utf8
	}
}
