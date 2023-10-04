#Hash functions will be used for hashing results of report
#Based on SHA-256 and SHA-512

function Get-SHA256Hash { 
	Param (
		[Parameter(Mandatory=$true)]
		[string]
		$ClearString
	)
	
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ClearString))
	
	$hashString = [System.BitConverter]::ToString($hash)
	$hashString.Replace('-', '')
}

function GenerateHashTable{
	Param (
		[Parameter(Mandatory=$true)]
		[Report]
		$report
	)
	
	#hashes for each recommendation
	$hashtable_sha256 = @{}
	foreach($recommendation in $report.Sections){
		$hash_sha256 = ""
		foreach($section in $recommendation.SubSections){
			foreach($test in $section.AuditInfos){
				#hash each test status
				$statusHash_sha256 = (Get-SHA256Hash $test.Status)
				$hash_sha256 += $statusHash_sha256
				#hash combination of tests
				$hash_sha256 = (Get-SHA256Hash $hash_sha256)
			}
		}
		#add final hash to hashlist
		$hashtable_sha256.add($recommendation.Title, $hash_sha256)
	}
	
	#checksum hash for overal check
	$overallHash_sha256 = ""
	foreach($hash in $hashtable_sha256.values){
		#add recommendation hash to overall hash
		$overallHash_sha256 += $hash
		#hash this value again
		try{
			$overallHash_sha256 = Get-SHA256Hash $overallHash_sha256 -ErrorAction Stop
		}
		catch{
			Write-Warning "Hash code for report section couldn't be created."
		}
	}

	$hashtable_sha256.add($report.Title, $overallHash_sha256) 
	return $hashtable_sha256
}