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

function Get-SHA512Hash { 
	Param (
		[Parameter(Mandatory=$true)]
		[string]
		$ClearString
	)
	
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha512')
	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ClearString))
	
	$hashString = [System.BitConverter]::ToString($hash)
	$hashString.Replace('-', '')
}