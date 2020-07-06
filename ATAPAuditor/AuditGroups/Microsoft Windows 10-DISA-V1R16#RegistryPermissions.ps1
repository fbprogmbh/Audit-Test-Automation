# Common
using namespace System.Security.AccessControl

# [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.PowerShell.Commands.Management')

enum GARights {
	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000
}

# Non official mappings
$GAToRRMaping = @{
	[GARights]::GENERIC_READ = `
		[RegistryRights]::ReadKey
	[GARights]::GENERIC_WRITE = `
		[RegistryRights]::WriteKey
	[GARights]::GENERIC_ALL = `
		[RegistryRights]::FullControl
}

function Convert-RegistryRights {
	param(
		[Parameter(Mandatory = $true)]
		[RegistryRights] $OriginalRights
	)

	[RegistryRights]$MappedRights = [RegistryRights]::new()

	# map generic access right
	foreach ($GAR in $GAToRRMaping.Keys) {
		if (($OriginalRights.value__ -band $GAR.value__) -eq $GAR.value__) {
			$MappedRights = $MappedRights -bor $GAToRRMaping[$GAR]
		}
	}

	# mask standard access rights and object-specific access rights
	$MappedRights = $MappedRights -bor ($OriginalRights -band 0x00FFFFFF)

	return $MappedRights
}

# Tests
[AuditTest] @{
    Id = "WN10-RG-000005 A"
    Task = "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."
    Test = {
        
        $acls = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SECURITY").Access
        
        Write-Verbose "Registry permissions for target: HKEY_LOCAL_MACHINE\SECURITY)"
        
        $PrincipalRights = @{
            "NT Authority\System" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [RegistryRights]$_ }
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                "Found '$($idKey)' with access '$($mappedRights)' instead of '$($PrincipalRights[$idKey])'"
            }
        
            return @{
                Status = "False"
                Message = $messages -join "; "
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN10-RG-000005 B"
    Task = "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."
    Test = {
        
        $acls = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE").Access
        
        Write-Verbose "Registry permissions for target: HKEY_LOCAL_MACHINE\SOFTWARE)"
        
        $PrincipalRights = @{
            "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" = "ReadKey"
            "BUILTIN\Administrators" = "FullControl"
            "BUILTIN\Users" = "ReadKey"
            "CREATOR OWNER" = "FullControl"
            "NT Authority\System" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [RegistryRights]$_ }
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                "Found '$($idKey)' with access '$($mappedRights)' instead of '$($PrincipalRights[$idKey])'"
            }
        
            return @{
                Status = "False"
                Message = $messages -join "; "
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
[AuditTest] @{
    Id = "WN10-RG-000005 C"
    Task = "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."
    Test = {
        
        $acls = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SYSTEM").Access
        
        Write-Verbose "Registry permissions for target: HKEY_LOCAL_MACHINE\SYSTEM)"
        
        $PrincipalRights = @{
            "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" = "ReadKey"
            "BUILTIN\Administrators" = "FullControl"
            "BUILTIN\Users" = "ReadKey"
            "CREATOR OWNER" = "FullControl"
            "NT Authority\System" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [RegistryRights]$_ }
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-RegistryRights -OriginalRights $_.RegistryRights
                "Found '$($idKey)' with access '$($mappedRights)' instead of '$($PrincipalRights[$idKey])'"
            }
        
            return @{
                Status = "False"
                Message = $messages -join "; "
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant"
        }
    }
}
