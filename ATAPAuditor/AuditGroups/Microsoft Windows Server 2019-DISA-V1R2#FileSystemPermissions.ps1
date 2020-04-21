# Common
using namespace System.Security.AccessControl

# [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.PowerShell.Commands.Management')

enum GARights {
	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000
}

# See https://docs.microsoft.com/en-us/windows/desktop/FileIO/file-security-and-access-rights for more information
$GAToFSRMapping = @{
	[GARights]::GENERIC_READ = `
		[FileSystemRights]::ReadAttributes -bor `
		[FileSystemRights]::ReadData -bor `
		[FileSystemRights]::ReadExtendedAttributes -bor `
		[FileSystemRights]::ReadPermissions -bor `
		[FileSystemRights]::Synchronize
	[GARights]::GENERIC_WRITE = `
		[FileSystemRights]::AppendData -bor `
		[FileSystemRights]::WriteAttributes -bor `
		[FileSystemRights]::WriteData -bor `
		[FileSystemRights]::WriteExtendedAttributes -bor `
		[FileSystemRights]::ReadPermissions -bor `
		[FileSystemRights]::Synchronize
	[GARights]::GENERIC_EXECUTE = `
		[FileSystemRights]::ExecuteFile -bor `
		[FileSystemRights]::ReadPermissions -bor `
		[FileSystemRights]::ReadAttributes -bor `
		[FileSystemRights]::Synchronize
	[GARights]::GENERIC_ALL = `
		[FileSystemRights]::FullControl
}

function Convert-FileSystemRights {
	param(
		[Parameter(Mandatory = $true)]
		[FileSystemRights] $OriginalRights
	)

	[FileSystemRights]$MappedRights = [FileSystemRights]::new()

	# map generic access right
	foreach ($GAR in $GAToFSRMapping.Keys) {
		if (($OriginalRights.value__ -band $GAR.value__) -eq $GAR.value__) {
			$MappedRights = $MappedRights -bor $GAToFSRMapping[$GAR]
		}
	}

	# mask standard access rights and object-specific access rights
	$MappedRights = $MappedRights -bor ($OriginalRights -band 0x00FFFFFF)

	return $MappedRights
}

# Tests
[AuditTest] @{
    Id = "WN19-AU-000030"
    Task = "Windows Server 2019 permissions for the Application event log must prevent access by non-privileged accounts."
    Test = {
        $acls = (Get-Acl "${Env:SystemRoot}\System32\winevt\Logs\Application.evtx").Access
        
        Write-Verbose "File system permissions for TARGET: ${Env:SystemRoot}\System32\winevt\Logs\Application.evtx)"
        
        $PrincipalRights = @{
            "BUILTIN\Administrators" = "FullControl"
            "NT AUTHORITY\SYSTEM" = "FullControl"
            "NT SERVICE\EventLog" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [FileSystemRights]$_ }
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
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
    Id = "WN19-AU-000040"
    Task = "Windows Server 2019 permissions for the Security event log must prevent access by non-privileged accounts."
    Test = {
        $acls = (Get-Acl "${Env:SystemRoot}\System32\winevt\Logs\Security.evtx").Access
        
        Write-Verbose "File system permissions for TARGET: ${Env:SystemRoot}\System32\winevt\Logs\Security.evtx)"
        
        $PrincipalRights = @{
            "BUILTIN\Administrators" = "FullControl"
            "NT AUTHORITY\SYSTEM" = "FullControl"
            "NT SERVICE\EventLog" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [FileSystemRights]$_ }
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
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
    Id = "WN19-AU-000050"
    Task = "Windows Server 2019 permissions for the System event log must prevent access by non-privileged accounts."
    Test = {
        $acls = (Get-Acl "${Env:SystemRoot}\System32\winevt\Logs\System.evtx").Access
        
        Write-Verbose "File system permissions for TARGET: ${Env:SystemRoot}\System32\winevt\Logs\System.evtx)"
        
        $PrincipalRights = @{
            "BUILTIN\Administrators" = "FullControl"
            "NT AUTHORITY\SYSTEM" = "FullControl"
            "NT SERVICE\EventLog" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [FileSystemRights]$_ }
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
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
    Id = "WN19-AU-000060"
    Task = "Windows Server 2019 Event Viewer must be protected from unauthorized modification and deletion."
    Test = {
        $acls = (Get-Acl "${Env:SystemRoot}\System32\Eventvwr.exe").Access
        
        Write-Verbose "File system permissions for TARGET: ${Env:SystemRoot}\System32\Eventvwr.exe)"
        
        $PrincipalRights = @{
            "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
            "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
            "BUILTIN\Administrators" = "ReadAndExecute, Synchronize"
            "BUILTIN\Users" = "ReadAndExecute, Synchronize"
            "NT Authority\System" = "ReadAndExecute, Synchronize"
            "NT SERVICE\TrustedInstaller" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [FileSystemRights]$_ }
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
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
    Id = "WN19-00-000140"
    Task = "Windows Server 2019 permissions for the system drive root directory (usually C:\) must conform to minimum requirements."
    Test = {
        $acls = (Get-Acl "${Env:SystemDrive}\").Access
        
        Write-Verbose "File system permissions for TARGET: ${Env:SystemDrive}\)"
        
        $PrincipalRights = @{
            "BUILTIN\Administrators" = "FullControl"
            "BUILTIN\Users" = "ReadAndExecute, Synchronize, CreateFiles, CreateDirectories"
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
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [FileSystemRights]$_ }
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
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
    Id = "WN19-00-000160"
    Task = "Windows Server 2019 permissions for the Windows installation directory must conform to minimum requirements."
    Test = {
        $acls = (Get-Acl "${Env:windir}\").Access
        
        Write-Verbose "File system permissions for TARGET: ${Env:windir}\)"
        
        $PrincipalRights = @{
            "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
            "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
            "BUILTIN\Administrators" = "FullControl, Modify, Synchronize"
            "BUILTIN\Users" = "ReadAndExecute, Synchronize"
            "CREATOR OWNER" = "FullControl"
            "NT Authority\System" = "FullControl, Modify, Synchronize"
            "NT SERVICE\TrustedInstaller" = "FullControl"
        }
        
        $principalsWithTooManyRights = $acls | Where-Object {
            $_.IdentityReference.Value -NotIn $PrincipalRights.Keys
        }
        $principalsWithWrongRights = $acls `
            | Where-Object { $_.IdentityReference.Value -in $PrincipalRights.Keys } `
            | Where-Object {
                # convert string to rights enum
                $referenceRights = $PrincipalRights[$_.IdentityReference.Value] | ForEach-Object { [FileSystemRights]$_ }
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                $mappedRights -notin $referenceRights
            }
        
        if (($principalsWithTooManyRights.Count -gt 0) -or ($principalsWithWrongRights.Count -gt 0)) {
            $messages = @()
            $messages += $principalsWithTooManyRights | ForEach-Object {
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
                "Unexpected '$($_.IdentityReference)' with access '$mappedRights'"
            }
            $messages += $principalsWithWrongRights | ForEach-Object {
                $idKey = $_.IdentityReference.Value
                $mappedRights = Convert-FileSystemRights -OriginalRights $_.FileSystemRights
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
