using namespace Microsoft.Web.Administration
using namespace Microsoft.Windows.ServerManager.Commands
Import-Module IISAdministration -Force

#region Helper Functions
$MESSAGE_ALLGOOD = "All Good"

function Get-IISSiteVirtualPaths {

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site,

		[switch] $AllVirtualDirectories
	)

	process {
		foreach ($App in $Site.Applications) {
			Write-Output ($App.Path)

			if ($AllVirtualDirectories) {
				foreach ($VirtualDirectory in $App.VirtualDirectories) {
					if ($VirtualDirectory.Path -ne "/") {
						$AppPath = if ($App.Path -ne "/") {
							$App.Path
						}
						else {
							""
						}
						Write-Output ($AppPath + $VirtualDirectory.Path)
					}
				}
			}
		}
	}
}

function Get-IISModules {
	(Get-IISConfigSection -SectionPath "system.webServer/modules").GetCollection() `
		| Get-IISConfigAttributeValue -AttributeName "Name"
}
#endregion

#region 1 Basic Configuration
#
# This section contains basic Web server-level recommendations

# 1.1
function Test-IISVirtualDirPartition {
	<#
	.Synopsis
		Ensure web content is on non-system partition
	.Description
		Web resources published through IIS are mapped, via Virtual Directories, to physical locations on disk. It is recommended to map all Virtual Directories to a non-system disk volume.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		$SystemDrive = [system.environment]::getenvironmentvariable("SystemDrive")
		$Path = $Site.Applications["/"].VirtualDirectories["/"].PhysicalPath

		if ($Path.StartsWith("%SystemDrive%") -or $Path.StartsWith($SystemDrive)) {
			$message = "Web content is on system partition"
			$audit = "False"
		}

		@{
			Id      = "1.1"
			Task    = "Ensure web content is on non-system partition"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 1.2
function Test-IISHostHeaders {
	<#
	.Synopsis
		Ensure 'host headers' are on all sites
	.DESCRIPTION
 		Host headers provide the ability to host multiple websites on the same IP address and port. It is recommended that host headers be configured for all sites. Wildcard host headers are now supported.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		[array]$Bindings = $Site.Bindings | Where-Object { [string]::IsNullOrEmpty($_.Host) }

		if ($Bindings.Count -gt 0) {
			$message = "The following bindings do no specify a host: " + ($Bindings.bindingInformation -join ", ")
			$audit = "False"
		}

		@{
			Id      = "1.2"
			Task    = "Ensure 'host headers' is set"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 1.3
function Test-IISDirectoryBrowsing {
	<#
	.Synopsis
		Ensure 'directory browsing' is set to disabled
	.Description
		Directory browsing allows the contents of a directory to be displayed upon request from a web client. If directory browsing is enabled for a directory in Internet Information Services, users receive a page that lists the contents of the directory when the following two conditions are met:

			1. No specific file is requested in the URL
			2. The Default Documents feature is disabled in IIS, or if it is enabled, IIS is unable to locate a file in the directory that matches a name specified in the IIS default document list

		It is recommended that directory browsing be disabled.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup){
		# Ensure directory browsing is installed
			if ((Get-WindowsFeature Web-Dir-Browsing).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/directoryBrowse"
				$section = $Configuration.GetSection($path)

				$Enabled = $section | Get-IISConfigAttributeValue -AttributeName "enabled"

				if ($Enabled -eq $true) {
					$message = "Directory Browsing is enabled"
					$audit = "False"
				}
				elseif ($null -eq $Enabled) {
					$message = "Directory Browsing not explicit set to false"
					$audit = "Warning"
				}
			}
		}
		else{
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}
		@{
			Id      = "1.3"
			Task    = "Ensure 'directory browsing' is set to disabled"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 1.4
function Test-IISAppPoolIdentity {
	<#
	.Synopsis
		Ensure 'application pool identity' is configured for all application pools
	.Description
		Application Pool Identities are the actual users/authorities that will run the worker process - w3wp.exe. Assigning the correct user authority will help ensure that applications can function properly, while not giving overly permissive permissions on the system. These identities can further be used in ACLs to protect system content. It is recommended that each Application Pool run under a unique identity.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ApplicationPool] $AppPool
	)

	begin {
		$AppPoolUsers = (Get-IISAppPool).ProcessModel.Username | Group-Object -NoElement
	}

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		if ($AppPool.ProcessModel.IdentityType -eq [ProcessModelIdentityType]::SpecificUser) {
			# Get the username of the specific application
			$Username = $AppPool.ProcessModel.UserName

			if (($AppPoolUsers | Where-Object Name -eq $Username).Count -gt 1) {
				$message = "ApplicationPoolIdentity $Username is used for more than one ApplicationPool"
				$audit = "False"
			}
			else {
				$message = "Unique ApplicationPoolIdentity $Username is used."
				$audit = "True"
			}
		}
		elseif ($AppPool.ProcessModel.IdentityType -ne [ProcessModelIdentityType]::ApplicationPoolIdentity)	{
			$message = "ApplicationPoolIdentity is not set"
			$audit = "False"
		}

		@{
			Id      = "1.4"
			Task    = "Ensure 'application pool identity' is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 1.5
function Test-IISUniqueSiteAppPool {
	<#
	.Synopsis
		Ensure 'unique application pools' is set for sites
	.Description
		IIS introduced a new security feature called Application Pool Identities that allows Application Pools to be run under unique accounts without the need to create and manage local or domain accounts. It is recommended that all Sites run under unique, dedicated Application Pools.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$Apps = foreach ($Site in (Get-IISSite)) {
		foreach ($App in $Site.Applications) {
			New-Object -TypeName PSObject -Property @{
				VirtualPath         = $Site.name + $App.path
				ApplicationPoolName = $App.ApplicationPoolName
			}
		}
	}

	[array]$Findings = $Apps `
		| Group-Object -Property ApplicationPoolName `
		| Where-Object -Property Count -gt 1

	if ($Findings.Count -gt 0) {
		$message = "Following sites do not have unique Application Pools: " + ($findings.Group.VirtualPath -join ", ")
		$audit = "False"
	}

	@{
		Id      = "1.5"
		Task    = "Ensure 'unique application pools' is set for sites"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 1.6
function Test-IISAnonymouseUserIdentity {
	<#
	.Synopsis
		Ensure 'application pool identity' is configured for anonymous user identity
	.Description
		To achieve isolation in IIS, application pools can be run as separate identities. IIS can be configured to automatically use the application pool identity if no anonymous user account is configured for a Web site. This can greatly reduce the number of accounts needed for Web sites and make management of the accounts easier. It is recommended the Application Pool Identity be set as the Anonymous User Identity.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup){
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.webServer/security/authentication/anonymousAuthentication"
			$section = $Configuration.GetSection($path)

			$username = $section | Get-IISConfigAttributeValue -AttributeName "userName"

			if ($username -ne "") {
				$message = "Username is set to: $username"
				$audit = "False"
			}
		}
		else{
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "1.6"
			Task    = "Ensure 'application pool identity' is configured for anonymous user identity"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

#endregion

#region 2 Configure Authentication and Authorization
#
# This section contains recommendations around the different layers of authentication in IIS.

# 2.1
function Test-IISGlobalAuthorization {
	<#
	.Synopsis
		Ensure 'global authorization rule' is set to restrict access
	.Description
		IIS introduced URL Authorization, which allows the addition of Authorization rules to the actual URL, instead of the underlying file system resource, as a way to protect it. Authorization rules can be configured at the server, web site, folder (including Virtual Directories), or file level. The native URL Authorization module applies to all requests, whether they are .NET managed or other types of files (e.g. static files or ASP files). It is recommended that URL Authorization be configured to only grant access to the necessary security principals.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			# Ensure URL Authentication is installed
			if ((Get-WindowsFeature Web-Url-Auth).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/authorization"
				$section = $Configuration.GetSection($path)

				[array]$elements = $section.GetCollection() `
				| Where-Object {
					$accessType = $_ | Get-IISConfigAttributeValue -AttributeName "accessType"
					$users = $_ | Get-IISConfigAttributeValue -AttributeName "users"
					$roles = $_ | Get-IISConfigAttributeValue -AttributeName "roles"
					($accessType -eq "Allow") -and ($users -eq "*" -or $roles -eq "?")
				}

				if ($elements.Count -ne 0) {
					$message = "Authorization rule to allow all or anonymous users is set"
					$audit = "False"
				}
			}
			else {
				$message = "URL Authorization is not installed"
				$audit = "Warning"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "2.1"
			Task    = "Ensure 'global authorization rule' is set to restrict access"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 2.2
function Test-IISAuthenticatedPricipals {
	<#
	.Synopsis
		Ensure access to sensitive site features is restricted to authenticated principals only
	.Description
		IIS supports both challenge-based and login redirection-based authentication methods. Challenge-based authentication methods, such as Integrated Windows Authentication, require a client to respond correctly to a server-initiated challenge. A login redirection-based authentication method such as Forms Authentication relies on redirection to a login page to determine the identity of the principal. Challenge-based authentication and login redirection-based authentication methods cannot be used in conjunction with one another.

		It is recommended that sites containing sensitive information, confidential data, or non-public web services be configured with a credentials-based authentication mechanism.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/authentication"
			$section = $Configuration.GetSection($path)

			$mode = $section | Get-IISConfigAttributeValue -AttributeName "mode"

			if (($mode -ne "Windows") -and ($mode -ne "Forms")) {
				$message = "Check authentication principals"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "2.2"
			Task    = "Ensure access to sensitive site features is restricted to authenticated principals only"
			Status  = $audit
			Message = $message
		} | Write-Output
	}

}

# 2.3
function Test-IISFormsAuthenticationSSL {
	<#
	.Synopsis
		Ensure 'forms authentication' require SSL
	.Description
		Forms-based authentication can pass credentials across the network in clear text. It is therefore imperative that the traffic between client and server be encrypted using SSL, especially in cases where the site is publicly accessible. It is recommended that communications with any portion of a site using Forms Authentication be encrypted using SSL.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/authentication"
			$section = $Configuration.GetSection($path)

			$mode = $section | Get-IISConfigAttributeValue -AttributeName "mode"

			if ((Get-IISModules) -contains "FormsAuthentication") {
				# Ensure authentication mode is set to Forms
				if ($mode -eq "Forms") {

					$requireSSL = $section `
					| Get-IISConfigElement -ChildElementName "forms" `
					| Get-IISConfigAttributeValue -AttributeName "requireSSL"

					if (-not $requireSSL) {
						$message = "Forms authentication does not require SSL"
						$audit = "False"
					}
				}
			}
			else {
				$message = "Forms authentication is not installed"
				$audit = "Warning"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "2.3"
			Task    = "Ensure 'forms authentication' require SSL"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 2.4
function Test-IISFormsAuthenticationCookies {
	<#
	.Synopsis
		Ensure 'forms authentication' is set to use cookies
	.Description
		Forms Authentication can be configured to maintain the site visitor's session identifier in either a URI or cookie. It is recommended that Forms Authentication be set to use cookies.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/authentication"
			$section = $Configuration.GetSection($path)

			$mode = $section | Get-IISConfigAttributeValue -AttributeName "mode"

			if ((Get-IISModules) -contains "FormsAuthentication") {
				if ($mode -eq "Forms") {
					$cookieless = $section | Get-IISConfigElement -ChildElementName "forms" `
					| Get-IISConfigAttributeValue -AttributeName "cookieless"

					if ($cookieless -ne "UseCookies") {
						$message = "Forms authentication is not set to use cookies"
						$audit = "False"
					}
				}
			}
			else {
				$message = "Forms authentication is not installed"
				$audit = "Warning"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "2.4"
			Task    = "Ensure 'forms authentication' is set to use cookies"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 2.5
function Test-IISFormsAuthenticationProtection {
	<#
	.Synopsis
		Ensure 'cookie protection mode' is configured for forms authentication
	.Description
		The cookie protection mode defines the protection Forms Authentication cookies will be given within a configured application.

		It is recommended that cookie protection mode always encrypt and validate Forms Authentication cookies.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/authentication"
			$section = $Configuration.GetSection($path)

			$mode = $section | Get-IISConfigAttributeValue -AttributeName "mode"

			if ((Get-IISModules) -contains "FormsAuthentication") {
				if ($mode -ieq "Forms") {
					$protection = $section `
					| Get-IISConfigElement -ChildElementName "forms" `
					| Get-IISConfigAttributeValue -AttributeName "protection"

					if ($protection -ne "All") {
						$message = "Cookie Protection Mode is not set to ALL"
						$audit = "False"
					}
				}
			}
			else {
				$message = "Forms authentication is not installed"
				$audit = "Warning"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "2.5"
			Task    = "Ensure 'cookie protection mode' is configured for forms authentication"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 2.6
function Test-IISTLSForBasicAuth {
	<#
	.Synopsis
		Ensure transport layer security for 'basic authentication' is configured
	.Description
		Basic Authentication can pass credentials across the network in clear text. It is therefore imperative that the traffic between client and server be encrypted, especially in cases where the site is publicly accessible and is recommended that TLS be configured and required for any Site or Application using Basic Authentication.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		if ((Get-WindowsFeature Web-Basic-Auth).InstallState -eq [InstallState]::Installed) {
			[array]$httpsBindings = $Site.Bindings | Where-Object -Property Protocol -eq "https"

			$sslFlags = Get-IISConfigSection -Location $Site.Name `
				-SectionPath "system.webServer/security/access" `
				| Get-IISConfigAttributeValue -AttributeName "sslFlags"

			# split the flags into an array
			$sslValues = $sslFlags.Split("{,}")

			# Ensure ssl-flag is set
			if (-not ($sslValues -contains "ssl")) {
				$message = "SSL is not required in configuration"
				$audit = "False"
			}
			# Ensure site has https bindings
			elseif ($httpsBindings.Count -eq 0) {
				$message = "Site has no secure protocol binding"
				$audit = "False"
			}
		}

		@{
			Id      = "2.6"
			Task    = "Ensure transport layer security for 'basic authentication' is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 2.7
function Test-IISPasswordFormatNotClear {
	<#
	.Synopsis
		Ensure 'passwordFormat' is not set to clear
	.Description
		The <credentials> element of the <authentication> element allows optional definitions of name and password for IIS Manager User accounts within the configuration file. Forms based authentication also uses these elements to define the users. IIS Manager Users can use the administration interface to connect to sites and applications in which they've been granted authorization. Note that the <credentials> element only applies when the default provider, ConfigurationAuthenticationProvider, is configured as the authentication provider. It is recommended that passwordFormat be set to a value other than Clear, such as SHA1.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/authentication"
			$section = $Configuration.GetSection($path)

			$passwordFormat = $section `
			| Get-IISConfigElement -ChildElementName "forms" `
			| Get-IISConfigElement -ChildElementName "credentials" `
			| Get-IISConfigAttributeValue -AttributeName "passwordFormat"

			if ($passwordFormat -eq "Clear" ) {
				$message = "Credentials passwordFormat set to 'Clear'"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}
	
		@{
			Id      = "2.7"
			Task    = "Ensure 'passwordFormat' is not set to clear"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 2.7
function Test-IISPasswordFormatNotClearMachineLevel {
	<#
	.Synopsis
		Ensure 'passwordFormat' is not set to clear
	.Description
		The <credentials> element of the <authentication> element allows optional definitions of name and password for IIS Manager User accounts within the configuration file. Forms based authentication also uses these elements to define the users. IIS Manager Users can use the administration interface to connect to sites and applications in which they've been granted authorization. Note that the <credentials> element only applies when the default provider, ConfigurationAuthenticationProvider, is configured as the authentication provider. It is recommended that passwordFormat be set to a value other than Clear, such as SHA1.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
	$passwordFormat = $machineConfig.GetSection("system.web/authentication").forms.credentials.passwordFormat

	if ($passwordFormat -eq "Clear" ) {
		$message = "Credentials passwordFormat set to 'Clear'"
		$audit = "False"
	}

	@{
		Id      = "2.7"
		Task    = "Ensure 'passwordFormat' is not set to clear"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 2.8
function Test-IISCredentialsNotStored {
	<#
	.Synopsis
		Ensure 'credentials' are not stored in configuration files
	.Description
		The <credentials> element of the <authentication> element allows optional definitions of name and password for IIS Manager User accounts within the configuration file. Forms based authentication also uses these elements to define the users. IIS Manager Users can use the administration interface to connect to sites and applications in which they've been granted authorization. Note that the <credentials> element only applies when the default provider, ConfigurationAuthenticationProvider, is configured as the authentication provider. It is recommended to avoid storing passwords in the configuration file even in form of hash.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/authentication"
			$section = $Configuration.GetSection($path)

			$credentials = $section `
			| Get-IISConfigElement -ChildElementName "forms" `
			| Get-IISConfigElement -ChildElementName "credentials"

			if ($credentials.IsLocallyStored) {
				$message = "'credentials' is stored in configuration"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}
	
		@{
			Id      = "2.8"
			Task    = "Ensure 'credentials' are not stored in configuration files"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 2.8
function Test-IISCredentialsNotStoredMachineLevel {
	<#
	.Synopsis
		Ensure 'credentials' are not stored in configuration files
	.Description
		The <credentials> element of the <authentication> element allows optional definitions of name and password for IIS Manager User accounts within the configuration file. Forms based authentication also uses these elements to define the users. IIS Manager Users can use the administration interface to connect to sites and applications in which they've been granted authorization. Note that the <credentials> element only applies when the default provider, ConfigurationAuthenticationProvider, is configured as the authentication provider. It is recommended to avoid storing passwords in the configuration file even in form of hash.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
	$credentials = $machineConfig.GetSection("system.web/authentication").forms.credentials

	if ($credentials.ElementInformation.IsPresent) {
		$message = "'credentials' is stored in configuration"
		$audit = "False"
	}

	@{
		Id      = "2.8"
		Task    = "Ensure 'credentials' are not stored in configuration files"
		Status  = $audit
		Message = $message
	} | Write-Output
}

#endregion

#region 3 ASP.NET Configuration Recommendation
#
# This section contains recommendations specific to ASP.NET.

# 3.1
function Test-IISDeploymentMethodRetail {
	<#
	.Synopsis
		Ensure 'deployment method retail' is set
	.Description
		The <deployment retail> switch is intended for use by production IIS servers. This switch is used to help applications run with the best possible performance and least possible security information leakages by disabling the application's ability to generate trace output on a page, disabling the ability to display detailed error messages to end users, and disabling the debug switch. Often times, switches and options that are developer-focused, such as failed request tracing and debugging, are enabled during active development. It is recommended that the deployment method on any production server be set to retail.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
	$deployment = $machineConfig.GetSection("system.web/deployment")

	if (-not $deployment.retail) {
		$message = "retail is not enabled in machine.config"
		$audit = "False"
	}

	@{
		Id      = "3.1"
		Task    = "Ensure 'deployment method retail' is set"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 3.2
function Test-IISDebugOff {
	<#
	.Synopsis
		Ensure 'debug' is turned off
	.Description
		Developers often enable the debug mode during active ASP.NET development so that they do not have to continually clear their browsers cache every time they make a change to a resource handler. The problem would arise from this being left "on" or set to "true". Compilation debug output is displayed to the end user, allowing malicious persons to obtain detailed information about applications.

		is recommended that debugging still be turned off.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/compilation"
			$section = $Configuration.GetSection($path)

			$debug = $section | Get-IISConfigAttributeValue -AttributeName "debug"

			if ($debug) {
				$message = "Debug is ON"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "3.2"
			Task    = "Ensure 'debug' is turned off"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.3
function Test-IISCustomErrorsNotOff {
	<#
	.Synopsis
		Ensure custom error messages are not off
	.Description
		When an ASP.NET application fails and causes an HTTP/1.x 500 Internal Server Error, or a feature configuration (such as Request Filtering) prevents a page from being displayed, an error message will be generated. Administrators can choose whether or not the application should display a friendly message to the client, detailed error message to the client, or detailed error message to localhost only.

		It is recommended that customErrors still be turned to On or RemoteOnly.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/customErrors"
			$section = $Configuration.GetSection($path)

			$mode = $section | Get-IISConfigAttributeValue -AttributeName "mode"

			if ($mode -eq "Off") {
				$message = "Custom errors are 'OFF'"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "3.3"
			Task    = "Ensure custom error messages are not off"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.4
function Test-IISHttpErrorsHidden {
	<#
	.Synopsis
		Ensure IIS HTTP detailed errors are hidden from displaying remotely
	.Description
		A Web site's error pages are often set to show detailed error information for troubleshooting purposes during testing or initial deployment. To prevent unauthorized users from viewing this privileged information, detailed error pages must not be seen by remote users. This setting can be modified in the errorMode attribute setting for a Web site's error pages. By default, the errorMode attribute is set in the Web.config file for the Web site or application and is located in the <httpErrors> element of the <system.webServer> section. It is recommended that custom errors be prevented from displaying remotely.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.webServer/httpErrors"
			$section = $Configuration.GetSection($path)

			$errorMode = $section | Get-IISConfigAttributeValue -AttributeName "errorMode"

			if (($errorMode -ne "Custom") -and ($errorMode -ne "DetailedLocalOnly")) {
				$message = "HTTP detailed errors are set to 'Detailed'"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "3.4"
			Task    = "Ensure IIS HTTP detailed errors are hidden from displaying remotely"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.5
function Test-IISAspNetTracingDisabled {
	<#
	.Synopsis
		Ensure ASP.NET stack tracing is not enabled
	.Description
		A Web site's error pages are often set to show detailed error information for troubleshooting purposes during testing or initial deployment. To prevent unauthorized users from viewing this privileged information, detailed error pages must not be seen by remote users. This setting can be modified in the errorMode attribute setting for a Web site's error pages. By default, the errorMode attribute is set in the Web.config file for the Web site or application and is located in the <httpErrors> element of the <system.webServer> section. It is recommended that custom errors be prevented from displaying remotely.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/trace"
			$section = $Configuration.GetSection($path)

			$traceEnabled = $section | Get-IISConfigAttributeValue -AttributeName "enabled"

			if ($traceEnabled) {
				$message = "trace is enabled"
				$audit = "FALSE"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "3.5"
			Task    = "Ensure ASP.NET stack tracing is not enabled"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.5
function Test-IISAspNetTracingDisabledMachineLevel {
	<#
	.Synopsis
		Ensure ASP.NET stack tracing is not enabled
	.Description
		A Web site's error pages are often set to show detailed error information for troubleshooting purposes during testing or initial deployment. To prevent unauthorized users from viewing this privileged information, detailed error pages must not be seen by remote users. This setting can be modified in the errorMode attribute setting for a Web site's error pages. By default, the errorMode attribute is set in the Web.config file for the Web site or application and is located in the <httpErrors> element of the <system.webServer> section. It is recommended that custom errors be prevented from displaying remotely.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
	$trace = $machineConfig.GetSection("system.web/trace")

	if ($trace.enabled) {
		$message = "trace is enabled in machine.config"
		$audit = "FALSE"
	}

	@{
		Id      = "3.5"
		Task    = "Ensure ASP.NET stack tracing is not enabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 3.6
function Test-IISCookielessSessionState {
	<#
	.Synopsis
		Ensure 'httpcookie' mode is configured for session state
	.Description
		A session cookie associates session information with client information for that session, which can be the duration of a user's connection to a site. The cookie is passed in a HTTP header together with all requests between the client and server.

		It is recommended that session state be configured to UseCookies.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/sessionState"
			$section = $Configuration.GetSection($path)

			$cookieless = $section | Get-IISConfigAttributeValue -AttributeName "cookieless"

			if (($cookieless -ne "UseCookies") -and ($cookieless -ne "False")) {
				$message = "sessionState set to $cookieless"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "3.6"
			Task    = "Ensure 'httpcookie' mode is configured for session state"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.7
function Test-IISCookiesHttpOnly {
	<#
	.Synopsis
		Ensure 'cookies' are set with HttpOnly attribute
	.Description
		The httpOnlyCookies attribute of the httpCookies node determines if IIS will set the HttpOnly flag on HTTP cookies it sets. The HttpOnly flag indicates to the user agent that the cookie must not be accessible by client-side script (i.e document.cookie). It is recommended that the httpOnlyCookies attribute be set to true.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.web/httpCookies"
			$section = $Configuration.GetSection($path)

			$httpOnlyCookies = $section | Get-IISConfigAttributeValue -AttributeName "httpOnlyCookies"

			if (-not $httpOnlyCookies) {
				$message = "httpOnlyCookies set to $httpOnlyCookies"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "3.7"
			Task    = "Ensure 'cookies' are set with HttpOnly attribute"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.8
function Test-IISMachineKeyValidation {
	<#
	.Synopsis
		Ensure 'MachineKey validation method - .Net 3.5' is configured
	.Description
		The machineKey element of the ASP.NET web.config specifies the algorithm and keys that ASP.NET will use for encryption. The Machine Key feature can be managed to specify hashing and encryption settings for application services such as view state, Forms authentication, membership and roles, and anonymous identification.

		It is recommended that AES or SHA1 methods be configured for use at the global level.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		$siteAppPool = $Site.Applications["/"].ApplicationPoolName
		$appPoolVersion = (Get-IISAppPool -Name $siteAppPool).managedRuntimeVersion

		# Ensure  ApplicationPool running is .NET 3.5 (which is an extension of 2.0 so we look for 2.*)
		if ($appPoolVersion -like "v2.*") {

			$validation = Get-IISConfigSection -CommitPath $Site.Name `
				-SectionPath "system.web/machineKey" `
				| Get-IISConfigAttributeValue -AttributeName "Validation"

			if ($validation -ne "SHA1") {
				$message = "Validation set to $validation"
				$audit = "False"
			}
		}

		@{
			Id      = "3.8"
			Task    = "Ensure 'MachineKey validation method - .Net 3.5' is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.9
function Test-IISMachineKeyValidationV45 {
	<#
	.Synopsis
		Ensure 'MachineKey validation method - .Net 4.5' is configured
	.Description
		The machineKey element of the ASP.NET web.config specifies the algorithm and keys that ASP.NET will use for encryption. The Machine Key feature can be managed to specify hashing and encryption settings for application services such as view state, Forms authentication, membership and roles, and anonymous identification.

		It is recommended that SHA-2 methods be configured for use at the global level.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		$siteAppPool = $site.Applications["/"].ApplicationPoolName
		$appPoolVersion = (Get-IISAppPool -Name $siteAppPool).managedRuntimeVersion

		# Ensure an ApplicationPool is running .NET 4.5
		if ($appPoolVersion -like "v4.*") {
			$validation = Get-IISConfigSection -CommitPath $Site.name `
				-SectionPath "system.web/machineKey" `
				| Get-IISConfigAttributeValue -AttributeName "Validation"

			if (($validation -ne "HMACSHA256") -and ($validation -ne "HMACSHA512")) {
				$message = "Validation set to $validation"
				$audit = "False"
			}
		}

		@{
			Id      = "3.9"
			Task    = "Ensure 'MachineKey validation method - .Net 4.5' is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 3.10
function Test-IISDotNetTrustLevel {
	<#
	.Synopsis
		Ensure global .NET trust level is configured
	.Description
		An application's trust level determines the permissions that are granted by the ASP.NET code access security (CAS) policy. CAS defines two trust categories: full trust and partial trust. An application that has full trust permissions may access all resource types on a server and perform privileged operations, while applications that run with partial trust have varying levels of operating permissions and access to resources.

		It is recommended that the global .NET Trust Level be set to Medium or lower.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		$siteAppPool = $site.Applications["/"].ApplicationPoolName
		$appPoolVersion = (Get-IISAppPool -Name $siteAppPool).managedRuntimeVersion

		if ($appPoolVersion -like "v4.*") {
			$message = "This only applies to .Net 2.0. Future versions have stopped supporting this feature."
			$audit = "None"
		}
		else {
			$level = Get-IISConfigSection -CommitPath $Site.name `
				-SectionPath "system.web/trust" `
			| Get-IISConfigAttributeValue -AttributeName "level"

			# medium trust level should be set in .NET 2.*, but not in later versions
			if (($appPoolVersion -like "v2.*" -and $level -ne "medium" -or $level -ne "low" -or $level -ne "minimal") `
			-or ($appPoolVersion -notlike "v4.*" -and -not [string]::IsNullOrEmpty($appPoolVersion))) {
				$message = "TrustLevel set to $level"
				$audit = "False"
			}
		}

		@{
			Id      = "3.10"
			Task    = "Ensure global .NET trust level is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

#endregion

#region 4 Request Filtering and Other Restriction Modules
#
# Request Filtering is a powerful module that provides a configurable set of rules that enables administrators to allow or reject the types of requests that they determine should be allowed or rejected at the server, web site, or web application levels.


# 4.1
function Test-IISMaxAllowedContentLength {
	<#
	.Synopsis
		Ensure 'maxAllowedContentLength' is configured
	.Description
		The maxAllowedContentLength Request Filter is the maximum size of the http request, measured in bytes, which can be sent from a client to the server. Configuring this value enables the total request size to be restricted to a configured value. It is recommended that the overall size of requests be restricted to a maximum value appropriate for the server, site, or application.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			# Ensure request filering is installed
			if ((Get-WindowsFeature Web-Filtering).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/requestFiltering"
				$section = $Configuration.GetSection($path)

				$maxContentLength = $section `
				| Get-IISConfigElement -ChildElementName "requestLimits" `
				| Get-IISConfigAttributeValue -AttributeName "maxAllowedContentLength"

				if ($maxContentLength -ge 0) {
					$message += "`n maxContentLength: $maxContentLength"
				}
				else {
					$message = "maxContentLength not configured"
					$audit = "False"
				}
			}
			else {
				$message = "Request Filering is not installed"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "4.1"
			Task    = "Ensure 'maxAllowedContentLength' is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.2
function Test-IISMaxURLRequestFilter {
	<#
	.Synopsis
		Ensure 'maxURL request filter' is configured
	.Description
		The maxURL attribute of the <requestLimits> property is the maximum length (in Bytes) in which a requested URL can be (excluding query string) in order for IIS to accept. Configuring this Request Filter enables administrators to restrict the length of the requests that the server will accept. It is recommended that a limit be put on the length of URL.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			# Ensure request filering is installed
			if ((Get-WindowsFeature Web-Filtering).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/requestFiltering"
				$section = $Configuration.GetSection($path)

				$maxURLRequestFilter = $section `
				| Get-IISConfigElement -ChildElementName "requestLimits" `
				| Get-IISConfigAttributeValue -AttributeName "maxURL"

				if ($maxURLRequestFilter -ge 1) {
					$message += "`n maxURLRequestFilter: $maxURLRequestFilter"
				}
				else {
					$message = "maxURLRequestFilter not configured"
					$audit = "False"
				}
			}
			else {
				$message = "Request Filering is not installed"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}


		@{
			Id      = "4.2"
			Task    = "Ensure 'maxURL request filter' is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.3
function Test-IISMaxQueryStringRequestFilter {
	<#
	.Synopsis
		Ensure 'MaxQueryString request filter' is configured
	.Description
		The MaxQueryString Request Filter describes the upper limit on the length of the query string that the configured IIS server will allow for websites or applications. It is recommended that values always be established to limit the amount of data will can be accepted in the query string.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			# Ensure request filering is installed
			if ((Get-WindowsFeature Web-Filtering).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/requestFiltering"
				$section = $Configuration.GetSection($path)

				$maxQueryStringRequestFilter = $section `
				| Get-IISConfigElement -ChildElementName "requestLimits" `
				| Get-IISConfigAttributeValue -AttributeName "maxQueryString"

				if ($maxQueryStringRequestFilter -ge 1) {
					$message += "`n maxQueryStringRequestFilter: $maxQueryStringRequestFilter"
				}
				else {
					$message = "maxQueryStringRequestFilter not configured"
					$audit = "False"
				}
			}
			else {
				$message = "Request Filering is not installed"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "4.3"
			Task    = "Ensure 'MaxQueryString request filter' is configured"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.4
function Test-IISNonASCIICharURLForbidden {
	<#
	.Synopsis
		Ensure non-ASCII characters in URLs are not allowed
	.Description
		This feature is used to allow or reject all requests to IIS that contain non-ASCII characters. When using this feature, Request Filtering will deny the request if high-bit characters are present in the URL. The UrlScan equivalent is AllowHighBitCharacters. It is recommended that requests containing non-ASCII characters be rejected, where possible.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			# Ensure request filering is installed
			if ((Get-WindowsFeature Web-Filtering).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/requestFiltering"
				$section = $Configuration.GetSection($path)

				$allowHighBitCharacters = $section `
				| Get-IISConfigAttributeValue -AttributeName "allowHighBitCharacters"

				if ($allowHighBitCharacters) {
					$message = "non-ASCII characters in URLs are allowed"
					$audit = "False"
				}
			}
			else {
				$message = "Request Filering is not installed"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "4.4"
			Task    = "Ensure non-ASCII characters in URLs are not allowed"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.5
function Test-IISRejectDoubleEncodedRequests {
	<#
	.Synopsis
		Ensure Double-Encoded requests will be rejected
	.Description
		This Request Filter feature prevents attacks that rely on double-encoded requests and applies if an attacker submits a double-encoded request to IIS. When the double-encoded requests filter is enabled, IIS will go through a two iteration process of normalizing the request. If the first normalization differs from the second, the request is rejected and the error code is logged as a 404.11. The double-encoded requests filter was the VerifyNormalization option in UrlScan. It is recommended that double-encoded requests be rejected.
	#>
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			# Ensure request filering is installed
			if ((Get-WindowsFeature Web-Filtering).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/requestFiltering"
				$section = $Configuration.GetSection($path)

				$allowDoubleEscaping = $section`
				| Get-IISConfigAttributeValue -AttributeName "allowDoubleEscaping"

				if ($allowDoubleEscaping) {
					$message = "Rejecting Double-Encoded requests not set"
					$audit = "False"
				}
			}
			else {
				$message = "Request Filering is not installed"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "4.5"
			Task    = "Ensure Double-Encoded requests will be rejected"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.6
function Test-IISHTTPTraceMethodeDisabled {
	<#
	.Synopsis
		Ensure 'HTTP Trace Method' is disabled
	.Description
		The HTTP TRACE method returns the contents of client HTTP requests in the entity-body of the TRACE response. Attackers could leverage this behavior to access sensitive information, such as authentication data or cookies, contained in the HTTP headers of the request. One such way to mitigate this is by using the <verbs> element of the <requestFiltering> collection. The <verbs> element replaces the [AllowVerbs] and [DenyVerbs] features in UrlScan. It is recommended the HTTP TRACE method be denied.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = "HTTP Trace Method is not filtered"
			$audit = "False"

			# Ensure request filering is installed
			if ((Get-WindowsFeature Web-Filtering).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/requestFiltering"
				$section = $Configuration.GetSection($path)

				[array]$httpTraceMethod = $section.GetCollection("verbs") `
				| Where-Object {
					$trace = $_ | Get-IISConfigAttributeValue -AttributeName "verb"
					$allowed = $_ | Get-IISConfigAttributeValue -AttributeName "allowed"
					($trace -eq "trace") -and (-not $allowed)
				}

				if ($httpTraceMethod.Count -eq 1) {
					$message = $MESSAGE_ALLGOOD
					$audit = "True"
				}
			}
			else {
				$message = "Request Filering is not installed"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "4.6"
			Task    = "Ensure 'HTTP Trace Method' is disabled"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.7
function Test-IISBlockUnlistedFileExtensions {
	<#
	.Synopsis
		Ensure Unlisted File Extensions are not allowed
	.Description
		The FileExtensions Request Filter allows administrators to define specific extensions their web server(s) will allow and disallow. The property allowUnlisted will cover all other file extensions not explicitly allowed or denied. Often times, extensions such as .config, .bat, .exe, to name a few, should never be served. The AllowExtensions and DenyExtensions options are the UrlScan equivalents. It is recommended that all extensions be unallowed at the most global level possible, with only those necessary being allowed.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			if ((Get-WindowsFeature Web-Filtering).InstallState -eq [InstallState]::Installed) {
				$path = "system.webServer/security/requestFiltering"

				$section = $Configuration.GetSection($path)

				$allowUnlisted = $section `
				| Get-IISConfigElement -ChildElementName "fileExtensions" `
				| Get-IISConfigAttributeValue -AttributeName "allowUnlisted"


				if ($allowUnlisted) {
					$message = "Unlisted file extensions allowed"
					$audit = "False"
				}
			}
			else {
				$message = "Request Filering is not installed"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "4.7"
			Task    = "Ensure Unlisted File Extensions are not allowed"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.8
function Test-IISHandlerDenyWrite {
	<#
	.Synopsis
		Ensure Handler is not granted Write and Script/Execute
	.Description
		Handler mappings can be configured to give permissions to Read, Write, Script, or Execute depending on what the use is for - reading static content, uploading files, executing scripts, etc. It is recommended to grant a handler either Execute/``Script or Write permissions, but not both.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"

			$path = "system.webServer/handlers"
			$section = $Configuration.GetSection($path)
			$accessPolicy = ($section | Get-IISConfigAttributeValue -AttributeName "accessPolicy").Split(",")

			if ((($accessPolicy -contains "Script") -or ($accessPolicy -contains "Execute")) `
					-and ($accessPolicy -contains "Write")) {
				$message = "Handler is granted write and script/execute"
				$audit = "False"
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "4.8"
			Task    = "Ensure Handler is not granted Write and Script/Execute"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 4.9
function Test-IISIsapisNotAllowed {
	<#
	.Synopsis
		Ensure 'notListedIsapisAllowed' is set to false
	.Description
		The notListedIsapisAllowed attribute is a server-level setting that is located in the ApplicationHost.config file in the <isapiCgiRestriction> element of the <system.webServer> section under <security>. This element ensures that malicious users cannot copy unauthorized ISAPI binaries to the Web server and then run them. It is recommended that notListedIsapisAllowed be set to false.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	try {
		$isapiCgiRestriction = Get-IISConfigSection `
			-SectionPath "system.webServer/security/isapiCgiRestriction" `
			| Get-IISConfigAttributeValue -AttributeName "notListedIsapisAllowed"

		# Verify that the notListedIsapisAllowed attribute in the <isapiCgiRestriction> element is set to false
		if ($isapiCgiRestriction) {
			$message = "IsapiCgiRestriction 'notListedIsapisAllowed' not set to false"
			$audit = "False"
		}
	}
	catch {
		$message = "Cannot get setting 'notListedIsapisAllowed' for IsapiCgiRestriction"
		$audit = "False"
	}

	@{
		Id      = "4.9"
		Task    = "Ensure 'notListedIsapisAllowed' is set to false"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 4.10
function Test-IISCgisNotAllowed {
	<#
	.Synopsis
		Ensure 'notListedCgisAllowed' is set to false
	.Description
		The notListedCgisAllowed attribute is a server-level setting that is located in the ApplicationHost.config file in the <isapiCgiRestriction> element of the <system.webServer> section under <security>. This element ensures that malicious users cannot copy unauthorized CGI binaries to the Web server and then run them. It is recommended that notListedCgisAllowed be set to false.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	try {
		$isapiCgiRestriction = Get-IISConfigSection `
			-SectionPath "system.webServer/security/isapiCgiRestriction" `
			| Get-IISConfigAttributeValue -AttributeName "notListedCgisAllowed"

		# Verify that the notListedCgisAllowed attribute in the <isapiCgiRestriction> element is set to false
		if ($isapiCgiRestriction) {
			$message = "IsapiCgiRestriction 'notListedCgisAllowed' not set to false"
			$audit = "False"
		}
	}
	catch {
		$message = "Cannot get setting 'notListedCgisAllowed' for IsapiCgiRestriction"
		$audit = "False"
	}

	@{
		Id      = "4.10"
		Task    = "Ensure 'notListedCgisAllowed' is set to false"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 4.11
function Test-IISDynamicIPRestrictionEnabled {
	<#
	.Synopsis
		Ensure 'Dynamic IP Address Restrictions' is enabled
	.Description
		IIS Dynamic IP Address Restrictions capability can be used to thwart DDos attacks. This is complimentary to the IP Addresses and Domain names Restrictions lists that can be manually maintained within IIS. In contrast, Dynamic IP address filtering allows administrators to configure the server to block access for IPs that exceed the specified request threshold. The default action Deny action for restrictions is to return a Forbidden response to the client.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		# Ensure the windows feature is installed
		if ((Get-WindowsFeature Web-Ip-Security).InstallState -ne [InstallState]::Installed) {
			$message = "`"IP and Domain Restrictions`" must be installed to enabled `"Dynamic IP Address Restrictions`""
			$audit = "False"
		}
		else {
			$dynamicIpSecurity = Get-IISConfigSection -Location $Site.Name `
				-SectionPath "system.webServer/security/dynamicIpSecurity"

			$denyByConcurrentRequests = $dynamicIpSecurity `
				| Get-IISConfigElement -ChildElementName "denyByConcurrentRequests" `
				| Get-IISConfigAttributeValue -AttributeName "enabled"

			$denyByRequestRate = $dynamicIpSecurity `
				| Get-IISConfigElement -ChildElementName "denyByRequestRate" `
				| Get-IISConfigAttributeValue -AttributeName "enabled"

			if ($denyByConcurrentRequests -and -not $denyByRequestRate) {
				$message = "Deny IP Address based on the number of requests over a period of time disabled"
				$audit = "False"
			}
			elseif (-not $denyByConcurrentRequests -and $denyByRequestRate) {
				$message = "Deny IP Address based on the number of concurrent requests disabled"
				$audit = "False"
			}
			elseif (-not $denyByConcurrentRequests -and -not $denyByRequestRate) {
				$message = "Dynamic IP Restriction disabled"
				$audit = "False"
			}
		}

		@{
			Id      = "4.11"
			Task    = "Ensure 'Dynamic IP Address Restrictions' is enabled"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

#endregion

#region 5 IIS Logging Recommendations
#
# This section contains recommendations regarding IIS logging that have not been covered in the Basic Configurations section.

# 5.1
function Test-IISLogFileLocation {
	<#
	.Synopsis
		Ensure Default IIS web log location is moved
	.Description
		IIS will log relatively detailed information on every request. These logs are usually the first item looked at in a security response, and can be the most valuable. Malicious users are aware of this, and will often try to remove evidence of their activities. It is therefore recommended that the default location for IIS log files be changed to a restricted, non-system drive.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$logFileLocation = ($Site.logFile.Directory).replace("%SystemDrive%", $env:SystemDrive)

		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		if ($logFileLocation.StartsWith($env:SystemDrive)) {
			$message = "Logfile location is on system drive: $logFileLocation"
			$audit = "False"
		}

		@{
			Id      = "5.1"
			Task    = "Ensure Default IIS web log location is moved"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

# 5.2
function Test-IISAdvancedLoggingEnabled {
	<#
	.Synopsis
		Ensure Advanced IIS logging is enabled
	.Description
		IIS Advanced Logging is a module which provides flexibility in logging requests and client data. It provides controls that allow businesses to specify what fields are important, easily add additional fields, and provide policies pertaining to log file rollover and Request Filtering. HTTP request/response headers, server variables, and client-side fields can be easily logged with minor configuration in the IIS management console. It is recommended that Advanced Logging be enabled, and the fields which could be of value to the type of business or application in the event of a security incident, be identified and logged.
	#>

	# check site defaults

	@{
		Id      = "5.2"
		Task    = "Ensure Advanced IIS logging is enabled"
		Status  = "None"
		Message = "Advanced Logging is not available for IIS 10. See enhanced logging instead."
	} | Write-Output
}

# 5.3
function Test-IISETWLoggingEnabled {
	<#
	.Synopsis
		Ensure 'ETW Logging' is enabled
	.Description
		IIS introduces a new logging method. Administrators can now send logging information to Event Tracing for Windows (ETW)
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site] $Site
	)

	process {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"

		if (-not ($Site.logFile.logTargetW3C -like "*ETW*")) {
			$message = "ETW Logging disabled"
			$audit = "False"
		}

		@{
			Id      = "5.3"
			Task    = "Ensure 'ETW Logging' is enabled"
			Status  = $audit
			Message = $message
		} | Write-Output
	}
}

#endregion

#region 6 FTP Requests
#
# This section contains a crucial configuration setting for running file transfer protocol (FTP).

# 6.1
function Test-IISFtpRequestsEncrypted {
	<#
	.Synopsis
		Ensure FTP requests are encrypted
	.Description
		The new FTP Publishing Service for IIS supports adding an SSL certificate to an FTP site. Using an SSL certificate with an FTP site is also known as FTP-S or FTP over Secure Socket Layers (SSL). FTP-S is an RFC standard (RFC 4217) where an SSL certificate is added to an FTP site and thereby making it possible to perform secure file transfers.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	if ((Get-WindowsFeature Web-Ftp-Server).InstallState -eq [InstallState]::Installed) {
		try {
			$sslConfigElement = Get-IISConfigSection `
				-SectionPath "system.applicationHost/sites" `
				| Get-IISConfigElement -ChildElementName "siteDefaults" `
				| Get-IISConfigElement -ChildElementName "ftpServer" `
				| Get-IISConfigElement -ChildElementName "security" `
				| Get-IISConfigElement -ChildElementName "ssl"

			$controlChannelPolicy = $sslConfigElement `
				| Get-IISConfigAttributeValue -AttributeName "controlChannelPolicy"

			$dataChannelPolicy = $sslConfigElement `
				| Get-IISConfigAttributeValue -AttributeName "dataChannelPolicy"

			if (($controlChannelPolicy -ne "SslRequire") -or ($dataChannelPolicy -ne "SslRequire")) {
				$message = "Found following settings: `n controlChannelPolicy: $controlChannelPolicy `n dataChannelPolicy: $dataChannelPolicy"
				$audit = "False"
			}
		}
		catch {
			$message = "Cannot get FTP security setting"
			$audit = "False"
		}
	}
	else {
		$message = "Skipped this benchmark - right now Web-Ftp-Server is not installed"
		$audit = "None"
	}

	@{
		Id      = "6.1"
		Task    = "Ensure FTP requests are encrypted"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 6.2
function Test-IISFtpLogonAttemptRestriction {
	<#
	.Synopsis
		Ensure FTP Logon attempt restrictions is enabled
	.Description
		IIS introduced a built-in network security feature to automatically block brute force FTP attacks. This can be used to mitigate a malicious client from attempting a brute-force attack on a discovered account, such as the local administrator account.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	if ((Get-WindowsFeature Web-Ftp-Server).InstallState -eq [InstallState]::Installed) {
		try {
			$denyByFailure = Get-IISConfigSection `
				-SectionPath "system.ftpServer/security/authentication" `
				| Get-IISConfigElement -ChildElementName "denyByFailure"

			$enabled = $denyByFailure `
				| Get-IISConfigAttributeValue -AttributeName "enabled"
			$maxFailure = $denyByFailure `
				| Get-IISConfigAttributeValue -AttributeName "maxFailure"
			$entryExpiration = $denyByFailure `
				| Get-IISConfigAttributeValue -AttributeName "entryExpiration"
			$loggingOnlyMode = $denyByFailure `
				| Get-IISConfigAttributeValue -AttributeName "loggingOnlyMode"

			if (($enabled) -and ($maxFailure -gt 0) -and ($entryExpiration -gt 0) -and (-not $loggingOnlyMode)) {
				# All good
			}
			elseif (-not $enabled ) {
				$message = "Feature disabled"
				$audit = "False"
			}
			else {
				$message = "Feature enabled, but check settings. Found: `n maxFailure: " `
					+ $maxFailure + "`n entryExpiration: " `
					+ $entryExpiration + "`n Only logging mode: " `
					+ $loggingOnlyMode
				$audit = "False"
			}
		}
		catch {
			$audit = "False"
			$message = "Cannot get FTP Logon attempt settings"
		}
	}
	else {
		$message = "Skipped this benchmark - right now Web-Ftp-Server is not installed"
		$audit = "None"
	}

	@{
		Id      = "6.2"
		Task    = "Ensure FTP Logon attempt restrictions is enabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

#endregion

#region 7 Transport Encryption
#
# This section contains recommendations for configuring IIS protocols and cipher suites.

# 7.1
function Test-IISHSTSHeaderSet {
	<#
	.Synopsis
		Ensure HSTS Header is set
	.Description
		HTTP Strict Transport Security (HSTS) allows a site to inform the user agent to communicate with the site only over HTTPS. This header takes two parameters: max-age, "specifies the number of seconds, after the reception of the STS header field, during which the user agent regards the host (from whom the message was received) as a Known HSTS Host [speaks only HTTPS]"; and includeSubDomains. includeSubDomains is an optional directive that defines how this policy is applied to subdomains. If includeSubDomains is included in the header, it provides the following definition: this HSTS Policy also applies to any hosts whose domain names are subdomains of the Known HSTS Host's domain name.
	#>

	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration] $Configuration
	)

	process {
		#Ensure $Configuration is not empty
		if ($Configuration.RootSectionGroup) {
			$message = "HSTS Header not set"
			$audit = "False"

			$path = "system.webServer/httpProtocol"
			$section = $Configuration.GetSection($path)

			[array]$customHeaders = $section.GetCollection("customHeaders") `
			| Where-Object {
				$name = $_ | Get-IISConfigAttributeValue -AttributeName "name"
				$name -eq "Strict-Transport-Security"
			}

			if ($customHeaders.Count -eq 1) {
				$value = $customHeaders[0] | Get-IISConfigAttributeValue -AttributeName "value"
				$pattern = [regex]::new("max-age=(?<maxage>[0-9]*)")
				$match = $pattern.Match($value)

				if ($match.Success) {
					[int]$maxAge = $match.Groups["maxage"].Value
					if ($maxAge -eq 0) {
						$message = "Max-age should be at least be higher than 0. It is recommended to set max-age to at least 480 seconds. Max-age is set at $maxAge"
						$audit = "False"
					}
					elseif ($maxAge -lt 480) {
						$message = "It is recommended to set max-age to at least 480 seconds. Max-age is set at $maxAge"
						$audit = "Warning"
					}
					else {
						$message = $MESSAGE_ALLGOOD + ". Max-age is set at $maxAge"
						$audit = "True"
					}
				}
			}
		}
		else {
			$message = "Cannot read configuration file, the reference to the directory may not be correct or present"
			$audit = "Warning"
		}

		@{
			Id      = "7.1"
			Task    = "Ensure HSTS Header is set"
			Status  = $audit
			Message = $message
		} | Write-Output
	}

}

# 7.2
function Test-IISSSL2Disabled {
	<#
	.Synopsis
		Ensure SSLv2 is disabled
	.Description
		This protocol is not considered cryptographically secure. Disabling it is recommended. This protocol is disabled by default if the registry key is not present. A reboot is required for these changes to be reflected.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"

	# SSL is disabled by default
	# if $path exists, $path/server should also exist
	if ((Test-Path $path) -and (Test-Path "$path\Server")) {
		# Ensure the following key exists
		$Key = Get-Item "$path\Server"
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
			# Ensure it is set to 0
			if ($value -ne 0) {
				$message = "SSL 2.0 is enabled"
				$audit = "False"
			}
		}
	}

	@{
		Id      = "7.2"
		Task    = "Ensure SSLv2 is disabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.3
function Test-IISSSL3Disabled {
	<#
	.Synopsis
		Ensure SSLv3 is disabled
	.Description
		This protocol is not considered cryptographically secure. Disabling it is recommended.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"

	# SSL is disabled by default
	# if $path exists, $path/server should also exist
	if ((Test-Path $path) -and (Test-Path "$path\Server")) {
		# Ensure the following key exists
		$Key = Get-Item "$path\Server"
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
			# Ensure it is set to 0
			if ($value -ne 0) {
				$message = "SSL 3.0 is enabled"
				$audit = "False"
			}
		}
	}

	@{
		Id      = "7.3"
		Task    = "Ensure SSLv3 is disabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.4
function Test-IISTLSDisabled {
	<#
	.Synopsis
		Ensure TLS 1.0 is disabled
	.Description
		The PCI Data Security Standard 3.1 recommends disabling "early TLS" along with SSL:

		SSL and early TLS are not considered strong cryptography and cannot be used as a security control after June 30, 2016.
	#>

	$message = "TLS 1.0 is enabled"
	$audit = "False"

	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"

	# TLS 1.0 is enabled by default
	if (Test-Path $path) {
		# Ensure the following key exists
		$Key = Get-Item $path
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty $path | Select-Object -ExpandProperty "Enabled"
			# Ensure it is set to 0
			if ($value -eq 0) {
				$message = $MESSAGE_ALLGOOD
				$audit = "True"
			}
		}
		elseif ($null -ne $Key.GetValue("DisabledByDefault", $null)) {
			$value = Get-ItemProperty $path | Select-Object -ExpandProperty "DisabledByDefault"
			# Ensure it is set to 1
			if ($value -eq 1) {
				$message = $MESSAGE_ALLGOOD
				$audit = "True"
			}
		}
	}

	@{
		Id      = "7.4"
		Task    = "Ensure TLS 1.0 is disabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.5
function Test-IISTLS1_1Disabled {
	<#
	.Synopsis
		Ensure TLS 1.1 is disabled
	.Description
		TLS 1.1 is required for backward compatibility. Ensure you fully test your application to ensure that backwards compatibility is not needed. If it is, build in exceptions as necessary for backwards compatibility.
	#>

	$message = "TLS 1.1 is enabled"
	$audit = "False"


	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"

	# TLS is enabled by default
	if (Test-Path $path) {
		# Ensure the following key exists
		$Key = Get-Item $path
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty $path | Select-Object -ExpandProperty "Enabled"
			# Ensure it is set to 0
			if ($value -eq 0) {
				$message = $MESSAGE_ALLGOOD
				$audit = "True"
			}
		}
		elseif ($null -ne $Key.GetValue("DisabledByDefault", $null)) {
			$value = Get-ItemProperty $path | Select-Object -ExpandProperty "DisabledByDefault"
			# Ensure it is set to 1
			if ($value -eq 1) {
				$message = $MESSAGE_ALLGOOD
				$audit = "True"
			}
		}
	}

	@{
		Id      = "7.5"
		Task    = "Ensure TLS 1.1 is disabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.6
function Test-IISTLS1_2Enabled {
	<#
	.Synopsis
		Ensure TLS 1.2 is enabled
	.Description
		TLS 1.2 is the most recent and mature protocol for protecting the confidentiality and integrity of HTTP traffic. Enabling TLS 1.2 is recommended. This protocol is enabled by default if the registry key is not present. As with any registry changes, a reboot is required for changes to take effect.
	#>

	$message = $MESSAGE_ALLGOOD
	$audit = "True"

	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"

	# if $path exists, $path/server should also exist
	# TLS 1.2 is enabled by default
	if ((Test-Path $path) -and (Test-Path "$path\Server")) {
		# Ensure the following key exists
		$Key = Get-Item "$path\Server"
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
			if ($value -ne 1) {
				$message = "TLS 1.2 is disabled"
				$audit = "False"
			}
		}
		else {
			$message = "TLS 1.2 is disabled"
			$audit = "False"
		}

		if ($null -ne $Key.GetValue("DisabledByDefault", $null)) {
			# Get-ItemProperty returns a [UInt32]
			$value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "DisabledByDefault"
			if ($value -ne 0) {
				$message = "TLS 1.2 is disabled by default"
				$audit = "False"
			}
		}
		else {
			$message = "TLS 1.2 is disabled"
			$audit = "False"
		}
	}

	@{
		Id      = "7.6"
		Task    = "Ensure TLS 1.2 is enabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.7
function Test-IISNullCipherDisabled {
	<#
	.Synopsis
		Ensure NULL Cipher Suites is disabled
	.Description
		The NULL cipher does not provide data confidentiality or integrity. It is recommended that the NULL cipher be disabled.
	#>

	$message = "NULL cipher is enabled"
	$audit = "False"

	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL\"

	if (Test-Path $path) {
		$Key = Get-Item $path
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty $path | Select-Object -ExpandProperty "Enabled"
			if ($value -eq 0) {
				$message = $MESSAGE_ALLGOOD
				$audit = "True"
			}
		}
	}
	else {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"
	}

	@{
		Id      = "7.7"
		Task    = "Ensure NULL Cipher Suites is disabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.8
function Test-IISDESCipherDisabled {
	<#
	.Synopsis
		Ensure DES Cipher Suites is disabled
	.Description
		DES is a weak symmetric-key cipher. It is recommended that it be disabled.
	#>

	$message = "DES cipher is enabled"
	$audit = "False"

	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56\"

	if (Test-Path $path) {
		$Key = Get-Item $path
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty $path | Select-Object -ExpandProperty "Enabled"
			if ($value -eq 0) {
				$message = $MESSAGE_ALLGOOD
				$audit = "True"
			}
		}
	}
	else {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"
	}

	@{
		Id      = "7.8"
		Task    = "Ensure DES Cipher Suites is disabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.9
function Test-IISRC4CipherDisabled {
	<#
	.Synopsis
		Ensure RC4 Cipher Suites is disabled
	.Description
		RC4 is a stream cipher that has known practical attacks. It is recommended that RC4 be disabled. The only RC4 cipher enabled by default on Server 2012 and 2012 R2 is RC4 128/128.
	#>

	$rc4Ciphers = @("RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128")

	$index = 1
	foreach ($rc4Cipher in $rc4Ciphers) {
		$message = "$rc4Cipher cipher is enabled"
		$audit = "False"

		$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$rc4Cipher\"

		if (Test-Path $path) {
			$Key = Get-Item $path
			if ($null -ne $Key.GetValue("Enabled", $null)) {
				$value = Get-ItemProperty $path | Select-Object -ExpandProperty "Enabled"
				if ($value -eq 0) {
					$message = $MESSAGE_ALLGOOD
					$audit = "True"
				}
			}
		}
		else {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"
		}

		@{
			Id      = "7.9.$index"
			Task    = "Ensure RC4 Cipher Suites is disabled"
			Status  = $audit
			Message = $message
		} | Write-Output

		$index++
	}
}

# 7.10
function Test-IISAES128Disabled {
	<#
	.Synopsis
		Ensure AES 128/128 Cipher Suite is configured
	.Description
		Enabling AES 128/128 may be required for client compatibility. Enable or disable this cipher suite accordingly.
	#>

	$message = "AES 128/128 Cipher Suite is still enabled"
	$audit = "False"

	try {
		# Get-ItemProperty returns a [UInt32]
		$enabled = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128\" `
			-ErrorAction Stop `
		| Select-Object `
			-ExpandProperty Enabled

		if ($enabled -eq 0) {
			$message = $MESSAGE_ALLGOOD
			$audit = "True"
		}

	}
	catch {
		# do anything here
	}

	# If the key/value is not present,Triple AES 128/128 Cipher is disabled

	@{
		Id      = "7.10"
		Task    = "Ensure AES 128/128 Cipher Suite is disabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.11
function Test-IISAES256Enabled {
	<#
	.Synopsis
		Ensure AES 256/256 Cipher Suite is enabled
	.Description
		AES 256/256 is the most recent and mature cipher suite for protecting the confidentiality and integrity of HTTP traffic. Enabling AES 256/256 is recommended. This is enabled by default on Server 2012 and 2012 R2.
	#>

	$message = "AES 256/256 Cipher is disabled"
	$audit = "False"

	$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256\"

	if (Test-Path $path) {
		$Key = Get-Item $path
		if ($null -ne $Key.GetValue("Enabled", $null)) {
			$value = Get-ItemProperty $path | Select-Object -ExpandProperty "Enabled"
			if ($value -eq 0xffffffff) {
				$message = $MESSAGE_ALLGOOD
				$audit = "True"
			}
		}
	}
	else {
		$message = $MESSAGE_ALLGOOD
		$audit = "True"
	}

	@{
		Id      = "7.11"
		Task    = "Ensure AES 256/256 Cipher Suite is enabled"
		Status  = $audit
		Message = $message
	} | Write-Output
}

# 7.12
function Test-IISTLSCipherOrder {
	<#
	.Synopsis
		Ensure TLS Cipher Suite ordering is configured
	.Description
		Cipher suites are a named combination of authentication, encryption, message authentication code, and key exchange algorithms used for the security settings of a network connection using TLS protocol. Clients send a cipher list and a list of ciphers that it supports in order of preference to a server. The server then replies with the cipher suite that it selects from the client cipher suite list.
	#>

    try 
    {
		$regValue = Get-ItemProperty -ErrorAction Stop `
		-Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
		-Name "Functions"
		$reference = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
		$res = $regValue.Functions.GetType().Name
					
		$typeTable = @{
			"String" = "String Value"
			"Byte" = "Byte Value"
			"Int32" = "DWORD (32-bit) Value"
			"Int64" = "QWORD (64-bit) Value"
			"String[]" = "Multi-String Value"
		}
		$currentType = $typeTable[$res]
		$regValue = $regValue | Select-Object -ExpandProperty "Functions"
		if ($res -ne [String]) {
			@{
                Id      = "7.12"
                Task    = "Ensure TLS Cipher Suite ordering is correctly configured"
                Status = "False"
                Message = "Wrong Registry type! Registry type is '$currentType'. Expected: String Value"
            } | Write-Output
		}
		if ($regValue -ne $reference) {
			@{
                Id      = "7.12"
                Task    = "Ensure TLS Cipher Suite ordering is correctly configured"
                Status  = "False"
                Message = "Registry value is '$regValue'. To implement CIS recommendation, please consult <a href='https://www.tenable.com/audits/items/CIS_MS_IIS_10_v1.2.0_Level_2.audit:3a283f2bfffa27bf2edee4be256d3e08'>following tenable recommendations</a>"
            } | Write-Output
		}
    }
    catch [System.Management.Automation.PSArgumentException] {
        @{
            Id      = "7.12"
            Task    = "Ensure TLS Cipher Suite ordering is correctly configured"
            Status  = "False"
            Message = "Registry value not found."
        } | Write-Output
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        @{
            Id      = "7.12"
            Task    = "Ensure TLS Cipher Suite ordering is correctly configured"
            Status  = "False"
            Message = "Registry key not found."
        } | Write-Output
    }

    @{
		Id      = "7.12"
		Task    = "Ensure TLS Cipher Suite ordering is correctly configured"
		Status  = "True"
		Message = "Compliant"
	} | Write-Output
}


#endregion

#region Report Generation

function Get-IIS10SystemReport {
	# Section 1
	Test-IISUniqueSiteAppPool

	# Section 2
	Test-IISPasswordFormatNotClearMachineLevel
	Test-IISCredentialsNotStoredMachineLevel

	# Section 3
	Test-IISDeploymentMethodRetail
	Test-IISAspNetTracingDisabledMachineLevel

	# Section 4
	Test-IISIsapisNotAllowed
	Test-IISCgisNotAllowed

	# Section 5
	Test-IISAdvancedLoggingEnabled

	# Section 6
	Test-IISFtpRequestsEncrypted
	Test-IISFtpLogonAttemptRestriction

	# Section 7
	Test-IISSSL2Disabled
	Test-IISSSL3Disabled
	Test-IISTLSDisabled
	Test-IISTLS1_1Disabled
	Test-IISTLS1_2Enabled
	Test-IISNullCipherDisabled
	Test-IISDESCipherDisabled
	Test-IISRC4CipherDisabled
	Test-IISAES128Disabled
	Test-IISAES256Enabled
	Test-IISTLSCipherOrder
}

function Get-IIS10ApplicationHostReport {
	$Configuration = (Get-IISServerManager).GetApplicationHostConfiguration()

	# Section 1
	$Configuration | Test-IISDirectoryBrowsing
	$Configuration | Test-IISAnonymouseUserIdentity

	# Section 2
	$Configuration | Test-IISGlobalAuthorization
	$Configuration | Test-IISAuthenticatedPricipals
	$Configuration | Test-IISFormsAuthenticationSSL
	$Configuration | Test-IISFormsAuthenticationCookies
	$Configuration | Test-IISFormsAuthenticationProtection
	$Configuration | Test-IISPasswordFormatNotClear
	$Configuration | Test-IISCredentialsNotStored

	# Section 3
	$Configuration | Test-IISDebugOff
	$Configuration | Test-IISCustomErrorsNotOff
	$Configuration | Test-IISHttpErrorsHidden
	$Configuration | Test-IISAspNetTracingDisabled
	$Configuration | Test-IISCookielessSessionState

	# Section 4
	$Configuration | Test-IISMaxAllowedContentLength
	$Configuration | Test-IISMaxURLRequestFilter
	$Configuration | Test-IISMaxQueryStringRequestFilter
	$Configuration | Test-IISNonASCIICharURLForbidden
	$Configuration | Test-IISRejectDoubleEncodedRequests
	$Configuration | Test-IISHTTPTraceMethodeDisabled
	$Configuration | Test-IISBlockUnlistedFileExtensions
	$Configuration | Test-IISHandlerDenyWrite

	# Section 5

	# Section 6

	# Section 7
	$Configuration | Test-IISHSTSHeaderSet

}

function Get-VirtualPathAudit {
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Configuration]
		$Configuration
	)

	process {
		# Section 1
		$Configuration | Test-IISDirectoryBrowsing
		$Configuration | Test-IISAnonymouseUserIdentity

		# Section 2
		$Configuration | Test-IISGlobalAuthorization
		$Configuration | Test-IISAuthenticatedPricipals
		$Configuration | Test-IISFormsAuthenticationSSL
		$Configuration | Test-IISFormsAuthenticationCookies
		$Configuration | Test-IISFormsAuthenticationProtection
		$Configuration | Test-IISPasswordFormatNotClear
		$Configuration | Test-IISCredentialsNotStored

		# Section 3
		$Configuration | Test-IISDebugOff
		$Configuration | Test-IISCustomErrorsNotOff
		$Configuration | Test-IISHttpErrorsHidden
		$Configuration | Test-IISAspNetTracingDisabled
		$Configuration | Test-IISCookielessSessionState
		$Configuration | Test-IISCookiesHttpOnly

		# Section 4
		$Configuration | Test-IISMaxAllowedContentLength
		$Configuration | Test-IISMaxURLRequestFilter
		$Configuration | Test-IISMaxQueryStringRequestFilter
		$Configuration | Test-IISNonASCIICharURLForbidden
		$Configuration | Test-IISRejectDoubleEncodedRequests
		$Configuration | Test-IISHTTPTraceMethodeDisabled
		$Configuration | Test-IISBlockUnlistedFileExtensions
		$Configuration | Test-IISHandlerDenyWrite

		# Section 5

		# Section 6

		# Section 7
		$Configuration | Test-IISHSTSHeaderSet
	}
}

function Get-SiteAudit {
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Site]
		$Site
	)

	process {
		$AppPools = $Site.Applications.ApplicationPoolName | Sort-Object | Get-Unique | Get-IISAppPool

		# Section 1
		$Site | Test-IISVirtualDirPartition
		$Site | Test-IISHostHeaders
		$AppPools | Test-IISAppPoolIdentity

		# Section 2
		$Site | Test-IISTLSForBasicAuth

		# Section 3
		$Site | Test-IISMachineKeyValidation
		$Site | Test-IISMachineKeyValidationV45
		$Site | Test-IISDotNetTrustLevel

		# Section 4
		$Site | Test-IISDynamicIPRestrictionEnabled

		# Section 5
		$Site | Test-IISLogFileLocation
		$Site | Test-IISETWLoggingEnabled

		# Section 6
		

		# Section 7

	}
}

function Get-IISHostInformation {
	$infos = Get-CimInstance Win32_OperatingSystem
	$disk = Get-CimInstance Win32_LogicalDisk | Where-Object -Property DeviceID -eq "C:"

	$IISinstallPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InetStp").Installpath

	return [ordered]@{
		"Hostname" = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
		"Operating System" = $infos.Caption
		"Build Number" = $infos.BuildNumber
		"IIS Version" = (Get-ItemProperty -Path ("$IISinstallPath\w3wp.exe")).VersionInfo.ProductVersion
		"Free physical memory (GB)" = "{0:N3}" -f ($infos.FreePhysicalMemory / 1MB)
		"Free disk space (GB)" = "{0:N1}" -f ($disk.FreeSpace / 1GB)
	}
}

[Report] @{
	Title = "IIS 10 Benchmarks"
	ModuleName = "ATAPAuditor"
	BasedOn = "CIS Microsoft IIS 10 Benchmark, Version: 1.1.0, Date: 12-11-2018"
	HostInformation = Get-IISHostInformation
	Sections = @(
		[ReportSection] @{
			Title = "System Report"
			AuditInfos = Get-IIS10SystemReport
		}
		[ReportSection] @{
			Title = "ApplicationHost"
			AuditInfos = Get-IIS10ApplicationHostReport
		}
		foreach ($Site in Get-IISSite) {
			$VirtualPaths = $Site | Get-IISSiteVirtualPaths -AllVirtualDirectories

			[ReportSection] @{
				Title = "Full site report for: $($Site.Name)"
				AuditInfos = $Site | Get-SiteAudit
				SubSections = @(
					foreach ($VirtualPath in $VirtualPaths) {
						$Configuration = (Get-IISServerManager).GetWebConfiguration($Site.Name, $VirtualPath)

						[ReportSection]@{
							Title = "Report for: $VirtualPath"
							AuditInfos = $Configuration | Get-VirtualPathAudit
						}
					}
				)
			}
		}
	)
}
#endregion