Configuration IISAuditTestSetup {

	param(
		[string] $MySite1Folder = "C:\MySite1",
		[string] $MyApp1Folder = "$MySite1Folder\MyApp1",
		[string] $MyApp2Folder = "$MyApp1Folder\MyApp2",
		[string] $VD1Folder = "$MySite1Folder\VD1",
		[string] $VD2Folder = "$MyApp1Folder\VD2",
		[string] $VD3Folder = "$MyApp2Folder\VD3"

	)

	Import-DscResource -ModuleName PsDesiredStateConfiguration
	Import-DscResource -ModuleName xWebAdministration

	Node 'localhost' {

		WindowsFeature WebServer {
			Ensure = "Present"
			Name = "Web-Server"
		}

		xWebAppPool MySite1AppPool {
			Ensure = "Present"
			Name = "MySite1"
			State = "Started"
		}

		# Directory Path Setup
		File MySite1Folder {
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $MySite1Folder
		}

		File MyApp1Folder {
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $MyApp1Folder
		}

		File MyApp2Folder {
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $MyApp2Folder
		}

		File VD1Folder {
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $VD1Folder
		}

		File VD2Folder {
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $VD2Folder
		}

		File VD3Folder {
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $VD3Folder
		}

		# Website Setup
		xWebsite MySite1 {
			Ensure = "Present"
			Name = "MySite1"
			State = "Started"
			PhysicalPath = $MySite1Folder
			BindingInfo = @(
				MSFT_xWebBindingInformation {
					Protocol = "http"
					Port = "81"
				}
			)
			DependsOn = @("[WindowsFeature]WebServer", "[xWebAppPool]MySite1AppPool")
		}

		# WebApplication Setup
		xWebApplication MyApp1 {
			Ensure = "Present"
			Website = "MySite1"
			Name = "MyApp1"
			WebAppPool = "MySite1"
			PhysicalPath = $MyApp1Folder
			DependsOn = "[xWebsite]MySite1"
		}

		xWebApplication MyApp2 {
			Ensure = "Present"
			Website = "MySite1"
			Name = "MyApp1/MyApp2"
			WebAppPool = "MySite1"
			PhysicalPath = $MyApp2Folder
			DependsOn = "[xWebApplication]MyApp1"
		}

		# Virtual Directory setup
		xWebVirtualDirectory VD1 {
			Ensure = "Present"
			Name = "VD1"
			Website = "MySite1"
			WebApplication = ""
			PhysicalPath = $VD1Folder
			DependsOn = "[xWebApplication]MyApp1"
		}

		xWebVirtualDirectory VD2 {
			Ensure = "Present"
			Name = "VD2"
			Website = "MySite1"
			WebApplication = "MyApp1"
			PhysicalPath = $VD2Folder
			DependsOn = "[xWebApplication]MyApp1"
		}

		xWebVirtualDirectory VD3 {
			Ensure = "Present"
			Name = "VD3"
			Website = "MySite1"
			WebApplication = "MyApp1/MyApp2"
			PhysicalPath = $VD3Folder
			DependsOn = "[xWebApplication]MyApp2"
		}
	}
}

IISAuditTestSetup
Start-DscConfiguration ./IISAuditTestSetup -Wait -Verbose