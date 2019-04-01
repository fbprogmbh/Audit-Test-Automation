# Requirements for Microsoft Skype for Business 2016 DISA STIG V1R1
# Created at 03/25/2019 18:07:12

@{
	RegistrySettings = @(
		@{
			Id    = "DTOO420"
			Task  = "The ability to store user passwords in Skype must be disabled."
			Path  = "HKLM:\Software\Policies\Microsoft\office\16.0\lync"
			Name  = "savepassword"
			Value = 0
		}
		@{
			Id    = "DTOO421"
			Task  = "Session Initiation Protocol (SIP) security mode must be configured."
			Path  = "HKLM:\Software\Policies\Microsoft\office\16.0\lync"
			Name  = "enablesiphighsecuritymode"
			Value = 1
		}
		@{
			Id    = "DTOO422"
			Task  = "In the event a secure Session Initiation Protocol (SIP) connection fails, the connection must be restricted from resorting to the unencrypted HTTP."
			Path  = "HKLM:\Software\Policies\Microsoft\office\16.0\lync"
			Name  = "disablehttpconnect"
			Value = 1
		}
	)
}
