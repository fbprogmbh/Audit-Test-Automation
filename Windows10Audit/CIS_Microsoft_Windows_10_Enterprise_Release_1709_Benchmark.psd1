@{
	Version = "2.0"
	RegistrySettings = @(
		@{
			Id = "2.3.1.2"
			Task = "(L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "NoConnectedUser"
				ValueData = @{
					Operation = "equals"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.1.4"
			Task = "(L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "LimitBlankPasswordUse"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.2.1"
			Task = "(L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "SCENoApplyLegacyAuditPolicy"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.2.2"
			Task = "(L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "CrashOnAuditFail"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.4.1"
			Task = "(L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
				ValueName = "AllocateDASD"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "2.3.4.2"
			Task = "(L2) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
				ValueName = "AddPrinterDrivers"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.6.1"
			Task = "(L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
				ValueName = "RequireSignOrSeal"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.6.2"
			Task = "(L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
				ValueName = "SealSecureChannel"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.6.3"
			Task = "(L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
				ValueName = "SignSecureChannel"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.6.4"
			Task = "(L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
				ValueName = "DisablePasswordChange"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.6.5"
			Task = "(L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
						ValueName = "MaximumPasswordAge"
						ValueData = @{
							Operation = "greater than"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
						ValueName = "MaximumPasswordAge"
						ValueData = @{
							Operation = "less than or equal"
							Value = "30"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "2.3.6.6"
			Task = "(L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
				ValueName = "RequireStrongKey"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.7.1"
			Task = "(L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "DontDisplayLastUserName"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.7.2"
			Task = "(L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "DisableCAD"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.7.3"
			Task = "(BL) Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
						ValueName = "MaxDevicePasswordFailedAttempts"
						ValueData = @{
							Operation = "less than or equal"
							Value = "10"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
						ValueName = "MaxDevicePasswordFailedAttempts"
						ValueData = @{
							Operation = "greater than"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "2.3.7.4"
			Task = "(L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
						ValueName = "InactivityTimeoutSecs"
						ValueData = @{
							Operation = "less than or equal"
							Value = "900"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
						ValueName = "InactivityTimeoutSecs"
						ValueData = @{
							Operation = "not equal"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "2.3.7.5"
			Task = "(L1) Configure 'Interactive logon: Message text for users attempting to log on'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "LegalNoticeText"
				ValueData = @{
					Operation = "pattern match"
					Value = ".+"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "2.3.7.6"
			Task = "(L1) Configure 'Interactive logon: Message title for users attempting to log on'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "LegalNoticeCaption"
				ValueData = @{
					Operation = "pattern match"
					Value = ".+"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "2.3.7.7"
			Task = "(L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
				ValueName = "CachedLogonsCount"
				ValueData = @{
					Operation = "pattern match"
					Value = "^[43210]$"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "2.3.7.8"
			Task = "(L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
						ValueName = "PasswordExpiryWarning"
						ValueData = @{
							Operation = "less than or equal"
							Value = "14"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
						ValueName = "passwordexpirywarning"
						ValueData = @{
							Operation = "greater than or equal"
							Value = "5"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "2.3.7.9"
			Task = "(L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
				ValueName = "ScRemoveOption"
				ValueData = @{
					Operation = "pattern match"
					Value = "^(1|2|3)$"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "2.3.8.1"
			Task = "(L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
				ValueName = "RequireSecuritySignature"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.8.2"
			Task = "(L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
				ValueName = "EnableSecuritySignature"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.8.3"
			Task = "(L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
				ValueName = "EnablePlainTextPassword"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.9.1"
			Task = "(L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
						ValueName = "AutoDisconnect"
						ValueData = @{
							Operation = "less than or equal"
							Value = "15"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
						ValueName = "AutoDisconnect"
						ValueData = @{
							Operation = "not equal"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "2.3.9.2"
			Task = "(L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
				ValueName = "RequireSecuritySignature"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.9.3"
			Task = "(L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
				ValueName = "EnableSecuritySignature"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.9.4"
			Task = "(L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
				ValueName = "enableforcedlogoff"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.9.5"
			Task = "(L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
				ValueName = "SMBServerNameHardeningLevel"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.10.2"
			Task = "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "RestrictAnonymousSAM"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.10.3"
			Task = "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "RestrictAnonymous"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.10.4"
			Task = "(L1) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "DisableDomainCreds"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.10.5"
			Task = "(L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "EveryoneIncludesAnonymous"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.10.6"
			Task = "(L1) Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
				ValueName = "NullSessionPipes"
				ValueData = @{
					Operation = "equals"
					Value = ".+"
				}
				ValueType = "reg_multi_sz"
			}
		}
		@{
			Id = "2.3.10.7"
			Task = "(L1) Ensure 'Network access: Remotely accessible registry paths'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
				ValueName = "Machine"
				ValueData = @{
					Operation = "equals"
					Value = "^((System\\CurrentControlSet\\Control\\ProductOptions)|(System\\CurrentControlSet\\Control\\Server Applications)|(Software\\Microsoft\\Windows NT\\CurrentVersion))$"
				}
				ValueType = "reg_multi_sz"
			}
		}
		@{
			Id = "2.3.10.8"
			Task = "(L1) Ensure 'Network access: Remotely accessible registry paths and sub-paths'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
				ValueName = "Machine"
				ValueData = @{
					Operation = "equals"
					Value = "^((System\\CurrentControlSet\\Control\\Print\\Printers)|(System\\CurrentControlSet\\Services\\Eventlog)|(Software\\Microsoft\\OLAP Server)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Print)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows)|(System\\CurrentControlSet\\Control\\ContentIndex)|(System\\CurrentControlSet\\Control\\Terminal Server)|(System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig)|(System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib)|(System\\CurrentControlSet\\Services\\SysmonLog))$"
				}
				ValueType = "reg_multi_sz"
			}
		}
		@{
			Id = "2.3.10.9"
			Task = "(L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
				ValueName = "RestrictNullSessAccess"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.10.10"
			Task = "(L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
				ValueName = "restrictremotesam"
				ValueData = @{
					Operation = "equals"
					Value = "O:BAG:BAD:(A;;RC;;;BA)"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "2.3.10.11"
			Task = "(L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
						ValueName = "NullSessionShares"
						ValueData = $Null
						ValueType = $Null
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
						ValueName = "NullSessionShares"
						ValueData = @{
							Operation = "pattern match"
							Value = "^$"
						}
						ValueType = "reg_multi_sz"
					}
				)
			}
		}
		@{
			Id = "2.3.10.12"
			Task = "(L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "ForceGuest"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.1"
			Task = "(L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "UseMachineId"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.2"
			Task = "(L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
				ValueName = "AllowNullSessionFallback"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.3"
			Task = "(L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa\pku2u"
				ValueName = "AllowOnlineID"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.4"
			Task = "(L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
						ValueName = "SupportedEncryptionTypes"
						ValueData = @{
							Operation = "equals"
							Value = "2147483644"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
						ValueName = "SupportedEncryptionTypes"
						ValueData = @{
							Operation = "equals"
							Value = "2147483640"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "2.3.11.5"
			Task = "(L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "NoLMHash"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.7"
			Task = "(L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM&NTLM'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
				ValueName = "LmCompatibilityLevel"
				ValueData = @{
					Operation = "equals"
					Value = "5"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.8"
			Task = "(L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\LDAP"
				ValueName = "LDAPClientIntegrity"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.9"
			Task = "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
				ValueName = "NTLMMinClientSec"
				ValueData = @{
					Operation = "equals"
					Value = "537395200"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.11.10"
			Task = "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
				ValueName = "NTLMMinServerSec"
				ValueData = @{
					Operation = "equals"
					Value = "537395200"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.14.1"
			Task = "(L2) Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Cryptography"
				ValueName = "ForceKeyProtection"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.15.1"
			Task = "(L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel"
				ValueName = "ObCaseInsensitive"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.15.2"
			Task = "(L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Control\Session Manager"
				ValueName = "ProtectionMode"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.1"
			Task = "(L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "FilterAdministratorToken"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.2"
			Task = "(L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "EnableUIADesktopToggle"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.3"
			Task = "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "ConsentPromptBehaviorAdmin"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.4"
			Task = "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "ConsentPromptBehaviorUser"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.5"
			Task = "(L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "EnableInstallerDetection"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.6"
			Task = "(L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "EnableSecureUIAPaths"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.7"
			Task = "(L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "EnableLUA"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.8"
			Task = "(L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "PromptOnSecureDesktop"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "2.3.17.9"
			Task = "(L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "EnableVirtualization"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.1"
			Task = "(L2) Ensure 'Bluetooth Handsfree Service (BthHFSrv)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\BthHFSrv"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.2"
			Task = "(L2) Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.3"
			Task = "(L1) Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.4"
			Task = "(L2) Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.5"
			Task = "(L2) Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.6"
			Task = "(L1) Ensure 'HomeGroup Listener (HomeGroupListener)' is set to 'Disabled'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupListener"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupListener"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.7"
			Task = "(L1) Ensure 'HomeGroup Provider (HomeGroupProvider)' is set to 'Disabled'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupProvider"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\HomeGroupProvider"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.8"
			Task = "(L1) Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.9"
			Task = "(L1) Ensure 'Infrared monitor service (irmon)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.10"
			Task = "(L1) Ensure 'Internet Connection Sharing (ICS) (SharedAccess) ' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.11"
			Task = "(L2) Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.12"
			Task = "(L1) Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.13"
			Task = "(L1) Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.14"
			Task = "(L2) Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.15"
			Task = "(L2) Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.16"
			Task = "(L2) Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.17"
			Task = "(L2) Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.18"
			Task = "(L2) Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.19"
			Task = "(L2) Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.20"
			Task = "(L2) Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.21"
			Task = "(L2) Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.22"
			Task = "(L2) Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.23"
			Task = "(L2) Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.24"
			Task = "(L1) Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.25"
			Task = "(L2) Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.26"
			Task = "(L1) Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.27"
			Task = "(L2) Ensure 'Server (LanmanServer)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.28"
			Task = "(L1) Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.29"
			Task = "(L2) Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.30"
			Task = "(L1) Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.31"
			Task = "(L1) Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.32"
			Task = "(L1) Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.33"
			Task = "(L2) Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.34"
			Task = "(L2) Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.35"
			Task = "(L1) Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "5.36"
			Task = "(L1) Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.37"
			Task = "(L2) Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.38"
			Task = "(L2) Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.39"
			Task = "(L2) Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.40"
			Task = "(L2) Ensure 'Windows Store Install Service (InstallService)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\InstallService"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.41"
			Task = "(L1) Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"
						ValueName = "Start"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"
						ValueName = "Start"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "5.42"
			Task = "(L1) Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.43"
			Task = "(L1) Ensure 'Xbox Game Monitoring (xbgm)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\xbgm"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.44"
			Task = "(L1) Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.45"
			Task = "(L1) Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "5.46"
			Task = "(L1) Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.1.1"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
				ValueName = "EnableFirewall"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.1.2"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
				ValueName = "DefaultInboundAction"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.1.3"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
				ValueName = "DefaultOutboundAction"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.1.4"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
				ValueName = "DisableNotifications"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.1.5"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
				ValueName = "LogFilePath"
				ValueData = @{
					Operation = "equals"
					Value = "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "9.1.6"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
				ValueName = "LogFileSize"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "16384"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.1.7"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
				ValueName = "LogDroppedPackets"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.1.8"
			Task = "(L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
				ValueName = "LogSuccessfulConnections"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.2.1"
			Task = "(L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
				ValueName = "EnableFirewall"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.2.2"
			Task = "(L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
				ValueName = "DefaultInboundAction"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.2.3"
			Task = "(L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
				ValueName = "DefaultOutboundAction"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.2.4"
			Task = "(L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
				ValueName = "DisableNotifications"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.2.5"
			Task = "(L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
				ValueName = "LogFilePath"
				ValueData = @{
					Operation = "equals"
					Value = "%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "9.2.6"
			Task = "(L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
				ValueName = "LogFileSize"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "16384"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.2.7"
			Task = "(L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
				ValueName = "LogDroppedPackets"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.2.8"
			Task = "(L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
				ValueName = "LogSuccessfulConnections"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.1"
			Task = "(L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
				ValueName = "EnableFirewall"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.2"
			Task = "(L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
				ValueName = "DefaultInboundAction"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.3"
			Task = "(L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
				ValueName = "DefaultOutboundAction"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.4"
			Task = "(L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
				ValueName = "DisableNotifications"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.5"
			Task = "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
				ValueName = "AllowLocalPolicyMerge"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.6"
			Task = "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
				ValueName = "AllowLocalIPsecPolicyMerge"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.7"
			Task = "(L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
				ValueName = "LogFilePath"
				ValueData = @{
					Operation = "equals"
					Value = "%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "9.3.8"
			Task = "(L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
				ValueName = "LogFileSize"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "16384"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.9"
			Task = "(L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
				ValueName = "LogDroppedPackets"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "9.3.10"
			Task = "(L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
				ValueName = "LogSuccessfulConnections"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.1.1.1"
			Task = "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
				ValueName = "NoLockScreenCamera"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.1.1.2"
			Task = "(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
				ValueName = "NoLockScreenSlideshow"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.1.2.2"
			Task = "(L1) Ensure 'Allow input personalization' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
				ValueName = "AllowInputPersonalization"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.1.3"
			Task = "(L2) Ensure 'Allow Online Tips' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
				ValueName = "AllowOnlineTips"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.2.1"
			Task = "(L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
						ValueName = "DllName"
						ValueData = @{
							Operation = "equals"
							Value = "C:\Program Files\LAPS\CSE\AdmPwd.dll"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
						ValueName = "DllName"
						ValueData = @{
							Operation = "equals"
							Value = "C:\Program Files\LAPS\CSE\AdmPwd.dll"
						}
						ValueType = "reg_expand_sz"
					}
				)
			}
		}
		@{
			Id = "18.2.2"
			Task = "(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
				ValueName = "PwdExpirationProtectionEnabled"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.2.3"
			Task = "(L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
				ValueName = "AdmPwdEnabled"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.2.4"
			Task = "(L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
				ValueName = "PasswordComplexity"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.2.5"
			Task = "(L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
				ValueName = "PasswordLength"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "15"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.2.6"
			Task = "(L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
				ValueName = "PasswordAgeDays"
				ValueData = @{
					Operation = "less than or equal"
					Value = "30"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.3.1"
			Task = "(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "LocalAccountTokenFilterPolicy"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.3.2"
			Task = "(L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
				ValueName = "Start"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.3.3"
			Task = "(L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
				ValueName = "SMB1"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.3.4"
			Task = "(L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
				ValueName = "DisableExceptionChainValidation"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.3.5"
			Task = "(L1) Ensure 'Turn on Windows Defender protection against Potentially Unwanted Applications' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
				ValueName = "MpEnablePus"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.3.6"
			Task = "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
				ValueName = "UseLogonCredential"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.1"
			Task = "(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
				ValueName = "AutoAdminLogon"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.4.2"
			Task = "(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters"
				ValueName = "DisableIPSourceRouting"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.3"
			Task = "(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
				ValueName = "DisableIPSourceRouting"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.4"
			Task = "(L2) Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\RasMan\Parameters"
				ValueName = "disablesavepassword"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.5"
			Task = "(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
				ValueName = "EnableICMPRedirect"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.6"
			Task = "(L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
				ValueName = "KeepAliveTime"
				ValueData = @{
					Operation = "equals"
					Value = "300000"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.7"
			Task = "(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters"
				ValueName = "nonamereleaseondemand"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.8"
			Task = "(L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
				ValueName = "PerformRouterDiscovery"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.9"
			Task = "(L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
				ValueName = "SafeDllSearchMode"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.10"
			Task = "(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
				ValueName = "ScreenSaverGracePeriod"
				ValueData = @{
					Operation = "less than or equal"
					Value = "5"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.4.11"
			Task = "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\TCPIP6\Parameters"
				ValueName = "tcpmaxdataretransmissions"
				ValueData = @{
					Operation = "equals"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.12"
			Task = "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
				ValueName = "tcpmaxdataretransmissions"
				ValueData = @{
					Operation = "equals"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.4.13"
			Task = "(L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
				ValueName = "WarningLevel"
				ValueData = @{
					Operation = "less than or equal"
					Value = "90"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.4.1"
			Task = "(L1) Set 'NetBIOS node type' to 'P-node' (Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)')"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters"
				ValueName = "NodeType"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.4.2"
			Task = "(L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
				ValueName = "EnableMulticast"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.5.1"
			Task = "(L2) Ensure 'Enable Font Providers' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
				ValueName = "EnableFontProviders"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.8.1"
			Task = "(L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
				ValueName = "AllowInsecureGuestAuth"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.9.1"
			Task = "(L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "AllowLLTDIOOnDomain"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "ProhibitLLTDIOOnPrivateNet"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "EnableLLTDIO"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "AllowLLTDIOOnPublicNet"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.5.9.2"
			Task = "(L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "AllowRspndrOnDomain"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "ProhibitRspndrOnPrivateNet"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "EnableRspndr"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
						ValueName = "AllowRspndrOnPublicNet"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.5.10.2"
			Task = "(L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Peernet"
				ValueName = "Disabled"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.11.2"
			Task = "(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
				ValueName = "NC_AllowNetBridge_NLA"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.11.3"
			Task = "(L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
				ValueName = "NC_ShowSharedAccessUI"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.11.4"
			Task = "(L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Network Connections"
				ValueName = "NC_StdDomainUserSetLocation"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.14.1"
			Task = "(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with `"Require Mutual Authentication`" and `"Require Integrity`" set for all NETLOGON and SYSVOL shares'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
						ValueName = "\\*\NETLOGON"
						ValueData = @{
							Operation = "pattern match"
							Value = "[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
						ValueName = "\\*\SYSVOL"
						ValueData = @{
							Operation = "pattern match"
							Value = "[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1"
						}
						ValueType = "reg_sz"
					}
				)
			}
		}
		@{
			Id = "18.5.19.2.1"
			Task = "(L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
				ValueName = "DisabledComponents"
				ValueData = @{
					Operation = "equals"
					Value = "255"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.20.1"
			Task = "(L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars"
						ValueName = "EnableRegistrars"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars"
						ValueName = "DisableWPDRegistrar"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars"
						ValueName = "DisableFlashConfigRegistrar"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars"
						ValueName = "DisableInBand802DOT11Registrar"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars"
						ValueName = "DisableUPnPRegistrar"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.5.20.2"
			Task = "(L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI"
				ValueName = "DisableWcnUi"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.21.1"
			Task = "(L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
				ValueName = "fMinimizeConnections"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.21.2"
			Task = "(L1) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
				ValueName = "fBlockNonDomain"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.5.23.2.1"
			Task = "(L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
				ValueName = "AutoConnectAllowedOEM"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.3.1"
			Task = "(L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
				ValueName = "ProcessCreationIncludeCmdLine_Enabled"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.4.1"
			Task = "(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
				ValueName = "AllowProtectedCreds"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.5.1"
			Task = "(NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
				ValueName = "EnableVirtualizationBasedSecurity"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.5.2"
			Task = "(NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
				ValueName = "RequirePlatformSecurityFeatures"
				ValueData = @{
					Operation = "equals"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.5.3"
			Task = "(NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
				ValueName = "HypervisorEnforcedCodeIntegrity"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.5.4"
			Task = "(NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
				ValueName = "HVCIMATRequired"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.5.5"
			Task = "(NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
				ValueName = "LsaCfgFlags"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.7.1.1"
			Task = "(BL) Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
				ValueName = "DenyDeviceIDs"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.7.1.2"
			Task = "(BL) Ensure 'Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs' is set to 'PCI\CC_0C0A'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
				ValueName = "1"
				ValueData = @{
					Operation = "equals"
					Value = "PCI\CC_0C0A"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.8.7.1.3"
			Task = "(BL) Ensure 'Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed.' is set to 'True' (checked)"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
				ValueName = "DenyDeviceIDsRetroactive"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.7.1.4"
			Task = "(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
				ValueName = "DenyDeviceClasses"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.7.1.5"
			Task = "(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
						ValueName = "\d+"
						ValueData = @{
							Operation = "equals"
							Value = "{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
						ValueName = "\d+"
						ValueData = @{
							Operation = "equals"
							Value = "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
						ValueName = "\d+"
						ValueData = @{
							Operation = "equals"
							Value = "{c06ff265-ae09-48f0-812c-16753d7cba83}"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
						ValueName = "\d+"
						ValueData = @{
							Operation = "equals"
							Value = "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
						}
						ValueType = "reg_sz"
					}
				)
			}
		}
		@{
			Id = "18.8.7.1.6"
			Task = "(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.' is set to 'True' (checked)"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
				ValueName = "DenyDeviceClassesRetroactive"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.14.1"
			Task = "(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Policies\EarlyLaunch"
				ValueName = "DriverLoadPolicy"
				ValueData = @{
					Operation = "equals"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.21.2"
			Task = "(L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
				ValueName = "NoBackgroundPolicy"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.21.3"
			Task = "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
				ValueName = "NoGPOListChanges"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.21.4"
			Task = "(L1) Ensure 'Continue experiences on this device' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
				ValueName = "EnableCdp"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.21.5"
			Task = "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "None"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "DisableBkGndGroupPolicy"
				ValueData = $Null
				ValueType = $Null
			}
		}
		@{
			Id = "18.8.22.1.1"
			Task = "(L2) Ensure 'Turn off access to the Store' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
				ValueName = "NoUseStoreOpenWith"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.2"
			Task = "(L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
				ValueName = "DisableWebPnPDownload"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.3"
			Task = "(L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\TabletPC"
				ValueName = "PreventHandwritingDataSharing"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.4"
			Task = "(L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"
				ValueName = "PreventHandwritingErrorReports"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.5"
			Task = "(L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard"
				ValueName = "ExitOnMSICW"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.6"
			Task = "(L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
				ValueName = "NoWebServices"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.7"
			Task = "(L1) Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
				ValueName = "DisableHTTPPrinting"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.8"
			Task = "(L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control"
				ValueName = "NoRegistration"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.9"
			Task = "(L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\SearchCompanion"
				ValueName = "DisableContentFileUpdates"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.10"
			Task = "(L2) Ensure 'Turn off the `"Order Prints`" picture task' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
				ValueName = "NoOnlinePrintsWizard"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.11"
			Task = "(L2) Ensure 'Turn off the `"Publish to Web`" task for files and folders' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
				ValueName = "NoPublishingWizard"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.12"
			Task = "(L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Messenger\Client"
				ValueName = "CEIP"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.13"
			Task = "(L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\SQMClient\Windows"
				ValueName = "CEIPEnable"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.22.1.14"
			Task = "(L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting"
						ValueName = "Disabled"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
						ValueName = "DoReport"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.8.25.1"
			Task = "(L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
						ValueName = "DevicePKInitBehavior"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
						ValueName = "DevicePKInitEnabled"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.8.26.1"
			Task = "(L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Control Panel\International"
				ValueName = "BlockUserInputMethodsForSignIn"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.27.1"
			Task = "(L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
				ValueName = "BlockUserFromShowingAccountDetailsOnSignin"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.27.2"
			Task = "(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\System"
				ValueName = "DontDisplayNetworkSelectionUI"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.27.3"
			Task = "(L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\System"
				ValueName = "DontEnumerateConnectedUsers"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.27.4"
			Task = "(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\System"
				ValueName = "EnumerateLocalUsers"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.27.5"
			Task = "(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\System"
				ValueName = "DisableLockScreenAppNotifications"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.27.6"
			Task = "(L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\System"
				ValueName = "BlockDomainPicturePassword"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.27.7"
			Task = "(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\System"
				ValueName = "AllowDomainPINLogon"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.33.6.1"
			Task = "(L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
				ValueName = "DCSettingIndex"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.33.6.2"
			Task = "(L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
				ValueName = "ACSettingIndex"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.33.6.3"
			Task = "(BL) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
				ValueName = "DCSettingIndex"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.33.6.4"
			Task = "(BL) Ensure 'Allow standby states (S1-S3) when sleeping (plugged in)' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
				ValueName = "ACSettingIndex"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.33.6.5"
			Task = "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
				ValueName = "DCSettingIndex"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.33.6.6"
			Task = "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
				ValueName = "ACSettingIndex"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.35.1"
			Task = "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fAllowUnsolicited"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.35.2"
			Task = "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fAllowToGetHelp"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.36.1"
			Task = "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc"
				ValueName = "EnableAuthEpResolution"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.36.2"
			Task = "(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc"
				ValueName = "RestrictRemoteClients"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.44.5.1"
			Task = "(L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
				ValueName = "DisableQueryRemoteServer"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.44.11.1"
			Task = "(L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
				ValueName = "ScenarioExecutionEnabled"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.46.1"
			Task = "(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo"
				ValueName = "DisabledByGroupPolicy"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.49.1.1"
			Task = "(L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
				ValueName = "Enabled"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.8.49.1.2"
			Task = "(L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
				ValueName = "Enabled"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.4.1"
			Task = "(L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
				ValueName = "AllowSharedLocalAppData"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.6.1"
			Task = "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "MSAOptional"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.6.2"
			Task = "(L2) Ensure 'Block launching Windows Store apps with Windows Runtime API access from hosted content.' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "BlockHostedAppAccessWinRT"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.8.1"
			Task = "(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
				ValueName = "NoAutoplayfornonVolume"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.8.2"
			Task = "(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
				ValueName = "NoAutorun"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.8.3"
			Task = "(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
				ValueName = "NoDriveTypeAutoRun"
				ValueData = @{
					Operation = "equals"
					Value = "255"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.10.1.1"
			Task = "(L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
				ValueName = "EnhancedAntiSpoofing"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.1"
			Task = "(BL) Ensure 'Allow access to BitLocker-protected fixed data drives from earlier versions of Windows' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "FDVDiscoveryVolumeType"
				ValueData = @{
					Operation = "equals"
					Value = "<none>"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.11.1.2"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVRecovery"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.3"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVManageDRA"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.4"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVRecoveryPassword"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.5"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVRecoveryKey"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.6"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVHideRecoveryPage"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.7"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVActiveDirectoryBackup"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.8"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVActiveDirectoryInfoToStore"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.9"
			Task = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVRequireActiveDirectoryBackup"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.10"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for fixed data drives' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVHardwareEncryption"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.11"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for fixed data drives: Use BitLocker software-based encryption when hardware encryption is not available' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVAllowSoftwareEncryptionFailover"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.12"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for fixed data drives: Restrict encryption algorithms and cipher suites allowed for hardware-based encryption' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVRestrictHardwareEncryptionAlgorithms"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.13"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for fixed data drives: Restrict crypto algorithms or cipher suites to the following:' is set to 'Enabled: 2.16.840.1.101.3.4.1.2;2.16.840.1.101.3.4.1.42'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "FDVAllowedHardwareEncryptionAlgorithms"
				ValueData = @{
					Operation = "equals"
					Value = "2.16.840.1.101.3.4.1.2;2.16.840.1.101.3.4.1.42"
				}
				ValueType = "reg_expand_sz"
			}
		}
		@{
			Id = "18.9.11.1.14"
			Task = "(BL) Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "FDVPassphrase"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.15"
			Task = "(BL) Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "FDVAllowUserCert"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.1.16"
			Task = "(BL) Ensure 'Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "FDVEnforceUserCert"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.1"
			Task = "(BL) Ensure 'Allow enhanced PINs for startup' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "UseEnhancedPin"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.2"
			Task = "(BL) Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "OSAllowSecureBootForIntegrity"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.3"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSRecovery"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.4"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSManageDRA"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.5"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSRecoveryPassword"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.6"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSRecoveryKey"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.7"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSHideRecoveryPage"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.8"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSActiveDirectoryBackup"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.9"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSActiveDirectoryInfoToStore"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.10"
			Task = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSRequireActiveDirectoryBackup"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.11"
			Task = "(BL) Ensure 'Configure minimum PIN length for startup' is set to 'Enabled: 7 or more characters'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "MinimumPIN"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "7"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.12"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSHardwareEncryption"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.13"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for operating system drives: Use BitLocker software-based encryption when hardware encryption is not available' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSAllowSoftwareEncryptionFailover"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.14"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for operating system drives: Restrict encryption algorithms and cipher suites allowed for hardware-based encryption' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSRestrictHardwareEncryptionAlgorithms"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.15"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for operating system drives: Restrict crypto algorithms or cipher suites to the following:' is set to 'Enabled: 2.16.840.1.101.3.4.1.2;2.16.840.1.101.3.4.1.42'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "OSAllowedHardwareEncryptionAlgorithms"
				ValueData = @{
					Operation = "equals"
					Value = "2.16.840.1.101.3.4.1.2;2.16.840.1.101.3.4.1.42"
				}
				ValueType = "reg_expand_sz"
			}
		}
		@{
			Id = "18.9.11.2.16"
			Task = "(BL) Ensure 'Configure use of passwords for operating system drives' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "OSPassphrase"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.17"
			Task = "(BL) Ensure 'Require additional authentication at startup' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "UseAdvancedStartup"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.18"
			Task = "(BL) Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "EnableBDEWithNoTPM"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.19"
			Task = "(BL) Ensure 'Require additional authentication at startup: Configure TPM startup:' is set to 'Enabled: Do not allow TPM'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "UseTPM"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.20"
			Task = "(BL) Ensure 'Require additional authentication at startup: Configure TPM startup PIN:' is set to 'Enabled: Require startup PIN with TPM'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "UseTPMPIN"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.21"
			Task = "(BL) Ensure 'Require additional authentication at startup: Configure TPM startup key:' is set to 'Enabled: Do not allow startup key with TPM'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "UseTPMKey"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.2.22"
			Task = "(BL) Ensure 'Require additional authentication at startup: Configure TPM startup key and PIN:' is set to 'Enabled: Do not allow startup key and PIN with TPM'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "UseTPMKeyPIN"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.1"
			Task = "(BL) Ensure 'Allow access to BitLocker-protected removable data drives from earlier versions of Windows' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "RDVDiscoveryVolumeType"
				ValueData = @{
					Operation = "equals"
					Value = "<none>"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.11.3.2"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVRecovery"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.3"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVManageDRA"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.4"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVRecoveryPassword"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.5"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVRecoveryKey"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.6"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVHideRecoveryPage"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.7"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVActiveDirectoryBackup"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.8"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVActiveDirectoryInfoToStore"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.9"
			Task = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVRequireActiveDirectoryBackup"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.10"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for removable data drives' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVHardwareEncryption"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.11"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for removable data drives: Use BitLocker software-based encryption when hardware encryption is not available' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVAllowSoftwareEncryptionFailover"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.12"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for removable data drives: Restrict encryption algorithms and cipher suites allowed for hardware-based encryption' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVRestrictHardwareEncryptionAlgorithms"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.13"
			Task = "(BL) Ensure 'Configure use of hardware-based encryption for removable data drives: Restrict crypto algorithms or cipher suites to the following:' is set to 'Enabled: 2.16.840.1.101.3.4.1.2;2.16.840.1.101.3.4.1.42'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "RDVAllowedHardwareEncryptionAlgorithms"
				ValueData = @{
					Operation = "equals"
					Value = "2.16.840.1.101.3.4.1.2;2.16.840.1.101.3.4.1.42"
				}
				ValueType = "reg_expand_sz"
			}
		}
		@{
			Id = "18.9.11.3.14"
			Task = "(BL) Ensure 'Configure use of passwords for removable data drives' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "RDVPassphrase"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.15"
			Task = "(BL) Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "RDVAllowUserCert"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.16"
			Task = "(BL) Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "RDVEnforceUserCert"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.17"
			Task = "(BL) Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
				ValueName = "RDVDenyWriteAccess"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.3.18"
			Task = "(BL) Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\FVE"
				ValueName = "RDVDenyCrossOrg"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.11.4"
			Task = "(BL) Ensure 'Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later)' is set to 'Enabled: XTS-AES 256-bit'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
						ValueName = "EncryptionMethodWithXtsFdv"
						ValueData = @{
							Operation = "equals"
							Value = "7"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
						ValueName = "EncryptionMethodWithXtsRdv"
						ValueData = @{
							Operation = "equals"
							Value = "4"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
						ValueName = "EncryptionMethodWithXtsOs"
						ValueData = @{
							Operation = "equals"
							Value = "7"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.11.5"
			Task = "(BL) Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
				ValueName = "DisableExternalDMAUnderLock"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.12.1"
			Task = "(L2) Ensure 'Allow Use of Camera' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
				ValueName = "AllowCamera"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.13.1"
			Task = "(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
				ValueName = "DisableWindowsConsumerFeatures"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.14.1"
			Task = "(L1) Ensure 'Require pin for pairing' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
				ValueName = "RequirePinForPairing"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.15.1"
			Task = "(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\CredUI"
				ValueName = "DisablePasswordReveal"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.15.2"
			Task = "(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI"
				ValueName = "EnumerateAdministrators"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.16.1"
			Task = "(L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
						ValueName = "AllowTelemetry"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
						ValueName = "AllowTelemetry"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.16.2"
			Task = "(L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
				ValueName = "DisableEnterpriseAuthProxy"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.16.3"
			Task = "(L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
				ValueName = "EnableConfigFlighting"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.16.4"
			Task = "(L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
				ValueName = "DoNotShowFeedbackNotifications"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.16.5"
			Task = "(L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
				ValueName = "AllowBuildPreview"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.17.1"
			Task = "(L1) Ensure 'Download Mode' is NOT set to 'Enabled: Internet'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization"
				ValueName = "DODownloadMode"
				ValueData = @{
					Operation = "not equal"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.26.1.1"
			Task = "(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application"
				ValueName = "Retention"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.26.1.2"
			Task = "(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application"
				ValueName = "MaxSize"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "32768"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.26.2.1"
			Task = "(L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security"
				ValueName = "Retention"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.26.2.2"
			Task = "(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security"
				ValueName = "MaxSize"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "196608"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.26.3.1"
			Task = "(L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup"
				ValueName = "Retention"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.26.3.2"
			Task = "(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup"
				ValueName = "MaxSize"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "32768"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.26.4.1"
			Task = "(L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System"
				ValueName = "Retention"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.26.4.2"
			Task = "(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System"
				ValueName = "MaxSize"
				ValueData = @{
					Operation = "greater than or equal"
					Value = "32768"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.30.2"
			Task = "(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
				ValueName = "NoDataExecutionPrevention"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.30.3"
			Task = "(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
				ValueName = "NoHeapTerminationOnCorruption"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.30.4"
			Task = "(L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
				ValueName = "PreXPSP2ShellProtocolBehavior"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.35.1"
			Task = "(L1) Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\HomeGroup"
				ValueName = "DisableHomeGroup"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.39.2"
			Task = "(L2) Ensure 'Turn off location' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
				ValueName = "DisableLocation"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.43.1"
			Task = "(L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
				ValueName = "AllowMessageSync"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.44.1"
			Task = "(L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
				ValueName = "DisableUserAuth"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.1"
			Task = "(L2) Ensure 'Allow Address bar drop-down list suggestions' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI"
				ValueName = "ShowOneBox"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.2"
			Task = "(L2) Ensure 'Allow Adobe Flash' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons"
				ValueName = "FlashPlayerEnabled"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.3"
			Task = "(L2) Ensure 'Allow InPrivate Browsing' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
				ValueName = "AllowInPrivate"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.4"
			Task = "(L1) Ensure 'Configure cookies' is set to 'Enabled: Block only 3rd-party cookies' or higher"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
				ValueName = "Cookies"
				ValueData = @{
					Operation = "less than or equal"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.5"
			Task = "(L1) Ensure 'Configure Password Manager' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
				ValueName = "FormSuggest Passwords"
				ValueData = @{
					Operation = "equals"
					Value = "no"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.45.6"
			Task = "(L2) Ensure 'Configure Pop-up Blocker' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
				ValueName = "AllowPopups"
				ValueData = @{
					Operation = "equals"
					Value = "yes"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "18.9.45.7"
			Task = "(L2) Ensure 'Configure search suggestions in Address bar' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes"
				ValueName = "ShowSearchSuggestionsGlobal"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.8"
			Task = "(L1) Ensure 'Configure the Adobe Flash Click-to-Run setting' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Security"
				ValueName = "FlashClickToRunMode"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.9"
			Task = "(L2) Ensure 'Prevent access to the about:flags page in Microsoft Edge' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
				ValueName = "PreventAccessToAboutFlagsInMicrosoftEdge"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.45.10"
			Task = "(L2) Ensure 'Prevent using Localhost IP address for WebRTC' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
				ValueName = "HideLocalHostIP"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.52.1"
			Task = "(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\OneDrive"
				ValueName = "DisableFileSyncNGSC"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.57.1"
			Task = "(L2) Ensure 'Turn off Push To Install service' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
				ValueName = "DisablePushToInstall"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.2.2"
			Task = "(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "DisablePasswordSaving"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.2.1"
			Task = "(L2) Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fDenyTSConnections"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.3.1"
			Task = "(L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fDisableCcm"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.3.2"
			Task = "(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fDisableCdm"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.3.3"
			Task = "(L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fDisableLPT"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.3.4"
			Task = "(L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fDisablePNPRedir"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.9.1"
			Task = "(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fPromptForPassword"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.9.2"
			Task = "(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "fEncryptRPCTraffic"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.9.3"
			Task = "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "MinEncryptionLevel"
				ValueData = @{
					Operation = "equals"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.10.1"
			Task = "(L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
						ValueName = "MaxIdleTime"
						ValueData = @{
							Operation = "less than or equal"
							Value = "900000"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
						ValueName = "MaxIdleTime"
						ValueData = @{
							Operation = "not equal"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.58.3.10.2"
			Task = "(L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "MaxDisconnectionTime"
				ValueData = @{
					Operation = "equals"
					Value = "60000"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.11.1"
			Task = "(L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "DeleteTempDirsOnExit"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.58.3.11.2"
			Task = "(L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
				ValueName = "PerSessionTempDir"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.59.1"
			Task = "(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
				ValueName = "DisableEnclosureDownload"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.60.2"
			Task = "(L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
						ValueName = "AllowCloudSearch"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
						ValueName = "AllowCloudSearch"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "18.9.60.3"
			Task = "(L1) Ensure 'Allow Cortana' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
				ValueName = "AllowCortana"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.60.4"
			Task = "(L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
				ValueName = "AllowCortanaAboveLock"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.60.5"
			Task = "(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
				ValueName = "AllowIndexingEncryptedStoresOrItems"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.60.6"
			Task = "(L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
				ValueName = "AllowSearchToUseLocation"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.65.1"
			Task = "(L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
				ValueName = "NoGenTicket"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.68.1"
			Task = "(L2) Ensure 'Disable all apps from Windows Store' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
				ValueName = "DisableStoreApps"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.68.2"
			Task = "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
				ValueName = "AutoDownload"
				ValueData = @{
					Operation = "equals"
					Value = "4"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.68.3"
			Task = "(L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
				ValueName = "DisableOSUpgrade"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.68.4"
			Task = "(L2) Ensure 'Turn off the Store application' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
				ValueName = "RemoveWindowsStore"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.3.1"
			Task = "(L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
				ValueName = "LocalSettingOverrideSpynetReporting"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.3.2"
			Task = "(L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"
						ValueName = "SpynetReporting"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "None"
						Key = "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"
						ValueName = "SpynetReporting"
						ValueData = $Null
						ValueType = $Null
					}
				)
			}
		}
		@{
			Id = "18.9.76.7.1"
			Task = "(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
				ValueName = "DisableBehaviorMonitoring"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.9.1"
			Task = "(L2) Ensure 'Configure Watson events' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
				ValueName = "DisableGenericReports"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.10.1"
			Task = "(L1) Ensure 'Scan removable drives' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
				ValueName = "DisableRemovableDriveScanning"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.10.2"
			Task = "(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
				ValueName = "DisableEmailScanning"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.13.1.1"
			Task = "(L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
				ValueName = "ExploitGuard_ASR_Rules"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.13.1.2"
			Task = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
						ValueName = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
						ValueName = "3b576869-a4ec-4529-8536-b80a7769e899"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
						ValueName = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
						ValueName = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
						ValueName = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
						ValueName = "d3e037e1-3eb8-44c8-a917-57927947596d"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
						ValueName = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_sz"
					}
				)
			}
		}
		@{
			Id = "18.9.76.13.3.1"
			Task = "(L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
				ValueName = "EnableNetworkProtection"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.76.14"
			Task = "(L1) Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
				ValueName = "DisableAntiSpyware"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.77.1"
			Task = "(NG) Ensure 'Allow auditing events in Windows Defender Application Guard' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
				ValueName = "AuditApplicationGuard"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.77.2"
			Task = "(NG) Ensure 'Allow data persistence for Windows Defender Application Guard' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
				ValueName = "AllowPersistence"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.77.3"
			Task = "(NG) Ensure 'Configure Windows Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
				ValueName = "AppHVSIClipboardSettings"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.77.4"
			Task = "(NG) Ensure 'Turn on Windows Defender Application Guard in Enterprise Mode' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
				ValueName = "AllowAppHVSI_ProviderSet"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.79.1.1"
			Task = "(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
				ValueName = "DisallowExploitProtectionOverride"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.80.1.1"
			Task = "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
						ValueName = "ShellSmartScreenLevel"
						ValueData = @{
							Operation = "equals"
							Value = "Block"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\Software\Policies\Microsoft\Windows\System"
						ValueName = "EnableSmartScreen"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.80.2.1"
			Task = "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
				ValueName = "EnabledV9"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.80.2.2"
			Task = "(L1) Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for files' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
				ValueName = "PreventOverrideAppRepUnknown"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.80.2.3"
			Task = "(L1) Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
				ValueName = "PreventOverride"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.82.1"
			Task = "(L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
				ValueName = "AllowGameDVR"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.84.1"
			Task = "(L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
				ValueName = "AllowSuggestedAppsInWindowsInkWorkspace"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.84.2"
			Task = "(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
						ValueName = "AllowWindowsInkWorkspace"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
						ValueName = "AllowWindowsInkWorkspace"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.85.1"
			Task = "(L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
				ValueName = "EnableUserControl"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.85.2"
			Task = "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
				ValueName = "AlwaysInstallElevated"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.85.3"
			Task = "(L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
				ValueName = "SafeForScripting"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.86.1"
			Task = "(L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
				ValueName = "DisableAutomaticRestartSignOn"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.95.1"
			Task = "(L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
				ValueName = "EnableScriptBlockLogging"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.95.2"
			Task = "(L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
				ValueName = "EnableTranscripting"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.97.1.1"
			Task = "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"
				ValueName = "AllowBasic"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.97.1.2"
			Task = "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"
				ValueName = "AllowUnencryptedTraffic"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.97.1.3"
			Task = "(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"
				ValueName = "AllowDigest"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.97.2.1"
			Task = "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
				ValueName = "AllowBasic"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.97.2.2"
			Task = "(L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
				ValueName = "AllowAutoConfig"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.97.2.3"
			Task = "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
				ValueName = "AllowUnencryptedTraffic"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.97.2.4"
			Task = "(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
				ValueName = "DisableRunAs"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.98.1"
			Task = "(L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"
				ValueName = "AllowRemoteShellAccess"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.101.1.1"
			Task = "(L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
						ValueName = "ManagePreviewBuilds"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
						ValueName = "ManagePreviewBuildsPolicyValue"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.101.1.2"
			Task = "(L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
						ValueName = "DeferFeatureUpdates"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
						ValueName = "BranchReadinessLevel"
						ValueData = @{
							Operation = "equals"
							Value = "32"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
						ValueName = "DeferFeatureUpdatesPeriodInDays"
						ValueData = @{
							Operation = "greater than or equal"
							Value = "180"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.101.1.3"
			Task = "(L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
						ValueName = "DeferQualityUpdates"
						ValueData = @{
							Operation = "equals"
							Value = "1"
						}
						ValueType = "reg_dword"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
						ValueName = "DeferQualityUpdatesPeriodInDays"
						ValueData = @{
							Operation = "equals"
							Value = "0"
						}
						ValueType = "reg_dword"
					}
				)
			}
		}
		@{
			Id = "18.9.101.2"
			Task = "(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
				ValueName = "NoAutoUpdate"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.101.3"
			Task = "(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
				ValueName = "ScheduledInstallDay"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "18.9.101.4"
			Task = "(L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
				ValueName = "NoAutoRebootWithLoggedOnUsers"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.1.3.1"
			Task = "(L1) Ensure 'Enable screen saver' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "ScreenSaveActive"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "19.1.3.2"
			Task = "(L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "SCRNSAVE.EXE"
				ValueData = @{
					Operation = "equals"
					Value = "scrnsave.scr"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "19.1.3.3"
			Task = "(L1) Ensure 'Password protect the screen saver' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "ScreenSaverIsSecure"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_sz"
			}
		}
		@{
			Id = "19.1.3.4"
			Task = "(L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKEY_USERS\"
						ValueName = "ScreenSaveTimeOut"
						ValueData = @{
							Operation = "less than or equal"
							Value = "900"
						}
						ValueType = "reg_sz"
					}
					@{
						Type = "RegistryConfig"
						Existence = "Yes"
						Key = "HKEY_USERS\"
						ValueName = "ScreenSaveTimeOut"
						ValueData = @{
							Operation = "not equal"
							Value = "0"
						}
						ValueType = "reg_sz"
					}
				)
			}
		}
		@{
			Id = "19.5.1.1"
			Task = "(L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "NoToastApplicationNotificationOnLockScreen"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.6.5.1.1"
			Task = "(L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "NoImplicitFeedback"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.4.1"
			Task = "(L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "SaveZoneInformation"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.4.2"
			Task = "(L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "ScanWithAntiVirus"
				ValueData = @{
					Operation = "equals"
					Value = "3"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.7.1"
			Task = "(L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "ConfigureWindowsSpotlight"
				ValueData = @{
					Operation = "equals"
					Value = "2"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.7.2"
			Task = "(L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "DisableThirdPartySuggestions"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.7.3"
			Task = "(L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "DisableTailoredExperiencesWithDiagnosticData"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.7.4"
			Task = "(L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "DisableWindowsSpotlightFeatures"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.26.1"
			Task = "(L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "NoInplaceSharing"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.40.1"
			Task = "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "AlwaysInstallElevated"
				ValueData = @{
					Operation = "equals"
					Value = "0"
				}
				ValueType = "reg_dword"
			}
		}
		@{
			Id = "19.7.44.2.1"
			Task = "(L2) Ensure 'Prevent Codec Download' is set to 'Enabled'"
			Config = @{
				Type = "RegistryConfig"
				Existence = "Yes"
				Key = "HKEY_USERS\"
				ValueName = "PreventCodecDownload"
				ValueData = @{
					Operation = "equals"
					Value = "1"
				}
				ValueType = "reg_dword"
			}
		}
	)
	UserRights = @(
		@{
			Id = "2.2.1"
			Task = "(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_TRUSTED_CREDMAN_ACCESS_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.2"
			Task = "(L1) Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_NETWORK_LOGON_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-32-(544|555)"
				}
			}
		}
		@{
			Id = "2.2.3"
			Task = "(L1) Ensure 'Act as part of the operating system' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_TCB_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.4"
			Task = "(L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_INCREASE_QUOTA_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(32-544|19|20)"
				}
			}
		}
		@{
			Id = "2.2.5"
			Task = "(L1) Ensure 'Allow log on locally' is set to 'Administrators, Users'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_INTERACTIVE_LOGON_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-32-(544|545)"
				}
			}
		}
		@{
			Id = "2.2.6"
			Task = "(L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_REMOTE_INTERACTIVE_LOGON_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-32-(544|555)"
				}
			}
		}
		@{
			Id = "2.2.7"
			Task = "(L1) Ensure 'Back up files and directories' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_BACKUP_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.8"
			Task = "(L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_SYSTEMTIME_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(32-544|19)"
				}
			}
		}
		@{
			Id = "2.2.9"
			Task = "(L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_TIME_ZONE_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(32-544|19|32-545)"
				}
			}
		}
		@{
			Id = "2.2.10"
			Task = "(L1) Ensure 'Create a pagefile' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_CREATE_PAGEFILE_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.11"
			Task = "(L1) Ensure 'Create a token object' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_CREATE_TOKEN_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.12"
			Task = "(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_CREATE_GLOBAL_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(32-544|19|20|6)"
				}
			}
		}
		@{
			Id = "2.2.13"
			Task = "(L1) Ensure 'Create permanent shared objects' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_CREATE_PERMANENT_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.14"
			Task = "(L1) Configure 'Create symbolic links'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_CREATE_SYMBOLIC_LINK_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(32-544|83-0)"
				}
			}
		}
		@{
			Id = "2.2.15"
			Task = "(L1) Ensure 'Debug programs' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_DEBUG_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.16"
			Task = "(L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "UserRightConfig"
						Existence = "Yes"
						UserRight = "SE_DENY_NETWORK_LOGON_NAME"
						Trustees = @{
							Operation = "equals"
							Value = "S-1-5-32-546"
						}
					}
					@{
						Type = "UserRightConfig"
						Existence = "Yes"
						UserRight = "SE_DENY_NETWORK_LOGON_NAME"
						Trustees = @{
							Operation = "equals"
							Value = "S-1-5-113"
						}
					}
				)
			}
		}
		@{
			Id = "2.2.17"
			Task = "(L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_DENY_BATCH_LOGON_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-546"
				}
			}
		}
		@{
			Id = "2.2.18"
			Task = "(L1) Ensure 'Deny log on as a service' to include 'Guests'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_DENY_SERVICE_LOGON_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-546"
				}
			}
		}
		@{
			Id = "2.2.19"
			Task = "(L1) Ensure 'Deny log on locally' to include 'Guests'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_DENY_INTERACTIVE_LOGON_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-546"
				}
			}
		}
		@{
			Id = "2.2.20"
			Task = "(L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "UserRightConfig"
						Existence = "Yes"
						UserRight = "SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME"
						Trustees = @{
							Operation = "equals"
							Value = "S-1-5-32-546"
						}
					}
					@{
						Type = "UserRightConfig"
						Existence = "Yes"
						UserRight = "SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME"
						Trustees = @{
							Operation = "equals"
							Value = "S-1-5-113"
						}
					}
				)
			}
		}
		@{
			Id = "2.2.21"
			Task = "(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_ENABLE_DELEGATION_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.22"
			Task = "(L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_REMOTE_SHUTDOWN_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.23"
			Task = "(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_AUDIT_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(19|20)"
				}
			}
		}
		@{
			Id = "2.2.24"
			Task = "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_IMPERSONATE_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(32-544|19|20|6)"
				}
			}
		}
		@{
			Id = "2.2.25"
			Task = "(L1) Ensure 'Increase scheduling priority' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_INC_BASE_PRIORITY_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.26"
			Task = "(L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_LOAD_DRIVER_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.27"
			Task = "(L1) Ensure 'Lock pages in memory' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_LOCK_MEMORY_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.28"
			Task = "(L2) Ensure 'Log on as a batch job' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_BATCH_LOGON_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.29"
			Task = "(L2) Ensure 'Log on as a service' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_SERVICE_LOGON_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.30"
			Task = "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_SECURITY_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.31"
			Task = "(L1) Ensure 'Modify an object label' is set to 'No One'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "None"
				UserRight = "SE_RELABEL_NAME"
				Trustees = $Null
			}
		}
		@{
			Id = "2.2.32"
			Task = "(L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_SYSTEM_ENVIRONMENT_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.33"
			Task = "(L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_MANAGE_VOLUME_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.34"
			Task = "(L1) Ensure 'Profile single process' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_PROF_SINGLE_PROCESS_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.35"
			Task = "(L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_SYSTEM_PROFILE_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(32-544|80(-\d{9,10}){1,5})"
				}
			}
		}
		@{
			Id = "2.2.36"
			Task = "(L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_ASSIGNPRIMARYTOKEN_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-(19|20)"
				}
			}
		}
		@{
			Id = "2.2.37"
			Task = "(L1) Ensure 'Restore files and directories' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_RESTORE_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
		@{
			Id = "2.2.38"
			Task = "(L1) Ensure 'Shut down the system' is set to 'Administrators, Users'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_SHUTDOWN_NAME"
				Trustees = @{
					Operation = "pattern match"
					Value = "S-1-5-32-(544|545)"
				}
			}
		}
		@{
			Id = "2.2.39"
			Task = "(L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
			Config = @{
				Type = "UserRightConfig"
				Existence = "Yes"
				UserRight = "SE_TAKE_OWNERSHIP_NAME"
				Trustees = @{
					Operation = "equals"
					Value = "S-1-5-32-544"
				}
			}
		}
	)
	PasswordPolicyConfig = @{
		Type = "PasswordPolicyConfig"
		MaxPasswordAge = "0"
		MinPasswordAge = "86400"
		MinPasswordLength = "14"
		PasswordHistLength = "24"
		PasswordComplexity = "1"
		ReversibleEncryption = "0"
	}
	LockoutPolicyConfig = @{
		Type = "LockoutPolicyConfig"
		ForceLogoff = @(
		
		)
		LockDuration = @(
			@{
				Operation = "greater than or equal"
				Value = "900"
			}
		)
		LockoutObserverationWindow = @(
			@{
				Operation = "greater than or equal"
				Value = "900"
			}
		)
		LockoutThreshold = @(
			@{
				Operation = "less than or equal"
				Value = "10"
			}
			@{
				Operation = "greater than"
				Value = "0"
			}
		)
	}
	AuditPolicies = @(
		@{
			Id = "17.1.1"
			Task = "(L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Credential Validation"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.2.1"
			Task = "(L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Application Group Management"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.2.2"
			Task = "(L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Computer Account Management"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.2.3"
			Task = "(L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Other Account Management Events"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.2.4"
			Task = "(L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Security Group Management"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.2.5"
			Task = "(L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "User Account Management"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.3.1"
			Task = "(L1) Ensure 'Audit PNP Activity' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Pnp Activity"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Pnp Activity"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.3.2"
			Task = "(L1) Ensure 'Audit Process Creation' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Process Creation"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Process Creation"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.5.1"
			Task = "(L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Account Lockout"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.5.2"
			Task = "(L1) Ensure 'Audit Group Membership' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Group Membership"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Group Membership"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.5.3"
			Task = "(L1) Ensure 'Audit Logoff' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Logoff"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Logoff"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.5.4"
			Task = "(L1) Ensure 'Audit Logon' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Logon"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.5.5"
			Task = "(L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Other Logon/Logoff Events"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.5.6"
			Task = "(L1) Ensure 'Audit Special Logon' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Special Logon"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Special Logon"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.6.1"
			Task = "(L1) Ensure 'Audit File Share' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "File Share"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.6.2"
			Task = "(L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Other Object Access Events"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.6.3"
			Task = "(L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Removable Storage"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.7.1"
			Task = "(L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Audit Policy Change"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.7.2"
			Task = "(L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Authentication Policy Change"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Authentication Policy Change"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.7.3"
			Task = "(L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Authorization Policy Change"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Authorization Policy Change"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.8.1"
			Task = "(L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Sensitive Privilege Use"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.9.1"
			Task = "(L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Ipsec Driver"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.9.2"
			Task = "(L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Other System Events"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.9.3"
			Task = "(L1) Ensure 'Audit Security State Change' is set to 'Success'"
			Config = @{
				Type = "ComplexConfig"
				Operation = "OR"
				Configs = @(
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Security State Change"
						AuditFlag = "Success"
					}
					@{
						Type = "AuditPolicyConfig"
						Subcategory = "Security State Change"
						AuditFlag = "Success and Failure"
					}
				)
			}
		}
		@{
			Id = "17.9.4"
			Task = "(L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "Security System Extension"
				AuditFlag = "Success and Failure"
			}
		}
		@{
			Id = "17.9.5"
			Task = "(L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'"
			Config = @{
				Type = "AuditPolicyConfig"
				Subcategory = "System Integrity"
				AuditFlag = "Success and Failure"
			}
		}
	)
}