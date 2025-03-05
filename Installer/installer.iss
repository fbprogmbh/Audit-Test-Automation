#define AppName "Audit Test Automation Package"
#define AppShortName "AuditTAP"
#define LicenseFile "LICENSE"
#define AppPublisher "FB Pro GmbH"
#define AppURL "https://www.fb-pro.com/"
#define AppIcon "AT.ico"
#define AppVersion "5.11.0"
//#define BaseFolder "Audit-Test-Automation"
#define BaseFolder ".."
#define AskVersionText "Please select the version to be installed"


[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppId={#AppShortName}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
WizardStyle=modern
DisableDirPage=yes
ArchitecturesAllowed=x86 x64
ArchitecturesInstallIn64BitMode=x64
DefaultDirName={autopf}\WindowsPowerShell\Modules
OutputDir=.
OutputBaseFilename={#AppShortName}-{#AppVersion}
LicenseFile={#BaseFolder}\{#LicenseFile}
DefaultGroupName={#AppShortName}
UninstallDisplayIcon={app}\{#AppIcon}
VersionInfoVersion={#AppVersion}

[Tasks]
Name: Stable; Description: "Stable (recommended)"; Flags: exclusive; GroupDescription: "{#AskVersionText}"
Name: Development; Description: "Download development version"; Flags: exclusive unchecked; GroupDescription: "{#AskVersionText}"


[Files]
Source: "icons\{#AppIcon}"; DestDir: "{app}"; Flags: ignoreversion
; Included files for the "Stable" version
Source: "{#BaseFolder}\ATAPAuditor\*"; DestDir: "{app}\ATAPAuditor"; Flags: ignoreversion recursesubdirs; Check: WizardIsTaskSelected('Stable')
Source: "{#BaseFolder}\ATAPHtmlReport\*"; DestDir: "{app}\ATAPHtmlReport"; Flags: ignoreversion recursesubdirs; Check: WizardIsTaskSelected('Stable')
; These files have to be downloaded if "Development" was chosen
Source: "{tmp}\atap-develop-extracted\Audit-Test-Automation-develop\ATAPAuditor\*"; DestDir: "{app}\ATAPAuditor"; Flags: ignoreversion recursesubdirs external; Check: WizardIsTaskSelected('Development')
Source: "{tmp}\atap-develop-extracted\Audit-Test-Automation-develop\ATAPHtmlReport\*"; DestDir: "{app}\ATAPHtmlReport"; Flags: ignoreversion recursesubdirs external; Check: WizardIsTaskSelected('Development')


[Icons]
Name: "{group}\{#AppShortName}"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy RemoteSigned -File ""{app}\ATAPAuditor\Helpers\Menu.ps1"""; IconFilename: {app}\{#AppIcon};
Name: "{group}\Uninstall {#AppShortName}"; Filename: "{uninstallexe}"


[Code]
var
  DownloadPage: TDownloadWizardPage;
function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  if Progress = ProgressMax then
    Log(Format('Successfully downloaded file to {tmp}: %s', [FileName]));
  Result := True;
end;
procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;
function NextButtonClick(CurPageID: Integer): Boolean;
var
  ExtResultCode: integer;
begin
  if CurPageID = wpReady then begin
    if not(WizardIsTaskSelected('Development')) then begin
      Result := True;
      exit;
    end;
    DownloadPage.Clear;
    DownloadPage.Add('https://github.com/fbprogmbh/Audit-Test-Automation/archive/refs/heads/approve.zip', 'atap-approve.zip', '');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download; // This downloads the files to {tmp}
        Result := True;
      except
        if DownloadPage.AbortedByUser then
          Log('Aborted by user.')
        else
          SuppressibleMsgBox(AddPeriod(GetExceptionMessage), mbCriticalError, MB_OK, IDOK);
        Result := False;
      end;
    finally
      DownloadPage.Hide;
      if (WizardIsTaskSelected('Development')) then begin
        Exec('powershell.exe', ExpandConstant('Expand-Archive -Path {tmp}\atap-develop.zip -DestinationPath {tmp}\atap-develop-extracted'), '', SW_HIDE, ewWaitUntilTerminated, ExtResultCode);
      end;
    end;
  end else
    Result := True;
end;
function InitializeSetup(): Boolean;
begin
  Result := True;
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#AppShortName}_is1') or RegKeyExists(HKEY_CURRENT_USER, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#AppShortName}_is1') then
  begin
    Result := (MsgBox('{#AppShortName} is already installed. Do you want to overwrite?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES);
  end;
end;
