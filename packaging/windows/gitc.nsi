; gitc Windows installer.
; Build with packaging\windows\build-nsis.ps1 so the payload is explicit:
;   payload\gitc.exe
;   payload\backend\... (the complete Git for Windows distribution)
;
; gitc is installed as the public `git` command. The bundled Git distribution is
; private backend state: it supplies git-remote helpers, libexec commands, shell,
; SSL/SSH support, and fast-export/fast-import for history rewriting.

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"

!define PRODUCT_NAME "gitc"
!define PRODUCT_VERSION "0.6.0"
!define PAYLOAD_ROOT "..\payload"
!define INSTALL_ROOT "$PROGRAMFILES64\gitc"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "..\..\dist\gitc-${PRODUCT_VERSION}-x86_64.exe"
InstallDir "${INSTALL_ROOT}"
InstallDirRegKey HKLM "Software\gitc" "InstallDir"
RequestExecutionLevel admin

VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "FileDescription" "gitc Rust Git-compatible command and private Git backend"
VIAddVersionKey "LegalCopyright" "BSD-3-Clause"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Section "gitc command" SecGitc
  SectionIn RO
  SetOutPath "$INSTDIR\bin"
  File /oname=gitc.exe "${PAYLOAD_ROOT}\gitc.exe"
  File /oname=git.exe "${PAYLOAD_ROOT}\gitc.exe"
SectionEnd

Section "Git for Windows backend" SecBackend
  ; The payload must be a complete Git-for-Windows installation tree. Keeping
  ; this tree intact is required for helpers and shell tools to resolve paths.
  SetOutPath "$INSTDIR\backend"
  File /r "${PAYLOAD_ROOT}\backend\*.*"
SectionEnd

Section "Install PATH and backend registration" SecEnvironment
  WriteRegStr HKLM "Software\gitc" "InstallDir" "$INSTDIR"
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" \
    "GITC_GIT_BACKEND" "$INSTDIR\backend\cmd\git.exe"
  Push "$INSTDIR\bin"
  Call AddMachinePath
  Call BroadcastEnvironment
SectionEnd

Section "Uninstall"
  DeleteRegValue HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" \
    "GITC_GIT_BACKEND"
  Push "$INSTDIR\bin"
  Call RemoveMachinePath
  Call BroadcastEnvironment
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\gitc"
  DeleteRegKey HKLM "Software\gitc"
  RMDir /r "$INSTDIR"
SectionEnd

Function .onInstSuccess
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\gitc" \
    "DisplayName" "gitc"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\gitc" \
    "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\gitc" \
    "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\gitc" \
    "InstallLocation" "$INSTDIR"
FunctionEnd

; Stack: path to add. PowerShell performs exact, case-insensitive segment
; comparison and preserves all unrelated PATH entries.
Function AddMachinePath
  Exch $0
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$p=[Environment]::GetEnvironmentVariable(''Path'',''Machine''); $$e=''$0''; if (($$p -split '';'' | ForEach-Object { $$_.TrimEnd(''\'') }) -notcontains $$e.TrimEnd(''\'')) { [Environment]::SetEnvironmentVariable(''Path'', ($$e + '';'' + $$p), ''Machine'') }"'
  Pop $0
FunctionEnd

Function RemoveMachinePath
  Exch $0
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$p=[Environment]::GetEnvironmentVariable(''Path'',''Machine''); $$e=''$0''.TrimEnd(''\''); $$v=( $$p -split '';'' | Where-Object { $$_.TrimEnd(''\'') -and $$_.TrimEnd(''\'') -ine $$e } ) -join '';''; [Environment]::SetEnvironmentVariable(''Path'', $$v, ''Machine'')"'
  Pop $0
FunctionEnd

Function BroadcastEnvironment
  ; WM_SETTINGCHANGE makes already-running Explorer/shells reload PATH.
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd
