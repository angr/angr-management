; angr-management NSIS Installer Script
; ==============================================================================
; Build with: makensis -V4 -DVERSION=9.2.166 angr-management.nsi
;
; Defines:
; - VERSION: May be PEP440 or any version scheme. Used only for output
;            executable filename.
; - PRODUCT_VERSION: Must be 3-4 dotted numeric-only component.
;                    Default is 0.0.0.0.

; Includes
;-------------------------------------------------------------------------------
!include "MUI2.nsh"

; Constants
;-------------------------------------------------------------------------------
!define PRODUCT "angr-management"
!define PRODUCT_NAME "${PRODUCT}"
!define PRODUCT_DESCRIPTION "Cross-platform, open-source, graphical binary analysis tool."
!define PRODUCT_URL "https://docs.angr.io/projects/angr-management/en/latest/"
!ifndef PRODUCT_VERSION
  !define PRODUCT_VERSION "0.0.0.0"
!endif
!define COPYRIGHT "Copyright © ${PRODUCT} Contributors"
!define SOURCE_DIR "dist\angr-management"
!define INST_KEY "Software\${PRODUCT}"
!define INST_EXE "${PRODUCT}-v${VERSION}-win64-x86_64-setup.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT}"
!define UNINST_EXE "uninstall.exe"

; Attributes
;-------------------------------------------------------------------------------
Name "${PRODUCT}"
OutFile "${INST_EXE}"
Unicode true
SetCompressor /SOLID lzma
InstallDir $PROGRAMFILES64\${PRODUCT}
InstallDirRegKey HKLM "${INST_KEY}" "InstallPath"
RequestExecutionLevel admin

; Version Info
;-------------------------------------------------------------------------------
VIProductVersion "${PRODUCT_VERSION}"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "FileDescription" "${PRODUCT_DESCRIPTION}"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"

; Appearance
;-------------------------------------------------------------------------------
!define MUI_ICON "angrmanagement\resources\images\angr.ico"
!define MUI_UNICON "${MUI_ICON}"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\orange.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\orange.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\orange-uninstall.bmp"
!define MUI_FINISHPAGE_NOAUTOCLOSE

; Installer Pages
;-------------------------------------------------------------------------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PRODUCT}.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${PRODUCT}"
!define MUI_FINISHPAGE_LINK "Check out ${PRODUCT} docs!"
!define MUI_FINISHPAGE_LINK_LOCATION "${PRODUCT_URL}"
!insertmacro MUI_PAGE_FINISH

; Uninstaller Pages
;-------------------------------------------------------------------------------
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
;-------------------------------------------------------------------------------
!insertmacro MUI_LANGUAGE "English"

; Installation
;-------------------------------------------------------------------------------
Section "Install" SectionInstall
  SetRegView 64
  SectionIn RO
  SetOutPath "$INSTDIR"
  File /r "${SOURCE_DIR}\*"
  WriteRegStr HKLM "${INST_KEY}" "InstallPath" "$INSTDIR"

  ; Setup for uninstallation
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\${UNINST_EXE}"'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  WriteUninstaller "${UNINST_EXE}"
SectionEnd

; Shortcuts
;-------------------------------------------------------------------------------
Section "Desktop Shortcut" SectionDesktopShortcut
  CreateDirectory "$SMPROGRAMS\${PRODUCT}"
  CreateShortCut "$DESKTOP\${PRODUCT}.lnk" "$INSTDIR\${PRODUCT}.exe"
SectionEnd

Section "Start Menu Shortcut" SectionStartMenuShortcut
  CreateDirectory "$SMPROGRAMS\${PRODUCT}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT}\${PRODUCT}.lnk" "$INSTDIR\${PRODUCT}.exe"
SectionEnd

; Uninstallation
;-------------------------------------------------------------------------------
Section "Uninstall"
  SetRegView 64

  ; Remove shortcuts
  Delete "$DESKTOP\${PRODUCT}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT}\${PRODUCT}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT}"

  ; Remove program files
  Delete "$INSTDIR\${PRODUCT}.exe"
  RMDir /r "$INSTDIR"

  ; Remove registry keys
  DeleteRegKey HKLM "${INST_KEY}"
  DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd

; Component hover descriptions
;--------------------------------
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SectionInstall} "Install ${PRODUCT}."
  !insertmacro MUI_DESCRIPTION_TEXT ${SectionDesktopShortcut} "Create a shortcut to ${PRODUCT} on the Desktop."
  !insertmacro MUI_DESCRIPTION_TEXT ${SectionStartMenuShortcut} "Create a shortcut to ${PRODUCT} in the Start Menu."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd
