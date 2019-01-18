/**
 * Copyright © 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.cloudsearch.fs;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.WinBase.FE_EXPORT_FUNC;
import com.sun.jna.platform.win32.WinBase.FE_IMPORT_FUNC;
import com.sun.jna.platform.win32.WinBase.FILETIME;
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION;
import com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES;
import com.sun.jna.platform.win32.WinBase.STARTUPINFO;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinDef.DWORDByReference;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.GENERIC_MAPPING;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.WinNT.HANDLEByReference;
import com.sun.jna.platform.win32.WinNT.LUID;
import com.sun.jna.platform.win32.WinNT.PRIVILEGE_SET;
import com.sun.jna.platform.win32.WinNT.PSID;
import com.sun.jna.platform.win32.WinNT.PSIDByReference;
import com.sun.jna.platform.win32.WinNT.TOKEN_PRIVILEGES;
import com.sun.jna.platform.win32.WinReg.HKEY;
import com.sun.jna.platform.win32.WinReg.HKEYByReference;
import com.sun.jna.platform.win32.Winsvc.SC_HANDLE;
import com.sun.jna.platform.win32.Winsvc.SERVICE_STATUS;
import com.sun.jna.platform.win32.Winsvc.SERVICE_STATUS_PROCESS;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * An Implementation of the Advapi32 Interface that throws
 * UnsupportedOperationException for everything.  Tests may
 * subclass this and override those methods used by the object
 * under test.
 */
public class UnsupportedAdvapi32 implements Advapi32 {

  @Override
  public boolean GetUserNameW(char[] buffer, IntByReference len) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean LookupAccountName(String lpSystemName, String lpAccountName,
      PSID Sid, IntByReference cbSid, char[] ReferencedDomainName,
      IntByReference cchReferencedDomainName, PointerByReference peUse) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean LookupAccountSid(String lpSystemName, PSID Sid,
      char[] lpName, IntByReference cchName, char[] ReferencedDomainName,
      IntByReference cchReferencedDomainName, PointerByReference peUse) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ConvertSidToStringSid(PSID Sid, PointerByReference StringSid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ConvertStringSidToSid(String StringSid, PSIDByReference Sid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetLengthSid(PSID pSid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean IsValidSid(PSID pSid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean IsWellKnownSid(PSID pSid, int wellKnownSidType) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateWellKnownSid(int wellKnownSidType, PSID domainSid,
      PSID pSid, IntByReference cbSid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean LogonUser(String lpszUsername, String lpszDomain,
      String lpszPassword, int logonType, int logonProvider,
      HANDLEByReference phToken) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean OpenThreadToken(HANDLE ThreadHandle, int DesiredAccess,
      boolean OpenAsSelf, HANDLEByReference TokenHandle) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean OpenProcessToken(HANDLE ProcessHandle, int DesiredAccess,
      HANDLEByReference TokenHandle) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DuplicateToken(HANDLE ExistingTokenHandle,
      int ImpersonationLevel, HANDLEByReference DuplicateTokenHandle) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DuplicateTokenEx(HANDLE hExistingToken, int dwDesiredAccess,
      SECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel,
      int TokenType, HANDLEByReference phNewToken) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetTokenInformation(HANDLE tokenHandle,
      int tokenInformationClass, Structure tokenInformation,
      int tokenInformationLength, IntByReference returnLength) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ImpersonateLoggedOnUser(HANDLE hToken) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ImpersonateSelf(int ImpersonationLevel) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean RevertToSelf() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegOpenKeyEx(HKEY hKey, String lpSubKey, int ulOptions,
      int samDesired, HKEYByReference phkResult) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegQueryValueEx(HKEY hKey, String lpValueName, int lpReserved,
      IntByReference lpType, char[] lpData, IntByReference lpcbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegQueryValueEx(HKEY hKey, String lpValueName, int lpReserved,
      IntByReference lpType, byte[] lpData, IntByReference lpcbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegQueryValueEx(HKEY hKey, String lpValueName, int lpReserved,
      IntByReference lpType, IntByReference lpData,
      IntByReference lpcbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegQueryValueEx(HKEY hKey, String lpValueName, int lpReserved,
      IntByReference lpType, LongByReference lpData,
      IntByReference lpcbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegQueryValueEx(HKEY hKey, String lpValueName, int lpReserved,
      IntByReference lpType, Pointer lpData, IntByReference lpcbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegCloseKey(HKEY hKey) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegDeleteValue(HKEY hKey, String lpValueName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegSetValueEx(HKEY hKey, String lpValueName, int Reserved,
      int dwType, char[] lpData, int cbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegSetValueEx(HKEY hKey, String lpValueName, int Reserved,
      int dwType, byte[] lpData, int cbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegCreateKeyEx(HKEY hKey, String lpSubKey, int Reserved,
      String lpClass, int dwOptions, int samDesired,
      SECURITY_ATTRIBUTES lpSecurityAttributes,
      HKEYByReference phkResult, IntByReference lpdwDisposition) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegDeleteKey(HKEY hKey, String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegEnumKeyEx(HKEY hKey, int dwIndex, char[] lpName,
      IntByReference lpcName, IntByReference reserved, char[] lpClass,
      IntByReference lpcClass, FILETIME lpftLastWriteTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegEnumValue(HKEY hKey, int dwIndex, char[] lpValueName,
      IntByReference lpcchValueName, IntByReference reserved,
      IntByReference lpType, byte[] lpData, IntByReference lpcbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegQueryInfoKey(HKEY hKey, char[] lpClass,
      IntByReference lpcClass, IntByReference lpReserved,
      IntByReference lpcSubKeys, IntByReference lpcMaxSubKeyLen,
      IntByReference lpcMaxClassLen, IntByReference lpcValues,
      IntByReference lpcMaxValueNameLen, IntByReference lpcMaxValueLen,
      IntByReference lpcbSecurityDescriptor,
      FILETIME lpftLastWriteTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int RegGetValue(HKEY hkey, String lpSubKey, String lpValue,
      int dwFlags, IntByReference pdwType, byte[] pvData,
      IntByReference pcbData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE RegisterEventSource(String lpUNCServerName,
      String lpSourceName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DeregisterEventSource(HANDLE hEventLog) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE OpenEventLog(String lpUNCServerName, String lpSourceName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CloseEventLog(HANDLE hEventLog) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNumberOfEventLogRecords(HANDLE hEventLog,
      IntByReference NumberOfRecords) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReportEvent(HANDLE hEventLog, int wType, int wCategory,
      int dwEventID, PSID lpUserSid, int wNumStrings, int dwDataSize,
      String[] lpStrings, Pointer lpRawData) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ClearEventLog(HANDLE hEventLog, String lpBackupFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean BackupEventLog(HANDLE hEventLog, String lpBackupFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE OpenBackupEventLog(String lpUNCServerName, String lpFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReadEventLog(HANDLE hEventLog, int dwReadFlags,
      int dwRecordOffset, Pointer lpBuffer, int nNumberOfBytesToRead,
      IntByReference pnBytesRead, IntByReference pnMinNumberOfBytesNeeded) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetOldestEventLogRecord(HANDLE hEventLog,
      IntByReference OldestRecord) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean QueryServiceStatusEx(SC_HANDLE hService, int InfoLevel,
      SERVICE_STATUS_PROCESS lpBuffer, int cbBufSize,
      IntByReference pcbBytesNeeded) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ControlService(SC_HANDLE hService, int dwControl,
      SERVICE_STATUS lpServiceStatus) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean StartService(SC_HANDLE hService, int dwNumServiceArgs,
      String[] lpServiceArgVectors) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CloseServiceHandle(SC_HANDLE hSCObject) {
    throw new UnsupportedOperationException();
  }

  @Override
  public SC_HANDLE OpenService(SC_HANDLE hSCManager, String lpServiceName,
      int dwDesiredAccess) {
    throw new UnsupportedOperationException();
  }

  @Override
  public SC_HANDLE OpenSCManager(String lpMachineName, String lpDatabaseName,
      int dwDesiredAccess) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateProcessAsUser(HANDLE hToken, String lpApplicationName,
      String lpCommandLine, SECURITY_ATTRIBUTES lpProcessAttributes,
      SECURITY_ATTRIBUTES lpThreadAttributes, boolean bInheritHandles,
      int dwCreationFlags, String lpEnvironment,
      String lpCurrentDirectory, STARTUPINFO lpStartupInfo,
      PROCESS_INFORMATION lpProcessInformation) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean AdjustTokenPrivileges(HANDLE TokenHandle,
      boolean DisableAllPrivileges, TOKEN_PRIVILEGES NewState,
      int BufferLength, TOKEN_PRIVILEGES PreviousState,
      IntByReference ReturnLength) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean LookupPrivilegeName(String lpSystemName, LUID lpLuid,
      char[] lpName, IntByReference cchName) {
    throw new UnsupportedOperationException();
  }
  @Override
  public boolean LookupPrivilegeValue(String lpSystemName, String lpName,
      LUID lpLuid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetFileSecurity(
      WString lpFileName,
      int RequestedInformation,
      Pointer pointer,
      int nLength,
      IntByReference lpnLengthNeeded) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean AccessCheck(
      Pointer arg0,
      HANDLE arg1,
      DWORD arg2,
      GENERIC_MAPPING arg3,
      PRIVILEGE_SET arg4,
      DWORDByReference arg5,
      DWORDByReference arg6,
      BOOLByReference arg7) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void CloseEncryptedFileRaw(Pointer arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DecryptFile(WString arg0, DWORD arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean EncryptFile(WString arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean EncryptionDisable(WString arg0, boolean arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FileEncryptionStatus(WString arg0, DWORDByReference arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetNamedSecurityInfo(
      String arg0,
      int arg1,
      int arg2,
      PointerByReference arg3,
      PointerByReference arg4,
      PointerByReference arg5,
      PointerByReference arg6,
      PointerByReference arg7) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetSecurityDescriptorLength(Pointer arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean IsValidAcl(Pointer arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean IsValidSecurityDescriptor(Pointer arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void MapGenericMask(DWORDByReference arg0, GENERIC_MAPPING arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int OpenEncryptedFileRaw(WString arg0, ULONG arg1, PointerByReference arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int ReadEncryptedFileRaw(FE_EXPORT_FUNC arg0, Pointer arg1, Pointer arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int SetNamedSecurityInfo(
      String arg0, int arg1, int arg2, Pointer arg3, Pointer arg4, Pointer arg5, Pointer arg6) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetThreadToken(HANDLEByReference arg0, HANDLE arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int WriteEncryptedFileRaw(FE_IMPORT_FUNC arg0, Pointer arg1, Pointer arg2) {
    throw new UnsupportedOperationException();
  }
}
