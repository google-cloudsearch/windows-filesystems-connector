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

import com.google.enterprise.cloudsearch.fs.WinApi.Kernel32Ex;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Tlhelp32.PROCESSENTRY32;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * An implementation of the Kernel32 Interface that throws UnsupportedOperationException for
 * everything. Tests may subclass this and override those methods used by the object under test.
 */
public class UnsupportedKernel32 implements Kernel32, Kernel32Ex {

  @Override
  public Pointer LocalFree(Pointer hLocal) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer GlobalFree(Pointer hGlobal) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HMODULE GetModuleHandle(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetSystemTime(SYSTEMTIME lpSystemTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetLocalTime(SYSTEMTIME lpSystemTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetTickCount() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetCurrentThreadId() {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE GetCurrentThread() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetCurrentProcessId() {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE GetCurrentProcess() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetProcessId(HANDLE process) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetProcessVersion(int processId) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetExitCodeProcess(HANDLE hProcess, IntByReference lpExitCode) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean TerminateProcess(HANDLE hProcess, int uExitCode) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetLastError() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void SetLastError(int dwErrCode) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetDriveType(String lpRootPathName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int FormatMessage(
      int dwFlags,
      Pointer lpSource,
      int dwMessageId,
      int dwLanguageId,
      PointerByReference lpBuffer,
      int nSize,
      Pointer va_list) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateFile(
      String lpFileName,
      int dwDesiredAccess,
      int dwShareMode,
      SECURITY_ATTRIBUTES lpSecurityAttributes,
      int dwCreationDisposition,
      int dwFlagsAndAttributes,
      HANDLE hTemplateFile) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CopyFile(String lpExistingFileName, String lpNewFileName, boolean bFailIfExists) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean MoveFile(String lpExistingFileName, String lpNewFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean MoveFileEx(String lpExistingFileName, String lpNewFileName, DWORD dwFlags) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateDirectory(String lpPathName, SECURITY_ATTRIBUTES lpSecurityAttributes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateIoCompletionPort(
      HANDLE FileHandle,
      HANDLE ExistingCompletionPort,
      Pointer CompletionKey,
      int NumberOfConcurrentThreads) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetQueuedCompletionStatus(
      HANDLE CompletionPort,
      IntByReference lpNumberOfBytes,
      ULONG_PTRByReference lpCompletionKey,
      PointerByReference lpOverlapped,
      int dwMilliseconds) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean PostQueuedCompletionStatus(
      HANDLE CompletionPort,
      int dwNumberOfBytesTransferred,
      Pointer dwCompletionKey,
      OVERLAPPED lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int WaitForSingleObject(HANDLE hHandle, int dwMilliseconds) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int WaitForSingleObjectEx(HANDLE hHandle, int dwMilliseconds, boolean bAlertable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int WaitForMultipleObjects(
      int nCount, HANDLE[] hHandle, boolean bWaitAll, int dwMilliseconds) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DuplicateHandle(
      HANDLE hSourceProcessHandle,
      HANDLE hSourceHandle,
      HANDLE hTargetProcessHandle,
      HANDLEByReference lpTargetHandle,
      int dwDesiredAccess,
      boolean bInheritHandle,
      int dwOptions) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CloseHandle(HANDLE hObject) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReadDirectoryChangesW(
      HANDLE directory,
      FILE_NOTIFY_INFORMATION info,
      int length,
      boolean watchSubtree,
      int notifyFilter,
      IntByReference bytesReturned,
      OVERLAPPED overlapped,
      OVERLAPPED_COMPLETION_ROUTINE completionRoutine) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetShortPathName(String lpszLongPath, char[] lpdzShortPath, int cchBuffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer LocalAlloc(int uFlags, int uBytes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean WriteFile(
      HANDLE hFile,
      byte[] lpBuffer,
      int nNumberOfBytesToWrite,
      IntByReference lpNumberOfBytesWritten,
      OVERLAPPED lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateEvent(
      SECURITY_ATTRIBUTES lpEventAttributes,
      boolean bManualReset,
      boolean bInitialState,
      String lpName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetEvent(HANDLE hEvent) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean PulseEvent(HANDLE hEvent) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateFileMapping(
      HANDLE hFile,
      SECURITY_ATTRIBUTES lpAttributes,
      int flProtect,
      int dwMaximumSizeHigh,
      int dwMaximumSizeLow,
      String lpName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer MapViewOfFile(
      HANDLE hFileMappingObject,
      int dwDesiredAccess,
      int dwFileOffsetHigh,
      int dwFileOffsetLow,
      int dwNumberOfBytesToMap) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean UnmapViewOfFile(Pointer lpBaseAddress) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetComputerName(char[] buffer, IntByReference lpnSize) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE OpenThread(int dwDesiredAccess, boolean bInheritHandle, int dwThreadId) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateProcess(
      String lpApplicationName,
      String lpCommandLine,
      SECURITY_ATTRIBUTES lpProcessAttributes,
      SECURITY_ATTRIBUTES lpThreadAttributes,
      boolean bInheritHandles,
      DWORD dwCreationFlags,
      Pointer lpEnvironment,
      String lpCurrentDirectory,
      STARTUPINFO lpStartupInfo,
      PROCESS_INFORMATION lpProcessInformation) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateProcessW(
      String lpApplicationName,
      char[] lpCommandLine,
      SECURITY_ATTRIBUTES lpProcessAttributes,
      SECURITY_ATTRIBUTES lpThreadAttributes,
      boolean bInheritHandles,
      DWORD dwCreationFlags,
      Pointer lpEnvironment,
      String lpCurrentDirectory,
      STARTUPINFO lpStartupInfo,
      PROCESS_INFORMATION lpProcessInformation) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE OpenProcess(int fdwAccess, boolean fInherit, int IDProcess) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetTempPath(DWORD nBufferLength, char[] buffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetVersion() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVersionEx(OSVERSIONINFO lpVersionInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVersionEx(OSVERSIONINFOEX lpVersionInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetSystemInfo(SYSTEM_INFO lpSystemInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetNativeSystemInfo(SYSTEM_INFO lpSystemInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean IsWow64Process(HANDLE hProcess, IntByReference Wow64Process) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetLogicalProcessorInformation(Pointer buffer, DWORDByReference returnLength) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GlobalMemoryStatusEx(MEMORYSTATUSEX lpBuffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetFileTime(
      HANDLE hFile, FILETIME lpCreationTime, FILETIME lpLastAccessTime, FILETIME lpLastWriteTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int SetFileTime(
      HANDLE hFile, FILETIME lpCreationTime, FILETIME lpLastAccessTime, FILETIME lpLastWriteTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetFileAttributes(String lpFileName, DWORD dwFileAttributes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetLogicalDriveStrings(DWORD nBufferLength, char[] lpBuffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetDiskFreeSpaceEx(
      String lpDirectoryName,
      LARGE_INTEGER lpFreeBytesAvailable,
      LARGE_INTEGER lpTotalNumberOfBytes,
      LARGE_INTEGER lpTotalNumberOfFreeBytes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DeleteFile(String filename) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreatePipe(
      HANDLEByReference hReadPipe,
      HANDLEByReference hWritePipe,
      SECURITY_ATTRIBUTES lpPipeAttributes,
      int nSize) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetHandleInformation(HANDLE hObject, int dwMask, int dwFlags) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetFileAttributes(String lpFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetFileType(HANDLE hFile) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DeviceIoControl(
      HANDLE hDevice,
      int dwIoControlCode,
      Pointer lpInBuffer,
      int nInBufferSize,
      Pointer lpOutBuffer,
      int nOutBufferSize,
      IntByReference lpBytesReturned,
      Pointer lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean Process32First(HANDLE hSnapshot, PROCESSENTRY32 lppe) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean Process32Next(HANDLE hSnapshot, PROCESSENTRY32 lppe) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetEnvironmentVariable(String lpName, String lpValue) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetEnvironmentVariable(String lpName, char[] lpBuffer, int nSize) {
    throw new UnsupportedOperationException();
  }

  @Override
  public LCID GetSystemDefaultLCID() {
    throw new UnsupportedOperationException();
  }

  @Override
  public LCID GetUserDefaultLCID() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetPrivateProfileInt(
      String appName, String keyName, int defaultValue, String fileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetPrivateProfileString(
      String lpAppName,
      String lpKeyName,
      String lpDefault,
      char[] lpReturnedString,
      DWORD nSize,
      String lpFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean WritePrivateProfileString(
      String lpAppName, String lpKeyName, String lpString, String lpFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean AllocConsole() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean AttachConsole(int arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FlushConsoleInputBuffer(HANDLE arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FreeConsole() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GenerateConsoleCtrlEvent(int arg0, int arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetConsoleCP() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetConsoleDisplayMode(IntByReference arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetConsoleMode(HANDLE arg0, IntByReference arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetConsoleOriginalTitle(char[] arg0, int arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetConsoleOutputCP() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetConsoleTitle(char[] arg0, int arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HWND GetConsoleWindow() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNumberOfConsoleInputEvents(HANDLE arg0, IntByReference arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNumberOfConsoleMouseButtons(IntByReference arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE GetStdHandle(int arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetConsoleCP(int arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetConsoleMode(HANDLE arg0, int arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetConsoleOutputCP(int arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetConsoleTitle(String arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetStdHandle(int arg0, HANDLE arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CallNamedPipe(
      String arg0, byte[] arg1, int arg2, byte[] arg3, int arg4, IntByReference arg5, int arg6) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ConnectNamedPipe(HANDLE arg0, OVERLAPPED arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateNamedPipe(
      String arg0,
      int arg1,
      int arg2,
      int arg3,
      int arg4,
      int arg5,
      int arg6,
      SECURITY_ATTRIBUTES arg7) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateRemoteThread(
      HANDLE arg0,
      SECURITY_ATTRIBUTES arg1,
      int arg2,
      FOREIGN_THREAD_START_ROUTINE arg3,
      Pointer arg4,
      DWORD arg5,
      Pointer arg6) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DefineDosDevice(int arg0, String arg1, String arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DeleteVolumeMountPoint(String arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DisconnectNamedPipe(HANDLE arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FileTimeToLocalFileTime(FILETIME arg0, FILETIME arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE FindFirstVolume(char[] arg0, int arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE FindFirstVolumeMountPoint(String arg0, char[] arg1, int arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FindNextVolume(HANDLE arg0, char[] arg1, int arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FindNextVolumeMountPoint(HANDLE arg0, char[] arg1, int arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FindVolumeClose(HANDLE arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FindVolumeMountPointClose(HANDLE arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FlushFileBuffers(HANDLE arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean FreeEnvironmentStrings(Pointer arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetCommState(HANDLE arg0, DCB arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetCommTimeouts(HANDLE arg0, COMMTIMEOUTS arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetComputerNameEx(int arg0, char[] arg1, IntByReference arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetDiskFreeSpace(
      String arg0,
      DWORDByReference arg1,
      DWORDByReference arg2,
      DWORDByReference arg3,
      DWORDByReference arg4) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer GetEnvironmentStrings() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNamedPipeClientComputerName(HANDLE arg0, char[] arg1, int arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNamedPipeClientProcessId(HANDLE arg0, ULONGByReference arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNamedPipeClientSessionId(HANDLE arg0, ULONGByReference arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNamedPipeHandleState(
      HANDLE arg0,
      IntByReference arg1,
      IntByReference arg2,
      IntByReference arg3,
      IntByReference arg4,
      char[] arg5,
      int arg6) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNamedPipeInfo(
      HANDLE arg0,
      IntByReference arg1,
      IntByReference arg2,
      IntByReference arg3,
      IntByReference arg4) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNamedPipeServerProcessId(HANDLE arg0, ULONGByReference arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetNamedPipeServerSessionId(HANDLE arg0, ULONGByReference arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetPrivateProfileSection(String arg0, char[] arg1, DWORD arg2, String arg3) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetPrivateProfileSectionNames(char[] arg0, DWORD arg1, String arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVolumeInformation(
      String arg0,
      char[] arg1,
      int arg2,
      IntByReference arg3,
      IntByReference arg4,
      IntByReference arg5,
      char[] arg6,
      int arg7) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVolumeNameForVolumeMountPoint(String arg0, char[] arg1, int arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVolumePathName(String arg0, char[] arg1, int arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVolumePathNamesForVolumeName(
      String arg0, char[] arg1, int arg2, IntByReference arg3) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean PeekNamedPipe(
      HANDLE arg0,
      byte[] arg1,
      int arg2,
      IntByReference arg3,
      IntByReference arg4,
      IntByReference arg5) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int QueryDosDevice(String arg0, char[] arg1, int arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReadFile(
      HANDLE arg0, byte[] arg1, int arg2, IntByReference arg3, OVERLAPPED arg4) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReadProcessMemory(
      HANDLE arg0, Pointer arg1, Pointer arg2, int arg3, IntByReference arg4) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ResetEvent(HANDLE arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetCommState(HANDLE arg0, DCB arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetCommTimeouts(HANDLE arg0, COMMTIMEOUTS arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetLocalTime(SYSTEMTIME arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetNamedPipeHandleState(
      HANDLE arg0, IntByReference arg1, IntByReference arg2, IntByReference arg3) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetSystemTime(SYSTEMTIME arg0) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetVolumeLabel(String arg0, String arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetVolumeMountPoint(String arg0, String arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SystemTimeToFileTime(SYSTEMTIME arg0, FILETIME arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SystemTimeToTzSpecificLocalTime(
      TIME_ZONE_INFORMATION arg0, SYSTEMTIME arg1, SYSTEMTIME arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean TransactNamedPipe(
      HANDLE arg0,
      byte[] arg1,
      int arg2,
      byte[] arg3,
      int arg4,
      IntByReference arg5,
      OVERLAPPED arg6) {
    throw new UnsupportedOperationException();
  }

  @Override
  public SIZE_T VirtualQueryEx(
      HANDLE arg0, Pointer arg1, MEMORY_BASIC_INFORMATION arg2, SIZE_T arg3) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean WaitNamedPipe(String arg0, int arg1) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean WritePrivateProfileSection(String arg0, String arg1, String arg2) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean WriteProcessMemory(
      HANDLE arg0, Pointer arg1, Pointer arg2, int arg3, IntByReference arg4) {
    throw new UnsupportedOperationException();
  }
}
