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

import com.google.enterprise.cloudsearch.fs.WinApi.Netapi32Ex;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.DsGetDC.PDOMAIN_CONTROLLER_INFO;
import com.sun.jna.platform.win32.Guid.GUID;
import com.sun.jna.platform.win32.NTSecApi.PLSA_FOREST_TRUST_INFORMATION;
import com.sun.jna.platform.win32.Netapi32;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * An implementation of the Netapi32 Interface that throws UnsupportedOperationException for
 * everything. Tests may subclass this and override those methods used by the object under test.
 */
public class UnsupportedNetapi32 implements Netapi32, Netapi32Ex {

  @Override
  public int NetShareGetInfo(
      String serverName, String netName, int level, PointerByReference bufptr) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetDfsGetInfo(
      String dfsEntryPath,
      String serverName,
      String shareName,
      int Level,
      PointerByReference buffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetDfsEnum(
      String DfsName,
      int Level,
      int PrefMaxLen,
      PointerByReference Buffer,
      IntByReference EntriesRead,
      IntByReference ResumeHandle) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetGetJoinInformation(
      String lpServer, PointerByReference lpNameBuffer, IntByReference bufferType) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetApiBufferFree(Pointer buffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetLocalGroupEnum(
      String serverName,
      int level,
      PointerByReference bufptr,
      int prefmaxlen,
      IntByReference entriesRead,
      IntByReference totalEntries,
      IntByReference resumeHandle) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetGetDCName(String serverName, String domainName, PointerByReference bufptr) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetGroupEnum(
      String servername,
      int level,
      PointerByReference bufptr,
      int prefmaxlen,
      IntByReference entriesRead,
      IntByReference totalEntries,
      IntByReference resumeHandle) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetUserEnum(
      String serverName,
      int level,
      int filter,
      PointerByReference bufptr,
      int prefmaxlen,
      IntByReference entriesRead,
      IntByReference totalEntries,
      IntByReference resumeHandle) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetUserGetGroups(
      String serverName,
      String userName,
      int level,
      PointerByReference bufptr,
      int prefmaxlen,
      IntByReference entriesRead,
      IntByReference totalEntries) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetUserGetLocalGroups(
      String serverName,
      String userName,
      int level,
      int flags,
      PointerByReference bufptr,
      int prefmaxlen,
      IntByReference entriesRead,
      IntByReference totalEntries) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetUserAdd(String serverName, int level, Structure buf, IntByReference parmError) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetUserDel(String serverName, String userName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetUserChangePassword(
      String domainName, String userName, String oldPassword, String newPassword) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int NetUserGetInfo(
      String serverName, String userName, int level, PointerByReference bufptr) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int DsGetDcName(
      String computerName,
      String domainName,
      GUID domainGuid,
      String siteName,
      int flags,
      PDOMAIN_CONTROLLER_INFO domainControllerInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int DsGetForestTrustInformation(
      String serverName,
      String trustedDomainName,
      int flags,
      PLSA_FOREST_TRUST_INFORMATION dorestTrustInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int DsEnumerateDomainTrusts(
      String serverName, int flags, PointerByReference domains, IntByReference domainCount) {
    throw new UnsupportedOperationException();
  }
}
