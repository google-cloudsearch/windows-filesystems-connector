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

import static com.google.enterprise.cloudsearch.fs.AclView.GenericPermission.GENERIC_ALL;
import static com.google.enterprise.cloudsearch.fs.AclView.GenericPermission.GENERIC_EXECUTE;
import static com.google.enterprise.cloudsearch.fs.AclView.GenericPermission.GENERIC_READ;
import static com.google.enterprise.cloudsearch.fs.AclView.GenericPermission.GENERIC_WRITE;
import static com.google.enterprise.cloudsearch.fs.AclView.group;
import static com.google.enterprise.cloudsearch.fs.AclView.user;
import static java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.FILE_INHERIT;
import static java.nio.file.attribute.AclEntryType.ALLOW;
import static java.nio.file.attribute.AclEntryType.DENY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.enterprise.cloudsearch.fs.WinApi.Netapi32Ex;
import com.google.enterprise.cloudsearch.fs.WinApi.Shlwapi;
import com.google.enterprise.cloudsearch.fs.WindowsAclFileAttributeViews.Mpr;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.SID_NAME_USE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/** Tests for {@link WindowsAclFileAttributeViews} */
public class WindowsAclFileAttributeViewsTest extends TestWindowsAclViews {

  private final WindowsAclFileAttributeViews wafav = new TestAclFileAttributeViews();

  @Rule public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testNewAclEntryUnsupportedAccessType() throws Exception {
    WinNT.ACCESS_ACEStructure ace =
        new AceBuilder().setSid(new AccountSid()).setType(WinNT.SYSTEM_AUDIT_ACE_TYPE).build();
    assertNull(wafav.newAclEntry(ace));
  }

  @Test
  public void testNewAclEntryUnresolvableSid() throws Exception {
    TestHelper.assumeOsIsWindows(); // For new Win32Exception().
    WinNT.ACCESS_ACEStructure ace = new AceBuilder().setSid(new AccountSid()).build();
    assertNull(wafav.newAclEntry(ace));
  }

  @Test
  public void testNewAclEntryUnsupportedAccountType() throws Exception {
    WinNT.ACCESS_ACEStructure ace =
        new AceBuilder().setSid(new AccountSid(SID_NAME_USE.SidTypeUnknown, "", "")).build();
    assertNull(wafav.newAclEntry(ace));
  }

  @Test
  public void testNewAclEntryUserPrincipal() throws Exception {
    testNewAclEntryUserPrincipal(AccountSid.user("userName", null), "userName");
  }

  @Test
  public void testNewAclEntryUserWithDomainPrincipal() throws Exception {
    testNewAclEntryUserPrincipal(AccountSid.user("userName", "domain"), "domain\\userName");
  }

  private void testNewAclEntryUserPrincipal(AccountSid account, String expectedName)
      throws Exception {
    WinNT.ACCESS_ACEStructure ace = new AceBuilder().setSid(account).build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    UserPrincipal principal = aclEntry.principal();
    assertNotNull(principal);
    assertFalse(principal instanceof GroupPrincipal);
    assertEquals(expectedName, principal.getName());
  }

  @Test
  public void testNewAclEntryGroupPrincipal() throws Exception {
    testNewAclEntryGroupPrincipal(AccountSid.group("groupName", null), "groupName");
  }

  @Test
  public void testNewAclEntryGroupWithDomainPrincipal() throws Exception {
    testNewAclEntryGroupPrincipal(AccountSid.group("groupName", "domain"), "domain\\groupName");
  }

  @Test
  public void testNewAclEntryAliasPrincipal() throws Exception {
    AccountSid account = new AccountSid(SID_NAME_USE.SidTypeAlias, "alias", "domain");
    testNewAclEntryGroupPrincipal(account, "domain\\alias");
  }

  @Test
  public void testNewAclEntryWellKnownGroupPrincipal() throws Exception {
    AccountSid account = new AccountSid(SID_NAME_USE.SidTypeWellKnownGroup, "wellKnown", null);
    testNewAclEntryGroupPrincipal(account, "wellKnown");
  }

  private void testNewAclEntryGroupPrincipal(AccountSid account, String expectedName)
      throws Exception {
    WinNT.ACCESS_ACEStructure ace = new AceBuilder().setSid(account).build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    UserPrincipal principal = aclEntry.principal();
    assertNotNull(principal);
    assertTrue(principal instanceof GroupPrincipal);
    assertEquals(expectedName, principal.getName());
  }

  @Test
  public void testNewAclEntryIndividualPermissions() throws Exception {
    testNewAclEntryPermissions(WinNT.FILE_READ_DATA, AclEntryPermission.READ_DATA);
    testNewAclEntryPermissions(WinNT.FILE_READ_ATTRIBUTES, AclEntryPermission.READ_ATTRIBUTES);
    testNewAclEntryPermissions(WinNT.FILE_READ_EA, AclEntryPermission.READ_NAMED_ATTRS);
    testNewAclEntryPermissions(WinNT.READ_CONTROL, AclEntryPermission.READ_ACL);
    testNewAclEntryPermissions(WinNT.FILE_WRITE_DATA, AclEntryPermission.WRITE_DATA);
    testNewAclEntryPermissions(WinNT.FILE_APPEND_DATA, AclEntryPermission.APPEND_DATA);
    testNewAclEntryPermissions(WinNT.FILE_WRITE_ATTRIBUTES, AclEntryPermission.WRITE_ATTRIBUTES);
    testNewAclEntryPermissions(WinNT.FILE_WRITE_EA, AclEntryPermission.WRITE_NAMED_ATTRS);
    testNewAclEntryPermissions(WinNT.WRITE_DAC, AclEntryPermission.WRITE_ACL);
    testNewAclEntryPermissions(WinNT.WRITE_OWNER, AclEntryPermission.WRITE_OWNER);
    testNewAclEntryPermissions(WinNT.DELETE, AclEntryPermission.DELETE);
    testNewAclEntryPermissions(WinNT.FILE_DELETE_CHILD, AclEntryPermission.DELETE_CHILD);
    testNewAclEntryPermissions(WinNT.SYNCHRONIZE, AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(WinNT.FILE_EXECUTE, AclEntryPermission.EXECUTE);
  }

  @Test
  public void testNewAclEntryFullPermissions() throws Exception {
    testNewAclEntryPermissions(WinNT.FILE_ALL_ACCESS, AclEntryPermission.values());
  }

  @Test
  public void testNewAclEntryGenericPermissions() throws Exception {
    testNewAclEntryPermissions(
        WinNT.GENERIC_READ,
        AclEntryPermission.READ_DATA,
        AclEntryPermission.READ_ATTRIBUTES,
        AclEntryPermission.READ_NAMED_ATTRS,
        AclEntryPermission.READ_ACL,
        AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(
        WinNT.GENERIC_WRITE,
        AclEntryPermission.WRITE_DATA,
        AclEntryPermission.APPEND_DATA,
        AclEntryPermission.READ_ACL,
        AclEntryPermission.WRITE_ATTRIBUTES,
        AclEntryPermission.WRITE_NAMED_ATTRS,
        AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(
        WinNT.GENERIC_EXECUTE,
        AclEntryPermission.EXECUTE,
        AclEntryPermission.READ_ATTRIBUTES,
        AclEntryPermission.READ_ACL,
        AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(WinNT.GENERIC_ALL, AclEntryPermission.values());
  }

  private void testNewAclEntryPermissions(
      int acePermissions, AclEntryPermission... expectedPermissions) throws Exception {
    Set<AclEntryPermission> expected = EnumSet.noneOf(AclEntryPermission.class);
    for (AclEntryPermission perm : expectedPermissions) {
      expected.add(perm);
    }
    WinNT.ACCESS_ACEStructure ace =
        new AceBuilder().setSid(AccountSid.user("userName", null)).setPerms(acePermissions).build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    assertEquals(expected, aclEntry.permissions());
  }

  @Test
  public void testNewAclEntryIndividualFlags() throws Exception {
    testNewAclEntryFlags(WinNT.OBJECT_INHERIT_ACE, AclEntryFlag.FILE_INHERIT);
    testNewAclEntryFlags(WinNT.INHERIT_ONLY_ACE, AclEntryFlag.INHERIT_ONLY);
    testNewAclEntryFlags(WinNT.CONTAINER_INHERIT_ACE, AclEntryFlag.DIRECTORY_INHERIT);
    testNewAclEntryFlags(WinNT.NO_PROPAGATE_INHERIT_ACE, AclEntryFlag.NO_PROPAGATE_INHERIT);
  }

  @Test
  public void testNewAclEntryMultipleFlags() throws Exception {
    testNewAclEntryFlags(
        (byte)
            (WinNT.OBJECT_INHERIT_ACE
                | WinNT.CONTAINER_INHERIT_ACE
                | WinNT.INHERIT_ONLY_ACE
                | WinNT.NO_PROPAGATE_INHERIT_ACE),
        AclEntryFlag.values());
  }

  private void testNewAclEntryFlags(byte aceFlags, AclEntryFlag... expectedFlags) throws Exception {
    Set<AclEntryFlag> expected = EnumSet.noneOf(AclEntryFlag.class);
    for (AclEntryFlag flag : expectedFlags) {
      expected.add(flag);
    }
    WinNT.ACCESS_ACEStructure ace =
        new AceBuilder().setSid(AccountSid.user("userName", null)).setFlags(aceFlags).build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    assertEquals(expected, aclEntry.flags());
  }

  @Test
  public void testGetAclViewsEmptyAcl() throws Exception {
    AclFileAttributeViews aclViews = getAclViews();
    assertNotNull(aclViews);
    assertTrue(aclViews.getDirectAclView().getAcl().isEmpty());
    assertTrue(aclViews.getInheritedAclView().getAcl().isEmpty());
  }

  @Test
  public void testGetAclViewsSingleDirectAce() throws Exception {
    AclFileAttributeView expected =
        new AclView(
            user("domain\\user")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    WinNT.ACCESS_ACEStructure ace =
        new AceBuilder()
            .setSid(AccountSid.user("user", "domain"))
            .setPerms(WinNT.GENERIC_READ)
            .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
            .build();
    AclFileAttributeViews aclViews = getAclViews(ace);
    assertNotNull(aclViews);
    assertTrue(aclViews.getInheritedAclView().getAcl().isEmpty());
    assertEquals(expected.getAcl(), aclViews.getDirectAclView().getAcl());
  }

  @Test
  public void testGetAclViewsSingleInheritedAce() throws Exception {
    AclFileAttributeView expected =
        new AclView(
            user("domain\\user")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    WinNT.ACCESS_ACEStructure ace =
        new AceBuilder()
            .setSid(AccountSid.user("user", "domain"))
            .setPerms(WinNT.GENERIC_READ)
            .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE, WinNT.INHERITED_ACE)
            .build();
    AclFileAttributeViews aclViews = getAclViews(ace);
    assertNotNull(aclViews);
    assertTrue(aclViews.getDirectAclView().getAcl().isEmpty());
    assertEquals(expected.getAcl(), aclViews.getInheritedAclView().getAcl());
  }

  @Test
  public void testGetAclViewsInheritedAndDirectAces() throws Exception {
    AclFileAttributeView expectedInherited =
        new AclView(
            group("Everyone")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT),
            group("Administrators")
                .type(ALLOW)
                .perms(GENERIC_ALL)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView expectedDirect =
        new AclView(
            user("BEDROCK\\Fred").type(ALLOW).perms(GENERIC_EXECUTE).flags(FILE_INHERIT),
            user("BEDROCK\\Barney").type(DENY).perms(GENERIC_WRITE).flags(DIRECTORY_INHERIT));
    AclFileAttributeViews aclViews =
        getAclViews(
            new AceBuilder()
                .setSid(AccountSid.user("Fred", "BEDROCK"))
                .setPerms(WinNT.GENERIC_EXECUTE)
                .setFlags(WinNT.OBJECT_INHERIT_ACE)
                .build(),
            new AceBuilder()
                .setSid(AccountSid.group("Everyone", null))
                .setPerms(WinNT.GENERIC_READ)
                .setFlags(
                    WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE, WinNT.INHERITED_ACE)
                .build(),
            new AceBuilder()
                .setSid(AccountSid.group("Administrators", null))
                .setPerms(WinNT.GENERIC_ALL)
                .setFlags(
                    WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE, WinNT.INHERITED_ACE)
                .build(),
            new AceBuilder()
                .setSid(AccountSid.user("Barney", "BEDROCK"))
                .setType(WinNT.ACCESS_DENIED_ACE_TYPE)
                .setPerms(WinNT.GENERIC_WRITE)
                .setFlags(WinNT.CONTAINER_INHERIT_ACE)
                .build());

    assertNotNull(aclViews);
    assertEquals(expectedDirect.getAcl(), aclViews.getDirectAclView().getAcl());
    assertEquals(expectedInherited.getAcl(), aclViews.getInheritedAclView().getAcl());
  }

  private AclFileAttributeViews getAclViews(WinNT.ACCESS_ACEStructure... aces) throws Exception {
    final byte[] dacl = buildDaclMemory(aces);
    Kernel32 kernel32 =
        new UnsupportedKernel32() {
          @Override
          public int GetLastError() {
            // For when GetFileSecurity returns false.
            return W32Errors.ERROR_INSUFFICIENT_BUFFER;
          }
        };
    Advapi32 advapi32 =
        new UnsupportedAdvapi32() {
          @Override
          public boolean GetFileSecurity(
              WString lpFileName,
              int RequestedInformation,
              Pointer pointer,
              int nLength,
              IntByReference lpnLengthNeeded) {
            if (nLength < dacl.length) {
              lpnLengthNeeded.setValue(dacl.length);
              return false;
            } else {
              pointer.write(0, dacl, 0, nLength);
              return true;
            }
          }
        };

    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(advapi32, kernel32, null, null, null);
    return wafav.getAclViews(newTempFile("test"));
  }

  /**
   * Test the first IOException that can be thrown out of getFileSecurity(). In that method, the
   * first call to advapi32.GetFileSecurity() is expected to return
   * W32Errors.ERROR_INSUFFICIENT_BUFFER and the required buffer size. This test returns a different
   * error, which gets rethrown as an IOException.
   */
  @Test
  public void testGetAclViewsException1() throws Exception {
    TestHelper.assumeOsIsWindows(); // For new Win32Exception().
    thrown.expect(IOException.class);
    testGetAclViewsException(W32Errors.ERROR_MORE_DATA);
  }

  /**
   * Test the second IOException that can be thrown out of getFileSecurity(). In that method, the
   * second call to advapi32.GetFileSecurity() is not expected to return any error. This test
   * returns an error on both calls - the expected error for the first call and that same error for
   * the second call.
   */
  @Test
  public void testGetAclViewsException2() throws Exception {
    TestHelper.assumeOsIsWindows(); // For new Win32Exception().
    thrown.expect(IOException.class);
    testGetAclViewsException(W32Errors.ERROR_INSUFFICIENT_BUFFER);
  }

  private void testGetAclViewsException(final int errorCode) throws Exception {
    Kernel32 kernel32 =
        new UnsupportedKernel32() {
          @Override
          public int GetLastError() {
            return errorCode;
          }
        };
    Advapi32 advapi32 =
        new UnsupportedAdvapi32() {
          @Override
          public boolean GetFileSecurity(
              WString lpFileName,
              int RequestedInformation,
              Pointer pointer,
              int nLength,
              IntByReference lpnLengthNeeded) {
            lpnLengthNeeded.setValue(10);
            return false;
          }
        };
    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(advapi32, kernel32, null, null, null);
    wafav.getAclViews(newTempFile("test"));
  }

  @Test
  public void testGetShareAclViewLocalDrive() throws Exception {
    Shlwapi shlwapi =
        new Shlwapi() {
          @Override
          public boolean PathIsNetworkPath(String pszPath) {
            return false;
          }

          @Override
          public boolean PathIsUNC(String pszPath) {
            return false;
          }
        };
    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, null, null, shlwapi);
    AclFileAttributeView aclView = wafav.getShareAclView(newTempDir("test"));
    assertNotNull(aclView);
    assertTrue(aclView.getAcl().isEmpty());
  }

  @Test
  public void testGetShareAclViewUncPath() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi =
        new Shlwapi() {
          @Override
          public boolean PathIsNetworkPath(String pszPath) {
            return false;
          }

          @Override
          public boolean PathIsUNC(String pszPath) {
            return true;
          }
        };
    Path share = Paths.get("\\\\server\\share");
    testGetShareAclView(share, shlwapi, null);
  }

  @Test
  public void testGetShareAclViewBadUncPath() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi =
        new Shlwapi() {
          @Override
          public boolean PathIsNetworkPath(String pszPath) {
            return false;
          }

          @Override
          public boolean PathIsUNC(String pszPath) {
            return true;
          }
        };
    thrown.expect(IOException.class);
    testGetShareAclView(newTempDir("test"), shlwapi, null);
  }

  @Test
  public void testGetShareAclViewNetworkPath() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi =
        new Shlwapi() {
          @Override
          public boolean PathIsNetworkPath(String pszPath) {
            return true;
          }

          @Override
          public boolean PathIsUNC(String pszPath) {
            return false;
          }
        };
    Mpr mpr =
        new Mpr() {
          @Override
          public int WNetGetUniversalNameW(
              String lpLocalPath, int dwInfoLevel, Pointer lpBuffer, IntByReference lpBufferSize) {
            Mpr.UNIVERSAL_NAME_INFO info = new Mpr.UNIVERSAL_NAME_INFO();
            info.lpUniversalName = "\\\\server\\share";
            info.write();
            // Force a reallocation, even though we do not need it.
            if (lpBufferSize.getValue() != info.size()) {
              lpBufferSize.setValue(info.size());
              return WinNT.ERROR_MORE_DATA;
            }
            byte[] buf = new byte[info.size()];
            info.getPointer().read(0, buf, 0, buf.length);
            lpBuffer.write(0, buf, 0, buf.length);
            return WinNT.NO_ERROR;
          }
        };
    testGetShareAclView(newTempDir("test"), shlwapi, mpr);
  }

  @Test
  public void testGetShareAclViewNetworkPathFailure() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi =
        new Shlwapi() {
          @Override
          public boolean PathIsNetworkPath(String pszPath) {
            return true;
          }

          @Override
          public boolean PathIsUNC(String pszPath) {
            return false;
          }
        };
    Mpr mpr =
        new Mpr() {
          @Override
          public int WNetGetUniversalNameW(
              String lpLocalPath, int dwInfoLevel, Pointer lpBuffer, IntByReference lpBufferSize) {
            return WinNT.ERROR_INVALID_PARAMETER;
          }
        };
    thrown.expect(IOException.class);
    testGetShareAclView(newTempDir("test"), shlwapi, mpr);
  }

  private void testGetShareAclView(Path share, Shlwapi shlwapi, Mpr mpr) throws Exception {
    AclFileAttributeView expectedAcl =
        new AclView(
            group("Everyone")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT),
            group("Administrators")
                .type(ALLOW)
                .perms(GENERIC_ALL)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    byte[] dacl =
        buildDaclMemory(
            new AceBuilder()
                .setSid(AccountSid.group("Everyone", null))
                .setPerms(WinNT.GENERIC_READ)
                .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
                .build(),
            new AceBuilder()
                .setSid(AccountSid.group("Administrators", null))
                .setPerms(WinNT.GENERIC_ALL)
                .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
                .build());

    Memory memory = new Memory(dacl.length);
    memory.write(0, dacl, 0, dacl.length);
    final Netapi32Ex.SHARE_INFO_502 info = new Netapi32Ex.SHARE_INFO_502();
    info.shi502_security_descriptor = memory;
    info.write();

    Netapi32Ex netapi =
        new UnsupportedNetapi32() {
          @Override
          public int NetShareGetInfo(
              String serverName, String netName, int level, PointerByReference bufptr) {
            bufptr.setValue(info.getPointer());
            return WinError.ERROR_SUCCESS;
          }

          @Override
          public int NetApiBufferFree(Pointer buf) {
            return WinError.ERROR_SUCCESS;
          }
        };

    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, mpr, netapi, shlwapi);

    AclFileAttributeView aclView = wafav.getShareAclView(share);
    assertNotNull(aclView);
    assertEquals(expectedAcl.getAcl(), aclView.getAcl());
  }

  @Test
  public void testGetShareAclViewNetShareGetInfoFailureAccessDenied() throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetShareGetInfoFailure(WinError.ERROR_ACCESS_DENIED);
  }

  @Test
  public void testGetShareAclViewNetShareGetInfoFailureInvalidLevel() throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetShareGetInfoFailure(WinError.ERROR_INVALID_LEVEL);
  }

  @Test
  public void testGetShareAclViewNetShareGetInfoFailureInvalidParameter() throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetShareGetInfoFailure(WinError.ERROR_INVALID_PARAMETER);
  }

  @Test
  public void testGetShareAclViewNetShareGetInfoFailureInsufficientMemory() throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetShareGetInfoFailure(WinError.ERROR_NOT_ENOUGH_MEMORY);
  }

  @Test
  public void testGetShareAclViewNetShareGetInfoFailureNetNameNotFound() throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetShareGetInfoFailure(LMErr.NERR_NetNameNotFound);
  }

  @Test
  public void testGetShareAclViewNetShareGetInfoFailureOther() throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetShareGetInfoFailure(WinError.ERROR_NOT_READY);
  }

  private void testGetShareAclViewNetShareGetInfoFailure(final int error) throws Exception {
    Shlwapi shlwapi =
        new Shlwapi() {
          @Override
          public boolean PathIsNetworkPath(String pszPath) {
            return false;
          }

          @Override
          public boolean PathIsUNC(String pszPath) {
            return true;
          }
        };
    Netapi32Ex netapi =
        new UnsupportedNetapi32() {
          @Override
          public int NetShareGetInfo(
              String serverName, String netName, int level, PointerByReference bufptr) {
            return error;
          }

          @Override
          public int NetApiBufferFree(Pointer buf) {
            return WinError.ERROR_SUCCESS;
          }
        };
    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, null, netapi, shlwapi);
    Path share = Paths.get("\\\\server\\share");

    thrown.expect(IOException.class);
    wafav.getShareAclView(share);
  }
}
