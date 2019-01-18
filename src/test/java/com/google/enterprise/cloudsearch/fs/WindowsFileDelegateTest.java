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

import static java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.FILE_INHERIT;
import static java.nio.file.attribute.AclEntryType.ALLOW;
import static java.nio.file.attribute.AclEntryType.DENY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.google.api.client.json.GenericJson;
import com.google.api.services.cloudsearch.v1.model.Item;
import com.google.api.services.cloudsearch.v1.model.PushItem;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.google.enterprise.cloudsearch.fs.AclView.GenericPermission;
import com.google.enterprise.cloudsearch.fs.FsRepository.RepositoryEventPusher;
import com.google.enterprise.cloudsearch.fs.WinApi.Kernel32Ex;
import com.google.enterprise.cloudsearch.fs.WinApi.Netapi32Ex;
import com.google.enterprise.cloudsearch.sdk.indexing.template.ApiOperation;
import com.google.enterprise.cloudsearch.sdk.indexing.template.ApiOperations;
import com.google.enterprise.cloudsearch.sdk.indexing.template.AsyncApiOperation;
import com.google.enterprise.cloudsearch.sdk.indexing.template.PushItems;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/** Tests for {@link WindowsFileDelegate} */
@RunWith(MockitoJUnitRunner.class)
public class WindowsFileDelegateTest extends TestWindowsAclViews {

  @BeforeClass
  public static void checkIfRunningOnWindows() {
    TestHelper.assumeOsIsWindows();
  }

  private static class MockEventPusher implements RepositoryEventPusher {
    Set<AsyncApiOperation> events = new HashSet<>();

    public void push(AsyncApiOperation event) {
      events.add(event);
    }
  };

  private static class SettableAsyncApiOperation extends AsyncApiOperation {
    private GenericJson result;

    SettableAsyncApiOperation(ApiOperation operation, GenericJson result) {
      super(operation);
      this.result = result;
    }

    @Override
    public ListenableFuture<List<GenericJson>> getResult() {
      SettableFuture<List<GenericJson>> result = SettableFuture.create();
      result.set(ImmutableList.of(this.result));
      return result;
    }
  }

  @Rule public ExpectedException thrown = ExpectedException.none();

  private FileDelegate delegate;
  private Path tempRoot;
  private MockEventPusher mockEventPusher;
  @Mock private WindowsFileDelegate.AsyncApiOperationFactory mockAsyncApiOperationFactory;

  @Before
  public void setUp() throws Exception {
    delegate = new WindowsFileDelegate(
        Advapi32.INSTANCE,
        Kernel32Ex.INSTANCE,
        Netapi32Ex.INSTANCE,
        new WindowsAclFileAttributeViews(),
        1000L,
        mockAsyncApiOperationFactory);
    tempRoot = getTempRoot();
    mockEventPusher = new MockEventPusher();
    // The monitor doesn't look at the content of the result, so we can just create a
    // default response here and override in test cases later if desired.
    doAnswer(
        invocation -> {
          ApiOperation op = invocation.getArgument(0);
          return new SettableAsyncApiOperation(op, new Item().setName("Default Item"));
        })
        .when(mockAsyncApiOperationFactory)
        .getAsyncApiOperation(any());
  }

  @After
  public void tearDown() {
    delegate.destroy();
  }

  @Test
  public void testLongPaths() throws Exception {
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Set<ApiOperation> changes = Sets.newHashSet();
    String alpha = "abcdefghijklmnopqrstuvwxyz";
    Path parent = tempRoot;
    for (int i = 0; i < 20; i++) {
      Path child = Paths.get(parent.toString(), "" + i + "_" + alpha);
      Files.createDirectory(child);
      assertTrue(delegate.isDirectory(child));
      assertFalse(delegate.isRegularFile(child));
      assertFalse(delegate.isHidden(child));
      assertFalse(delegate.isDfsNamespace(child));
      assertFalse(delegate.isDfsLink(child));

      FileTime lastAccess = FileTime.fromMillis(10000);
      delegate.setLastAccessTime(child, lastAccess);
      BasicFileAttributes attrs = delegate.readBasicAttributes(child);
      assertEquals(lastAccess, attrs.lastAccessTime());

      Path file = Paths.get(child.toString(), "test.txt");
      Files.write(file, alpha.getBytes("UTF-8"));
      InputStream in = delegate.newInputStream(file);
      assertEquals('a', in.read());
      in.close();
      assertEquals("text/plain", delegate.probeContentType(file));

      DirectoryStream<Path> ds = delegate.newDirectoryStream(child);
      assertNotNull(ds.iterator().next());
      ds.close();

      delegate.getAclViews(child);
      delegate.getAclViews(file);

      changes.add(newRecord(child));
      changes.add(newRecord(file));
      parent = child;
    }
    // Verify the monitor has not died.
    Path file = newTempFile("test.txt");
    Files.write(file, alpha.getBytes("UTF-8"));
    changes.add(newRecord(file));

    checkForChanges(changes);
    delegate.destroy();
  }

  private void testGetDfsShareAclView(String path, int lastError, boolean isLinkAcl)
      throws Exception {
    // The *_OBJECT_ACE_TYPEs will get filtered out by newAclEntry().
    AclFileAttributeView expectedAcl =
        new AclView(
            AclView.group("AccessAllowedAce")
                .type(ALLOW)
                .perms(GenericPermission.GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT),
            AclView.user("AccessDeniedAce")
                .type(DENY)
                .perms(GenericPermission.GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT));

    AclFileAttributeView aclView =
        getDfsShareAclView(
            path,
            lastError,
            isLinkAcl,
            new AceBuilder()
                .setSid(AccountSid.group("AccessAllowedAce", null))
                .setType(WinNT.ACCESS_ALLOWED_ACE_TYPE)
                .setPerms(WinNT.GENERIC_READ)
                .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
                .build(),
            new AceBuilder()
                .setSid(AccountSid.user("AccessAllowedObjectAce", null))
                .setType(WinNT.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                .setPerms(WinNT.GENERIC_ALL)
                .setFlags(WinNT.OBJECT_INHERIT_ACE)
                .build(),
            new AceBuilder()
                .setSid(AccountSid.user("AccessDeniedAce", null))
                .setType(WinNT.ACCESS_DENIED_ACE_TYPE)
                .setPerms(WinNT.GENERIC_READ)
                .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
                .build(),
            new AceBuilder()
                .setSid(AccountSid.group("AccessDeniedObjectAce", null))
                .setType(WinNT.ACCESS_DENIED_OBJECT_ACE_TYPE)
                .setPerms(WinNT.GENERIC_ALL)
                .setFlags(WinNT.OBJECT_INHERIT_ACE)
                .build());

    assertNotNull(aclView);
    assertEquals(expectedAcl.getAcl(), aclView.getAcl());
  }

  @Test
  public void testGetDfsShareAclViewAclOnLink() throws Exception {
    testGetDfsShareAclView("\\\\host\\namespace\\link", 0, true);
  }

  @Test
  public void testGetDfsShareAclViewNoAclOnLink() throws Exception {
    testGetDfsShareAclView("\\\\host\\namespace\\link", W32Errors.ERROR_INSUFFICIENT_BUFFER, false);
  }

  @Test
  public void testGetDfsShareAclViewAclOnNamespace() throws Exception {
    testGetDfsShareAclView("\\\\host\\namespace", W32Errors.ERROR_INSUFFICIENT_BUFFER, false);
  }

  @Test
  public void testGetDfsShareAclViewNotDfs() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    testGetDfsShareAclView("\\\\host\\share", 0, false);
  }

  @Test
  public void testGetDfsShareAclViewUnsupportedAceType() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    getDfsShareAclView(
        "\\\\host\\namespace\\link",
        0,
        true,
        new AceBuilder()
            .setSid(AccountSid.group("SystemAuditAce", null))
            .setType(WinNT.SYSTEM_AUDIT_ACE_TYPE)
            .setPerms(WinNT.GENERIC_ALL)
            .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
            .build());
  }

  @Test
  public void testGetDfsShareAclViewError() throws Exception {
    thrown.expect(Win32Exception.class);
    getDfsShareAclView("\\\\host\\namespace\\link", WinError.ERROR_ACCESS_DENIED, false);
  }

  private AclFileAttributeView getDfsShareAclView(
      String path, final int lastError, final boolean isLinkAcl, WinNT.ACCESS_ACEStructure... aces)
      throws Exception {
    final byte[] dacl = buildDaclMemory(aces);

    Kernel32Ex kernel32 =
        new UnsupportedKernel32() {
          @Override
          public int GetLastError() {
            // For when GetFileSecurity returns false.
            return lastError;
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
            // If we were expecting to pull the ACL of the DFS Link,
            // we should never get here.
            assertFalse(isLinkAcl);
            // Any error other than INSUFFICIENT_BUFFER is intended to
            // simulate a failed system call.
            if (lastError != W32Errors.ERROR_INSUFFICIENT_BUFFER) {
              return false;
            }
            if (nLength < dacl.length) {
              lpnLengthNeeded.setValue(dacl.length);
              return false;
            } else {
              pointer.write(0, dacl, 0, nLength);
              return true;
            }
          }
        };

    final Netapi32Ex.DFS_INFO_150 dfsInfo150 = new Netapi32Ex.DFS_INFO_150();
    if (isLinkAcl) {
      Memory daclMemory = new Memory(dacl.length);
      daclMemory.write(0, dacl, 0, dacl.length);
      dfsInfo150.SdLengthReserved = new ULONG(dacl.length);
      dfsInfo150.pSecurityDescriptor = daclMemory;
    } else {
      dfsInfo150.SdLengthReserved = new ULONG(0);
      dfsInfo150.pSecurityDescriptor = null;
    }
    dfsInfo150.write();
    final Netapi32Ex.DFS_INFO_3 linkDfsInfo3 = newDfsInfo3(0x00000001);
    final Netapi32Ex.DFS_INFO_3 namespaceDfsInfo3 = newDfsInfo3(0x00000101);

    Netapi32Ex netapi =
        new UnsupportedNetapi32() {
          @Override
          public int NetDfsGetInfo(
              String dfsPath,
              String serverName,
              String shareName,
              int level,
              PointerByReference bufptr) {
            if (level == 3) {
              if (dfsPath.contains("link")) {
                bufptr.setValue(linkDfsInfo3.getPointer());
                return LMErr.NERR_Success;
              } else if (dfsPath.contains("namespace")) {
                bufptr.setValue(namespaceDfsInfo3.getPointer());
                return LMErr.NERR_Success;
              } else {
                return WinError.ERROR_NOT_FOUND;
              }
            }
            if (level == 150 && dfsPath.contains("link")) {
              bufptr.setValue(dfsInfo150.getPointer());
              return LMErr.NERR_Success;
            }
            return WinError.ERROR_NOT_SUPPORTED;
          }

          @Override
          public int NetApiBufferFree(Pointer buf) {
            return LMErr.NERR_Success;
          }
        };

    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, null, netapi, null);
    WindowsFileDelegate delegate =
        new WindowsFileDelegate(advapi32, kernel32, netapi, wafav, 0, mockAsyncApiOperationFactory);

    return delegate.getDfsShareAclView(Paths.get(path));
  }

  @Test
  public void testIsDfsNamespaceError() throws Exception {
    Netapi32Ex netapi =
        new UnsupportedNetapi32() {
          @Override
          public int NetDfsGetInfo(
              String dfsPath, String server, String share, int level, PointerByReference bufptr) {
            return WinError.ERROR_ACCESS_DENIED;
          }
        };
    Path dfsPath = Paths.get("\\\\host\\namespace");
    assertFalse(isDfsNamespace(dfsPath, netapi));
  }

  @Test
  public void testIsDfsNamespaceButIsShare() throws Exception {
    // Pathname could be a root, but NetDfsGetInfo returns NOT_FOUND
    Path dfsPath = Paths.get("\\\\host\\share");
    final Netapi32Ex.DFS_INFO_3 info = null;
    assertFalse(isDfsNamespace(dfsPath, info));
  }

  @Test
  public void testIsDfsNamespaceButIsLongPath() throws Exception {
    // Pathname could be not be a DFS root, it is too long.
    Path dfsPath = Paths.get("\\\\host\\share\\dir\\file.txt");
    final Netapi32Ex.DFS_INFO_3 info = null;
    assertFalse(isDfsNamespace(dfsPath, info));
  }

  @Test
  public void testIsDfsNamespaceButIsLink() throws Exception {
    // This is a Link, not a Root
    // DFS_VOLUME_STATE_OK is 1
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000001);
    Path dfsPath = Paths.get("\\\\host\\namespace\\link");
    assertFalse(isDfsNamespace(dfsPath, info));
  }

  @Test
  public void testIsDfsNamespaceButIsBrokenLink() throws Exception {
    // This is a Link, with a malformed name.
    // DFS_VOLUME_STATE_OK is 1
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000001);
    Path dfsPath = Paths.get("\\\\host\\namespace");
    assertFalse(isDfsNamespace(dfsPath, info));
  }

  @Test
  public void testIsDfsNamespaceStandaloneDfs() throws Exception {
    // DFS_VOLUME_FLAVOR_STANDALONE is 0x00000100
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000101);
    Path dfsPath = Paths.get("\\\\host\\namespace");
    assertTrue(isDfsNamespace(dfsPath, info));
  }

  @Test
  public void testIsDfsNamespaceDomainBasedDfs() throws Exception {
    // DFS_VOLUME_FLAVOR_AD_BLOB is 0x00000200
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000201);
    Path dfsPath = Paths.get("\\\\domainhost.example.com\\namespace");
    assertTrue(isDfsNamespace(dfsPath, info));
  }

  private boolean isDfsNamespace(Path dfsPath, final Netapi32Ex.DFS_INFO_3 info)
      throws Exception {
    return isDfsNamespace(dfsPath, getNetapi(info));
  }

  private boolean isDfsNamespace(Path dfsPath, final Netapi32Ex netapi) throws Exception {
    WindowsFileDelegate delegate =
        new WindowsFileDelegate(null, null, netapi, null, 0, mockAsyncApiOperationFactory);
    return delegate.isDfsNamespace(dfsPath);
  }

  @Test
  public void testIsDfsLinkError() throws Exception {
    Netapi32Ex netapi =
        new UnsupportedNetapi32() {
          @Override
          public int NetDfsGetInfo(
              String dfsPath, String server, String share, int level, PointerByReference bufptr) {
            return WinError.ERROR_ACCESS_DENIED;
          }
        };
    Path dfsPath = Paths.get("\\\\host\\namespace\\link");
    assertFalse(isDfsLink(dfsPath, netapi));
  }

  @Test
  public void testIsDfsLink() throws Exception {
    // DFS_VOLUME_STATE_OK is 1
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000001);
    Path dfsPath = Paths.get("\\\\host\\namespace\\link");
    assertTrue(isDfsLink(dfsPath, info));
  }

  @Test
  public void testIsDfsLinkButIsShare() throws Exception {
    // The pathname is too short to be a DFS link.
    Path dfsPath = Paths.get("\\\\host\\share");
    final Netapi32Ex.DFS_INFO_3 info = null;
    assertFalse(isDfsLink(dfsPath, info));
  }

  @Test
  public void testIsDfsLinkButIsSharedFile() throws Exception {
    // The pathname looks like it could be a DFS link, but
    // NetDfsGetInfo returns NOT_FOUND;
    Path dfsPath = Paths.get("\\\\host\\share\\file");
    final Netapi32Ex.DFS_INFO_3 info = null;
    assertFalse(isDfsLink(dfsPath, info));
  }

  @Test
  public void testIsDfsLinkButIsLongPath() throws Exception {
    // Long path that is not a link.
    Path dfsPath = Paths.get("\\\\host\\share\\dir\\dir\\file");
    final Netapi32Ex.DFS_INFO_3 info = null;
    assertFalse(isDfsLink(dfsPath, info));
  }

  @Test
  public void testIsDfsLinkWithLongLinkPath() throws Exception {
    // Now try a long path that is a link.
    Path dfsPath = Paths.get("\\\\server\\namespace\\folder\\folder\\link");
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000001);
    assertTrue(isDfsLink(dfsPath, info));
  }

  @Test
  public void testIsDfsLinkStandaloneRoot() throws Exception {
    // DFS_VOLUME_FLAVOR_STANDALONE is 0x00000100
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000101);
    Path dfsPath = Paths.get("\\\\host\\namespace");
    assertFalse(isDfsLink(dfsPath, info));
  }

  @Test
  public void testIsDfsLinkDomainRoot() throws Exception {
    // DFS_VOLUME_FLAVOR_AD_BLOB is 0x00000200
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(0x00000201);
    Path dfsPath = Paths.get("\\\\domainhost.example.com\\namespace");
    assertFalse(isDfsLink(dfsPath, info));
  }

  private boolean isDfsLink(final Path dfsPath, final Netapi32Ex.DFS_INFO_3 info)
      throws Exception {
    return isDfsLink(dfsPath, getNetapi(info));
  }

  private boolean isDfsLink(final Path dfsPath, final Netapi32Ex netapi) throws Exception {
    WindowsFileDelegate delegate =
        new WindowsFileDelegate(null, null, netapi, null, 0, mockAsyncApiOperationFactory);
    return delegate.isDfsLink(dfsPath);
  }

  @Test
  public void testResolveDfsLinkError() throws Exception {
    Netapi32Ex netapi =
        new UnsupportedNetapi32() {
          @Override
          public int NetDfsGetInfo(
              String dfsPath, String server, String share, int level, PointerByReference bufptr) {
            return WinError.ERROR_ACCESS_DENIED;
          }
        };
    assertNull(resolveDfsLink(netapi));
  }

  @Test
  public void testResolveDfsLinkNoStorage() throws Exception {
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3();

    assertEquals(0, info.NumberOfStorages.intValue());
    thrown.expect(IOException.class);
    resolveDfsLink(info);
  }

  @Test
  public void testResolveDfsLinkSingleActiveStorage() throws Exception {
    final Netapi32Ex.DFS_INFO_3 info =
        newDfsInfo3(new Storage(Netapi32Ex.DFS_STORAGE_STATE_ONLINE, "server", "share"));

    assertEquals(1, info.NumberOfStorages.intValue());
    assertEquals(Paths.get("\\\\server\\share"), resolveDfsLink(info));
  }

  @Test
  public void testResolveDfsLinkNoActiveStorage() throws Exception {
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(new Storage(0, "server", "share"));

    assertEquals(1, info.NumberOfStorages.intValue());
    thrown.expect(IOException.class);
    resolveDfsLink(info);
  }

  @Test
  public void testResolveDfsLinkSomeActiveStorage() throws Exception {
    final Netapi32Ex.DFS_INFO_3 info =
        newDfsInfo3(
            new Storage(0, "inactive", "inactive"),
            new Storage(Netapi32Ex.DFS_STORAGE_STATE_ONLINE, "server", "share"),
            new Storage(Netapi32Ex.DFS_STORAGE_STATE_ONLINE, "active", "active"));

    assertEquals(3, info.NumberOfStorages.intValue());
    assertEquals(Paths.get("\\\\server\\share"), resolveDfsLink(info));
  }

  private static Netapi32Ex getNetapi(final Netapi32Ex.DFS_INFO_3 info) {
    return new UnsupportedNetapi32() {
      @Override
      public int NetDfsGetInfo(
          String dfsPath, String server, String share, int level, PointerByReference bufptr) {
        if (info != null) {
          bufptr.setValue(info.getPointer());
          return LMErr.NERR_Success;
        } else {
          return WinError.ERROR_NOT_FOUND;
        }
      }

      @Override
      public int NetApiBufferFree(Pointer buf) {
        return WinError.ERROR_SUCCESS;
      }
    };
  }

  private Path resolveDfsLink(final Netapi32Ex.DFS_INFO_3 info) throws Exception {
    return resolveDfsLink(getNetapi(info));
  }

  private Path resolveDfsLink(Netapi32Ex netapi) throws Exception {
    WindowsFileDelegate delegate =
        new WindowsFileDelegate(null, null, netapi, null, 0, mockAsyncApiOperationFactory);
    Path dfsPath = Paths.get("\\\\host\\namespace\\link");
    return delegate.resolveDfsLink(dfsPath);
  }

  @Test
  public void testEnumerateDfsLinksNotNamespace() throws Exception {
    thrown.expect(IOException.class);
    enumerateDfsLinks((Memory) null);
  }

  @Test
  public void testEnumerateDfsLinksNoLinks() throws Exception {
    // Enumerate always include the namespace itself in the result.
    final Memory infos = newDfsInfo1("\\\\host\\namespace");
    List<Path> links = enumerateDfsLinks(infos);
    // But the namespace should have been removed from the enumeration.
    assertEquals(0, links.size());
  }

  @Test
  public void testEnumerateDfsLinksOneLink() throws Exception {
    List<Path> expected = ImmutableList.of(Paths.get("\\\\host\\namespace\\link"));
    final Memory infos = newDfsInfo1("\\\\host\\namespace", "\\\\host\\namespace\\link");
    List<Path> links = enumerateDfsLinks(infos);
    assertEquals(expected, links);
  }

  @Test
  public void testEnumerateDfsLinksSeveralLinks() throws Exception {
    List<Path> expected =
        ImmutableList.of(
            Paths.get("\\\\host\\namespace\\link1"),
            Paths.get("\\\\host\\namespace\\link2"),
            Paths.get("\\\\host\\namespace\\link3"));

    final Memory infos =
        newDfsInfo1(
            "\\\\host\\namespace",
            "\\\\host\\namespace\\link1",
            "\\\\host\\namespace\\link2",
            "\\\\host\\namespace\\link3");
    List<Path> links = enumerateDfsLinks(infos);
    assertEquals(expected, links);
  }

  private List<Path> enumerateDfsLinks(final Memory infos) throws Exception {
    Netapi32Ex netapi =
        new UnsupportedNetapi32() {
          @Override
          public int NetDfsEnum(
              String dfsPath,
              int level,
              int prefMaxLen,
              PointerByReference bufptr,
              IntByReference entriesRead,
              IntByReference resumeHandle) {
            if (infos != null) {
              int sizeofInfo = new Netapi32Ex.DFS_INFO_1().size();
              bufptr.setValue(infos.share(0));
              entriesRead.setValue((int) (infos.size() / sizeofInfo));
              return LMErr.NERR_Success;
            } else {
              return WinError.ERROR_NOT_FOUND;
            }
          }

          @Override
          public int NetApiBufferFree(Pointer buf) {
            return WinError.ERROR_SUCCESS;
          }
        };

    WindowsFileDelegate delegate =
        new WindowsFileDelegate(null, null, netapi, null, 0, mockAsyncApiOperationFactory);
    Path namespace = Paths.get("\\\\host\\namespace");
    return ImmutableList.copyOf(delegate.newDfsLinkStream(namespace));
  }

  @Test
  public void testPreserveOriginalNamespace() throws Exception {
    Path original = Paths.get("\\\\server\\namespace");
    Path expected = Paths.get("\\\\server\\namespace", "link");
    assertEquals(
        expected,
        WindowsFileDelegate.preserveOriginalNamespace(
            original, Paths.get("\\\\server\\namespace\\link")));
    assertEquals(
        expected,
        WindowsFileDelegate.preserveOriginalNamespace(
            original, Paths.get("\\\\SERVER\\namespace\\link")));
    assertEquals(
        expected,
        WindowsFileDelegate.preserveOriginalNamespace(
            original, Paths.get("\\\\ALIAS\\namespace\\link")));
    assertEquals(
        expected,
        WindowsFileDelegate.preserveOriginalNamespace(
            original, Paths.get("\\\\server.example.com\\namespace\\link")));

    expected = Paths.get("\\\\server\\namespace", "folder", "link");
    assertEquals(
        expected,
        WindowsFileDelegate.preserveOriginalNamespace(
            original, Paths.get("\\\\SERVER\\namespace\\folder\\link")));
  }

  @Test
  public void testNewDocIdLocalFiles() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile(dir, "test");

    String id = delegate.newDocId(tempRoot);
    assertTrue(id.startsWith(tempRoot.toString()));
    assertFalse(id.endsWith("\\"));

    id = delegate.newDocId(dir);
    assertTrue(id.startsWith(tempRoot.toString()));
    assertTrue(id.startsWith(dir.toString()));
    assertFalse(id.endsWith("\\"));

    id = delegate.newDocId(file);
    assertTrue(id.startsWith(tempRoot.toString()));
    assertTrue(id.startsWith(dir.toString()));
    assertTrue(id.equals(file.toString()));
    assertFalse(id.endsWith("\\"));
  }

  @Test
  public void testNewDocIdVirtualUncPaths() throws Exception {
    assertEquals("\\\\host\\share", delegate.newDocId(Paths.get("\\\\host\\share")));
    assertEquals("\\\\host\\share", delegate.newDocId(Paths.get("\\\\host\\share\\")));
    assertEquals(
        "\\\\host\\share\\foo\\bar", delegate.newDocId(Paths.get("\\\\host\\share\\foo\\bar")));
  }

  @Test
  public void testNewDocIdLocalUncPaths() throws Exception {
    String uncTempRoot = getTempRootAsUncPath();
    assumeNotNull(uncTempRoot);
    Path tempRoot = Paths.get(uncTempRoot);
    String expectedTempRootId = uncTempRoot;

    assertEquals(expectedTempRootId, delegate.newDocId(tempRoot));

    newTempDir("testDir");
    assertEquals(expectedTempRootId + "\\" + "testDir",
        delegate.newDocId(tempRoot.resolve("testDir")));

    newTempFile("test");
    assertEquals(expectedTempRootId + "\\" + "test", delegate.newDocId(tempRoot.resolve("test")));
  }

  private String getTempRootAsUncPath() throws IOException {
    String tempPath = temp.getRoot().getCanonicalPath();
    if (tempPath.length() > 2 && tempPath.charAt(1) == ':') {
      String uncPath = "\\\\localhost\\" + tempPath.substring(0, 1) + "$" + tempPath.substring(2);
      try {
        // Now verify we have access to the local administrative share.
        if (new File(uncPath).list() != null) {
          return uncPath;
        }
      } catch (SecurityException e) {
        // Cannot access local administrative share.
      }
    }
    return null;
  }

  // Test file name from Path.getFileName that's used for the title metadata field. This
  // test is here to check behavior on Windows; FsRepositoryTest also checks the title set
  // in metadata.
  @Test
  public void testFileName() throws Exception {
    Path dir = newTempDir("testDir");
    assertEquals("testDir", dir.getFileName().toString());

    Path file = newTempFile(dir, "test.txt");
    assertEquals("test.txt", file.getFileName().toString());

    Path share = Paths.get("\\\\host\\share");
    assertNull(share.getFileName());

    Path dfsNamespace = Paths.get("\\\\host.domain\\namespace");
    assertNull(dfsNamespace.getFileName());

    Path dfsLink = Paths.get("\\\\host.domain\\namespace\\link");
    assertEquals("link", dfsLink.getFileName().toString());
  }

  @Test
  public void testStartMonitorBadPath() throws Exception {
    Path file = newTempFile("test.txt");
    thrown.expect(IOException.class);
    delegate.startMonitorPath(file, mockEventPusher);
  }

  @Test
  public void testStartStopMonitor() throws Exception {
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    delegate.destroy();
  }

  @Test
  public void testMonitorAddFile() throws Exception {
    // These shouldn't show up as new or modified.
    newTempDir("existingDir");
    newTempFile("existingFile");
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Path file = newTempFile("test.txt");
    checkForChanges(Collections.singleton(newRecord(file)));
  }

  @Test
  public void testMonitorDeleteFile() throws Exception {
    Path file = newTempFile("test.txt");
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.delete(file);
    checkForChanges(Collections.singleton(newDeleteRecord(file)));
  }

  @Test
  public void testMonitorRenameFile() throws Exception {
    Path file = newTempFile("test.txt");
    Path newFile = file.resolveSibling("newName.txt");
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.move(file, newFile, StandardCopyOption.ATOMIC_MOVE);
    // Renaming a file shows up as a change to its old name, its new name.
    checkForChanges(Sets.newHashSet(newDeleteRecord(file), newRecord(newFile)));
  }

  @Test
  public void testMonitorMoveAccrossDirs() throws Exception {
    Path dir1 = newTempDir("dir1");
    Path dir2 = newTempDir("dir2");
    Path file1 = newTempFile(dir1, "test.txt");
    Path file2 = dir2.resolve(file1.getFileName());
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.move(file1, file2);
    // Moving a file shows up as a change to its old name, its new name,
    // its old parent, and its new parent.
    checkForChanges(
        Sets.newHashSet(
            newDeleteRecord(file1), newRecord(file2), newRecord(dir1), newRecord(dir2)));
  }

  @Test
  public void testMonitorModifyFile() throws Exception {
    Path file = newTempFile("test.txt");
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.write(file, "Hello World".getBytes("UTF-8"));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Collections.singleton(newRecord(file)));
  }

  @Test
  public void testMonitorModifyFileAttributes() throws Exception {
    Path file = newTempFile("test.txt");
    FileTime lastModified = Files.getLastModifiedTime(file);
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.setLastModifiedTime(file, FileTime.fromMillis(lastModified.toMillis() + 10000L));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Collections.singleton(newRecord(file)));
  }

  @Test
  public void testMonitorRenameDir() throws Exception {
    Path dir = newTempDir("dir1");
    Path newDir = dir.resolveSibling("newName.dir");
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.move(dir, newDir, StandardCopyOption.ATOMIC_MOVE);
    // Renaming a directory shows up as a change to its old name, its new name.
    checkForChanges(Sets.newHashSet(newDeleteRecord(dir), newRecord(newDir)));
  }

  @Test
  public void testMonitorMoveDir() throws Exception {
    Path dir1 = newTempDir("dir1");
    Path dir2 = newTempDir("dir2");
    Path dir1dir2 = dir1.resolve(dir2.getFileName());
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.move(dir2, dir1dir2);
    // Moving a file shows up as a change to its old name, its new name,
    // and its new parent.
    checkForChanges(Sets.newHashSet(newRecord(dir1), newDeleteRecord(dir2), newRecord(dir1dir2)));
  }

  @Test
  public void testMonitorChangesInSubDirs() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile(dir, "test.txt");
    delegate.startMonitorPath(tempRoot, mockEventPusher);
    Files.write(file, "Hello World".getBytes("UTF-8"));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Sets.newHashSet(newRecord(file), newRecord(dir)));
  }

  @Test
  public void testMonitorBackOffOnError() throws Exception {
    Path file1 = newTempFile(tempRoot, "test1.txt");
    Path file2 = newTempFile(tempRoot, "test2.txt");
    Path file3 = newTempFile(tempRoot, "test3.txt");
    byte[] contents = "Hello World".getBytes("UTF-8");

    // Delegate with a Kernel32Ex that fails ReadDirectoryChangesW.
    Kernel32Ex kernel32 = new ChangeFailingKernel32(Kernel32Ex.INSTANCE, 0, 64, 64, 53);
    WindowsFileDelegate delegate =
        new WindowsFileDelegate(null, kernel32, null, null, 0, mockAsyncApiOperationFactory);
    delegate.startMonitorPath(tempRoot, mockEventPusher);

    Files.write(file1, contents);
    checkForChanges(Collections.singleton(newRecord(file1)));

    // This should be missed during the ReadDirectoryChangesW errors
    Files.write(file2, contents);

    // Wait for the 3 error BackOffs to expire (0.5 + 0.75 + 1.125 = 2.375)
    Thread.sleep(2500);

    // Monitoring should be re-enabled, so this one should go through.
    Files.write(file3, contents);
    checkForChanges(Collections.singleton(newRecord(file3)));
    delegate.destroy();
  }

  /**
   * A Kernel32 implementation that returns one of the specified error codes on each call to
   * ReadDirectoryChangesW. A non-zero return code indicates the call will fail, and the code will
   * be returned by GetLastError. A code of 0 indicates the delegate's ReadDirectoryChangesW should
   * be called.
   */
  private class ChangeFailingKernel32 extends UnsupportedKernel32 {
    private final Kernel32Ex delegate1;
    private final int[] codes;
    int index;
    int lastError;

    public ChangeFailingKernel32(Kernel32Ex delegate, int... codes) {
      this.delegate1 = delegate;
      this.codes = codes;
      index = 0;
      lastError = Integer.MAX_VALUE;
    }

    @Override
    public boolean ReadDirectoryChangesW(
        HANDLE handle,
        FILE_NOTIFY_INFORMATION info,
        int length,
        boolean watchSubtree,
        int notifyFilter,
        IntByReference bytesReturned,
        OVERLAPPED overlapped,
        OVERLAPPED_COMPLETION_ROUTINE completionRoutine) {
      if (index < codes.length && codes[index] != 0) {
        lastError = codes[index++];
        return false;
      }
      index++;
      return delegate1.ReadDirectoryChangesW(
          handle,
          info,
          length,
          watchSubtree,
          notifyFilter,
          bytesReturned,
          overlapped,
          completionRoutine);
    }

    @Override
    public int GetLastError() {
      if (lastError == Integer.MAX_VALUE) {
        return delegate1.GetLastError();
      } else {
        int error = lastError;
        lastError = Integer.MAX_VALUE;
        return error;
      }
    }

    @Override
    public HANDLE CreateFile(
        String fileName,
        int access,
        int mode,
        WinBase.SECURITY_ATTRIBUTES attrs,
        int disposition,
        int flags,
        HANDLE templateFile) {
      return delegate1.CreateFile(fileName, access, mode, attrs, disposition, flags, templateFile);
    }

    @Override
    public HANDLE CreateEvent(
        WinBase.SECURITY_ATTRIBUTES attrs, boolean manualReset, boolean initialState, String name) {
      return delegate1.CreateEvent(attrs, manualReset, initialState, name);
    }

    @Override
    public boolean SetEvent(HANDLE handle) {
      return delegate1.SetEvent(handle);
    }

    @Override
    public boolean CloseHandle(HANDLE handle) {
      return delegate1.CloseHandle(handle);
    }

    @Override
    public int WaitForSingleObjectEx(HANDLE handle, int milliseconds, boolean alertable) {
      return delegate1.WaitForSingleObjectEx(handle, milliseconds, alertable);
    }
  }

  // Wait a bit here; otherwise the events might not have been handed to the pusher.
  private void checkForChanges(Set<ApiOperation> expected) throws Exception {
    // Collect up the changes.
    Set<AsyncApiOperation> changes = Sets.newHashSet();
    final long maxLatencyMillis = 10000;
    long latencyMillis = maxLatencyMillis;
    long batchLatencyMillis = 500;
    boolean inFollowup = false;
    while (latencyMillis > 0) {
      Thread.sleep(batchLatencyMillis);
      latencyMillis -= batchLatencyMillis;

      changes.addAll(mockEventPusher.events);
      mockEventPusher.events.clear();
      if (changes.size() == expected.size()) {
        // If the changes size is equal to the expected size then
        // keep listening for changes for the same period of time
        // that it took to get the current notifications to see if
        // we find any additional changes.
        if (!inFollowup) {
          latencyMillis = maxLatencyMillis - latencyMillis;
          inFollowup = true;
        }
      }
      if (changes.size() > expected.size()) {
        // We've found more changes than are expected. Just stop
        // listening, we'll fail below.
        break;
      }
    }

    Set<ApiOperation> actual = changes.stream()
        .map(AsyncApiOperation::getOperation)
        .collect(Collectors.toSet());
    assertEquals(expected, actual);
  }

  private ApiOperation newRecord(Path path) throws Exception {
    return new PushItems.Builder()
        .addPushItem(delegate.newDocId(path), new PushItem().setType("MODIFIED"))
        .build();
  }

  private ApiOperation newDeleteRecord(Path path) throws Exception {
    return ApiOperations.deleteItem(delegate.newDocId(path));
  }

  private static Memory newDfsInfo1(String... entries) {
    final int sizeOfInfo = new Netapi32Ex.DFS_INFO_1().size();
    final int numberOfEntries = entries.length;

    // Cannot supply length of 0 so always allocate 1 more byte than needed.
    Memory infosMem = new Memory(1 + numberOfEntries * sizeOfInfo);
    int offset = 0;
    for (String entry : entries) {
      writeWString(infosMem, offset, new WString(entry));
      offset += sizeOfInfo;
    }
    return infosMem;
  }

  private static Netapi32Ex.DFS_INFO_3 newDfsInfo3(Storage... storages) {
    // State of 1 is DFS_VOLUME_STATE_OK.
    return newDfsInfo3(1, storages);
  }

  private static Netapi32Ex.DFS_INFO_3 newDfsInfo3(long state, Storage... storages) {
    final int sizeOfInfo = new Netapi32Ex.DFS_STORAGE_INFO().size();
    final int numberOfStorages = storages.length;

    // Cannot supply length of 0 so always allocate 1 more byte than needed.
    Memory storagesMem = new Memory(1 + numberOfStorages * sizeOfInfo);
    int offset = 0;
    for (Storage storage : storages) {
      storagesMem.setLong(offset, storage.state);
      offset += Pointer.SIZE;
      writeWString(storagesMem, offset, storage.serverName);
      offset += Pointer.SIZE;
      writeWString(storagesMem, offset, storage.shareName);
      offset += Pointer.SIZE;
    }

    Memory ptr = new Memory(40);
    writeWString(ptr, 0, new WString(""));
    writeWString(ptr, Pointer.SIZE, new WString(""));
    ptr.setLong(2 * Pointer.SIZE, state);
    ptr.setLong(2 * Pointer.SIZE + Native.LONG_SIZE, numberOfStorages);
    ptr.setPointer(2 * Pointer.SIZE + 2 * Native.LONG_SIZE, storagesMem);
    return new Netapi32Ex.DFS_INFO_3(ptr);
  }

  private static void writeWString(Memory m, int offset, WString str) {
    int len = (str.length() + 1) * Native.WCHAR_SIZE;
    Memory ptr = new Memory(len);
    ptr.setString(0, str);
    m.setPointer(offset, ptr);
  }

  static class Storage {
    protected final int state;
    protected final WString serverName;
    protected final WString shareName;

    public Storage(int state, String serverName, String shareName) {
      this.state = state;
      this.serverName = new WString(serverName);
      this.shareName = new WString(shareName);
    }
  }
}
