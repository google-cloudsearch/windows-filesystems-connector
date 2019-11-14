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

import static com.google.enterprise.cloudsearch.fs.AclView.GenericPermission;
import static com.google.enterprise.cloudsearch.fs.AclView.group;
import static com.google.enterprise.cloudsearch.fs.AclView.user;
import static com.google.enterprise.cloudsearch.fs.FileDelegate.PathDirectoryStream;
import static com.google.enterprise.cloudsearch.fs.FsRepository.ASYNC_PUSH_ITEMS_BATCH_SIZE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.FILE_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.INHERIT_ONLY;
import static java.nio.file.attribute.AclEntryFlag.NO_PROPAGATE_INHERIT;
import static java.nio.file.attribute.AclEntryType.ALLOW;
import static org.hamcrest.CoreMatchers.anything;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.api.client.http.AbstractInputStreamContent;
import com.google.api.client.http.FileContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.DateTime;
import com.google.api.services.cloudsearch.v1.model.Item;
import com.google.api.services.cloudsearch.v1.model.ItemAcl;
import com.google.api.services.cloudsearch.v1.model.ItemMetadata;
import com.google.api.services.cloudsearch.v1.model.Principal;
import com.google.api.services.cloudsearch.v1.model.PushItem;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.enterprise.cloudsearch.sdk.CloseableIterable;
import com.google.enterprise.cloudsearch.sdk.InvalidConfigurationException;
import com.google.enterprise.cloudsearch.sdk.RepositoryException;
import com.google.enterprise.cloudsearch.sdk.StartupException;
import com.google.enterprise.cloudsearch.sdk.config.Configuration.ResetConfigRule;
import com.google.enterprise.cloudsearch.sdk.config.Configuration.SetupConfigRule;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl.InheritanceType;
import com.google.enterprise.cloudsearch.sdk.indexing.DefaultAcl.DefaultAclMode;
import com.google.enterprise.cloudsearch.sdk.indexing.IndexingItemBuilder.ItemType;
import com.google.enterprise.cloudsearch.sdk.indexing.IndexingService.ContentFormat;
import com.google.enterprise.cloudsearch.sdk.indexing.IndexingService.RequestMode;
import com.google.enterprise.cloudsearch.sdk.indexing.template.ApiOperation;
import com.google.enterprise.cloudsearch.sdk.indexing.template.ApiOperations;
import com.google.enterprise.cloudsearch.sdk.indexing.template.BatchApiOperation;
import com.google.enterprise.cloudsearch.sdk.indexing.template.PushItems;
import com.google.enterprise.cloudsearch.sdk.indexing.template.RepositoryContext;
import com.google.enterprise.cloudsearch.sdk.indexing.template.RepositoryDoc;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * Tests FsRepository.
 */
@RunWith(MockitoJUnitRunner.class)
public class FsRepositoryTest {
  @Rule public ExpectedException thrown = ExpectedException.none();
  @Rule public ResetConfigRule resetConfig = new ResetConfigRule();
  @Rule public SetupConfigRule setupConfig = SetupConfigRule.uninitialized();
  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();

  @Mock FileDelegate mockFileDelegate;
  @Mock DirectoryStream<Path> mockDirectoryStream;
  @Mock RepositoryContext mockRepositoryContext;

  private Path setUpStartPath(String pathname) throws IOException {
    Path path = Paths.get(pathname);
    when(mockFileDelegate.newDocId(path)).thenReturn(pathname);
    when(mockFileDelegate.getPath(pathname)).thenReturn(path);
    AclFileAttributeView mockAttributeView = mock(AclFileAttributeView.class);
    when(mockFileDelegate.getShareAclView(path)).thenReturn(mockAttributeView);
    when(mockFileDelegate.newDirectoryStream(path)).thenReturn(mockDirectoryStream);
    return path;
  }

  private void setConfig(String fsSrc) {
    setConfig(fsSrc, new Properties());
  }

  private void setConfig(String fsSrc, Properties testProperties) {
    Properties config = new Properties();
    config.put("api.identitySourceId", "idSource");
    config.put("fs.src", fsSrc);
    config.put("fs.src.separator", ";");
    config.put("fs.builtinGroupPrefix", "BUILTIN\\\\");
    config.put(
        "fs.supportedAccounts",
        "BUILTIN\\Administrators,Everyone,BUILTIN\\Users,BUILTIN\\Guest,"
            + "NT AUTHORITY\\INTERACTIVE,NT AUTHORITY\\Authenticated Users");
    config.put("fs.crawlHiddenFiles", "false");
    config.put("fs.preserveLastAccessTime", "ALWAYS");
    config.put("fs.directoryCacheSize", "50000");
    config.put("fs.skipShareAccessControl", "");
    config.put("fs.lastAccessedDays", "");
    config.put("fs.lastAccessedDate", "");
    config.put("fs.lastModifiedDays", "");
    config.put("fs.lastModifiedDate", "");
    config.put("fs.monitorForUpdates", "true");

    config.putAll(testProperties);
    setupConfig.initConfig(config);
  }

  private Path writeMimeTypes(String content) throws IOException {
    Path file = tempFolder.newFile("test-mime-types.properties").toPath();
    Files.write(file, content.getBytes(UTF_8));
    return file;
  }

  @Test
  public void testLoadMimeTypesFileNotFound() throws Exception {
    Path file = tempFolder.getRoot().toPath()
        .resolve("non-existent-mime-types.properties");
    Properties defaults = new Properties();
    assertSame(defaults, FsRepository.loadMimeTypeProperties(file, defaults));
  }

  @Test
  public void testLoadMimeTypesEmptyFile() throws Exception {
    Path file = writeMimeTypes("");
    Properties defaults = new Properties();
    defaults.setProperty("ext1", "foo/bar");
    defaults.setProperty("ext2", "foo/baz");
    Properties mimeTypes = FsRepository.loadMimeTypeProperties(file, defaults);
    assertEquals(new Properties(), mimeTypes);
    // But the defaults should still work.
    assertEquals("foo/bar", mimeTypes.getProperty("ext1"));
    assertEquals("foo/baz", mimeTypes.getProperty("ext2"));
  }

  @Test
  public void testLoadMimeTypesUniqueKey() throws Exception {
    Path file = writeMimeTypes("ext1=foo/bar\n");
    Properties defaults = new Properties();
    defaults.setProperty("ext2", "foo/baz");
    Properties mimeTypes = FsRepository.loadMimeTypeProperties(file, defaults);
    assertEquals("foo/bar", mimeTypes.getProperty("ext1"));
    assertEquals("foo/baz", mimeTypes.getProperty("ext2"));
  }

  @Test
  public void testLoadMimeTypesMultipleKeys() throws Exception {
    Path file = writeMimeTypes("ext1=foo/bar\next2=foo/baz\n");
    Properties defaults = new Properties();
    Properties mimeTypes = FsRepository.loadMimeTypeProperties(file, defaults);
    assertEquals("foo/bar", mimeTypes.getProperty("ext1"));
    assertEquals("foo/baz", mimeTypes.getProperty("ext2"));
  }

  @Test
  public void testLoadMimeTypesOverrideDefaultValue() throws Exception {
    Path file = writeMimeTypes("ext1=text/plain\n");
    Properties defaults = new Properties();
    defaults.setProperty("ext1", "foo/bar");
    defaults.setProperty("ext2", "foo/baz");
    Properties mimeTypes = FsRepository.loadMimeTypeProperties(file, defaults);
    assertEquals("text/plain", mimeTypes.getProperty("ext1"));
    assertEquals("foo/baz", mimeTypes.getProperty("ext2"));
  }

  @Test
  public void testLoadMimeTypesToLowerExtensions() throws Exception {
    Path file = writeMimeTypes("EXT1=text/plain\n");
    Properties defaults = new Properties();
    Properties mimeTypes = FsRepository.loadMimeTypeProperties(file, defaults);
    assertEquals("text/plain", mimeTypes.getProperty("ext1"));
    assertNull(mimeTypes.getProperty("EXT1"));
  }

  @Test
  public void testLoadMimeTypesTrimValues() throws Exception {
    Path file = writeMimeTypes("ext1=text/plain    \n");
    Properties defaults = new Properties();
    Properties mimeTypes = FsRepository.loadMimeTypeProperties(file, defaults);
    assertEquals("text/plain", mimeTypes.getProperty("ext1"));
  }

  // Verifies that the built-in list is loaded by default.
  @Test
  public void getDocMimeType_builtinMimeTypes() throws IOException {
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    assertEquals("application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        fsRepository.getDocMimeType(Paths.get("file.docx")));
    verify(mockFileDelegate, never()).probeContentType(any());
  }

  @Test
  public void getDocMimeType_probeNull_returnsNull() throws IOException {
    when(mockFileDelegate.probeContentType(any())).thenReturn(null);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    assertNull(fsRepository.getDocMimeType(Paths.get("file.pdf")));
  }

  @Test
  public void getDocMimeType_probeIoException_returnsNull() throws IOException {
    when(mockFileDelegate.probeContentType(any())).thenThrow(IOException.class);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    assertNull(fsRepository.getDocMimeType(Paths.get("file.pdf")));
  }

  @Test
  public void testConstructorDefaultWindows() {
    TestHelper.assumeOsIsWindows();
    new FsRepository();
  }

  @Test
  public void testConstructorDefaultNonWindows() {
    TestHelper.assumeOsIsNotWindows();
    thrown.expect(IllegalStateException.class);
    new FsRepository();
  }

  @Test
  public void testConstructor() {
    new FsRepository(mockFileDelegate);
  }

  @Test
  public void testInit() throws Exception {
    setUpStartPath("/");
    setConfig("/");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitWithNullContext() {
    setConfig("/");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(NullPointerException.class);
    fsRepository.init(null);
  }

  @Test
  public void testInitNoSourcePath() throws Exception {
    setConfig("");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitNoIdentitySource() throws Exception {
    Properties config = new Properties();
    config.put("api.identitySourceId", "");
    setConfig("", config);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitConfigurationIsUninitialized() throws Exception {
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(IllegalStateException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidPathException() throws Exception {
    when(mockFileDelegate.getPath(any())).thenThrow(InvalidPathException.class);

    setConfig("invalid path");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitIOPathException() throws Exception {
    when(mockFileDelegate.getPath(any())).thenThrow(IOException.class);

    setConfig("invalid path");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitNonRootSourcePath() throws Exception {
    String startName = "/path/to/dir";
    Path startPath = setUpStartPath(startName);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitDfsLink() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    AclFileAttributeView mockAttributeView = mock(AclFileAttributeView.class);
    when(mockFileDelegate.getDfsShareAclView(startPath))
        .thenReturn(mockAttributeView);
    when(mockFileDelegate.isDfsLink(startPath)).thenReturn(true);
    when(mockFileDelegate.resolveDfsLink(startPath)).thenReturn(startPath);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitDfsPath() throws Exception {
    String startName = "/path/to/dir";
    Path startPath = setUpStartPath(startName);
    AclFileAttributeView mockAttributeView = mock(AclFileAttributeView.class);
    when(mockFileDelegate.getDfsShareAclView(startPath))
        .thenReturn(mockAttributeView);
    when(mockFileDelegate.isDfsLink(startPath)).thenReturn(true);
    when(mockFileDelegate.resolveDfsLink(startPath)).thenReturn(startPath);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitDfsLinkNoActiveStorage() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.isDfsLink(startPath)).thenReturn(true);
    AclFileAttributeView mockAttributeView = mock(AclFileAttributeView.class);
    when(mockFileDelegate.getDfsShareAclView(startPath)).thenReturn(mockAttributeView);
    // resolveDfsLink (WindowsFileDelegate) throws IOException when no active storage is found
    when(mockFileDelegate.resolveDfsLink(startPath)).thenThrow(IOException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitDfsNamespace() throws Exception {
    String dfsNamespace = "\\\\dfs-server\\share";
    Path startPath = setUpStartPath(dfsNamespace);
    List<Path> links = addDfsLinks(dfsNamespace, 2);

    setConfig(dfsNamespace);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitDfsNamespaceWithBadDfsLink() throws Exception {
    String dfsNamespace = "\\\\dfs-server\\share";
    Path startPath = setUpStartPath(dfsNamespace);
    List<Path> links = addDfsLinks(dfsNamespace, 3);
    when(mockFileDelegate.resolveDfsLink(links.get(1))).thenThrow(IOException.class);

    setConfig(dfsNamespace);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  private List<Path> addDfsLinks(String dfsNamespace, int count) throws IOException {
    Path dfsPath = Paths.get(dfsNamespace);
    when(mockFileDelegate.getPath(dfsNamespace)).thenReturn(dfsPath);
    when(mockFileDelegate.isDfsNamespace(dfsPath)).thenReturn(true);
    AclFileAttributeView mockAttributeView = mock(AclFileAttributeView.class);
    when(mockFileDelegate.getDfsShareAclView(dfsPath)).thenReturn(mockAttributeView);
    List<Path> links = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      Path link = Paths.get(dfsNamespace, "link" + i);
      when(mockFileDelegate.resolveDfsLink(link)).thenReturn(link);
      links.add(link);
    }
    doAnswer(
        invocation -> {
          return new PathDirectoryStream(links);
        })
        .when(mockFileDelegate)
        .newDfsLinkStream(dfsPath);
    return links;
  }

  @Test
  public void testInitSupportedWindowsAccounts() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    String accounts = "Everyone, BUILTIN\\Users, NT AUTH\\New Users";
    Set<String> expected =
        ImmutableSet.of("Everyone", "BUILTIN\\Users", "NT AUTH\\New Users");
    Properties p = new Properties();
    p.put("fs.supportedAccounts", accounts);

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    assertEquals(expected, fsRepository.getSupportedWindowsAccounts());
  }

  @Test
  public void testInitBuiltinGroupPrefix() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    String expected = "TestPrefix";
    Properties p = new Properties();
    p.put("fs.builtinGroupPrefix", expected);

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    assertEquals(expected, fsRepository.getBuiltinPrefix());
  }

  @Test
  public void testInitAclMode_Fallback() throws Exception {
    setUpStartPath("/");
    setConfig("/");
    Logger log = Logger.getLogger(FsRepository.class.getName());
    ByteArrayOutputStream logStream = new ByteArrayOutputStream();
    Handler logHandler = new StreamHandler(logStream, new SimpleFormatter());
    log.addHandler(logHandler);
    when(mockRepositoryContext.getDefaultAclMode()).thenReturn(DefaultAclMode.FALLBACK);

    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    logHandler.flush();
    assertThat(logStream.toString(),
        containsString("The default ACL in FALLBACK mode will be ignored."));
  }

  @Test
  public void testInitAclMode_nonFallback() throws Exception {
    setUpStartPath("/");
    setConfig("/");
    Logger log = Logger.getLogger(FsRepository.class.getName());
    ByteArrayOutputStream logStream = new ByteArrayOutputStream();
    Handler logHandler = new StreamHandler(logStream, new SimpleFormatter());
    log.addHandler(logHandler);
    when(mockRepositoryContext.getDefaultAclMode()).thenReturn(DefaultAclMode.OVERRIDE);

    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    logHandler.flush();
    assertThat("Should not contain FALLBACK", logStream.toString(),
        not(containsString("FALLBACK")));
  }

  @Test
  public void testInitNoCrawlHiddenRoot() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.isHidden(startPath)).thenReturn(true);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitCrawlHiddenRoot() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    // implementation detail: since fs.crawlHiddenFiles is true, the check to see if the
    // file is hidden is not executed, causing mockito to complain if we leave this stub
    // in.
    //when(mockFileDelegate.isHidden(startPath)).thenReturn(true);

    Properties p = new Properties();
    p.put("fs.crawlHiddenFiles", "true");
    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitBadPreserveLastAccessTime() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.preserveLastAccessTime", "true");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitMultipleStartPaths() throws Exception {
    String dfsNamespace1 = "\\\\dfs-server\\share1";
    addDfsLinks(dfsNamespace1, 3);
    String dfsNamespace2 = "\\\\dfs-server\\share2";
    addDfsLinks(dfsNamespace2, 2);
    String dfsNamespace3 = "\\\\dfs-server\\share3";
    addDfsLinks(dfsNamespace3, 4);

    setConfig(dfsNamespace1 + ";" + dfsNamespace2 + ";" + dfsNamespace3);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    assertEquals(ImmutableSet.of(Paths.get(dfsNamespace1), Paths.get(dfsNamespace2),
            Paths.get(dfsNamespace3)),
        fsRepository.getStartPaths());
  }

  @Test
  public void testGetStartPathsNoSeparator() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    // Believe it or not, semicolons are valid filename characters in Windows.
    String sources = "/semicolons;in;filename";
    Set<Path> expected = ImmutableSet.of(Paths.get("/semicolons;in;filename"));
    assertEquals(expected, fsRepository.getStartPaths(sources, ""));
  }

  @Test
  public void testGetStartPathsDefaultSeparator() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    String separator = ";";
    String sources = "/dir1" + separator + "/dir2" + separator + "/dir3";
    Set<Path> expected = ImmutableSet.of(
        Paths.get("/dir1"), Paths.get("/dir2"), Paths.get("/dir3"));
    assertEquals(expected, fsRepository.getStartPaths(sources, separator));
  }

  @Test
  public void testGetStartPathsNonDefaultSeparator() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    // Believe it or not, semicolons are valid filename characters in Windows.
    String separator = ":";
    String sources = "/dir;1" + separator + "/dir;2" + separator + "/dir;3";
    Set<Path> expected = ImmutableSet.of(
        Paths.get("/dir;1"), Paths.get("/dir;2"), Paths.get("/dir;3"));
    assertEquals(expected, fsRepository.getStartPaths(sources, separator));
  }

  @Test
  public void testGetStartPathsEmptyItems() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    String separator = ";";
    String sources = "/dir1" + separator + separator + "/dir2" + separator;
    Set<Path> expected = ImmutableSet.of(
        Paths.get("/dir1"), Paths.get("/dir2"));
    assertEquals(expected, fsRepository.getStartPaths(sources, separator));
  }

  @Test
  public void testGetStartPathsEmbeddedWhiteSpace() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    String separator = ";";
    String sources = "/dir 1" + separator + "/dir 2";
    Set<Path> expected = ImmutableSet.of(Paths.get("/dir 1"), Paths.get("/dir 2"));
    assertEquals(expected, fsRepository.getStartPaths(sources, separator));
  }

  @Test
  public void testGetStartPathsTrimExtraneousWhiteSpace() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    String separator = ";";
    String sources = " /dir 1" + separator + " /dir 2 ";
    Set<Path> expected = ImmutableSet.of(Paths.get("/dir 1"), Paths.get("/dir 2"));
    assertEquals(expected, fsRepository.getStartPaths(sources, separator));
  }

  @Test
  public void testGetStartPathsUncPaths() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    String separator = ";";
    String sources = "\\\\server\\share1" + separator + "\\\\server\\share2"
        + separator + "\\\\server\\share3";
    Set<Path> expected =
        ImmutableSet.of(Paths.get("\\\\server\\share1"), Paths.get("\\\\server\\share2"),
            Paths.get("\\\\server\\share3"));
    assertEquals(expected, fsRepository.getStartPaths(sources, separator));
  }

  @Test
  public void testValidateStartPathInvalidDocId() throws Exception {
    Path p = Paths.get("/invalid");
    when(mockFileDelegate.newDocId(p)).thenThrow(IOException.class);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.validateStartPath(p, false);
  }

  @Test
  public void testValidateShareNotDirectory() throws Exception {
    String startName = "\\\\server\\share\\file";
    Path startPath = setUpStartPath(startName);
    setConfig(startName);
    when(mockFileDelegate.newDirectoryStream(startPath)).thenThrow(NotDirectoryException.class);

    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.validateShare(startPath);
  }

  @Test
  public void testValidateShareNotFound() throws Exception {
    String startName = "\\\\server\\share\\file";
    Path startPath = setUpStartPath(startName);
    setConfig(startName);
    when(mockFileDelegate.newDirectoryStream(startPath)).thenThrow(FileNotFoundException.class);

    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.validateShare(startPath);
  }

  @Test
  public void testValidateShareNoSuchFile() throws Exception {
    String startName = "\\\\server\\share\\file";
    Path startPath = setUpStartPath(startName);
    setConfig(startName);
    when(mockFileDelegate.newDirectoryStream(startPath)).thenThrow(NoSuchFileException.class);

    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(InvalidConfigurationException.class);
    fsRepository.validateShare(startPath);
  }

  @Test
  public void testValidateShareIOException() throws Exception {
    String startName = "\\\\server\\share\\file";
    Path startPath = setUpStartPath(startName);
    setConfig(startName);
    when(mockFileDelegate.newDirectoryStream(startPath)).thenThrow(IOException.class);

    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(IOException.class);
    fsRepository.validateShare(startPath);
  }

  @Test
  public void testGetFolderName() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    assertEquals("share", fsRepository.getFileName(Paths.get("\\\\host/share/")));
    assertEquals("folder2", fsRepository.getFileName(Paths.get("C:/folder1/folder2/")));
    assertEquals("folder2", fsRepository.getFileName(Paths.get("/folder1/folder2/")));
    assertEquals("share", fsRepository.getFileName(Paths.get("\\\\host/share")));
    assertEquals("folder1", fsRepository.getFileName(Paths.get("/folder1")));
    // Windows flips the '/' to '\'.
    assertEquals(File.separator, fsRepository.getFileName(Paths.get("/")));
    assertEquals("C:\\", fsRepository.getFileName(Paths.get("C:\\")));
  }

  @Test
  public void testIsFileOrFolder() throws Exception {
    MockFile root = new MockFile("/", true);
    MockFile foo = new MockFile("foo", false);
    MockFile bar = new MockFile("bar", true);
    MockFile link = new MockFile("link", false).setIsRegularFile(false);
    root.addChildren(foo, bar, link);
    MockFileDelegate delegate = new MockFileDelegate(root);
    FsRepository fsRepository = new FsRepository(delegate);

    assertTrue(fsRepository.isFileOrFolder(Paths.get(root.getPath())));
    assertTrue(fsRepository.isFileOrFolder(Paths.get(foo.getPath())));
    assertTrue(fsRepository.isFileOrFolder(Paths.get(bar.getPath())));
    assertFalse(fsRepository.isFileOrFolder(Paths.get(link.getPath())));
  }

  @Test
  public void testIsVisibleDescendantOfRoot() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    MockFile foo = new MockFile("foo", false);
    MockFile hiddenTxt = new MockFile("hidden.txt", false).setIsHidden(true);
    MockFile dir1 = new MockFile("dir1", true);
    MockFile bar = new MockFile("bar", false);
    MockFile hiddenPdf = new MockFile("hidden.pdf", false).setIsHidden(true);
    MockFile hiddenDir = new MockFile("hidden.dir", true).setIsHidden(true);
    MockFile baz = new MockFile("baz", false);
    root.addChildren(
        foo,
        hiddenTxt,
        dir1.addChildren(
            bar,
            hiddenPdf),
        hiddenDir.addChildren(
            baz));
    MockFileDelegate delegate = new MockFileDelegate(root);
    setConfig("/");
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(root.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(foo.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(dir1.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(bar.getPath())));
    assertFalse(fsRepository.isVisibleDescendantOfRoot(Paths.get(hiddenTxt.getPath())));
    assertFalse(fsRepository.isVisibleDescendantOfRoot(Paths.get(hiddenPdf.getPath())));
    assertFalse(fsRepository.isVisibleDescendantOfRoot(Paths.get(hiddenDir.getPath())));
    assertFalse(fsRepository.isVisibleDescendantOfRoot(Paths.get(baz.getPath())));
  }

  @Test
  public void testIsVisibleDescendantOfRootCrawlHiddenTrue() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    MockFile foo = new MockFile("foo", false);
    MockFile hiddenTxt = new MockFile("hidden.txt", false).setIsHidden(true);
    MockFile dir1 = new MockFile("dir1", true);
    MockFile bar = new MockFile("bar", false);
    MockFile hiddenPdf = new MockFile("hidden.pdf", false).setIsHidden(true);
    MockFile hiddenDir = new MockFile("hidden.dir", true).setIsHidden(true);
    MockFile baz = new MockFile("baz", false);
    root.addChildren(
        foo,
        hiddenTxt,
        dir1.addChildren(
            bar,
            hiddenPdf),
        hiddenDir.addChildren(
            baz));
    MockFileDelegate delegate = new MockFileDelegate(root);
    Properties config = new Properties();
    config.put("fs.crawlHiddenFiles", "true");
    setConfig("/", config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(root.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(foo.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(dir1.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(bar.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(hiddenTxt.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(hiddenPdf.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(hiddenDir.getPath())));
    assertTrue(fsRepository.isVisibleDescendantOfRoot(Paths.get(baz.getPath())));
  }

  @Test
  public void testInitListRootContentsAccessDenied() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.newDirectoryStream(startPath)).thenThrow(AccessDeniedException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitUncDenyShareAclAccess() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.getShareAclView(startPath)).thenThrow(IOException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  /*
   * As best as I can tell, this FsAdaptor test was verifying that init is fine even when
   * getDfsShareAclView throws an exception, since for a non-dfs-share root that method is
   * never called. With mockito, we can't stub it to throw an exception and then never
   * call it, so verify that it's never called.
   */
  @Test
  public void testInitUncDenyDfsShareAclAccess() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    verify(mockFileDelegate, never()).getDfsShareAclView(startPath);
  }

  @Test
  public void testInitDfsDenyShareAclAccess() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.isDfsLink(startPath)).thenReturn(true);
    when(mockFileDelegate.resolveDfsLink(startPath)).thenReturn(startPath);
    AclFileAttributeView mockAttributeView = mock(AclFileAttributeView.class);
    when(mockFileDelegate.getDfsShareAclView(startPath)).thenReturn(mockAttributeView);
    when(mockFileDelegate.getShareAclView(startPath)).thenThrow(IOException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitDfsDenyDfsShareAclAccess() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.isDfsLink(startPath)).thenReturn(true);
    when(mockFileDelegate.getDfsShareAclView(startPath)).thenThrow(IOException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitLastAccessDays() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastAccessedDays", "365");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastAccessDaysNonNumeric() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastAccessedDays", "ten");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastAccessDaysNegative() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastAccessedDays", "-365");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitLastAccessDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastAccessedDate", "2000-01-31");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastAccessDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastAccessedDate", "01/31/2000");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitFutureLastAccessDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastAccessedDate", "2999-12-31");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastAccessDaysAndDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastAccessedDays", "365");
    p.put("fs.lastAccessedDate", "2000-01-31");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitLastModifiedDays() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastModifiedDays", "365");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastModifiedDaysNonNumeric() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastModifiedDays", "ten");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastModifiedDaysNegative() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastModifiedDays", "-365");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitLastModifiedDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastModifiedDate", "2000-01-31");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastModifiedDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastModifiedDate", "01/31/2000");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitFutureLastModifiedDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastModifiedDate", "2999-12-31");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testInitInvalidLastModifiedDaysAndDate() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    Properties p = new Properties();
    p.put("fs.lastModifiedDays", "365");
    p.put("fs.lastModifiedDate", "2000-01-31");

    setConfig(startName, p);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    thrown.expect(StartupException.class);
    fsRepository.init(mockRepositoryContext);
  }

  @Test
  public void testGetStartPaths() throws InvalidPathException, IOException {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.getPath("/path1")).thenReturn(Paths.get("/path1"));
    when(mockFileDelegate.getPath("/p/path2")).thenReturn(Paths.get("/p/path2"));

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    fsRepository.getStartPaths("/", ";");
    fsRepository.getStartPaths("/path1;/p/path2", ";");

    InOrder inOrder = Mockito.inOrder(mockFileDelegate);
    inOrder.verify(mockFileDelegate).getPath("/"); // init
    inOrder.verify(mockFileDelegate).getPath("/");
    inOrder.verify(mockFileDelegate).getPath("/path1");
    inOrder.verify(mockFileDelegate).getPath("/p/path2");
    inOrder.verifyNoMoreInteractions();
  }

  @Test
  public void testGetIds() throws IOException {
    String startName = "/";
    Path startPath = setUpStartPath(startName);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    CloseableIterable<ApiOperation> result = fsRepository.getIds(null);
    List<ApiOperation> expectedList = Collections.singletonList(
        (ApiOperation) new PushItems.Builder()
        .addPushItem(startName, new PushItem().setType("MODIFIED"))
        .build());
    assertTrue(Iterables.elementsEqual(expectedList, result));
    verify(mockFileDelegate).startMonitorPath(eq(startPath), any());
  }

  @Test
  public void testGetIdsIOException() throws IOException {
    String startName = "/";
    Path startPath = setUpStartPath(startName);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    // If this exception is set up before calling init(), init fails instead of getIds.
    when(mockFileDelegate.newDocId(startPath)).thenThrow(IOException.class);
    thrown.expect(RepositoryException.class);
    fsRepository.getIds(null);
  }

  @Test
  public void testGetIdsNoMonitor() throws IOException {
    String startName = "/";
    Path startPath = setUpStartPath(startName);

    Properties config = new Properties();
    config.put("fs.monitorForUpdates", "false");
    setConfig(startName, config);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    CloseableIterable<ApiOperation> result = fsRepository.getIds(null);
    List<ApiOperation> expectedList = Collections.singletonList(
        (ApiOperation) new PushItems.Builder()
        .addPushItem(startName, new PushItem().setType("MODIFIED"))
        .build());
    assertTrue(Iterables.elementsEqual(expectedList, result));
    verify(mockFileDelegate, never()).startMonitorPath(eq(startPath), any());
  }

  @Test
  public void testGetIdsDfsNamespaceNoLinks() throws Exception {
    String startName = "\\\\dfs-server\\share";
    Path startPath = setUpStartPath(startName);
    List<Path> links = addDfsLinks(startName, 0);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    CloseableIterable<ApiOperation> result = fsRepository.getIds(null);
    List<ApiOperation> expectedList = Collections.singletonList(
        (ApiOperation) new PushItems.Builder()
        .addPushItem(startName, new PushItem().setType("MODIFIED"))
        .build());
    assertTrue(Iterables.elementsEqual(expectedList, result));
    verify(mockFileDelegate, never()).startMonitorPath(any(), any());
  }

  @Test
  public void testGetIdsDfsNamespaceLinks() throws Exception {
    String startName = "\\\\dfs-server\\share";
    Path startPath = setUpStartPath(startName);
    List<Path> links = addDfsLinks(startName, 2);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    CloseableIterable<ApiOperation> result = fsRepository.getIds(null);
    List<ApiOperation> expectedList = Collections.singletonList(
        (ApiOperation) new PushItems.Builder()
        .addPushItem(startName, new PushItem().setType("MODIFIED"))
        .build());
    assertTrue(Iterables.elementsEqual(expectedList, result));
    verify(mockFileDelegate, never()).startMonitorPath(eq(startPath), any());
    verify(mockFileDelegate, times(1)).startMonitorPath(eq(links.get(0)), any());
    verify(mockFileDelegate, times(1)).startMonitorPath(eq(links.get(1)), any());
  }

  @Test
  public void testGetIdsMultipleStartPaths() throws Exception {
    String startName1 = "\\\\dfs-server\\share";
    Path startPath1 = setUpStartPath(startName1);
    List<Path> links = addDfsLinks(startName1, 2);
    String startName2 = "\\\\server\\share";
    Path startPath2 = setUpStartPath(startName2);

    setConfig(startName1 + ";" + startName2);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    CloseableIterable<ApiOperation> result = fsRepository.getIds(null);
    List<ApiOperation> expectedList = Arrays.asList(
        (ApiOperation) new PushItems.Builder()
        .addPushItem(startName1, new PushItem().setType("MODIFIED"))
        .addPushItem(startName2, new PushItem().setType("MODIFIED"))
        .build());
    assertTrue(Iterables.elementsEqual(expectedList, result));
    verify(mockFileDelegate, never()).startMonitorPath(eq(startPath1), any());
    verify(mockFileDelegate, times(1)).startMonitorPath(eq(links.get(0)), any());
    verify(mockFileDelegate, times(1)).startMonitorPath(eq(links.get(1)), any());
    verify(mockFileDelegate, times(1)).startMonitorPath(eq(startPath2), any());
  }

  @Test
  public void testGetDocInvalidPathException() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.getPath("/invalid")).thenThrow(InvalidPathException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName("/invalid"));
    assertEquals(ApiOperations.deleteItem("/invalid"), result);
  }

  @Test
  public void testGetDocUnsupportedPath() throws Exception {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    setUpMockFile("/unsupported", false);
    when(mockFileDelegate.isRegularFile(Paths.get("/unsupported"))).thenReturn(false);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName("/unsupported"));
    assertEquals(ApiOperations.deleteItem("/unsupported"), result);
  }

  @Test
  public void testGetDocBadDocId() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(new MockFile("badfile", false));
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig("/");
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    // The requested item is missing the root component of the path.
    ApiOperation result = fsRepository.getDoc(new Item().setName("badfile"));
    assertEquals(ApiOperations.deleteItem("badfile"), result);
  }

  @Test
  public void testGetDocBrokenDfsLink() throws Exception {
    // Mockito didn't like overriding the setup method's mock of resolveDfsLink, which
    // needs to succeed when called in init, with one that fails in getDoc, so this test
    // uses MockFile and MultiRootMockFileDelegate.
    MockFile dfsTarget = new MockFile("\\\\host\\share", true)
        .setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile dfsLink = getDfsLink("dfsLink", dfsTarget)
        .setAclView(FULL_ACCESS_ACLVIEW)
        .setDfsShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile dfsNamespace = getDfsNamespace("/")
        .setAclView(FULL_ACCESS_ACLVIEW)
        .addChildren(dfsLink);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsNamespace, dfsTarget);

    setConfig(dfsNamespace.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    // Now make the active storage disappear.
    dfsLink.setDfsActiveStorage(null);

    thrown.expect(RepositoryException.class);
    fsRepository.getDoc(new Item().setName(delegate.newDocId(dfsLink)));
  }

  /* testGetDocContentBrokenDfsNamespace(): this adaptor test was setting up a DFS
   * namespace as the child of the root, then trying to read the contents as a directory
   * stream. FsRepository doesn't currently support that.
   */

  @Test
  public void testGetDocFileNotFound() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig("/");
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName("/non-existent"));
    assertEquals(ApiOperations.deleteItem("/non-existent"), result);
  }

  @Test
  public void testGetDocHiddenFile() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(new MockFile("hidden.txt").setIsHidden(true));
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig("/");
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName("/hidden.txt"));
    assertEquals(ApiOperations.deleteItem("/hidden.txt"), result);
  }

  @Test
  public void testGetDocHiddenDirectory() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(new MockFile("hidden.dir", true).setIsHidden(true));
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig("/");
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName("/hidden.dir"));
    assertEquals(ApiOperations.deleteItem("/hidden.dir"), result);
  }

  @Test
  public void testGetDocHiddenFileCrawlHiddenTrue() throws Exception {
    MockFile hiddenTxt = new MockFile("hidden.txt")
        .setIsHidden(true)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(hiddenTxt);
    MockFileDelegate delegate = new MockFileDelegate(root);

    Properties config = new Properties();
    config.put("fs.crawlHiddenFiles", "true");
    setConfig("/", config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(hiddenTxt);
    RepositoryDoc result = getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertNotNull(result);
  }

  @Test
  public void testGetDocHiddenDirectoryCrawlHiddenTrue()
      throws Exception {
    MockFile hiddenDir = new MockFile("hidden.dir", true)
        .setIsHidden(true)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(hiddenDir);
    MockFileDelegate delegate = new MockFileDelegate(root);

    Properties config = new Properties();
    config.put("fs.crawlHiddenFiles", "true");
    setConfig("/", config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(hiddenDir);
    RepositoryDoc result = getDocFromBatch(docId,
        fsRepository.getDoc(new Item().setName(docId)));
    assertNotNull(result);
  }

  @Test
  public void testGetDocRegularFile() throws Exception {
    String rootName = "/";
    String fname = "test.html";
    DateTime createDateTime = new DateTime(10000);
    DateTime updateDateTime = new DateTime(30000);
    MockFile file = new MockFile(fname)
        .setCreationTime(FileTime.fromMillis(createDateTime.getValue()))
        .setLastModifiedTime(FileTime.fromMillis(updateDateTime.getValue()))
        .setContentType("text/html")
        .setAclView(EMPTY_ACLVIEW)
        .setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews(rootName)
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(rootName);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(file);
    RepositoryDoc result = getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    ItemMetadata expectedMetadata = new ItemMetadata()
        .setContainerName(rootName)
        .setCreateTime(createDateTime.toStringRfc3339())
        .setMimeType("text/html")
        .setTitle(fname)
        .setSourceRepositoryUrl(delegate.getPath(docId).toUri().toString())
        .setUpdateTime(updateDateTime.toStringRfc3339());
    Item expectedItem = new Item()
        .setAcl(expectedItemAcl)
        .setItemType(ItemType.CONTENT_ITEM.name())
        .setMetadata(expectedMetadata)
        .setName(docId);
    assertJsonEquals(expectedItem, result.getItem());

    // FileContent doesn't support equals, so test the RepositoryDoc fields individually
    // rather than building an expected RepositoryDoc.
    AbstractInputStreamContent content = result.getContent();
    assertEquals(file.getContentType(), content.getType());
    assertThat(content, instanceOf(FileContent.class));
    assertEquals(delegate.getPath(file.getPath()).toFile(),
        ((FileContent) content).getFile());
    assertEquals(ContentFormat.RAW, result.getContentFormat());
    assertNotNull(result.getFragments());
    assertThat(result.getFragments().entrySet(), not(hasItem(anything())));
  }

  @Test
  public void testGetDocDirectory() throws Exception {
    String rootName = "/";
    String dirName = "testDir";
    DateTime createDateTime = new DateTime(10000);
    DateTime updateDateTime = new DateTime(30000);
    MockFile dir = new MockFile(dirName, true)
        .setCreationTime(FileTime.fromMillis(createDateTime.getValue()))
        .setLastModifiedTime(FileTime.fromMillis(updateDateTime.getValue()))
        .setAclView(EMPTY_ACLVIEW)
        .setShareAclView(FULL_ACCESS_ACLVIEW);
    String[] files = { "subdir1", "subdir2", "test1.txt", "test2.txt" };
    for (String file : files) {
      dir.addChildren(new MockFile(file, file.contains("dir")));
    }
    MockFile root = getShareRootDefaultAclViews(rootName)
        .addChildren(dir);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(rootName);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(dir);
    RepositoryDoc result = getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    ItemMetadata expectedMetadata = new ItemMetadata()
        .setContainerName(rootName)
        .setCreateTime(createDateTime.toStringRfc3339())
        .setTitle(dirName)
        .setSourceRepositoryUrl(delegate.getPath(docId).toUri().toString())
        .setUpdateTime(updateDateTime.toStringRfc3339());
    Item expectedItem = new Item()
        .setAcl(expectedItemAcl)
        .setItemType(ItemType.CONTAINER_ITEM.name())
        .setMetadata(expectedMetadata)
        .setName(docId);
    assertJsonEquals(expectedItem, result.getItem());
    RepositoryDoc expectedDoc = new RepositoryDoc.Builder()
        .addChildId("/testDir/subdir1", new PushItem())
        .addChildId("/testDir/subdir2", new PushItem())
        .addChildId("/testDir/test1.txt", new PushItem())
        .addChildId("/testDir/test2.txt", new PushItem())
        .setItem(expectedItem)
        .setRequestMode(RequestMode.ASYNCHRONOUS)
        .build();
    assertEquals(expectedDoc, result);
  }

  @Test
  public void testGetDocDirectoryBadChildDocid() throws Exception {
    String rootName = "/";
    String dirName = "testDir";
    MockFile dir = new MockFile(dirName, true)
        .setAclView(EMPTY_ACLVIEW)
        .setShareAclView(FULL_ACCESS_ACLVIEW);
    String[] files = { "subdir1", "subdir2", "test1.txt", "test2.txt" };
    for (String file : files) {
      dir.addChildren(new MockFile(file, file.contains("dir")));
    }
    MockFile root = getShareRootDefaultAclViews(rootName)
        .addChildren(dir);
    MockFileDelegate delegate = spy(new MockFileDelegate(root));
    Path childWithBadId = Paths.get("/testDir/test2.txt");
    when(delegate.newDocId(childWithBadId)).thenThrow(IOException.class);

    setConfig(rootName);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(dir);
    RepositoryDoc result = getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    Map<String, PushItem> expectedIds = new HashMap<>();
    expectedIds.put("/testDir/subdir1", new PushItem());
    expectedIds.put("/testDir/subdir2", new PushItem());
    expectedIds.put("/testDir/test1.txt", new PushItem());
    assertEquals(expectedIds, result.getChildIds());
  }

  private MockFileDelegate addDfsNamespaceContent(MockFile dfsNamespace, int numLinks, int numFiles,
      int numFolders) {
    List<MockFile> roots = new ArrayList<>();
    roots.add(dfsNamespace);
    for (int i = 0; i < numLinks; i++) {
      MockFile target = new MockFile("\\\\host\\share" + i, true)
          .setShareAclView(FULL_ACCESS_ACLVIEW);
      MockFile link = getDfsLink("dfsLink" + i, target)
          .setDfsShareAclView(FULL_ACCESS_ACLVIEW);
      roots.add(target);
      dfsNamespace.addChildren(link);
    }

    for (int i = 0; i < numFiles; i++) {
      dfsNamespace.addChildren(new MockFile("file" + i, false));
    }
    for (int i = 0; i < numFolders; i++) {
      dfsNamespace.addChildren(new MockFile("dir" + i, true));
    }
    return new MultiRootMockFileDelegate(Iterables.toArray(roots, MockFile.class));
  }

  @Test
  public void testGetDocDfsNamespace() throws Exception {
    String rootName = "/";
    DateTime createDateTime = new DateTime(10000);
    DateTime updateDateTime = new DateTime(30000);
    MockFile dfsNamespace = getDfsNamespace(rootName)
        .setCreationTime(FileTime.fromMillis(createDateTime.getValue()))
        .setLastModifiedTime(FileTime.fromMillis(updateDateTime.getValue()));
    MockFileDelegate delegate = addDfsNamespaceContent(dfsNamespace,
        /*links*/ 2, /*files*/ 0, /*folders*/ 0);

    setConfig(rootName);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(dfsNamespace);
    RepositoryDoc result = getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    ItemMetadata expectedMetadata = new ItemMetadata()
        .setCreateTime(createDateTime.toStringRfc3339())
        .setTitle(delegate.getPath(rootName).toString())
        .setSourceRepositoryUrl(delegate.getPath(docId).toUri().toString())
        .setUpdateTime(updateDateTime.toStringRfc3339());
    // Virtual containers don't have to have ACLs.
    Item expectedItem = new Item()
        .setItemType(ItemType.VIRTUAL_CONTAINER_ITEM.name())
        .setMetadata(expectedMetadata)
        .setName(docId);
    assertJsonEquals(expectedItem, result.getItem());
    RepositoryDoc expectedDoc = new RepositoryDoc.Builder()
        .addChildId("/dfsLink0", new PushItem())
        .addChildId("/dfsLink1", new PushItem())
        .setItem(expectedItem)
        .setRequestMode(RequestMode.ASYNCHRONOUS)
        .build();
    assertEquals(expectedDoc, result);
  }

  @Test
  public void testGetDocDfsNamespaceHasFilesButNotAllowed() throws Exception {
    String rootName = "/";
    MockFile dfsNamespace = getDfsNamespace(rootName);
    MockFileDelegate delegate = addDfsNamespaceContent(dfsNamespace,
        /*links*/ 2, /*files*/ 2, /*folders*/ 1);

    Properties config = new Properties();
    config.put("fs.allowFilesInDfsNamespaces", "false");
    setConfig(rootName, config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(dfsNamespace);
    RepositoryDoc result = getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    Map<String, PushItem> childIds = result.getChildIds();
    Map<String, PushItem> expectedIds = new HashMap<>();
    expectedIds.put("/dfsLink0", new PushItem());
    expectedIds.put("/dfsLink1", new PushItem());
    assertEquals(expectedIds, childIds);
  }

  @Test
  public void testGetDocDfsNamespaceHasFilesAllowed() throws Exception {
    String rootName = "/";
    MockFile dfsNamespace = getDfsNamespace(rootName)
        .setAclView(FULL_ACCESS_ACLVIEW);
    MockFileDelegate delegate = addDfsNamespaceContent(dfsNamespace,
        /*links*/ 2, /*files*/ 2, /*folders*/ 1);

    Properties config = new Properties();
    config.put("fs.allowFilesInDfsNamespaces", "true");
    setConfig(rootName, config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(dfsNamespace);
    RepositoryDoc result = getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    Map<String, PushItem> childIds = result.getChildIds();
    Map<String, PushItem> expectedIds = new HashMap<>();
    ImmutableSet.of("/dfsLink0", "/dfsLink1", "/file0", "/file1", "/dir0")
        .stream().forEach(key -> expectedIds.put(key, new PushItem()));
    assertEquals(expectedIds, childIds);
  }

  private static final JacksonFactory jacksonFactory = JacksonFactory.getDefaultInstance();

  // Using strings lets JUnit do its "which parts of this string don't match" trick and
  // provide more-readable output.
  private void assertJsonEquals(GenericJson expected, GenericJson actual) throws IOException {
    if (!expected.equals(actual)) {
      assertEquals(jacksonFactory.toPrettyString(expected),
          jacksonFactory.toPrettyString(actual));
    }
  }

  @Test
  public void testGetDocNullPath() throws IOException {
    String startName = "/";
    Path startPath = setUpStartPath(startName);
    // test delegate.getPath returning null
    when(mockFileDelegate.getPath("/foo")).thenReturn(null);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    ApiOperation result = fsRepository.getDoc(new Item().setName("/foo"));

    assertEquals(ApiOperations.deleteItem("/foo"), result);
  }

  @Test
  public void testGetDocNullParent() throws IOException {
    String startName = "/";
    Path startPath = setUpStartPath(startName);

    Path fooPathMock = mock(Path.class);
    when(mockFileDelegate.getPath("/foo")).thenReturn(fooPathMock);
    // Mock what FsRepository.getParent does in order to get a null return value.
    when(fooPathMock.getParent()).thenReturn(null);
    when(fooPathMock.getRoot()).thenReturn(fooPathMock);
    setConfig(startName);
    FsRepository fsRepository = spy(new FsRepository(mockFileDelegate));
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName("/foo"));
    // We still get a delete request, though it's actually triggered later, but
    // importantly we don't get a NullPointerException
    assertEquals(ApiOperations.deleteItem("/foo"), result);
  }

  public void testGetDocDirectoryIndexItemType() throws IOException {
    MockFile child = new MockFile("test.dir", true)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);

    Properties config = new Properties();
    config.put("fs.indexFolders", "true"); // default value, but show here for testing
    setConfig(root.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result = (RepositoryDoc) fsRepository.getDoc(
        new Item().setName(delegate.newDocId(child)));
    assertEquals("CONTAINER_ITEM", result.getItem().getItemType());
  }

  @Test
  public void testGetDocDirectoryNoIndexItemType() throws IOException {
    MockFile child = new MockFile("test.dir", true)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);

    Properties config = new Properties();
    config.put("fs.indexFolders", "false");
    setConfig(root.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result = getDocFromBatch(delegate.newDocId(child),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(child))));
    assertEquals("VIRTUAL_CONTAINER_ITEM", result.getItem().getItemType());
  }

  @Test
  public void testGetDocDfsNamespaceIndexItemType() throws IOException {
    MockFile dfsTarget = new MockFile("\\\\host\\share", true)
        .setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile dfsLink = getDfsLink("dfsLink", dfsTarget)
        .setAclView(FULL_ACCESS_ACLVIEW)
        .setDfsShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile dfsNamespace = getDfsNamespace("/")
        .setAclView(FULL_ACCESS_ACLVIEW)
        .addChildren(dfsLink);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsNamespace, dfsTarget);

    Properties config = new Properties();
    config.put("fs.indexFolders", "true"); // default value, but show here for testing
    setConfig(dfsNamespace.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    RepositoryDoc result = getDocFromBatch(delegate.newDocId(dfsNamespace),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(dfsNamespace))));
    // Always set to VIRTUAL_CONTAINER_ITEM
    assertEquals("VIRTUAL_CONTAINER_ITEM", result.getItem().getItemType());
  }

  @Test
  public void testGetDocDfsNamespaceNoIndexItemType() throws IOException {
    MockFile dfsTarget = new MockFile("\\\\host\\share", true)
        .setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile dfsLink = getDfsLink("dfsLink", dfsTarget)
        .setAclView(FULL_ACCESS_ACLVIEW)
        .setDfsShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile dfsNamespace = getDfsNamespace("/")
        .setAclView(FULL_ACCESS_ACLVIEW)
        .addChildren(dfsLink);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsNamespace, dfsTarget);

    Properties config = new Properties();
    config.put("fs.indexFolders", "false");
    setConfig(dfsNamespace.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    RepositoryDoc result = getDocFromBatch(delegate.newDocId(dfsNamespace),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(dfsNamespace))));
    assertEquals("VIRTUAL_CONTAINER_ITEM", result.getItem().getItemType());
  }

  @Test
  public void testGetDocAclFragment() throws IOException, InterruptedException {
    String startName = "/base";
    Path startPath = setUpStartPath(startName);
    String fragmentId = Acl.fragmentId(startName, FsRepository.SHARE_ACL);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName(fragmentId));
    PushItems expected = new PushItems.Builder().addPushItem(
        fragmentId, new PushItem().setType("NOT_MODIFIED")).build();
    assertEquals(expected, result);
  }

  @Test
  public void testGetDocNonAclFragment() throws IOException, InterruptedException {
    String startName = "/base";
    Path startPath = setUpStartPath(startName);
    String fragmentId = Acl.fragmentId(startName, "foo");
    // Throw an exception at a call that occurs past the fragment handling.
    when(mockFileDelegate.getPath(fragmentId)).thenThrow(InvalidPathException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    ApiOperation result = fsRepository.getDoc(new Item().setName(fragmentId));
    assertEquals(ApiOperations.deleteItem(fragmentId), result);
  }

  @Test
  public void testGetDocEmptyAclFragment() throws IOException, InterruptedException {
    String startName = "/base";
    Path startPath = setUpStartPath(startName);
    String fragmentId = "/base#";
    // Throw an exception at a call that occurs past the fragment handling.
    when(mockFileDelegate.getPath(fragmentId)).thenThrow(InvalidPathException.class);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    ApiOperation result = fsRepository.getDoc(new Item().setName(fragmentId));
    assertEquals(ApiOperations.deleteItem(fragmentId), result);
  }

  @Test
  public void testGetDocAsRoot() throws InvalidPathException, IOException {
    String startName = "/base";
    Path startPath = setUpStartPath(startName);
    when(mockFileDelegate.isRegularFile(startPath)).thenReturn(true);
    when(mockFileDelegate.isHidden(startPath)).thenReturn(false);

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    fsRepository.getDoc(new Item().setName(startName));

    InOrder inOrder = Mockito.inOrder(mockFileDelegate);
    inOrder.verify(mockFileDelegate).getPath(startName);
    inOrder.verify(mockFileDelegate).isDfsLink(startPath);
    inOrder.verify(mockFileDelegate).getPath(startName);
    inOrder.verify(mockFileDelegate).readBasicAttributes(startPath);
    inOrder.verify(mockFileDelegate, (times(2))).isRegularFile(startPath);
    inOrder.verify(mockFileDelegate).isHidden(startPath);
    inOrder.verify(mockFileDelegate).isHidden(Paths.get("/"));
    inOrder.verifyNoMoreInteractions();
  }


  @Test
  public void testGetDocAsNotRootFile() throws InvalidPathException, IOException {
    String startName = "/base";
    Path startPath = setUpStartPath(startName);
    String fileName = "/base/folder/file";
    Path filePath = setUpMockFile(fileName, false);
    Path folderPath = Paths.get("/base/folder");

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result = getDocFromBatch(fileName,
        fsRepository.getDoc(new Item().setName(fileName)));
    assertEquals(ItemType.CONTENT_ITEM.name(), result.getItem().getItemType());
    assertEquals(ContentFormat.RAW, result.getContentFormat());

    // Interactions in getDoc
    InOrder inOrder = Mockito.inOrder(mockFileDelegate);
    inOrder.verify(mockFileDelegate).getPath(startName);
    inOrder.verify(mockFileDelegate).isDfsLink(filePath);
    inOrder.verify(mockFileDelegate).newDocId(folderPath);
    inOrder.verify(mockFileDelegate).readBasicAttributes(filePath);
    inOrder.verify(mockFileDelegate, (times(2))).isRegularFile(filePath); // 2
    inOrder.verify(mockFileDelegate).isHidden(filePath);
    inOrder.verify(mockFileDelegate).isHidden(folderPath);
    inOrder.verify(mockFileDelegate).isHidden(startPath);
    inOrder.verify(mockFileDelegate, (times(2))).isDfsNamespace(filePath);
    inOrder.verify(mockFileDelegate).isDfsLink(filePath);
    inOrder.verify(mockFileDelegate).isDirectory(filePath);
    inOrder.verify(mockFileDelegate).getAclViews(filePath);
    inOrder.verify(mockFileDelegate).isDfsLink(filePath);
    inOrder.verify(mockFileDelegate).isDfsLink(folderPath);
    inOrder.verify(mockFileDelegate).newDocId(startPath);
    inOrder.verify(mockFileDelegate).probeContentType(filePath); // mock it ?
    inOrder.verify(mockFileDelegate).setLastAccessTime(eq(filePath), any(FileTime.class));
    inOrder.verifyNoMoreInteractions();
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testGetDocAsNotRootDirectory() throws InvalidPathException, IOException {
    String startName = "/base";
    Path startPath = setUpStartPath(startName);
    String folderName = "/base/folder";
    Path folderPath = setUpMockFile(folderName, true);
    // set up folder content
    List<Path> pathList = new ArrayList<>();
    DirectoryStream<Path> mockFolderStream = (DirectoryStream<Path>) mock(DirectoryStream.class);
    when(mockFileDelegate.newDirectoryStream(folderPath)).thenReturn(mockFolderStream);
    when(mockFolderStream.iterator()).thenReturn(pathList.iterator());

    setConfig(startName);
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result = getDocFromBatch(folderName,
        fsRepository.getDoc(new Item().setName(folderName)));
    Item item = result.getItem();
    assertEquals(ItemType.CONTAINER_ITEM.name(), item.getItemType());
    assertEquals(RequestMode.ASYNCHRONOUS, result.getRequestMode());

    InOrder inOrder = Mockito.inOrder(mockFileDelegate);
    inOrder.verify(mockFileDelegate).getPath(folderName);
    inOrder.verify(mockFileDelegate).isDfsLink(folderPath);
    inOrder.verify(mockFileDelegate).newDocId(startPath);
    inOrder.verify(mockFileDelegate).readBasicAttributes(folderPath);
    inOrder.verify(mockFileDelegate, (times(2))).isRegularFile(folderPath); // 2
    inOrder.verify(mockFileDelegate).isHidden(folderPath);
    inOrder.verify(mockFileDelegate).isHidden(startPath);
    inOrder.verify(mockFileDelegate, (times(2))).isDfsNamespace(folderPath);
    inOrder.verify(mockFileDelegate).isDfsLink(folderPath);
    inOrder.verify(mockFileDelegate).isDirectory(folderPath);
    inOrder.verify(mockFileDelegate).getAclViews(folderPath);
    inOrder.verify(mockFileDelegate).isDfsLink(folderPath);
    inOrder.verify(mockFileDelegate).newDocId(startPath);
    inOrder.verify(mockFileDelegate).newDirectoryStream(folderPath);
    inOrder.verify(mockFileDelegate).setLastAccessTime(eq(folderPath), any(FileTime.class));
    inOrder.verifyNoMoreInteractions();
  }

  private Path setUpMockFile(String fileName, boolean isDirectory) throws IOException {
    Path path = Paths.get(fileName);
    when(mockFileDelegate.getPath(fileName)).thenReturn(path);
    when(mockFileDelegate.isRegularFile(path)).thenReturn(true);
    when(mockFileDelegate.isHidden(path)).thenReturn(false);
    when(mockFileDelegate.isDfsNamespace(path)).thenReturn(false);
    BasicFileAttributes mockBasicFileAttributes = mock(BasicFileAttributes.class);
    when(mockBasicFileAttributes.lastAccessTime()).thenReturn(FileTime.fromMillis(1234567890L));
    when(mockBasicFileAttributes.lastModifiedTime()).thenReturn(FileTime.fromMillis(1234567890L));
    when(mockBasicFileAttributes.creationTime()).thenReturn(FileTime.fromMillis(1234567890L));
    when(mockBasicFileAttributes.isDirectory()).thenReturn(isDirectory);
    when(mockFileDelegate.readBasicAttributes(path)).thenReturn(mockBasicFileAttributes);
    AclFileAttributeViews mockAclFileAttributeViews = mock(AclFileAttributeViews.class);
    when(mockFileDelegate.getAclViews(path)).thenReturn(mockAclFileAttributeViews);
    when(mockAclFileAttributeViews.getInheritedAclView()).thenReturn(new AclView());
    AclFileAttributeView combinedAclView = mock(AclFileAttributeView.class);
    when(mockAclFileAttributeViews.getCombinedAclView()).thenReturn(combinedAclView);
    return path;
  }

  @Test
  public void testGetDocItemMetadataTimes() throws Exception {
    MockFile unmodifiedFile = new MockFile("unmodifiedFile", false)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile modifiedFile = new MockFile("modifiedFile", false)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(unmodifiedFile, modifiedFile);
    MockFileDelegate delegate = new MockFileDelegate(root);

    FileTime createTime = FileTime.fromMillis(1234567890L);
    FileTime updateTime = FileTime.fromMillis(createTime.toMillis() + 5000L);
    unmodifiedFile.setCreationTime(createTime);
    unmodifiedFile.setLastModifiedTime(createTime);
    modifiedFile.setCreationTime(createTime);
    modifiedFile.setLastModifiedTime(updateTime);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    RepositoryDoc unmodifiedResult = getDocFromBatch(delegate.newDocId(unmodifiedFile),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(unmodifiedFile))));
    ItemMetadata unmodifiedMetadata = unmodifiedResult.getItem().getMetadata();
    assertEquals("unmodified",
        unmodifiedMetadata.getCreateTime(), unmodifiedMetadata.getUpdateTime());

    RepositoryDoc modifiedResult = getDocFromBatch(delegate.newDocId(modifiedFile),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(modifiedFile))));
    ItemMetadata modifiedMetadata = modifiedResult.getItem().getMetadata();
    assertNotEquals("modified",
        modifiedMetadata.getCreateTime(), modifiedMetadata.getUpdateTime());
  }

  @Test
  public void testGetDocItemMetadataTitle() throws Exception {
    MockFile file = new MockFile("testFile.txt", false)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile folder = new MockFile("testFolder", true)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/");
    root.addChildren(folder);
    folder.addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    RepositoryDoc fileResult = getDocFromBatch(delegate.newDocId(file),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(file))));
    ItemMetadata fileMetadata = fileResult.getItem().getMetadata();
    assertEquals("testFile.txt", fileMetadata.getTitle());

    RepositoryDoc folderResult = getDocFromBatch(delegate.newDocId(folder),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(folder))));
    ItemMetadata folderMetadata = folderResult.getItem().getMetadata();
    assertEquals("testFolder", folderMetadata.getTitle());

    RepositoryDoc rootResult = getDocFromBatch(delegate.newDocId(root),
        fsRepository.getDoc(new Item().setName(delegate.newDocId(root))));
    ItemMetadata rootMetadata = rootResult.getItem().getMetadata();
    assertEquals(delegate.getPath(delegate.newDocId(root)).toString(), rootMetadata.getTitle());
  }

  @Test
  public void testGetDocMimeType() throws Exception {
    MockFile file = new MockFile("test.txt")
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals("text/plain", fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocMimeTypeFromLocalMap() throws Exception {
    MockFile file = new MockFile("test.xlsm")
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals("application/vnd.ms-excel.sheet.macroEnabled.12",
        fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocMimeTypeFromProperties() throws Exception {
    MockFile file = new MockFile("test.ppt")
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    Properties mimetypes = new Properties();
    mimetypes.put("ppt", "presentation format");
    fsRepository.setMimeTypeProperties(mimetypes);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals("presentation format", fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocMimeTypeNoExtension() throws Exception {
    MockFile file = new MockFile("docx")
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals("text/plain", fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocMimeTypeUnknownExtension() throws Exception {
    MockFile file = new MockFile("test.xyz")
        .setAclView(EMPTY_ACLVIEW)
        .setContentType(null); // mimics null return from Files.probeContentType
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals(null, fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocMimeTypeFromLocalMapMixedCaseExtension() throws Exception {
    MockFile file = new MockFile("test.Xlsm")
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals("application/vnd.ms-excel.sheet.macroEnabled.12",
        fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocMimeTypeFromPropertiesMixedCaseExtension() throws Exception {
    MockFile file = new MockFile("test.Ppt")
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    Properties mimetypes = new Properties();
    mimetypes.put("ppt", "presentation format");
    fsRepository.setMimeTypeProperties(mimetypes);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals("presentation format", fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocMimeTypeFromPropertiesMixedCaseProperty() throws Exception {
    MockFile file = new MockFile("test.ppt")
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    setConfig(root.getPath());
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    Properties mimetypes = new Properties();
    mimetypes.put("Ppt", "presentation format");
    fsRepository.setMimeTypeProperties(mimetypes);

    String docId = delegate.newDocId(file);
    RepositoryDoc fileResult =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));
    assertEquals("presentation format", fileResult.getItem().getMetadata().getMimeType());
  }

  @Test
  public void testGetDocLargeDirectoryBadDocId() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    for (int i = 0; i < 10; i++) {
      root.addChildren(new MockFile(String.format("child%07d", i), false));
    }
    // Fail on one doc id in the list
    MockFileDelegate delegate = new MockFileDelegate(root) {
        @Override
        public String newDocId(Path doc) throws IOException {
          String badDocId = Paths.get("/child0000004").toString();
          if (doc.toString().equals(badDocId)) {
            throw new IOException("newDocId mock failure on " + badDocId);
          }
          return super.newDocId(doc);
        }
      };
    String docId = delegate.newDocId(root);

    Properties config = new Properties();
    config.put("fs.largeDirectoryLimit", "1");
    setConfig(root.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    // All the children other than the one that failed should be sent.
    PushItems.Builder expectedBuilder = new PushItems.Builder();
    for (int i = 0; i < 10; i++) {
      if (i != 4) {
        expectedBuilder.addPushItem(
            delegate.newDocId(Paths.get(String.format("/child%07d", i))), new PushItem());
      }
    }
    PushItems expectedItems = expectedBuilder.build();

    ArgumentCaptor<ApiOperation> c = ArgumentCaptor.forClass(ApiOperation.class);
    Thread.sleep(2000); // Need to wait for the async thread to finish
    verify(mockRepositoryContext).postApiOperationAsync(c.capture());
    List<ApiOperation> values = c.getAllValues();
    assertEquals(expectedItems, values.get(0));
  }

  @Test
  public void testGetDocLargeDirectoryBadStream() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    for (int i = 0; i < 10; i++) {
      root.addChildren(new MockFile(String.format("child%07d", i), false));
    }
    // Fail to read children.
    MockFileDelegate delegate = new MockFileDelegate(root) {
        int count = 0;
        @Override
        public DirectoryStream<Path> newDirectoryStream(Path doc) throws IOException {
          // Called in init->validateShare, getDoc->validateShare, getDoc->getDirectoryContent
          // before being called in async pusher.
          if (count == 3) {
            throw new IOException("newDirectoryStream mock failure");
          }
          count++;
          return super.newDirectoryStream(doc);
        }
      };
    String docId = delegate.newDocId(root);

    Properties config = new Properties();
    config.put("fs.largeDirectoryLimit", "1");
    setConfig(root.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    // largeDirectoryLimit children are sent in the RepositoryDoc, no children are sent
    // asynchronously.
    assertEquals(1, result.getChildIds().size());
    verify(mockRepositoryContext, times(0)).postApiOperationAsync(any());
  }

  @Test
  public void testGetDocLargeDirectoryLastAccessTimeRestoreFailed() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    for (int i = 0; i < 10; i++) {
      root.addChildren(new MockFile(String.format("child%07d", i), false));
    }
    // Fail on one doc id in the list
    MockFileDelegate delegate = new MockFileDelegate(root) {
        int count = 0;
        @Override
        public void setLastAccessTime(Path doc, FileTime time) throws IOException {
          // Called in getDirectoryContent as well as async pusher.
          if (count == 1) {
            throw new IOException("setLastAccessTime mock failure");
          }
          count++;
          super.setLastAccessTime(doc, time);
        }
      };
    String docId = delegate.newDocId(root);

    Properties config = new Properties();
    config.put("fs.largeDirectoryLimit", "1");
    setConfig(root.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    PushItems.Builder expectedBuilder = new PushItems.Builder();
    for (int i = 0; i < 10; i++) {
      expectedBuilder.addPushItem(
          delegate.newDocId(Paths.get(String.format("/child%07d", i))), new PushItem());
    }
    PushItems expectedItems = expectedBuilder.build();

    // All the children are pushed; the setLastAccessTime exception should be logged but
    // not cause other issues.
    ArgumentCaptor<ApiOperation> c = ArgumentCaptor.forClass(ApiOperation.class);
    Thread.sleep(2000); // Need to wait for the async thread to finish
    verify(mockRepositoryContext).postApiOperationAsync(c.capture());
    List<ApiOperation> values = c.getAllValues();
    assertEquals(expectedItems, values.get(0));
  }

  @Test
  public void testGetDocLargeDirectoryFilesMultipleOfBatch() throws Exception {
    int numChildren = (ASYNC_PUSH_ITEMS_BATCH_SIZE * 100);
    verifyLargeDirectory(numChildren, /* largeDirectoryLimit */ 10);
  }

  @Test
  public void testGetDocLargeDirectoryFilesNotMultipleOfBatch() throws Exception {
    int numChildren = (ASYNC_PUSH_ITEMS_BATCH_SIZE * 100) + 1;
    verifyLargeDirectory(numChildren, /* largeDirectoryLimit */ 10);
  }

  @Test
  public void testGetDocLargeDirectoryFilesLessThanBatch() throws Exception {
    int numChildren = ASYNC_PUSH_ITEMS_BATCH_SIZE - 1;
    verifyLargeDirectory(numChildren, /* largeDirectoryLimit */ 1);
  }

  @Test
  public void testGetDocLargeDirectorySendAllAsync() throws Exception {
    int numChildren = ASYNC_PUSH_ITEMS_BATCH_SIZE - 1;
    verifyLargeDirectory(numChildren, /* largeDirectoryLimit */ 0);
  }

  // This test compares a collection of expected children, with names generated in the
  // test, to the collection created in the connector using a DirectoryStream. The
  // MockFile implementation sorts the children when constructing the DirectoryStream, so
  // use padding in the names so that our test data and the stream end up using the same
  // order.
  private void verifyLargeDirectory(int numChildren, int largeDirectoryLimit) throws Exception {
    assertTrue("numChildren = 0", numChildren > 0);
    int batchSize = ASYNC_PUSH_ITEMS_BATCH_SIZE;

    MockFile root = getShareRootDefaultAclViews("/");
    for (int i = 0; i < numChildren; i++) {
      root.addChildren(new MockFile(String.format("child%07d", i), false));
    }
    MockFileDelegate delegate = new MockFileDelegate(root);
    String docId = delegate.newDocId(root);

    Properties config = new Properties();
    config.put("fs.largeDirectoryLimit", String.valueOf(largeDirectoryLimit));
    setConfig(root.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);
    RepositoryDoc result =
        getDocFromBatch(docId, fsRepository.getDoc(new Item().setName(docId)));

    // Only largeDirectoryLimit children are sent in the RepositoryDoc
    RepositoryDoc.Builder expectedDocBuilder = new RepositoryDoc.Builder()
        .setItem(result.getItem()) // Avoid modeling the item; this test cares about the children
        .setRequestMode(RequestMode.ASYNCHRONOUS);
    for (int i = 0; i < largeDirectoryLimit; i++) {
      expectedDocBuilder.addChildId(
          delegate.newDocId(Paths.get(String.format("/child%07d", i))), new PushItem());
    }
    RepositoryDoc expectedDoc = expectedDocBuilder.build();

    // All the children are sent asynchronously, but they're sent in multiple PushItems.
    int numBatches = numChildren / batchSize;
    int remainder = numChildren % batchSize;
    List<PushItems> expectedBatches = new ArrayList<>(numBatches + 1);
    PushItems.Builder batchBuilder = new PushItems.Builder();
    for (int i = 1; i <= numChildren; i++) {
      batchBuilder.addPushItem(
          delegate.newDocId(Paths.get(String.format("/child%07d", (i - 1)))), new PushItem());
      if ((i % batchSize) == 0) {
        expectedBatches.add(batchBuilder.build());
        batchBuilder = new PushItems.Builder();
      }
    }
    if (remainder != 0) {
        expectedBatches.add(batchBuilder.build());
    }

    assertEquals("repository docs differ", expectedDoc, result);
    ArgumentCaptor<ApiOperation> c = ArgumentCaptor.forClass(ApiOperation.class);
    Thread.sleep(2000); // Need to wait for the async thread to finish
    verify(mockRepositoryContext, times(remainder > 0 ? numBatches + 1 : numBatches))
        .postApiOperationAsync(c.capture());
    List<ApiOperation> values = c.getAllValues();
    assertEquals("number of batches differ", expectedBatches.size(), values.size());
    for (int i = 0; i < expectedBatches.size(); i++) {
      assertEquals("batch unequal at " + i, expectedBatches.get(i), values.get(i));
    }
  }

  private static final AclFileAttributeView EMPTY_ACLVIEW = new AclView();

  private static final AclFileAttributeView FULL_ACCESS_ACLVIEW = new AclView(
      group("Everyone")
      .type(ALLOW)
      .perms(GenericPermission.GENERIC_READ)
      .flags(FILE_INHERIT, DIRECTORY_INHERIT));

  private Principal groupPrincipal(String name) {
    return new Principal().setGroupResourceName(name);
  }

  private Principal userPrincipal(String name) {
    return new Principal().setUserResourceName(name);
  }

  // These AclView settings were treated as defaults in MockFile when no other values were
  // set. Set them here instead in order to keep test data within the test class; override
  // in individual tests as needed.
  private MockFile getShareRootDefaultAclViews(String name) {
    return new MockFile(name, true)
        .setAclView(FULL_ACCESS_ACLVIEW)
        .setShareAclView(FULL_ACCESS_ACLVIEW);
  }

  private MockFile getDfsLink(String name, MockFile activeStorage) {
    MockFile file = new MockFile(name, true).setIsDfsLink(true);
    if (activeStorage != null) {
      file.setDfsActiveStorage(Paths.get(activeStorage.getPath()));
    }
    return file;
  }

  private MockFile getDfsNamespace(String name) {
    return new MockFile(name, true)
        .setIsDfsNamespace(true)
        .setDfsShareAclView(FULL_ACCESS_ACLVIEW);
  }

  private void verifyDocAcls(FileDelegate delegate, Properties config, String startPoint,
      String docId, ItemAcl expectedAcl, Map<String, Acl> expectedFragments) throws Exception {
    setConfig(startPoint, config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    BatchApiOperation batch = (BatchApiOperation) fsRepository.getDoc(new Item().setName(docId));
    Map<String, RepositoryDoc> ops = new HashMap<>();
    batch.forEach(op -> {
          if (op instanceof RepositoryDoc) {
            ops.put(((RepositoryDoc) op).getItem().getName(), (RepositoryDoc) op);
          }
        });

    assertEquals(ops.size(), expectedFragments.size() + 1);
    // RepositoryDoc has no fragments
    assertThat(ops.get(docId).getFragments().entrySet(), not(hasItem(anything())));
    // Doc has expected ACL.
    Item docItem = ops.get(docId).getItem();
    assertEquals("ItemAcl", expectedAcl, docItem.getAcl());
    for (Map.Entry<String, Acl> entry : expectedFragments.entrySet()) {
      Item expectedFragmentItem = entry.getValue().createFragmentItemOf(docId, entry.getKey());
      Item actualFragmentItem = ops.get(expectedFragmentItem.getName()).getItem();

      // Fragment item exists and has expected ACL.
      assertNotNull(actualFragmentItem);
      assertEquals(expectedFragmentItem.getAcl(), actualFragmentItem.getAcl());

      // No metadata is created for ACL fragemnts for root items; others are contained in
      // their item.
      ItemMetadata fragmentMetadata = actualFragmentItem.getMetadata();
      if (fragmentMetadata != null) {
        assertEquals(docItem.getName(), fragmentMetadata.getContainerName());
        assertNotEquals(docItem.getAcl().getInheritAclFrom(), actualFragmentItem.getName());
      }
    }
  }

  @Test
  public void testGetDocRootAcl() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    MockFileDelegate delegate = new MockFileDelegate(root);
    String rootDocId = delegate.newDocId(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(rootDocId, FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .build();
    // All of the folder/file fragment acls are the same since the root acl has
    // FILE_INHERIT, DIRECTORY_INHERIT on the single AclEntry.
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(rootDocId, FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(root),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocDfsNamespaceAcl() throws Exception {
    MockFile dfsNamespace = getDfsNamespace("/") // original test uses root as dfs namespace
        .setAclView(EMPTY_ACLVIEW);
    MockFileDelegate delegate = new MockFileDelegate(dfsNamespace);

    // Virtual containers are allowed to be acl-free, and a DFS namespace item is never a
    // search result.
    verifyDocAcls(delegate, new Properties(), dfsNamespace.getPath(),
        delegate.newDocId(dfsNamespace), /*expectedItemAcl*/ null, Collections.emptyMap());
  }

  @Test
  public void testGetDocEmptyAcl() throws Exception {
    MockFile child = new MockFile("acltest", false).setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, Collections.emptyMap());
  }

  @Test
  public void testGetDocDirectAcl() throws Exception {
    AclFileAttributeView aclView = new AclView((user("joe")
        .type(ALLOW).perms(GenericPermission.GENERIC_READ).build()));
    MockFile child = new MockFile("acltest", false).setAclView(aclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("joe")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, Collections.emptyMap());
  }

  @Test
  public void testGetDocNoInheritAcl() throws Exception {
    AclFileAttributeView aclView = new AclView((user("joe")
        .type(ALLOW).perms(GenericPermission.GENERIC_READ).build()));
    MockFile child = new MockFile("acltest", false)
        .setAclView(aclView).setInheritedAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);

    // Should inherit from the share, not the parent.
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("joe")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, Collections.emptyMap());
  }

  /*
  // This test from FsAdaptorTest is the same as testGetDocRootAcl
  @Test
  public void testGetDocContentDefaultRootAcls() throws Exception {
    testGetDocContentDefaultStartPathAcls(rootPath);
  }
  */

  @Test
  public void testGetDocDefaultNonRootStartPathAcls() throws Exception {
    MockFile child = new MockFile("test.dir", true)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);
    String childDocId = delegate.newDocId(child);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(childDocId, FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .build();
    // All of the folder/file fragment acls are the same since the root acl has
    // FILE_INHERIT, DIRECTORY_INHERIT on the single AclEntry.
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(childDocId, FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), child.getPath(), childDocId,
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocDfsLinkStartPointAcls() throws Exception {
    AclFileAttributeView linkAclView = new AclView(
        group("FsRootGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView dfsAclView = new AclView(
        group("DfsGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView shareAclView = new AclView(
        group("ShareGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    // We only read the Share ACL from the active storage.  All other
    // ACLs are read using the DFS path to the file/directory.
    MockFile dfsTarget = new MockFile("\\\\host\\share", true)
        .setShareAclView(shareAclView);
    MockFile dfsLink = getDfsLink("/", dfsTarget) // original test uses root as dfsLink
        .setAclView(linkAclView)
        .setDfsShareAclView(dfsAclView);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsLink, dfsTarget);

    Acl expectedDfsShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("DfsGroup")))
        .build();
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("ShareGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.DFS_SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT).build();
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsRootGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsRootGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.DFS_SHARE_ACL, expectedDfsShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), dfsLink.getPath(), delegate.newDocId(dfsLink),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocDfsLinkInNamespaceAcls() throws Exception {
    AclFileAttributeView dfsLinkAclView = new AclView(
        group("FsRootGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView shareAclView = new AclView(
        group("ShareGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView dfsAclView = new AclView(
        group("DfsGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile dfsTarget = new MockFile("\\\\host\\share", true)
        .setShareAclView(shareAclView);
    MockFile dfsLink = getDfsLink("dfsLink", dfsTarget)
        .setAclView(dfsLinkAclView)
        .setDfsShareAclView(dfsAclView);
    MockFile dfsNamespace = getDfsNamespace("/") // original test uses root as dfs namespace
        .setAclView(EMPTY_ACLVIEW)
        .addChildren(dfsLink);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsNamespace, dfsTarget);

    Acl expectedDfsShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("DfsGroup")))
        .build();
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("ShareGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.DFS_SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT).build();
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsRootGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsRootGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.DFS_SHARE_ACL, expectedDfsShareAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), dfsNamespace.getPath(), delegate.newDocId(dfsLink),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocNonRootStartPointAcls() throws Exception {
    AclFileAttributeView shareAclView = new AclView(
        group("ShareGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView dfsAclView = new AclView(
        group("DfsGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView nonRootAclView = new AclView(
        group("FsNonRootGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile dfsTarget = new MockFile("\\\\host\\share", true)
        .setShareAclView(shareAclView);
    MockFile nonRoot = new MockFile("subdir", true)
        .setAclView(nonRootAclView);
    MockFile dfsLink = getDfsLink("dfsLink", dfsTarget)
        .setDfsShareAclView(dfsAclView)
        .addChildren(nonRoot);
    MockFile dfsNamespace = getDfsNamespace("/") // original test uses root as dfs namespace
        .setAclView(EMPTY_ACLVIEW)
        .addChildren(dfsLink);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsNamespace, dfsTarget);

    Acl expectedDfsShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("DfsGroup")))
        .build();
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("ShareGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.DFS_SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT).build();
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsNonRootGroup")))
        .setInheritFrom(delegate.newDocId(nonRoot), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsNonRootGroup")))
        .setInheritFrom(delegate.newDocId(nonRoot), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.DFS_SHARE_ACL, expectedDfsShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), nonRoot.getPath(), delegate.newDocId(nonRoot),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocNonRootStartPointWithInheritedAcls() throws Exception {
    AclFileAttributeView shareAclView = new AclView(
        group("ShareGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView dfsAclView = new AclView(
        group("DfsGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView nonRootAclView = new AclView(
        group("FsNonRootGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView nonRootInheritedAclView = new AclView(
        group("FsRootGroup").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile dfsTarget = new MockFile("\\\\host\\share", true)
        .setShareAclView(shareAclView);
    MockFile nonRoot = new MockFile("subdir", true)
        .setAclView(nonRootAclView)
        .setInheritedAclView(nonRootInheritedAclView);
    MockFile dfsLink = getDfsLink("dfsLink", dfsTarget)
        .setDfsShareAclView(dfsAclView)
        .addChildren(nonRoot);
    MockFile dfsNamespace = getDfsNamespace("/") // original test uses root as dfs namespace
        .setAclView(EMPTY_ACLVIEW)
        .addChildren(dfsLink);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsNamespace, dfsTarget);

    Acl expectedDfsShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("DfsGroup")))
        .build();
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("ShareGroup")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.DFS_SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT).build();
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsNonRootGroup"),
                groupPrincipal("FsRootGroup")))
        .setInheritFrom(delegate.newDocId(nonRoot), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("FsNonRootGroup"),
                groupPrincipal("FsRootGroup")))
        .setInheritFrom(delegate.newDocId(nonRoot), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.DFS_SHARE_ACL, expectedDfsShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), nonRoot.getPath(), delegate.newDocId(nonRoot),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocRootSkipShareAcls() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    // The connector constructs a share acl as a placeholder with no access control
    // functionality.
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(Acl.getCustomerPrincipal()))
        .build();
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    Properties config = new Properties();
    config.put("fs.skipShareAccessControl", "true");
    verifyDocAcls(delegate, config, root.getPath(), delegate.newDocId(root),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocDfsNamespaceSkipShareAcls() throws Exception {
    AclFileAttributeView dfsAclView = new AclView(
        group("EVERYBODY").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView shareAclView = new AclView(
        group("Everyone").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile dfsTarget = new MockFile("\\\\host\\share", true);
    MockFile dfsLink = getDfsLink("/", dfsTarget) // original test uses root as dfsLink
        .setAclView(FULL_ACCESS_ACLVIEW)
        .setDfsShareAclView(dfsAclView)
        .setShareAclView(shareAclView);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(dfsLink, dfsTarget);

    // The connector constructs a share acl as a placeholder with no access control
    // functionality.
    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Collections.singleton(Acl.getCustomerPrincipal()))
        .build();
    Acl expectedFragmentAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .setInheritFrom(delegate.newDocId(dfsLink), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build().applyTo(new Item()).getAcl();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    Properties config = new Properties();
    config.put("fs.skipShareAccessControl", "true");
    verifyDocAcls(delegate, config, dfsLink.getPath(), delegate.newDocId(dfsLink),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocInheritOnlyRootAcls() throws Exception {
    AclFileAttributeView inheritOnlyAclView = new AclView(
        user("Longfellow Deeds").type(ALLOW).perms(GenericPermission.GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT, INHERIT_ONLY),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile root = getShareRootDefaultAclViews("/")
        .setAclView(inheritOnlyAclView);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .build();
    // The root ACL should only include Administrators, not Mr. Deeds.
    Acl expectedAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = expectedAcl.applyTo(new Item()).getAcl();
    // But the childrens' inherited ACLs should include Mr. Deeds
    Acl expectedInheritableAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Longfellow Deeds"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedInheritableAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedInheritableAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedInheritableAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedInheritableAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(root),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocNoPropagateRootAcls() throws Exception {
    AclFileAttributeView noPropagateAclView = new AclView(
        user("Barren von Dink").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT, NO_PROPAGATE_INHERIT),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile root = getShareRootDefaultAclViews("/")
        .setAclView(noPropagateAclView);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .build();
    // The root ACL should include both Administrators and the Barren.
    Acl expectedAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Barren von Dink"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = expectedAcl.applyTo(new Item()).getAcl();
    // The direct childrens' inherited ACLs should include both the
    // Administrators and the Barren, but grandchildren should not
    // inherit the Barren's NO_PROPAGATE permission.
    Acl expectedNonChildAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    Acl expectedChildAcl = expectedAcl;
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedNonChildAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedNonChildAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedChildAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedChildAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(root),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocFilesOnlyRootAcls() throws Exception {
    AclFileAttributeView noPropagateAclView = new AclView(
        user("For Your Files Only").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(FILE_INHERIT),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile root = getShareRootDefaultAclViews("/")
        .setAclView(noPropagateAclView);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .build();
    Acl expectedAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("For Your Files Only"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = expectedAcl.applyTo(new Item()).getAcl();
    // Folders shouldn't include the file-only permissions.
    Acl expectedFolderAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    Acl expectedFileAcl = expectedAcl;
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFolderAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFileAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFolderAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFileAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(root),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocFoldersOnlyRootAcls() throws Exception {
    AclFileAttributeView noPropagateAclView = new AclView(
        user("Fluff 'n Folder").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(DIRECTORY_INHERIT),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile root = getShareRootDefaultAclViews("/")
        .setAclView(noPropagateAclView);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    Acl expectedShareAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Everyone")))
        .build();
    Acl expectedAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Fluff 'n Folder"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = expectedAcl.applyTo(new Item()).getAcl();
    // Files shouldn't include the folder-only permissions.
    Acl expectedFilesAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    Acl expectedFoldersAcl = expectedAcl;
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.SHARE_ACL, expectedShareAcl)
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFoldersAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFilesAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFoldersAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFilesAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(root),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocDefaultDirectoryAcls() throws Exception {
    MockFile child = new MockFile("subdir", true)
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    Acl expectedFoldersAcl = new Acl.Builder()
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Acl expectedFilesAcl = new Acl.Builder()
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFoldersAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFilesAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFoldersAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFilesAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocNoInheritDirectoryAcls() throws Exception {
    AclFileAttributeView orphanAclView = new AclView(user("Annie").type(ALLOW)
        .perms(GenericPermission.GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile child = new MockFile("subdir", true)
        .setAclView(orphanAclView)
        .setInheritedAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    Acl expectedAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Annie")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.SHARE_ACL)
        .setInheritanceType(InheritanceType.BOTH_PERMIT)
        .build();
    ItemAcl expectedItemAcl = expectedAcl.applyTo(new Item()).getAcl();
    Acl expectedFragmentAcl = expectedAcl;
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFragmentAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFragmentAcl)
        .build();

    // Folders with no inherited acl behave like the root and are assigned an acl.
    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocInheritOnlyDirectoryAcls() throws Exception {
    AclFileAttributeView inheritOnlyAclView = new AclView(
        user("Longfellow Deeds").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT, INHERIT_ONLY),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile child = new MockFile("subdir", true)
        .setAclView(inheritOnlyAclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    // The childrens' inherited ACLs should include Mr. Deeds
    Acl expectedFoldersAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Longfellow Deeds"),
              groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Acl expectedFilesAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Longfellow Deeds"),
              groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, expectedFoldersAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, expectedFilesAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, expectedFoldersAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, expectedFilesAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocNoPropagateDirectoryAcls() throws Exception {
    AclFileAttributeView noPropagateAclView = new AclView(
        user("Barren von Dink").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT, NO_PROPAGATE_INHERIT),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile child = new MockFile("subdir", true)
        .setAclView(noPropagateAclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    // The root ACL should include both Administrators and the Barren.
    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Barren von Dink"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    // The direct childrens' inherited ACLs should include both the
    // Administrators and the Barren, but grandchildren should not
    // inherit the Barren's NO_PROPAGATE permission.
    Acl allFoldersAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Acl allFilesAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Acl childFoldersAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Barren von Dink"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Acl childFilesAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Barren von Dink"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, allFoldersAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, allFilesAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, childFoldersAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, childFilesAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocFilesOnlyDirectoryAcls() throws Exception {
    AclFileAttributeView filesOnlyAclView = new AclView(
        user("For Your Files Only").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(FILE_INHERIT),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile child = new MockFile("subdir", true)
        .setAclView(filesOnlyAclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("For Your Files Only"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    Acl filesAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("For Your Files Only"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    // Folders shouldn't include the file-only permissions.
    Acl foldersAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, foldersAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, filesAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, foldersAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, filesAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocFoldersOnlyDirectoryAcls() throws Exception {
    AclFileAttributeView foldersOnlyAclView = new AclView(
        user("Fluff 'n Folder").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(DIRECTORY_INHERIT),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile child = new MockFile("subdir", true)
        .setAclView(foldersOnlyAclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Fluff 'n Folder"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    Acl foldersAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Fluff 'n Folder"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    // Files shouldn't include the folder-only permissions.
    Acl filesAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.ALL_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, foldersAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, filesAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, foldersAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, filesAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void testGetDocNestedFoldersOnlyDirectoryAcls() throws Exception {
    AclFileAttributeView foldersOnlyAclView = new AclView(
        user("Fluff 'n Folder").type(ALLOW).perms(GenericPermission.GENERIC_READ)
            .flags(DIRECTORY_INHERIT),
        group("Administrators").type(ALLOW).perms(GenericPermission.GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    MockFile child1 = new MockFile("subdir1", true)
        .setAclView(EMPTY_ACLVIEW);
    MockFile child2 = new MockFile("subdir2", true)
        .setAclView(EMPTY_ACLVIEW);
    MockFile child3 = new MockFile("subdir3", true)
        .setAclView(foldersOnlyAclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child1);
    child1.addChildren(child2);
    child2.addChildren(child3);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Fluff 'n Folder"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(child2), FsRepository.CHILD_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();
    Acl foldersAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("Fluff 'n Folder"),
                groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(child2), FsRepository.ALL_FOLDER_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    // Files shouldn't include the folder-only permissions.
    Acl filesAcl = new Acl.Builder()
        .setReaders(Arrays.asList(groupPrincipal("Administrators")))
        .setInheritFrom(delegate.newDocId(child2), FsRepository.ALL_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build();
    Map<String, Acl> expectedFragments = new ImmutableMap.Builder<String, Acl>()
        .put(FsRepository.ALL_FOLDER_INHERIT_ACL, foldersAcl)
        .put(FsRepository.ALL_FILE_INHERIT_ACL, filesAcl)
        .put(FsRepository.CHILD_FOLDER_INHERIT_ACL, foldersAcl)
        .put(FsRepository.CHILD_FILE_INHERIT_ACL, filesAcl)
        .build();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child3),
        expectedItemAcl, expectedFragments);
  }

  @Test
  public void getDoc_defaultAclOverride_noAclContainersCreated() throws Exception {
    MockFile child = new MockFile("subdir", true)
        .setAclView(EMPTY_ACLVIEW);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    when(mockRepositoryContext.getDefaultAclMode()).thenReturn(DefaultAclMode.OVERRIDE);

    // This class tests FsRepository. The default ACL, when configured, is set in the
    // connector template class, so we should just have a null ACL here.
    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(root),
        null, Collections.emptyMap());
    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        null, Collections.emptyMap());
  }

  @Test
  public void getDoc_defaultAclOverride_aclFragmentsDeleted() throws Exception {
    MockFile root = getShareRootDefaultAclViews("/");
    MultiRootMockFileDelegate delegate = new MultiRootMockFileDelegate(root);

    when(mockRepositoryContext.getDefaultAclMode()).thenReturn(DefaultAclMode.OVERRIDE);

    setConfig("/");
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    ApiOperation result = fsRepository.getDoc(new Item().setName("/file#shareAcl"));
    assertEquals(ApiOperations.deleteItem("/file#shareAcl"), result);
  }

  @Test
  public void testGetDocRemoveUserDomain() throws Exception {
    AclFileAttributeView aclView = new AclView((user("domaintoremove\\joe")
        .type(ALLOW).perms(GenericPermission.GENERIC_READ).build()));
    MockFile child = new MockFile("acltest", false).setAclView(aclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList(userPrincipal("joe")))
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();

    Properties config = new Properties();
    config.put("fs.supportedDomain", "DOMAINTOREMOVE");
    verifyDocAcls(delegate, config, root.getPath(), delegate.newDocId(child),
        expectedItemAcl, Collections.emptyMap());
  }

  @Test
  public void testGetDocNoSupportedDomain() throws Exception {
    AclFileAttributeView aclView = new AclView((user("domaintoremove\\joe")
        .type(ALLOW).perms(GenericPermission.GENERIC_READ).build()));
    MockFile child = new MockFile("acltest", false).setAclView(aclView);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(child);
    MockFileDelegate delegate = new MockFileDelegate(root);

    ItemAcl expectedItemAcl = new Acl.Builder()
        .setReaders(Arrays.asList())
        .setInheritFrom(delegate.newDocId(root), FsRepository.CHILD_FILE_INHERIT_ACL)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
        .build().applyTo(new Item()).getAcl();

    verifyDocAcls(delegate, new Properties(), root.getPath(), delegate.newDocId(child),
        expectedItemAcl, Collections.emptyMap());
  }

  private RepositoryDoc getDocFromBatch(String name, ApiOperation batch) {
    assertThat(batch, instanceOf(BatchApiOperation.class));
    for (ApiOperation op : (BatchApiOperation) batch) {
      if (op instanceof RepositoryDoc
          && ((RepositoryDoc) op).getItem().getName().equals(name)) {
        return (RepositoryDoc) op;
      }
    }
    return null;
  }

  private static final long ONE_MINUTE_MILLIS =  60 * 1000L;
  private static final long ONE_HOUR_MILLIS =  60 * ONE_MINUTE_MILLIS;
  private static final long ONE_DAY_MILLIS = 24 * ONE_HOUR_MILLIS;

  @Test
  public void testAbsoluteLastAccessTimeFilterTooEarly() throws Exception {
    FileTime fileLastAccess = getFileTime("2000-01-30");
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastAccessedDate", "2000-01-31", MockFile::setLastAccessTime, fileLastAccess);
    assertEquals(ApiOperations.deleteItem("/testFile.txt"), result);
  }

  @Test
  public void testAbsoluteLastAccessTimeFilterStartDate() throws Exception {
    FileTime fileLastAccess = getFileTime("2000-01-31");
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastAccessedDate", "2000-01-31", MockFile::setLastAccessTime, fileLastAccess);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  @Test
  public void testAbsoluteLastAccessTimeFilterMuchLater() throws Exception {
    FileTime fileLastAccess = getFileTime("2014-01-31");
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastAccessedDate", "2000-01-31", MockFile::setLastAccessTime, fileLastAccess);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  @Test
  public void testRelativeLastAccessTimeFilterTooEarly() throws Exception {
    FileTime fileLastAccess =
        FileTime.fromMillis(System.currentTimeMillis() - (ONE_DAY_MILLIS + ONE_HOUR_MILLIS));
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastAccessedDays", "1", MockFile::setLastAccessTime, fileLastAccess);
    assertEquals(ApiOperations.deleteItem("/testFile.txt"), result);
  }

  @Test
  public void testRelativeLastAccessTimeFilterStartTime() throws Exception {
    FileTime fileLastAccess =
        FileTime.fromMillis(System.currentTimeMillis() - (ONE_DAY_MILLIS - ONE_MINUTE_MILLIS));
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastAccessedDays", "1", MockFile::setLastAccessTime, fileLastAccess);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  @Test
  public void testRelativeLastAccessTimeFilterMuchLater() throws Exception {
    FileTime fileLastAccess = FileTime.fromMillis(System.currentTimeMillis());
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastAccessedDays", "1", MockFile::setLastAccessTime, fileLastAccess);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  @Test
  public void testAbsoluteLastModifiedTimeFilterTooEarly() throws Exception {
    FileTime fileLastModified = getFileTime("2000-01-30");
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastModifiedDate", "2000-01-31", MockFile::setLastModifiedTime, fileLastModified);
    assertEquals(ApiOperations.deleteItem("/testFile.txt"), result);
  }

  @Test
  public void testAbsoluteLastModifiedTimeFilterStartDate() throws Exception {
    FileTime fileLastModified = getFileTime("2000-01-31");
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastModifiedDate", "2000-01-31", MockFile::setLastModifiedTime, fileLastModified);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  @Test
  public void testAbsoluteLastModifiedTimeFilterMuchLater() throws Exception {
    FileTime fileLastModified = getFileTime("2014-01-31");
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastModifiedDate", "2000-01-31", MockFile::setLastModifiedTime, fileLastModified);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  @Test
  public void testRelativeLastModifiedTimeFilterTooEarly() throws Exception {
    FileTime fileLastModified =
        FileTime.fromMillis(System.currentTimeMillis() - (ONE_DAY_MILLIS + ONE_HOUR_MILLIS));
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastModifiedDays", "1", MockFile::setLastModifiedTime, fileLastModified);
    assertEquals(ApiOperations.deleteItem("/testFile.txt"), result);
  }

  @Test
  public void testRelativeLastModifiedTimeFilterStartTime() throws Exception {
    FileTime fileLastModified =
        FileTime.fromMillis(System.currentTimeMillis() - (ONE_DAY_MILLIS - ONE_MINUTE_MILLIS));
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastModifiedDays", "1", MockFile::setLastModifiedTime, fileLastModified);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  @Test
  public void testRelativeLastModifiedTimeFilterMuchLater() throws Exception {
    FileTime fileLastModified = FileTime.fromMillis(System.currentTimeMillis());
    ApiOperation result = getDocWithDateFilter("testFile.txt",
        "fs.lastModifiedDays", "1", MockFile::setLastModifiedTime, fileLastModified);
    assertNotNull(getDocFromBatch("/testFile.txt", result));
  }

  private FileTime getFileTime(String date) throws Exception {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setCalendar(Calendar.getInstance());
    dateFormat.setLenient(true);
    return FileTime.fromMillis(dateFormat.parse(date).getTime());
  }

  private ApiOperation getDocWithDateFilter(String fileName,
      String configProperty, String configValue,
      BiConsumer<MockFile, FileTime> setter, FileTime fileTime) throws Exception {
    MockFile file = new MockFile(fileName, false)
        .setAclView(EMPTY_ACLVIEW).setShareAclView(FULL_ACCESS_ACLVIEW);
    setter.accept(file, fileTime);
    MockFile root = getShareRootDefaultAclViews("/")
        .addChildren(file);
    MockFileDelegate delegate = new MockFileDelegate(root);

    Properties config = new Properties();
    config.put(configProperty, configValue);
    setConfig(root.getPath(), config);
    FsRepository fsRepository = new FsRepository(delegate);
    fsRepository.init(mockRepositoryContext);

    String fileDocId = delegate.newDocId(file);
    Item requestItem = new Item().setName(fileDocId);
    return fsRepository.getDoc(requestItem);
  }

  @Test
  public void testGetChanges() throws Exception {
    setUpStartPath("/");
    setConfig("/");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    assertNull(fsRepository.getChanges(new byte[0]));
  }

  @Test
  public void testGetAllDocs() throws Exception {
    setUpStartPath("/");
    setConfig("/");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    thrown.expect(UnsupportedOperationException.class);
    fsRepository.getAllDocs(null);
  }

  @Test
  public void testExists() throws Exception {
    setUpStartPath("/");
    setConfig("/");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    thrown.expect(UnsupportedOperationException.class);
    fsRepository.exists(new Item());
  }

  @Test
  public void testClose() throws Exception {
    setUpStartPath("/");
    setConfig("/");
    FsRepository fsRepository = new FsRepository(mockFileDelegate);
    fsRepository.init(mockRepositoryContext);
    fsRepository.close();
    verify(mockFileDelegate).destroy();
  }
}
