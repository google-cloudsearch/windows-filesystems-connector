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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import com.google.common.io.CharStreams;
import com.google.enterprise.cloudsearch.fs.FsRepository.RepositoryEventPusher;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

/** Tests for {@link NioFileDelegate} */
public class NioFileDelegateTest {
  private FileDelegate delegate = new TestNioFileDelegate();

  @Rule public ExpectedException thrown = ExpectedException.none();

  @Rule public TemporaryFolder temp = new TemporaryFolder();

  private Path newTempDir(String name) throws IOException {
    return temp.newFolder(name).toPath().toRealPath();
  }

  private Path newTempFile(String name) throws IOException {
    return temp.newFile(name).toPath().toRealPath();
  }

  private Path newTempFile(Path parent, String name) throws IOException {
    Preconditions.checkArgument(parent.startsWith(temp.getRoot().toPath().toRealPath()));
    return Files.createFile(parent.resolve(name));
  }

  @Test
  public void testGetPath() throws Exception {
    testGetPath("foo");
    testGetPath("/foo/bar/baz");
    testGetPath("\\\\host\\share\\file.txt");
    testGetPath(temp.getRoot().getAbsolutePath());
  }

  private void testGetPath(String pathname) throws Exception {
    assertTrue(Paths.get(pathname).equals(delegate.getPath(pathname)));
  }

  @Test
  public void testGetPathInvalidPathException() throws Exception {
    TestHelper.assumeOsIsWindows();
    thrown.expect(InvalidPathException.class);
    testGetPath("\\\\host\\"); // UNC path with no share.
  }

  @Test
  public void testIsDirectory() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile("test");
    assertTrue(delegate.isDirectory(dir));
    assertFalse(delegate.isDirectory(file));
    assertFalse(delegate.isDirectory(dir.resolve("notExist")));
  }

  @Test
  public void testIsRegularFile() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile("test");
    assertTrue(delegate.isRegularFile(file));
    assertFalse(delegate.isRegularFile(dir));
    assertFalse(delegate.isRegularFile(dir.resolve("notExist")));
  }

  @Test
  public void testIsHidden() throws Exception {
    Path hiddenFile = newTempFile(".hiddenFile");
    if (System.getProperty("os.name").startsWith("Windows")) {
      Files.setAttribute(hiddenFile, "dos:hidden", Boolean.TRUE);
    }
    try {
      assertTrue(delegate.isHidden(hiddenFile));
      assertFalse(delegate.isHidden(newTempFile("bar")));
    } finally {
      // Windows won't let me delete the hidden file in tearDown().
      if (System.getProperty("os.name").startsWith("Windows")) {
        Files.setAttribute(hiddenFile, "dos:hidden", Boolean.FALSE);
      }
    }
  }

  @Test
  public void testReadBasicAttributesDirectory() throws Exception {
    Path dir = newTempDir("testDir");
    BasicFileAttributes attrs = delegate.readBasicAttributes(dir);
    assertTrue(attrs.isDirectory());
    assertFalse(attrs.isRegularFile());
    assertFalse(attrs.isSymbolicLink());
    assertFalse(attrs.isOther());
  }

  @Test
  public void testReadBasicAttributesFile() throws Exception {
    byte[] content = "Hello World".getBytes(Charsets.UTF_8);
    Path file = newTempFile("test");
    Files.write(file, content);
    BasicFileAttributes attrs = delegate.readBasicAttributes(file);
    assertTrue(attrs.isRegularFile());
    assertFalse(attrs.isDirectory());
    assertFalse(attrs.isSymbolicLink());
    assertFalse(attrs.isOther());
    assertEquals(content.length, attrs.size());
  }

  @Test
  public void testReadBasicAttributesFileNotFound() throws Exception {
    Path file = Paths.get(temp.getRoot().toString(), "notFound");
    thrown.expect(NoSuchFileException.class);
    delegate.readBasicAttributes(file);
  }

  @Test
  public void testProbeContentType() throws Exception {
    TestHelper.assumeOsIsNotMac();
    String content = "<html><title>Foo</title><body>Bar</body></html>";
    Path file = newTempFile("Foo.html");
    Files.write(file, content.getBytes(Charsets.UTF_8));
    assertEquals("text/html", delegate.probeContentType(file));
  }

  @Test
  public void testNewInputStream() throws Exception {
    String content = "<html><title>Foo</title><body>Bar</body></html>";
    Path file = newTempFile("Foo.html");
    Files.write(file, content.getBytes(Charsets.UTF_8));
    assertEquals(
        content,
        CharStreams.toString(new InputStreamReader(delegate.newInputStream(file), Charsets.UTF_8)));
  }

  @Test
  public void testNewDirectoryStream() throws Exception {
    Path dir = newTempDir("testDir");
    Path file1 = newTempFile(dir, "test1");
    Path file2 = newTempFile(dir, "test2");
    Path file3 = newTempFile(dir, "test3");
    Set<Path> expected = Sets.newHashSet(file1, file2, file3);
    DirectoryStream<Path> ds = delegate.newDirectoryStream(dir);
    assertNotNull(ds);
    Set<Path> actual = Sets.newHashSet(ds);
    ds.close();
    assertEquals(expected, actual);
  }

  @Test
  public void testNewDocId() throws Exception {
    Path root = temp.getRoot().toPath().toRealPath();
    Path dir = newTempDir("testDir");
    Path file = newTempFile(dir, "test");

    String id = delegate.newDocId(root);
    assertTrue(id.contains(root.toString()));
    assertFalse(id.endsWith("/"));

    id = delegate.newDocId(dir);
    assertTrue(id.contains(root.toString()));
    assertTrue(id.contains(dir.toString()));
    assertFalse(id.endsWith("/"));

    id = delegate.newDocId(file);
    assertTrue(id.contains(root.toString()));
    assertTrue(id.contains(dir.toString()));
    assertTrue(id.contains(file.toString()));
    assertFalse(id.endsWith("/"));
  }

  @Test
  public void testSetLastAccessTime() throws Exception {
    Path file = newTempFile("test");
    BasicFileAttributes attrs = delegate.readBasicAttributes(file);
    FileTime originalTime = attrs.lastAccessTime();
    FileTime newTime = FileTime.fromMillis(originalTime.toMillis() + 10000);
    delegate.setLastAccessTime(file, newTime);
    attrs = delegate.readBasicAttributes(file);
    assertEquals(newTime, attrs.lastAccessTime());
  }

  private static class TestNioFileDelegate extends NioFileDelegate {
    @Override
    public void destroy() {}

    @Override
    public AclFileAttributeViews getAclViews(Path doc) throws IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public AclFileAttributeView getShareAclView(Path doc) throws IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public AclFileAttributeView getDfsShareAclView(Path doc) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean isDfsNamespace(Path doc) throws IOException {
      return false;
    }

    @Override
    public boolean isDfsLink(Path doc) throws IOException {
      return false;
    }

    @Override
    public Path resolveDfsLink(Path doc) throws IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<Path> enumerateDfsLinks(Path doc) throws IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public void startMonitorPath(Path watchPath, RepositoryEventPusher eventPusher)
        throws IOException {
      throw new UnsupportedOperationException();
    }
  }
}
