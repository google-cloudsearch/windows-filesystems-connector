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
import static java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.FILE_INHERIT;
import static java.nio.file.attribute.AclEntryType.ALLOW;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test cases for {@link MockFileDelegate}.
 */
public class MockFileDelegateTest {
  private static final AclFileAttributeView EMPTY_ACLVIEW = new AclView();
  private static final AclFileAttributeView FULL_ACCESS_ACLVIEW = new AclView(
      group("Everyone")
      .type(ALLOW)
      .perms(GenericPermission.GENERIC_READ)
      .flags(FILE_INHERIT, DIRECTORY_INHERIT));

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testConstructorNullRoot() throws Exception {
    thrown.expect(NullPointerException.class);
    new MockFileDelegate(null);
  }

  @Test
  public void testGetPathNullPathname() throws Exception {
    thrown.expect(NullPointerException.class);
    new MockFileDelegate(new MockFile("root", true)).getPath(null);
  }

  @Test
  public void testGetPath() throws Exception {
    String delim = File.separator;
    FileDelegate delegate = new MockFileDelegate(new MockFile("root", true));
    assertEquals("root", delegate.getPath("root").toString());
    assertEquals("root" + delim + "foo" + delim + "bar",
        delegate.getPath("root/foo/bar").toString());
    assertEquals(delim + "foo" + delim + "bar" + delim + "baz",
        delegate.getPath("/foo/bar/baz").toString());
    assertEquals("\\\\server\\share\\dir\\file.txt",
        delegate.getPath("\\\\server\\share\\dir\\file.txt").toString());
  }

  @Test
  public void testGetFileNotFound() throws Exception {
    MockFile root = new MockFile("root", true).addChildren(new MockFile("foo"));
    MockFileDelegate delegate = new MockFileDelegate(root);
    thrown.expect(FileNotFoundException.class);
    delegate.getFile(delegate.getPath("root/nonExistent"));
  }

  @Test
  public void testGetFileRelativeRoot() throws Exception {
    testGetFile("root");
  }

  @Test
  public void testGetFileUncRoot() throws Exception {
    testGetFile("\\\\host\\share");
    testGetFile("\\\\host\\share\\");
  }

  @Test
  public void testGetFileUnixRoot() throws Exception {
    testGetFile("/");
  }

  @Test
  public void testGetFileDosRoot() throws Exception {
    testGetFile("C:\\");
  }

  private void testGetFile(String rootPath) throws Exception {
    MockFile root = new MockFile(rootPath, true).addChildren(
        new MockFile("dir1", true).addChildren(new MockFile("foo")),
        new MockFile("dir2", true).addChildren(new MockFile("bar")),
        new MockFile("test.txt"));
    MockFileDelegate delegate = new MockFileDelegate(root);

    assertSame(root, delegate.getFile(delegate.getPath(rootPath)));
    testGetFile(delegate, getPath(rootPath, "test.txt"));
    testGetFile(delegate, getPath(rootPath, "dir1"));
    testGetFile(delegate, getPath(rootPath, "dir2"));
    testGetFile(delegate, getPath(rootPath, "dir1/foo"));
    testGetFile(delegate, getPath(rootPath, "dir2/bar"));
  }

  private String getPath(String parent, String child) {
    return (parent.endsWith("/")) ? parent + child : parent + "/" + child;
  }

  private void testGetFile(MockFileDelegate delegate, String pathname)
      throws Exception {
    Path path = delegate.getPath(pathname);
    MockFile file = delegate.getFile(path);
    assertEquals(pathname, file.getPath());
    MockFile parent = file.getParent();
    if (parent != null) {
      assertSame(parent, delegate.getFile(path.getParent()));
    }
  }

  @Test
  public void testNewDocId() throws Exception {
    MockFile root = new MockFile("/", true).addChildren(
        new MockFile("dir1", true).addChildren(new MockFile("foo")));
    MockFileDelegate delegate = new MockFileDelegate(root);
    assertEquals("/", getDocId(delegate, "/"));
    assertEquals("/dir1", getDocId(delegate, "/dir1"));
    assertEquals("/dir1/foo", getDocId(delegate, "/dir1/foo"));
  }

  private String getDocId(FileDelegate delegate, String pathname)
      throws Exception {
    return delegate.newDocId(delegate.getPath(pathname));
  }

  @Test
  public void testSetLastAccessTime() throws Exception {
    MockFile root = new MockFile("root", true)
        .addChildren(new MockFile("test.txt"));
    FileDelegate delegate = new MockFileDelegate(root);
    Path path = delegate.getPath("root/test.txt");

    BasicFileAttributes attrs = delegate.readBasicAttributes(path);
    assertEquals(MockFile.DEFAULT_FILETIME, attrs.lastAccessTime());

    FileTime accessTime = FileTime.fromMillis(40000);
    delegate.setLastAccessTime(path, accessTime);
    attrs = delegate.readBasicAttributes(path);
    assertEquals(accessTime, attrs.lastAccessTime());
  }

  /**
   * Most of the MockDelegate methods are simple passthrough calls to the
   * MockFile methods.  This is a sanity check to make sure I'm calling the
   * right ones.
   */
  @Test
  public void testPassthroughGetters() throws Exception {
    FileTime createTime = FileTime.fromMillis(20000);
    FileTime modifyTime = FileTime.fromMillis(30000);
    FileTime accessTime = FileTime.fromMillis(40000);
    String content = "<html><title>Hello World</title></html>";
    MockFile root = new MockFile("root", true)
        .setAclView(FULL_ACCESS_ACLVIEW)
        .setShareAclView(FULL_ACCESS_ACLVIEW)
        .addChildren(
            new MockFile("test.html").setCreationTime(createTime)
            .setLastModifiedTime(modifyTime).setLastAccessTime(accessTime)
            .setFileContents(content).setContentType("text/html")
            .setAclView(EMPTY_ACLVIEW));

    FileDelegate delegate = new MockFileDelegate(root);
    Path path = delegate.getPath("root");
    assertTrue(delegate.isDirectory(path));
    assertFalse(delegate.isRegularFile(path));
    assertNull(delegate.resolveDfsLink(path));
    assertFalse(delegate.isDfsNamespace(path));
    root.setIsDfsNamespace(true);
    assertTrue(delegate.isDfsNamespace(path));
    root.setIsDfsNamespace(false);
    assertFalse(delegate.isDfsNamespace(path));
    assertFalse(delegate.isDfsLink(path));
    root.setIsDfsLink(true);
    assertTrue(delegate.isDfsLink(path));
    Path uncPath = delegate.getPath("\\\\server\\share");
    root.setDfsActiveStorage(uncPath);
    assertEquals(uncPath, delegate.resolveDfsLink(path));
    assertNull(delegate.getDfsShareAclView(path));
    root.setDfsShareAclView(FULL_ACCESS_ACLVIEW);
    assertEquals(FULL_ACCESS_ACLVIEW,
                 delegate.getDfsShareAclView(path));
    AclFileAttributeViews aclViews = delegate.getAclViews(path);
    assertNotNull(aclViews);
    assertEquals(FULL_ACCESS_ACLVIEW, aclViews.getDirectAclView());
    assertEquals(EMPTY_ACLVIEW, aclViews.getInheritedAclView());

    path = delegate.getPath("root/test.html");
    assertTrue(delegate.isRegularFile(path));
    assertFalse(delegate.isDirectory(path));
    assertFalse(delegate.isHidden(path));
    assertEquals("text/html", delegate.probeContentType(path));
    assertEquals(content, readContents(delegate, path));
    aclViews = delegate.getAclViews(path);
    assertNotNull(aclViews);
    assertEquals(EMPTY_ACLVIEW, aclViews.getDirectAclView());
    assertEquals(FULL_ACCESS_ACLVIEW, aclViews.getInheritedAclView());

    BasicFileAttributes attrs = delegate.readBasicAttributes(path);
    assertTrue(attrs.isRegularFile());
    assertFalse(attrs.isDirectory());
    assertFalse(attrs.isOther());
    assertEquals(createTime, attrs.creationTime());
    assertEquals(modifyTime, attrs.lastModifiedTime());
    assertEquals(accessTime, attrs.lastAccessTime());
    assertEquals(content.getBytes(Charsets.UTF_8).length, attrs.size());
  }

  private String readContents(FileDelegate delegate, Path path)
      throws IOException {
    return CharStreams.toString(
        new InputStreamReader(delegate.newInputStream(path), Charsets.UTF_8));
  }
}
