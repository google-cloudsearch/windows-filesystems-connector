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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.cloudsearch.fs.FsRepository.RepositoryEventPusher;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Iterator;

class MockFileDelegate implements FileDelegate {

  private final MockFile root;

  // Required for subclasses.
  MockFileDelegate() {
    this.root = null;
  }

  MockFileDelegate(MockFile root) {
    Preconditions.checkNotNull(root, "root cannot be null");
    this.root = root;
  }

  /**
   * Returns the {@link MockFile} identified by the supplied {@link Path}.
   * @throws FileNotFoundException if the file is not found.
   */
  MockFile getFile(Path doc) throws FileNotFoundException {
    Preconditions.checkNotNull(doc, "doc cannot be null");
    MockFile file = root;
    Iterator<Path> iter = doc.iterator();
    if (doc.getRoot() != null) {
      // Using startsWith because Path adds a trailing backslash to
      // UNC roots.  The second check accounts for Windows Path
      // implementation flipping slashes on Unix paths.
      String rootStr = "" + doc.getRoot();
      if (!(rootStr.startsWith(root.getPath())
          || root.getPath().equals(rootStr.replace('\\', '/')))) {
        throw new FileNotFoundException("not found: " + doc.toString());
      }
    } else if (iter.hasNext()) {
      if (!(root.getPath().equals(iter.next().toString()))) {
        throw new FileNotFoundException("not found: " + doc.toString());
      }
    }
    while (iter.hasNext()) {
      file = file.getChild(iter.next().toString());
    }
    return file;
  }

  @Override
  public Path getPath(String pathname) throws IOException {
    return Paths.get(pathname);
  }

  @Override
  public boolean isDirectory(Path doc) throws IOException {
    try {
      return getFile(doc).isDirectory();
    } catch (FileNotFoundException e) {
      return false;
    }
  }

  @Override
  public boolean isRegularFile(Path doc) throws IOException {
    try {
      return getFile(doc).isRegularFile();
    } catch (FileNotFoundException e) {
      return false;
    }
  }

  @Override
  public boolean isHidden(Path doc) throws IOException {
    try {
      return getFile(doc).isHidden();
    } catch (FileNotFoundException e) {
      return false;
    }
  }

  @Override
  public BasicFileAttributes readBasicAttributes(Path doc) throws IOException {
    return getFile(doc).readBasicAttributes();
  }

  @Override
  public void setLastAccessTime(Path doc, FileTime time) throws IOException {
    getFile(doc).setLastAccessTime(time);
  }

  @Override
  public String probeContentType(Path doc) throws IOException {
    return getFile(doc).getContentType();
  }

  @Override
  public InputStream newInputStream(Path doc) throws IOException {
    return getFile(doc).newInputStream();
  }

  @Override
  public DirectoryStream<Path> newDirectoryStream(Path doc) throws IOException {
    return getFile(doc).newDirectoryStream();
  }

  @Override
  public String newDocId(Path doc) throws IOException {
    return doc.toString().replace('\\', '/');
  }

  String newDocId(MockFile doc) throws IOException {
    return newDocId(getPath(doc.getPath()));
  }

  @Override
  public AclFileAttributeViews getAclViews(Path doc) throws IOException {
    MockFile file = getFile(doc);
    return new AclFileAttributeViews(file.getAclView(),
                                     file.getInheritedAclView());
  }

  @Override
  public AclFileAttributeView getShareAclView(Path doc) throws IOException {
    return getFile(doc).getShareAclView();
  }

  @Override
  public AclFileAttributeView getDfsShareAclView(Path doc) throws IOException {
    return getFile(doc).getDfsShareAclView();
  }

  @Override
  public boolean isDfsNamespace(Path doc) throws IOException {
    return getFile(doc).isDfsNamespace();
  }

  @Override
  public boolean isDfsLink(Path doc) throws IOException {
    // WindowsFileDelegate doesn't throw an exception whcn the file is not found, it just
    // returns false.
    try {
      return getFile(doc).isDfsLink();
    } catch (FileNotFoundException e) {
      return false;
    }
  }

  @Override
  public Path resolveDfsLink(Path doc) throws IOException {
    return getFile(doc).getDfsActiveStorage();
  }

  @Override
  public DirectoryStream<Path> newDfsLinkStream(Path doc) throws IOException {
    MockFile file = getFile(doc);
    if (!file.isDfsNamespace()) {
      throw new IOException("Not a DFS Root: " + doc);
    }
    ImmutableList.Builder<Path> builder = ImmutableList.builder();
    for (Path path : file.newDirectoryStream()) {
      if (isDfsLink(path)) {
        builder.add(path);
      }
    }
    return new PathDirectoryStream(builder.build());
  }

  @Override
  public void startMonitorPath(Path watchPath, RepositoryEventPusher eventPusher)
      throws IOException {
  }

  @Override
  public void destroy() {
  }
}
