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
import com.google.enterprise.cloudsearch.fs.FsRepository.RepositoryEventPusher;
import com.google.enterprise.cloudsearch.sdk.indexing.template.AsyncApiOperation;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Iterator;

interface FileDelegate {
  /**
   * Returns the real {@link Path} represented by the path string.
   * This is equivalent to {@code Paths.get(pathname)}.
   *
   * @param pathname the path string
   * @return the real Path
   */
  Path getPath(String pathname) throws IOException, InvalidPathException;

  /**
   * Returns {@code true} if the specified path represents
   * a directory, {@code false} otherwise.
   */
  boolean isDirectory(Path doc) throws IOException;

  /**
   * Returns {@code true} if the specified path represents
   * a regular file, {@code false} otherwise.
   */
  boolean isRegularFile(Path doc) throws IOException;

  /**
   * Returns {@code true} if the specified path represents
   * a hidden file or directory, {@code false} otherwise.
   */
  boolean isHidden(Path doc) throws IOException;

  /**
   * Returns the {@link BasicFileAttributes} for the file or directory.
   *
   * @param doc the file/folder to get the {@link BasicFileAttributes} for
   */
  BasicFileAttributes readBasicAttributes(Path doc) throws IOException;

  /**
   * Sets the lastAccess time for the file or directory.
   *
   * @param doc the file/folder to set the last accessed time on
   * @param time the last access time
   * @throws IOException
   */
  void setLastAccessTime(Path doc, FileTime time) throws IOException;

  /**
   * Probes the content type of a file.
   *
   * @param doc the file to get the content type
   * @return the content type of the file, or {@code null} if the
   * content type cannot be determined
   * @throws IOException
   */
  String probeContentType(Path doc) throws IOException;

  /**
   * Returns an {@link InputStream} to read the file contents.
   *
   * @param doc the file to read
   * @return an InputStream to read the file contents
   * @throws IOException
   */
  InputStream newInputStream(Path doc) throws IOException;

  /**
   * Returns a {@link DirectoryStream} to read the directory entries.
   *
   * @param doc the directory to list
   * @return a DirectoryStream to read the directory entries
   * @throws IOException
   */
  DirectoryStream<Path> newDirectoryStream(Path doc) throws IOException;

  /**
   * Returns {@code true} if the supplied UNC path is a DFS
   * Namespace.  This would typically be a path like
   * {@code \\\\server\\namespace} or {@code \\\\domain\\namespace}.
   *
   * @param doc a UNC Path that may be a DFS namespace or DFS link
   * @return {@code true} if the path is a DFS namespace, or {@code false}
   *          otherwise
   * @throws IOException
   */
  boolean isDfsNamespace(Path doc) throws IOException;

  /**
   * Returns {@code true} if the supplied UNC path is a DFS Link.
   * This would typically be a path like
   * {@code \\\\server\\namespace\\link} or {@code \\\\domain\\namespace\\link}.
   *
   * @param doc a UNC Path that may be a DFS namespace or DFS link
   * @return {@code true} if the path is a DFS link, {@code false} otherwise
   * @throws IOException
   */
  boolean isDfsLink(Path doc) throws IOException;

  /**
   * Returns the active storage UNC path of a DFS link UNC path.
   * The supplied value would typically be a path like
   * {@code \\\\server\\namespace\\link} or {@code \\\\domain\\namespace\\link},
   * and resolve to a path like {@code \\\\server\\share}.
   *
   * @param doc the DFS UNC path to get the storage for
   * @return the backing storage path, or {@code null} if doc is not a
   *     DFS link path
   * @throws IOException
   */
  Path resolveDfsLink(Path doc) throws IOException;

  /**
   * Returns a DirectoryStream of DFS links contained within a DFS namespace.
   * The supplied path would typically be like
   * {@code \\\\server\\namespace} or {@code \\\\domain\\namespace}.
   *
   * @param doc the DFS UNC path to a DFS namespace
   * @return a DirectoryStream of DFS link paths
   * @throws IOException if doc is not a DFS namespace or is not accessable
   */
  DirectoryStream<Path> newDfsLinkStream(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeViews} that contains the directly
   * applied and inherited {@link AclFileAttributeView} for the specified path.
   *
   * @param doc the file/folder to get the {@link AclFileAttributeViews} for
   * @return AclFileAttributeViews for the specified path
   */
  AclFileAttributeViews getAclViews(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeView} that contains share ACL for the
   * specified path.
   *
   * @param doc the file/folder to get the {@link AclFileAttributeView} for
   * @throws IOException
   */
  AclFileAttributeView getShareAclView(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeView} that contains share ACL for the
   * specified DFS namespace.
   *
   * @param doc a DFS namespace to get the {@link AclFileAttributeView} for
   * @throws IOException
   */
  AclFileAttributeView getDfsShareAclView(Path doc) throws IOException;

  /**
   * Creates a new Item ID for the supplied file or folder.
   *
   * @param doc the file/folder to get the Item ID for
   * @throws IOException
   */
  String newDocId(Path doc) throws IOException;

  /**
   * Start monitoring the file system identified by {@code watchPath} for changes. Changes include
   * creating, deleting, modifying, renaming, or moving files or folders, as well as changes to
   * certain metadata and ACLs. The ID of each file or folder experiencing changes is pushed to the
   * API via the supplied {@code operationHandler}.
   *
   * <p>Multiple file system monitors may be created by calling this method with different
   * watchPaths. If a the supplied {@code watchPath} is already being monitored, a new monitor is
   * not created.
   *
   * @param watchPath root of a directory tree to monitor for changes
   * @param eventPusher the {@link RepositoryEventPusher} to push {@link AsyncApiOperation} changes
   * @throws IOException
   */
  void startMonitorPath(Path watchPath, RepositoryEventPusher eventPusher) throws IOException;

  /**
   * Shut down the {@code FileDelegate}, releasing its resources, and
   * terminating any file system change monitors.
   */
  void destroy();

  /** Helper class for wrapping a collection of {@link Path} as a {@link DirectoryStream}. */
  static class PathDirectoryStream implements DirectoryStream<Path> {
    private final Iterable<Path> paths;
    private boolean mayGetIterator = true;

    PathDirectoryStream(Iterable<Path> paths) {
      this.paths = paths;
    }

    @Override
    public Iterator<Path> iterator() {
      Preconditions.checkState(mayGetIterator, "DirectoryStream can only have one iterator.");
      mayGetIterator = false;
      return paths.iterator();
    }

    @Override
    public void close() {
      mayGetIterator = false;
    }
  }
}
