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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static com.google.enterprise.cloudsearch.sdk.indexing.IndexingServiceImpl.IDENTITY_SOURCE_ID;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Locale.ENGLISH;

import com.google.api.client.http.FileContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.DateTime;
import com.google.api.services.cloudsearch.v1.model.Item;
import com.google.api.services.cloudsearch.v1.model.ItemMetadata;
import com.google.api.services.cloudsearch.v1.model.PushItem;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.enterprise.cloudsearch.sdk.CheckpointCloseableIterable;
import com.google.enterprise.cloudsearch.sdk.CheckpointCloseableIterableImpl;
import com.google.enterprise.cloudsearch.sdk.InvalidConfigurationException;
import com.google.enterprise.cloudsearch.sdk.RepositoryException;
import com.google.enterprise.cloudsearch.sdk.StartupException;
import com.google.enterprise.cloudsearch.sdk.config.Configuration;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl.InheritanceType;
import com.google.enterprise.cloudsearch.sdk.indexing.DefaultAcl.DefaultAclMode;
import com.google.enterprise.cloudsearch.sdk.indexing.IndexingItemBuilder.ItemType;
import com.google.enterprise.cloudsearch.sdk.indexing.IndexingService.ContentFormat;
import com.google.enterprise.cloudsearch.sdk.indexing.IndexingService.RequestMode;
import com.google.enterprise.cloudsearch.sdk.indexing.template.ApiOperation;
import com.google.enterprise.cloudsearch.sdk.indexing.template.ApiOperations;
import com.google.enterprise.cloudsearch.sdk.indexing.template.PushItems;
import com.google.enterprise.cloudsearch.sdk.indexing.template.Repository;
import com.google.enterprise.cloudsearch.sdk.indexing.template.RepositoryContext;
import com.google.enterprise.cloudsearch.sdk.indexing.template.RepositoryDoc;

import java.io.BufferedReader;
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
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

// TODO(b/119498228): Support\Verify that we can handle \\host\C$ shares. Support\Verify
// that we can handle \\host only shares. Decide what we want to discover within \\host
// only shares.
/**
 * Runs on Microsoft Windows and serves files from networked shares.
 *
 * <p>Features:<br>
 *
 * <ul>
 *   <li>Supports UNC path to single machine's share, such as \\host\share
 *   <li>Supports UNC path to standalone or domain-based DFS namespace, such as
 *       \\dfs-server\namespace or \\domain-dfs-server\namespace and will follow all the DFS links
 *       within that namespace
 *   <li>Supports UNC path to standalone or domain-based DFS link, such as
 *       \\dfs-server\namespace\link or \\domain-dfs-server\namespace\link
 *   <li>Supports multiple UNC paths to any combination of simple file shares, DFS namespaces, or
 *       DFS links
 *   <li>Uses hierarchical ACL model
 * </ul>
 *
 * <p>This repository attempts to replicate the Windows file system ACL inheritance model
 * in a manner that Google Cloud Search can apply. All ACLs, including those from a DFS
 * server, network share, and the file system are supplied as named resources at
 * processing time in {@link #getDoc(Item)}.  The resource names are a combination of the
 * Id of the item being crawled and a "fragment" identifying the type of ACL that the
 * named resource value contains.
 *
 * <p>Windows permission inheritance has many nuances:
 *
 * <ul>
 *   <li>Generally, files and folders inherit permissions from their parent folder.
 *   <li>Files and folders may also have explicit permissions that enhance or reduce permissions
 *       inherited from their parent.
 *   <li>A file or folder can be configured to not inherit any permissions from its parent.
 *   <li>A folder can have permissions that apply only to itself and child folders.
 *   <li>A folder can have permissions that apply only to child files.
 *   <li>A folder can have permissions that do not apply to itself, but do apply to its children.
 *   <li>A folder can have permissions that apply to itself, but do not apply to any of its
 *       children.
 *   <li>A folder can have permissions that apply only to its direct children, but none of their
 *       descendants.
 * </ul>
 *
 * For more details, see {@link AclBuilder}.
 *
 * <p>To model these various behaviors, folders typically supply four separate ACLs as named
 * resources used for inheritance purposes:
 *
 * <ul>
 *   <li>{@code ALL_FOLDER_INHERIT_ACL}: Permissions inheritable by all descendent folders.
 *   <li>{@code ALL_FILE_INHERIT_ACL}: Permissions inheritable by all descendent regular files.
 *   <li>{@code CHILD_FOLDER_INHERIT_ACL}: Permissions inheritable only by direct child folders, but
 *       no other descendent folders.
 *   <li>{@code CHILD_FILE_INHERIT_ACL}: Permissions inheritable only by direct child files, but no
 *       other descendent regular files.
 * </ul>
 *
 * Folders and regular files also supply their own specific ACL, which contains any explicit
 * permissions set on that item. Usually, this ACL is empty and simply inherits from one of its
 * parent's four inheritable ACLs.
 *
 * <p>File system ACLs are not the only ACLs supplied by the connector to Google Cloud
 * Search. Windows shares and DFS links also gate access to the file system, so their
 * permissions must be considered as well.
 *
 * <p>The Share ACL is used by the system to control access to the network share and usually
 * presents itself as a username/password prompt when the user attempts to mount the network file
 * system. The Share ACL is supplied as a named resource when the root of the shared folder is
 * crawled, in addition to the four inheritable named resources. The file share may be an explicit
 * network share supplied as a start path, or it may be the target of a DFS link (see below). The
 * root of the share (the folder that was made sharable) inherits from the Share ACL, not its parent
 * folder. Note that the user must be permitted by the Share ACL <em>AND</em> the file system ACL to
 * be granted access to an item.
 *
 * <p>In 2003, Microsoft rolled out Distributed File System (DFS). A typical DFS configuration
 * consists of one or more <em>Namespaces</em>. Each Namespace contains one or more <em>Links</em>.
 * Each Link redirects to one or more <em>Targets</em>. Targets are network shared folders. Users
 * generally access a single Target. The others are often used for replication and fail-over. The
 * DFS configuration may be stored on a domain controller such as Active Directory, in which case it
 * is known as a <em>Domain-based</em> DFS configuration. DFS configuration hosted by a member
 * server, rather than the domain controller, is known as a <em>Stand-alone</em> DFS configuration.
 * Note that from the point of view of this connector, we do not distinguish between Domain-based
 * and Stand-alone DFS.
 *
 * <p>The DFS system employs access control when navigating its links, and usually each DFS Link has
 * its own ACL. One of the more exotic mechanisms employed by this is <em>Access-based
 * Enumeration</em> (ABE). With ABE deployed, users may only see a subset of the DFS Links, possibly
 * only one when ABE is used to isolate hosted home directories. When traversing a DFS system, this
 * connector supplies the DFS Link ACL, in addition to the target's Share ACL as a named resource
 * when the DFS Link is crawled. In this case, the Share ACL inherits from the DFS ACL. The user
 * must be permitted by the DFS ACL <em>AND</em> the Share ACL <em>AND</em> the file system ACL to
 * be granted access to an item.
 *
 * <p>Note: If the DFS system employs Access-based Enumeration, make sure the traversal user has
 * sufficient permissions to see all the links that require indexing.
 */
public class FsRepository implements Repository {
  private static final Logger log  = Logger.getLogger(FsRepository.class.getName());

  /** The config parameter name for the start paths. */
  private static final String CONFIG_SRC = "fs.src";

  /**
   * The config parameter name defining the delimiter used to separate
   * multiple start paths supplied in CONFIG_SRC. Default is ";".
   */
  private static final String CONFIG_SRC_SEPARATOR = "fs.src.separator";

  /** The config parameter name for the supported Windows accounts. */
  private static final String CONFIG_SUPPORTED_ACCOUNTS = "fs.supportedAccounts";

  /** The config parameter name for the supported Windows domain. */
  private static final String CONFIG_SUPPORTED_DOMAIN = "fs.supportedDomain";

  /** The config parameter name for turning on/off hidden file indexing. */
  private static final String CONFIG_CRAWL_HIDDEN_FILES = "fs.crawlHiddenFiles";

  /** The config parameter name for turning on/off folder indexing. */
  private static final String CONFIG_INDEX_FOLDERS = "fs.indexFolders";

  /** The config parameter name for strategy of preserving last access time. */
  private static final String CONFIG_PRESERVE_LAST_ACCESS_TIME = "fs.preserveLastAccessTime";

  /** The config parameter name for the size of the isVisible directory cache. */
  private static final String CONFIG_DIRECTORY_CACHE_SIZE = "fs.directoryCacheSize";

  /**
   * The config parameter name to specify the number of days relative to the current date
   * for earliest last accessed time allowed.
   */
  private static final String CONFIG_LAST_ACCESSED_DAYS = "fs.lastAccessedDays";

  /**
   * The config parameter name to specify the absolute date for earliest last accessed
   * time allowed.
   */
  private static final String CONFIG_LAST_ACCESSED_DATE = "fs.lastAccessedDate";

  /**
   * The config parameter name to specify the number of days relative to the current date
   * for earliest last modified time allowed.
   */
  private static final String CONFIG_LAST_MODIFIED_DAYS = "fs.lastModifiedDays";

  /**
   * The config parameter name to specify the absolute date for earliest last modified
   * time allowed.
   */
  private static final String CONFIG_LAST_MODIFIED_DATE = "fs.lastModifiedDate";

  /** The config parameter name to enable/disable filesystem change monitors. */
  private static final String CONFIG_MONITOR_UPDATES = "fs.monitorForUpdates";

  /** The config parameter name to force the connector to ignore the share ACL. */
  private static final String CONFIG_SKIP_SHARE_ACL = "fs.skipShareAccessControl";

  /** The config parameter name for the prefix for BUILTIN groups. */
  private static final String CONFIG_BUILTIN_PREFIX = "fs.builtinGroupPrefix";

  /** The config parameter name for the directory size that triggers async processing. */
  private static final String CONFIG_LARGE_DIRECTORY_LIMIT = "fs.largeDirectoryLimit";

  /** The config parameter name to indicate if files/folders are supported in DFS namespaces. */
  private static final String CONFIG_ALLOW_FILES_IN_DFS_NAMESPACES = "fs.allowFilesInDfsNamespaces";

  /** Properties filename to specify mime types. */
  private static final String MIME_TYPE_PROP_FILENAME = "mime-type.properties";

  /* mime type mapping */
  private static final Properties mimeTypeProperties = getMimeTypes();

  /** Fragments used for creating the inherited ACL named resources. */
  @VisibleForTesting static final String ALL_FOLDER_INHERIT_ACL = "allFoldersAcl";
  @VisibleForTesting static final String ALL_FILE_INHERIT_ACL = "allFilesAcl";
  @VisibleForTesting static final String CHILD_FOLDER_INHERIT_ACL = "childFoldersAcl";
  @VisibleForTesting static final String CHILD_FILE_INHERIT_ACL = "childFilesAcl";

  /** Fragment used for creating the DFS share ACL named resource. */
  @VisibleForTesting static final String DFS_SHARE_ACL = "dfsShareAcl";

  /** Fragment used for creating the share ACL named resource. */
  @VisibleForTesting static final String SHARE_ACL = "shareAcl";

  private static final List<String> DEFAULT_SUPPORTED_ACCOUNTS =
      ImmutableList.of(
          "BUILTIN\\Administrators",
          "Everyone",
          "BUILTIN\\Users",
          "BUILTIN\\Guest",
          "NT AUTHORITY\\INTERACTIVE",
          "NT AUTHORITY\\Authenticated Users");

  /** The number of items in a batch, when pushing directory contents asynchronously. */
  @VisibleForTesting static final int ASYNC_PUSH_ITEMS_BATCH_SIZE = 100;

  /**
   * The set of Windows accounts that qualify for inclusion in an ACL
   * regardless of the value.
   */
  private Set<String> supportedWindowsAccounts;

  /**
   * The known Windows domain.
   */
  private String supportedDomain;

  /**
   * The prefix used to determine if an account is a built-in account.
   * If an account starts with this string then it is considered a built-in account.
   */
  private String builtinPrefix;

  /** If true, crawl hidden files and folders.  Default is false. */
  private boolean crawlHiddenFiles;

  /**
   * If true, create CONTAINER_ITEM items for folders, otherwise create
   * VIRTUAL_CONTAINER_ITEM items.
   */
  private boolean indexFolders;

  /** How to enforce preservation of last access time of files and folders. */
  private enum PreserveLastAccessTime { NEVER, IF_ALLOWED, ALWAYS }
  private PreserveLastAccessTime preserveLastAccessTime;

  /** Cache of hidden and visible directories. */
  private Cache<Path, Hidden> isVisibleCache;

  private FileDelegate delegate;
  private RepositoryContext context;
  private boolean skipShareAcl;
  private boolean monitorForUpdates;

  /** The set of file systems we will be traversing. */
  private Set<Path> startPaths;

  /** The namespace links discovered during init. */
  private Map<Path, Set<Path>> dfsNamespaceLinks = new HashMap<>();

  /** The set of file systems currently blocked from traversing. */
  private Set<Path> blockedPaths = Sets.newConcurrentHashSet();

  /** Filter that may exclude files whose last modified time is too old. */
  private FileTimeFilter lastModifiedTimeFilter;

  /** Filter that may exclude files whose last access time is too old. */
  private FileTimeFilter lastAccessTimeFilter;

  private int largeDirectoryLimit;

  /** ExecutorService for asychronous pushing of large directory content. */
  private ExecutorService asyncDirectoryPusherService;

  /** Allow files/folders in DFS namespaces. */
  private boolean allowFilesInDfsNamespaces;

  public FsRepository() {
    // We only support Windows.
    if (System.getProperty("os.name").startsWith("Windows")) {
      delegate = new WindowsFileDelegate();
    } else {
      throw new IllegalStateException("Windows is the only supported platform.");
    }
  }

  @VisibleForTesting
  FsRepository(FileDelegate delegate) {
    this.delegate = delegate;
  }

  @VisibleForTesting
  Set<String> getSupportedWindowsAccounts() {
    return supportedWindowsAccounts;
  }

  @VisibleForTesting
  String getBuiltinPrefix() {
    return builtinPrefix;
  }

  @VisibleForTesting
  Set<Path> getStartPaths() {
    return startPaths;
  }

  @Override
  public void init(RepositoryContext context) {
    checkState(Configuration.isInitialized(), "configuration not initialized");
    this.context = checkNotNull(context);

    // ACLs are always sent, so a valid identity source is required for this connector.
    String identitySource = Configuration.getString(IDENTITY_SOURCE_ID, "").get();
    if (identitySource.isEmpty()) {
      throw new InvalidConfigurationException("The configuration value "
          + IDENTITY_SOURCE_ID + " is empty. Please specify a valid identity source.");
    }

    String sources = Configuration.getString(CONFIG_SRC, "").get();
    if (sources.isEmpty()) {
      throw new InvalidConfigurationException("The configuration value "
          + CONFIG_SRC + " is empty. Please specify a valid root path.");
    }
    try {
      startPaths = getStartPaths(sources, Configuration.getString(CONFIG_SRC_SEPARATOR, ";").get());
    } catch (InvalidPathException e) {
      throw new InvalidConfigurationException(CONFIG_SRC
          + " contains an invalid start path. " + e.getMessage());
    } catch (IOException e) {
      throw new InvalidConfigurationException("Exception during resolving start paths", e);
    }

    builtinPrefix = Configuration.getString(CONFIG_BUILTIN_PREFIX, "BUILTIN\\").get();
    log.log(Level.CONFIG, "builtinPrefix: {0}", builtinPrefix);

    List<String> accountsStr =
        Configuration.getMultiValue(
                CONFIG_SUPPORTED_ACCOUNTS, DEFAULT_SUPPORTED_ACCOUNTS, Configuration.STRING_PARSER)
            .get();
    supportedWindowsAccounts = ImmutableSet.copyOf(accountsStr);
    log.log(Level.CONFIG, "supportedWindowsAccounts: {0}", supportedWindowsAccounts);

    supportedDomain = Configuration.getString(CONFIG_SUPPORTED_DOMAIN, "").get();
    log.log(Level.CONFIG, "supportedWindowsDomain: {0}", supportedDomain);

    crawlHiddenFiles = Configuration.getBoolean(CONFIG_CRAWL_HIDDEN_FILES, Boolean.FALSE).get();
    log.log(Level.CONFIG, "crawlHiddenFiles: {0}", crawlHiddenFiles);

    indexFolders = Configuration.getBoolean(CONFIG_INDEX_FOLDERS, Boolean.TRUE).get();
    log.log(Level.CONFIG, "indexFolders: {0}", indexFolders);

    try {
      preserveLastAccessTime =
          Enum.valueOf(
              PreserveLastAccessTime.class,
              Configuration.getString(
                      CONFIG_PRESERVE_LAST_ACCESS_TIME, PreserveLastAccessTime.ALWAYS.toString())
                  .get());
    } catch (IllegalArgumentException e) {
      throw new InvalidConfigurationException("The value of "
          + CONFIG_PRESERVE_LAST_ACCESS_TIME + " must be one of "
          + EnumSet.allOf(PreserveLastAccessTime.class) + ".", e);
    }
    log.log(Level.CONFIG, "preserveLastAccessTime: {0}",
        preserveLastAccessTime);

    int directoryCacheSize = Configuration.getInteger(CONFIG_DIRECTORY_CACHE_SIZE, 50000).get();
    log.log(Level.CONFIG, "directoryCacheSize: {0}", directoryCacheSize);
    isVisibleCache = CacheBuilder.newBuilder()
        .initialCapacity(directoryCacheSize / 4)
        .maximumSize(directoryCacheSize)
        .expireAfterWrite(4, TimeUnit.HOURS) // Notice if someone hides a dir.
        .build();

    if (context.getDefaultAclMode() == DefaultAclMode.FALLBACK) {
      log.log(Level.WARNING, "The default ACL in FALLBACK mode will be ignored.");
    }

    // The Administrator may bypass Share access control.
    skipShareAcl = Configuration.getBoolean(CONFIG_SKIP_SHARE_ACL, Boolean.FALSE).get();
    log.log(Level.CONFIG, "skipShareAcl: {0}", skipShareAcl);

    // Add filters that may exclude older content.
    lastAccessTimeFilter = getFileTimeFilter(CONFIG_LAST_ACCESSED_DAYS, CONFIG_LAST_ACCESSED_DATE);
    lastModifiedTimeFilter =
        getFileTimeFilter(CONFIG_LAST_MODIFIED_DAYS, CONFIG_LAST_MODIFIED_DATE);

    allowFilesInDfsNamespaces = Configuration.getBoolean(
        CONFIG_ALLOW_FILES_IN_DFS_NAMESPACES, Boolean.FALSE).get();

    monitorForUpdates = Configuration.getBoolean(CONFIG_MONITOR_UPDATES, Boolean.TRUE).get();
    log.log(Level.CONFIG, "monitorForUpdates: {0}", monitorForUpdates);

    largeDirectoryLimit = Configuration.getInteger(CONFIG_LARGE_DIRECTORY_LIMIT, 1000).get();
    log.log(Level.CONFIG, "largeDirectoryLimit: {0}", largeDirectoryLimit);

    // Service for pushing large directory contents asynchronously.
    asyncDirectoryPusherService = Executors.newCachedThreadPool();

    // Verify that the startPaths are good.
    int validStartPaths = 0;
    for (Path startPath : startPaths) {
      try {
        validateStartPath(startPath, /* logging = */ true);
        validStartPaths++;
      } catch (IOException e) {
        log.log(Level.WARNING, "Unable to validate start path: " + startPath, e);
      }
    }
    if (validStartPaths == 0) {
      throw new StartupException("All start paths failed validation.");
    }
  }

  /** Parses the collection of startPaths from the supplied sources. */
  @VisibleForTesting
  Set<Path> getStartPaths(String sources, String separator)
      throws IOException, InvalidPathException {
    if (separator.isEmpty()) {
      // No separator implies a single startPath.
      return ImmutableSet.of(delegate.getPath(sources));
    }
    ImmutableSet.Builder<Path> builder = ImmutableSet.builder();
    Iterable<String> startPoints = Splitter.on(separator)
        .trimResults().omitEmptyStrings().split(sources);
    for (String startPoint : startPoints) {
      Path startPath = delegate.getPath(startPoint);
      builder.add(startPath);
      log.log(Level.CONFIG, "startPath: {0}", startPath);
    }
    return builder.build();
  }

  /** Verify that a startPath is valid. */
  @VisibleForTesting
  void validateStartPath(Path startPath, boolean logging)
      throws IOException, InvalidConfigurationException {
    try {
      delegate.newDocId(startPath);
    } catch (IOException e) {
      throw new InvalidConfigurationException("The path " + startPath
             + " is not valid path - " + e.getMessage() + ".");
    }

    // Do this as soon as possible, since it is selective in how it handles
    // various exceptions.
    validateShare(startPath);

    if (!crawlHiddenFiles && delegate.isHidden(startPath)) {
      throw new InvalidConfigurationException("The path " + startPath + " is "
          + "hidden. To crawl hidden content, you must set the configuration "
          + "property \"fs.crawlHiddenFiles\" to \"true\".");
    }

    // Using a path of \\host\ns\link\FolderA will be
    // considered non-DFS even though \\host\ns\link is a DFS link path.
    // This is OK for now since it will fail all three checks below and
    // will throw an InvalidConfigurationException.
    if (delegate.isDfsLink(startPath)) {
      Path dfsActiveStorage = delegate.resolveDfsLink(startPath);
      if (logging) {
        log.log(Level.INFO, "Using a DFS path resolved to {0}", dfsActiveStorage);
      }
    } else if (delegate.isDfsNamespace(startPath)) {
      if (logging) {
        log.log(Level.INFO, "Using a DFS namespace {0}", startPath);
      }
      Set<Path> linkSet = new HashSet<>();
      try (DirectoryStream<Path> links = delegate.newDfsLinkStream(startPath)) {
        for (Path link : links) {
          // Postpone full validation until crawl time.
          try {
            Path dfsActiveStorage = delegate.resolveDfsLink(link);
            linkSet.add(link);
            if (logging) {
              log.log(Level.INFO, "DFS path {0} resolved to {1}",
                  new Object[] {link, dfsActiveStorage});
            }
          } catch (IOException e) {
            log.log(Level.WARNING, "Unable to resolve DFS link " + startPath, e);
          }
        }
      }
      dfsNamespaceLinks.put(startPath, linkSet);
    } else {
      if (logging) {
        log.log(Level.INFO, "Using a {0}DFS path {1}", new Object[] {
            ((getDfsRoot(startPath) == null) ? "non-" : ""), startPath });
      }
    }
  }

  /** Returns the DFS Link or Namespace for a path; or null if not DFS. */
  private Path getDfsRoot(Path path) throws IOException {
    for (Path file = path; file != null; file = getParent(file)) {
      if (delegate.isDfsNamespace(file) || delegate.isDfsLink(file)) {
        return file;
      }
    }
    return null;
  }

  /** Verify the path is available and we have access to it. */
  @VisibleForTesting
  void validateShare(Path sharePath) throws IOException {
    // Verify that the connector has permission to read the contents of the root.
    try {
      if (delegate.isDfsNamespace(sharePath)) {
        delegate.newDfsLinkStream(sharePath).close();
      }
      if (!delegate.isDfsNamespace(sharePath) || allowFilesInDfsNamespaces) {
        delegate.newDirectoryStream(sharePath).close();
      }
    } catch (AccessDeniedException e) {
      throw new IOException("Unable to list the contents of " + sharePath + ". This can happen if "
          + "the Windows account used to crawl the path does not have sufficient permissions.", e);
    } catch (NotDirectoryException e) {
      throw new InvalidConfigurationException("The path " + sharePath
          + " is not a directory. Acceptable paths need to be either "
          + "\\\\host\\namespace or \\\\host\\namespace\\link or \\\\host\\shared directory.");
    } catch (FileNotFoundException e) {
      throw new InvalidConfigurationException("The path " + sharePath + " was not found.");
    } catch (NoSuchFileException e) {
      throw new InvalidConfigurationException("The path " + sharePath + " was not found.");
    } catch (IOException e) {
      throw new IOException("The path " + sharePath + " is not accessible. The path does not exist,"
          + " or it is not shared, or its hosting file server is currently unavailable.", e);
    }

    // Verify that the connector has permission to read the ACL and share ACL.
    try {
      readShareAcls(sharePath);
      if (!delegate.isDfsNamespace(sharePath) || allowFilesInDfsNamespaces) {
        delegate.getAclViews(sharePath);
      }
    } catch (IOException e) {
      throw new IOException("Unable to read ACLs for " + sharePath
          + ". This can happen if the Windows account used to crawl the path does not have "
          + "sufficient permissions. A Windows account with sufficient permissions to read content,"
          + " attributes and ACLs is required to crawl a path.", e);
    }
  }

  private FileTimeFilter getFileTimeFilter(String configDaysKey, String configDateKey)
      throws StartupException {
    String configDays = Configuration.getString(configDaysKey, "").get();
    String configDate = Configuration.getString(configDateKey, "").get();
    if (!configDays.isEmpty() && !configDate.isEmpty()) {
      throw new InvalidConfigurationException("Please specify only one of "
          + configDaysKey + " or " + configDateKey + ".");
    } else if (!configDays.isEmpty()) {
      log.log(Level.CONFIG, configDaysKey + ": " + configDays);
      try {
        return new ExpiringFileTimeFilter(Integer.parseInt(configDays));
      } catch (NumberFormatException e) {
        throw new InvalidConfigurationException(configDaysKey
            + " must be specified as a positive integer number of days.", e);
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationException(configDaysKey
            + " must be specified as a positive integer number of days.", e);
      }
    } else if (!configDate.isEmpty()) {
      log.log(Level.CONFIG, configDateKey + ": " + configDate);
      SimpleDateFormat iso8601DateFormat = new SimpleDateFormat("yyyy-MM-dd");
      iso8601DateFormat.setCalendar(Calendar.getInstance());
      iso8601DateFormat.setLenient(true);
      try {
        return new AbsoluteFileTimeFilter(FileTime.fromMillis(
            iso8601DateFormat.parse(configDate).getTime()));
      } catch (ParseException e) {
        throw new InvalidConfigurationException(configDateKey
            + " must be specified in the format \"YYYY-MM-DD\".", e);
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationException(configDateKey + " must be a date in the past.", e);
      }
    } else {
      return new AlwaysAllowFileTimeFilter();
    }
  }

  private ShareAcls readShareAcls(Path share) throws IOException {
    if (skipShareAcl) {
      // Ignore the Share ACL, but create a placeholder. Since items that inherit from the
      // Share ACL use BOTH_PERMIT (must be allowed by item + share), create an ACL here
      // that allows everyone.
      Acl shareAcl = new Acl.Builder()
          .setReaders(Collections.singleton(Acl.getCustomerPrincipal()))
          .setInheritanceType(InheritanceType.BOTH_PERMIT)
          .build();
      return new ShareAcls(shareAcl, null);
    }

    Path dfsRoot = getDfsRoot(share);
    if (dfsRoot == null) {
      // For a non-DFS UNC we have only have a share ACL to push.
      AclBuilder builder = new AclBuilder(share,
          delegate.getShareAclView(share),
          supportedWindowsAccounts, builtinPrefix, supportedDomain);
      Acl shareAcl = builder.getAcl()
          .setInheritanceType(InheritanceType.BOTH_PERMIT)
          .build();
      return new ShareAcls(shareAcl, null);
    } else {
      // For a DFS UNC we have a DFS ACL that must be sent. Also, the share ACL
      // must be the ACL for the target storage UNC.
      AclBuilder builder = new AclBuilder(share,
          delegate.getDfsShareAclView(dfsRoot),
          supportedWindowsAccounts, builtinPrefix, supportedDomain);
      Acl dfsShareAcl = builder.getAcl()
          .setInheritanceType(InheritanceType.BOTH_PERMIT)
          .build();
      if (delegate.isDfsNamespace(dfsRoot)) {
        // Use the DFS Acl as the Share Acl for ordinary files and folders
        // in the DFS Namespace.
        return new ShareAcls(dfsShareAcl, null);
      } else {  // Is a DFS Link.
        // Push the Acl for the active storage UNC path.
        Path activeStorage = delegate.resolveDfsLink(dfsRoot);
        if (activeStorage == null) {
          throw new IOException("The DFS path " + share
              + " does not have an active storage.");
        }
        builder = new AclBuilder(activeStorage,
            delegate.getShareAclView(activeStorage),
            supportedWindowsAccounts, builtinPrefix, supportedDomain);
        Acl shareAcl = builder.getAcl()
            .setInheritFrom(delegate.newDocId(dfsRoot), DFS_SHARE_ACL)
            .setInheritanceType(InheritanceType.BOTH_PERMIT).build();
        return new ShareAcls(shareAcl, dfsShareAcl);
      }
    }
  }

  @Override
  public CheckpointCloseableIterable<ApiOperation> getIds(byte[] checkpoint)
      throws RepositoryException {
    log.entering("FsConnector", "getIds");
    PushItems.Builder builder = new PushItems.Builder();
    for (Path startPath : startPaths) {
      try {
        String docid = delegate.newDocId(startPath);
        log.log(Level.FINE, "Pushing docid {0}", docid);
        builder.addPushItem(docid, new PushItem().setType("MODIFIED"));

        if (monitorForUpdates) {
          if (!delegate.isDfsNamespace(startPath)) {
            delegate.startMonitorPath(startPath, (event) -> context.postApiOperationAsync(event));
          } else {
            Set<Path> links = dfsNamespaceLinks.get(startPath);
            if (links != null) {
              for (Path link : links) {
                delegate.startMonitorPath(link, (event) -> context.postApiOperationAsync(event));
              }
            }
          }
        }
      } catch (IOException e) {
        throw new RepositoryException.Builder().setCause(e).build();
      }
    }
    ApiOperation operation = builder.build();
    log.exiting("FsConnector", "getIds");
    return new CheckpointCloseableIterableImpl.Builder<ApiOperation>(
        Arrays.asList(operation)).build();
  }

  @Override
  public ApiOperation getDoc(Item docItem) throws RepositoryException {
    log.entering("FsConnector", "getDoc", new Object[] {docItem});
    final String docName = docItem.getName(); // DocId
    final Path doc;

    // Ignore ACL fragment containers. ItemType is not set in the Item passed here (or we
    // might also check to see that it's a VIRTUAL_CONTAINER_ITEM), so test for the
    // fragment names.
    int fragmentIndex = docName.lastIndexOf('#');
    if (fragmentIndex != -1) {
      String fragmentName = docName.substring(fragmentIndex + 1);
      switch (fragmentName) {
        case ALL_FOLDER_INHERIT_ACL:
        case ALL_FILE_INHERIT_ACL:
        case CHILD_FOLDER_INHERIT_ACL:
        case CHILD_FILE_INHERIT_ACL:
        case DFS_SHARE_ACL:
        case SHARE_ACL:
          log.log(Level.FINEST, "Not re-indexing ACL fragment item");
          PushItem notModified = new PushItem().setType("NOT_MODIFIED");
          return new PushItems.Builder().addPushItem(docItem.getName(), notModified).build();
        default:
          // fall through to rest of method
      }
    }

    final boolean isRoot;
    final String parent;
    try {
      doc = delegate.getPath(docName);
      if (doc == null) {
        log.log(
            Level.WARNING, "The docid {0} is not a valid id generated by the connector.", docName);
        return ApiOperations.deleteItem(docName);
      }
      isRoot = startPaths.contains(doc) || delegate.isDfsLink(doc);
      Path docParent = getParent(doc);
      parent = (isRoot || docParent == null) ? null : delegate.newDocId(docParent);
    } catch (InvalidPathException e) {
      log.log(
          Level.WARNING, "The docid {0} is not a valid id generated by the connector.", docName);
      return ApiOperations.deleteItem(docName);
    } catch (IOException e) {
      throw new RepositoryException.Builder().setCause(e).setErrorMessage(docName).build();
    }

    BasicFileAttributes attrs;
    try {
      attrs = delegate.readBasicAttributes(doc);
    } catch (FileNotFoundException | NoSuchFileException e) {
      log.log(Level.INFO, "Not found: {0}", doc);
      return ApiOperations.deleteItem(docName);
    } catch (IOException e) {
      throw new RepositoryException.Builder().setCause(e).setErrorMessage(docName).build();
    }

    if (!isFileOrFolder(doc)) {
      log.log(Level.INFO, "The path {0} is not a regular file or directory.", doc);
      return ApiOperations.deleteItem(docName);
    }

    if (!isVisibleDescendantOfRoot(doc)) {
      log.log(Level.FINEST, "{0} is not a descendant of root", docName);
      return ApiOperations.deleteItem(docName);
    }

    // Check isEmpty first (nearly always true) to avoid calling getStartPath().
    if (!blockedPaths.isEmpty() && blockedPaths.contains(getStartPath(doc))) {
      throw new IllegalStateException("Skipping " + doc + " because its start path is blocked.");
    }

    final boolean docIsDirectory = attrs.isDirectory();
    final FileTime lastAccessTime = attrs.lastAccessTime();

    if (!docIsDirectory) {
      if (lastAccessTimeFilter.excluded(lastAccessTime)) {
        log.log(Level.FINE, "Deleting {0} because it was last accessed {1}.",
            new Object[] {doc, lastAccessTime.toString().substring(0, 10)});
        return ApiOperations.deleteItem(docName);
      }
      if (lastModifiedTimeFilter.excluded(attrs.lastModifiedTime())) {
        log.log(Level.FINE, "Deleting {0} because it was last modified {1}.",
            new Object[] {doc, attrs.lastModifiedTime().toString().substring(0, 10)});
        return ApiOperations.deleteItem(docName);
      }
    }

    Date lastModified = new Date(attrs.lastModifiedTime().toMillis());
    Date created = new Date(attrs.creationTime().toMillis());

    ItemMetadata metadata =
        new ItemMetadata()
            .setTitle(getTitle(doc))
            .setSourceRepositoryUrl(doc.toUri().toString())
            .setCreateTime(new DateTime(created).toStringRfc3339())
            .setUpdateTime(new DateTime(lastModified).toStringRfc3339());
    if (parent != null) {
      metadata.setContainerName(parent);
    }
    Item item = new Item()
        .setName(docName)
        .setMetadata(metadata);
    RepositoryDoc.Builder operationBuilder = new RepositoryDoc.Builder();
    operationBuilder.setItem(item);
    operationBuilder.setRequestMode(RequestMode.ASYNCHRONOUS);

    Map<String, Acl> aclFragments = new HashMap<>();
    List<ApiOperation> operations = new ArrayList<>();
    try {
      if (!allowFilesInDfsNamespaces && delegate.isDfsNamespace(doc)) {
        try {
          // Enumerate links in a namespace.
          getDirectoryStreamContent(doc, null, item, operationBuilder,
              new DirectoryStreamFactory() {
                @Override
                public DirectoryStream<Path> newDirectoryStream(Path dir)
                    throws IOException {
                  return delegate.newDfsLinkStream(dir);
                }
              });
        } catch (IOException e) {
          throw new RepositoryException.Builder().setCause(e).build();
        }
      } else {
        // If we are at the root of a filesystem or share point, supply the
        // Share ACL. If it is a DFS Link, also include the DFS Share ACL.
        if (isRoot) {
          try {
            validateShare(doc);
          } catch (IOException e) {
            throw new RepositoryException.Builder().setCause(e).build();
          }
          ShareAcls shareAcls = readShareAcls(doc);
          if (shareAcls.dfsShareAcl != null) {
            aclFragments.put(DFS_SHARE_ACL, shareAcls.dfsShareAcl);
          }
          aclFragments.put(SHARE_ACL, shareAcls.shareAcl);

          if (monitorForUpdates) {
            delegate.startMonitorPath(doc, (event) -> context.postApiOperationAsync(event));
          }
        }

        // Populate the document filesystem ACL.
        aclFragments.putAll(getFileAcls(doc, item));

        // Populate the document content.
        // Some filesystems let us read the metadata and ACL, but throw
        // NoSuchFileException when trying to read directory contents.
        try {
          if (docIsDirectory) {
            getDirectoryStreamContent(doc, lastAccessTime, item, operationBuilder,
                new DirectoryStreamFactory() {
                  @Override
                  public DirectoryStream<Path> newDirectoryStream(Path dir)
                      throws IOException {
                    return delegate.newDirectoryStream(dir);
                  }
                });
          } else {
            getFileContent(doc, lastAccessTime, item, operationBuilder);
          }
        } catch (FileNotFoundException | NoSuchFileException e) {
          log.log(Level.INFO, "File or directory not found: {0}", doc);
          return ApiOperations.deleteItem(docName);
        } catch (IOException e) {
          throw new RepositoryException.Builder().setCause(e).build();
        }

        // Set up the ACL containment. Only container types have fragments. ACL fragment
        // items are contained in their corresponding folder items, unless the folder item
        // is a start path or DFS link, or sets inheritAclFrom to the fragment item (root
        // items inherit from their own share ACLs).
        String itemInheritAclFrom = item.getAcl().getInheritAclFrom();
        for (Map.Entry<String, Acl> fragment : aclFragments.entrySet()) {
          Item fragmentItem = fragment.getValue()
              .createFragmentItemOf(item.getName(), fragment.getKey());
          if (!isRoot && !fragmentItem.getName().equals(itemInheritAclFrom)) {
            fragmentItem.setMetadata(new ItemMetadata().setContainerName(item.getName()));
          } else {
            log.log(Level.FINER,
                "Not setting container for acl fragment item: " + fragmentItem.getName());
          }
          RepositoryDoc.Builder fragmentOperationBuilder = new RepositoryDoc.Builder();
          fragmentOperationBuilder.setItem(fragmentItem);
          // TODO(gemerson): should we set request mode here, or let the SDK do it?
          fragmentOperationBuilder.setRequestMode(RequestMode.ASYNCHRONOUS);
          operations.add(fragmentOperationBuilder.build());
        }
      }
    } catch (IOException e) {
      if (e instanceof RepositoryException) {
        throw (RepositoryException) e;
      } else {
        throw new RepositoryException.Builder().setCause(e).build();
      }
    }
    log.exiting("FsConnector", "getDoc");
    operations.add(operationBuilder.build());
    return ApiOperations.batch(operations.iterator());
  }

  /**
   * Factory interface for creating new DirectoryStreams.
   */
  private interface DirectoryStreamFactory {
    DirectoryStream<Path> newDirectoryStream(Path dir) throws IOException;
  }

  private String getTitle(Path doc) {
    Path filename = doc.getFileName();
    if (filename == null) {
      return doc.toString();
    }
    return filename.toString();
  }

  /**
   * Returns the parent of a Path, or its root if it has no parent,
   * or null if already at root.
   *
   * UNC paths to DFS namespaces and DFS links behave somewhat oddly.
   * A DFS namespace contains one or more DFS links with a path like
   * \\host\namespace\link. However a call to Path.getParent() for
   * \\host\namespace\link does not return \\host\namespace; instead
   * it returns null. But, Path.getRoot() for \\host\namespace\link
   * does return \\host\namespace, which is exactly what I need.
   */
  private Path getParent(Path path) {
    Path parent = path.getParent();
    if (parent != null) {
      return parent;
    } else {
      Path root = path.getRoot();
      return (path.equals(root)) ? null : root;
    }
  }

  /* Populate the document ACL in the response. */
  private Map<String, Acl> getFileAcls(Path doc, Item item) throws IOException {
    final boolean isRoot = startPaths.contains(doc)
        || delegate.isDfsNamespace(doc)
        || delegate.isDfsLink(doc);
    final boolean isDirectory = delegate.isDirectory(doc);
    AclFileAttributeViews aclViews = delegate.getAclViews(doc);
    boolean hasNoInheritedAcl = aclViews.getInheritedAclView().getAcl().isEmpty();
    Path inheritFrom;
    if (isRoot) {
      // Roots will inherit from their own share ACLs.
      inheritFrom = doc;
    } else if (hasNoInheritedAcl) {
      // Files and folders that do not inherit permissions from their parent
      // inherit directly from the share ACL. Crawl up to node with share ACL.
      for (inheritFrom = doc;
          !startPaths.contains(inheritFrom) && !delegate.isDfsLink(inheritFrom);
          inheritFrom = getParent(inheritFrom)) {
        // Empty body.
      }
    } else {
      // All others inherit permissions from their parent.
      inheritFrom = getParent(doc);
    }
    if (inheritFrom == null) {
      throw new RepositoryException.Builder()
          .setErrorMessage("Unable to determine inherited ACL for " + doc).build();
    }
    String inheritFromDocId = delegate.newDocId(inheritFrom);

    AclBuilder builder;
    Acl acl;
    if (isRoot || hasNoInheritedAcl) {
      builder = new AclBuilder(doc, aclViews.getCombinedAclView(),
          supportedWindowsAccounts, builtinPrefix, supportedDomain);
      acl = builder.getAcl()
          .setInheritFrom(inheritFromDocId, SHARE_ACL)
          .setInheritanceType(InheritanceType.BOTH_PERMIT).build();
    } else {
      builder = new AclBuilder(doc, aclViews.getDirectAclView(),
          supportedWindowsAccounts, builtinPrefix, supportedDomain);
      if (isDirectory) {
        acl = builder.getAcl()
            .setInheritFrom(inheritFromDocId, CHILD_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDE).build();
      } else {
        acl = builder.getAcl()
            .setInheritFrom(inheritFromDocId, CHILD_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDE)
            .build();
      }
    }
    log.log(Level.FINEST, "Setting Acl: doc: {0}, acl: {1}", new Object[] { doc, acl });
    if (acl != null) {
      acl.applyTo(item);
    }

    Map<String, Acl> aclFragments = new HashMap<String, Acl>();
    // Add the additional ACLs for a folder.
    if (isDirectory) {
      if (isRoot || hasNoInheritedAcl) {
        aclFragments.put(ALL_FOLDER_INHERIT_ACL,
            builder.getInheritableByAllDescendentFoldersAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.BOTH_PERMIT).build());
        aclFragments.put(ALL_FILE_INHERIT_ACL,
            builder.getInheritableByAllDescendentFilesAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.BOTH_PERMIT).build());
        aclFragments.put(CHILD_FOLDER_INHERIT_ACL,
            builder.getInheritableByChildFoldersOnlyAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.BOTH_PERMIT).build());
        aclFragments.put(CHILD_FILE_INHERIT_ACL,
            builder.getInheritableByChildFilesOnlyAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.BOTH_PERMIT).build());
      } else {
        aclFragments.put(ALL_FOLDER_INHERIT_ACL,
            builder.getInheritableByAllDescendentFoldersAcl()
            .setInheritFrom(inheritFromDocId, ALL_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDE).build());
        aclFragments.put(ALL_FILE_INHERIT_ACL,
            builder.getInheritableByAllDescendentFilesAcl()
            .setInheritFrom(inheritFromDocId, ALL_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDE).build());
        aclFragments.put(CHILD_FOLDER_INHERIT_ACL,
            builder.getInheritableByChildFoldersOnlyAcl()
            .setInheritFrom(inheritFromDocId, ALL_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDE).build());
        aclFragments.put(CHILD_FILE_INHERIT_ACL,
            builder.getInheritableByChildFilesOnlyAcl()
            .setInheritFrom(inheritFromDocId, ALL_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDE).build());
      }
    }
    return aclFragments;
  }

  private void getDirectoryStreamContent(
      Path doc, FileTime lastAccessTime, Item item, RepositoryDoc.Builder operationBuilder,
      DirectoryStreamFactory factory) throws IOException {
    if (delegate.isDfsNamespace(doc)) {
      item.setItemType(ItemType.VIRTUAL_CONTAINER_ITEM.name());
    } else if (indexFolders) {
      item.setItemType(ItemType.CONTAINER_ITEM.name());
    } else {
      item.setItemType(ItemType.VIRTUAL_CONTAINER_ITEM.name());
    }
    // Large directories can have tens or hundreds of thousands of files. The SDK
    // enforces a time limit on calls to getDoc. If there are more items in the directory
    // than the configured limit, stop at the limit and use a separate thread to send the
    // complete contents.
    try (DirectoryStream<Path> paths = factory.newDirectoryStream(doc)) {
      int children = 0;
      for (Path path : paths) {
        String docId;
        try {
          docId = delegate.newDocId(path);
        } catch (IOException e) {
          log.log(Level.WARNING, "Skipping {0} because {1}.", new Object[] {path, e.getMessage()});
          continue;
        }
        if (children++ < largeDirectoryLimit) {
          operationBuilder.addChildId(docId, new PushItem());
        } else {
          log.log(Level.FINE, "Listing of children for {0} exceeds largeDirectoryLimit of {1}."
              + " Switching to asynchronous feed of child IDs.",
              new Object[] { doc, largeDirectoryLimit });
          asyncDirectoryPusherService.submit(new AsyncDirectoryContentPusher(doc, lastAccessTime));
          break;
        }
      }
    } finally {
      setLastAccessTime(doc, lastAccessTime);
    }
  }

  /* Pushes the directory's content. */
  private class AsyncDirectoryContentPusher implements Runnable {
    private final Path dir;
    private final FileTime lastAccessTime;

    public AsyncDirectoryContentPusher(Path dir, FileTime lastAccessTime) {
      this.dir = dir;
      this.lastAccessTime = lastAccessTime;
    }

    public void run() {
      log.log(Level.FINE, "Pushing children of {0}", getFileName(dir));
      try (DirectoryStream<Path> paths = delegate.newDirectoryStream(dir)) {
        int count = 0;
        PushItems.Builder builder = new PushItems.Builder();
        for (Path path : paths) {
          String docid;
          try {
            docid = delegate.newDocId(path);
          } catch (IOException e) {
            log.log(Level.WARNING, "Not pushing " + path, e);
            continue;
          }
          builder.addPushItem(docid, new PushItem());
          count++;
          if (count % ASYNC_PUSH_ITEMS_BATCH_SIZE == 0) {
            context.postApiOperationAsync(builder.build());
            builder = new PushItems.Builder();
            count = 0;
          }
        }
        if (count > 0) {
          context.postApiOperationAsync(builder.build());
        }
      } catch (IOException e) {
        log.log(Level.WARNING, "Failed to push children of " + dir, e);
      } finally {
        try {
          setLastAccessTime(dir, lastAccessTime);
        } catch (IOException e) {
          log.log(Level.WARNING, "Failed to restore last access time for "
                  + dir, e);
        }
      }
    }
  }

  /* Adds the file's content to the response. */
  private void getFileContent(Path doc, FileTime lastAccessTime, Item item,
      RepositoryDoc.Builder operationBuilder) throws IOException {
    String mimeType = getDocMimeType(doc);
    item.getMetadata().setMimeType(mimeType);
    item.setItemType(ItemType.CONTENT_ITEM.name());

    operationBuilder.setContent(new FileContent(mimeType, doc.toFile()), ContentFormat.RAW);
    setLastAccessTime(doc, lastAccessTime);
  }

  @VisibleForTesting
  String getDocMimeType(Path doc) {
    String fileName = doc.toString();
    int pos = fileName.lastIndexOf(".");
    if (pos != -1) {
      String extension = fileName.substring(pos + 1).toLowerCase(ENGLISH);
      String mimetype = mimeTypeProperties.getProperty(extension);
      if (mimetype != null) {
        return mimetype.trim();
      }
    }
    try {
      return delegate.probeContentType(doc);
    } catch (IOException e) {
      log.log(Level.WARNING, "Failed to determine a MIME type for {0}", doc);
      return null;
    }
  }

  /**
   * Load mime types from properties file.
   * @param userMimeTypes the mime types file
   * @param defaults the default properties; overridden by values from userMimeTypes
   * @return a Properties.
   */
  @VisibleForTesting
  static Properties loadMimeTypeProperties(Path userMimeTypes, Properties defaults) {
    Properties properties = new Properties(defaults);
    try (BufferedReader fileInput = Files.newBufferedReader(userMimeTypes, UTF_8)) {
      Properties overrides = new Properties();
      overrides.load(fileInput);
      for (String key : overrides.stringPropertyNames()) {
        properties.setProperty(key.toLowerCase(ENGLISH), overrides.getProperty(key).trim());
      }
    } catch (FileNotFoundException | NoSuchFileException e1) {
      log.log(Level.FINE, "No {0} file found", userMimeTypes);
      return defaults;
    } catch (IOException e) {
      log.log(Level.FINE, "IOException reading {0} file", userMimeTypes);
    }
    return properties;
  }

  private static Properties getMimeTypes() {
    Properties properties = new Properties();

    // mime type mapping from Microsoft Technet reference.
    // https://technet.microsoft.com/en-us/library/ee309278(office.12).aspx
    properties.setProperty("docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    properties.setProperty("docm", "application/vnd.ms-word.document.macroEnabled.12");
    properties.setProperty("dotx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template");
    properties.setProperty("dotm", "application/vnd.ms-word.template.macroEnabled.12");
    properties.setProperty("xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    properties.setProperty("xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12");
    properties.setProperty("xltx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template");
    properties.setProperty("xltm", "application/vnd.ms-excel.template.macroEnabled.12");
    properties.setProperty("xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12");
    properties.setProperty("xlam", "application/vnd.ms-excel.addin.macroEnabled.12");
    properties.setProperty("pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation");
    properties.setProperty("pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12");
    properties.setProperty("ppsx",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow");
    properties.setProperty("ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12");
    properties.setProperty("potx",
        "application/vnd.openxmlformats-officedocument.presentationml.template");
    properties.setProperty("potm", "application/vnd.ms-powerpoint.template.macroEnabled.12");
    properties.setProperty("ppam", "application/vnd.ms-powerpoint.addin.macroEnabled.12");
    properties.setProperty("sldx",
        "application/vnd.openxmlformats-officedocument.presentationml.slide");
    properties.setProperty("sldm", "application/vnd.ms-powerpoint.slide.macroEnabled.12");

    // Other MS Office mime types not included in the above reference.
    properties.setProperty("msg", "application/vnd.ms-outlook");

    // get mime types from properties file.
    return loadMimeTypeProperties(Paths.get(MIME_TYPE_PROP_FILENAME), properties);
  }

  /* Set mime type properties. */
  @VisibleForTesting
  protected void setMimeTypeProperties(Properties prop) {
    for (String key : prop.stringPropertyNames()) {
      mimeTypeProperties.setProperty(key.toLowerCase(ENGLISH),
          prop.getProperty(key));
    }
  }

  /**
   * Sets the last access time for the file to the supplied {@code FileTime}.
   * Failure to preserve last access times can fool backup and archive systems
   * into thinking the file or folder has been recently accessed by a human,
   * preventing the movement of least recently used items to secondary storage.
   * </p>
   * If the connector is unable to restore the last access time for the file,
   * it is likely the traversal user does not have sufficient privileges to
   * write the file's attributes.  We therefore halt crawls on this volume
   * unless the administrator allows us to proceed even if file timestamps
   * might not be preserved.
   */
  private void setLastAccessTime(Path doc, FileTime lastAccessTime)
      throws IOException {
    if (lastAccessTime == null
        || preserveLastAccessTime == PreserveLastAccessTime.NEVER) {
      return;
    }
    try {
      delegate.setLastAccessTime(doc, lastAccessTime);
    } catch (AccessDeniedException e) {
      if (preserveLastAccessTime == PreserveLastAccessTime.ALWAYS) {
        String message = String.format("Unable to restore the last access time "
            + "for %1$s. This can happen if the Windows account used to crawl "
            + "the path does not have sufficient permissions to write file "
            + "attributes. If you do not wish to enforce preservation of the "
            + "last access time for files and folders as they are crawled, "
            + "please set the '%2$s' configuration property to '%3$s' or "
            + "'%4$s'.",
            new Object[] { doc.toString(), CONFIG_PRESERVE_LAST_ACCESS_TIME,
                PreserveLastAccessTime.IF_ALLOWED, PreserveLastAccessTime.NEVER });
        log.log(Level.WARNING, message, e);
        Path startPath = getStartPath(doc);
        blockedPaths.add(startPath);
      } else {
        // This failure can be expected. We can have full permissions
        // to read but not write/update permissions.
        log.log(Level.FINER, "Unable to restore the last access time for {0}", doc);
      }
    }
  }

  /** Returns the startPath that {@code doc} resides under. */
  private Path getStartPath(Path doc) throws RepositoryException {
    for (Path startPath : startPaths) {
      if (doc.startsWith(startPath)) {
        return startPath;
      }
    }
    throw new RepositoryException.Builder()
        .setErrorMessage("Unable to determine the start path for " + doc).build();
  }

  @VisibleForTesting
  String getFileName(Path file) {
    // NOTE: file.getFileName() fails for UNC paths. Use file.toFile() instead.
    String name = file.toFile().getName();
    return name.isEmpty() ? file.getRoot().toString() : name;
  }

  /**
   * Returns true if the path is a regular file or a folder;
   * false if the path is a link, a special file, or doesn't exist.
   */
  @VisibleForTesting
  boolean isFileOrFolder(Path p) throws RepositoryException {
    try {
      return delegate.isRegularFile(p) || delegate.isDirectory(p);
    } catch (IOException e) {
      throw new RepositoryException.Builder().setCause(e).build();
    }
  }

  /** These are the cached entities in the isVisibleCache. */
  private static enum HiddenType {
      VISIBLE, HIDDEN, HIDDEN_UNDER, NOT_UNDER_STARTPATH
  }

  private static class Hidden {
    public HiddenType type;
    public Path hiddenBy;

    public Hidden(HiddenType type) {
      this.type = type;
    }

    public Hidden(HiddenType type, Path hiddenBy) {
      this.type = type;
      this.hiddenBy = hiddenBy;
    }
  }

  /**
   * Verifies that the file is a descendant of one of the startPaths,
   * and that it, nor none of its ancestors, is hidden.
   */
  @VisibleForTesting
  boolean isVisibleDescendantOfRoot(final Path doc) throws RepositoryException {
    final Path dir;
    // We only want to cache directories, not regular files; so check
    // for hidden files directly, but cache its parent.
    try {
      if (delegate.isRegularFile(doc)) {
        if (!crawlHiddenFiles && delegate.isHidden(doc)) {
          log.log(Level.WARNING, "Skipping file {0} because it is hidden.", doc);
          return false;
        }
        dir = getParent(doc);
      } else {
        dir = doc;
      }
    } catch (IOException e) {
      throw new RepositoryException.Builder().setCause(e).build();
    }

    // Cache isVisibleDecendantOfRoot results for directories.
    Hidden hidden;
    try {
      hidden = isVisibleCache.get(dir, new Callable<Hidden>() {
        @Override
        public Hidden call() throws IOException {
          for (Path file = dir; file != null; file = getParent(file)) {
            if (!crawlHiddenFiles && delegate.isHidden(file)) {
              if (doc == file) {
                return new Hidden(HiddenType.HIDDEN);
              } else {
                return new Hidden(HiddenType.HIDDEN_UNDER, file);
              }
            }
            if (startPaths.contains(file)) {
              return new Hidden(HiddenType.VISIBLE);
            }
          }
          return new Hidden(HiddenType.NOT_UNDER_STARTPATH);
        }
      });
    } catch (ExecutionException e) {
      throw new RepositoryException.Builder().setCause(e).build();
    }

    if (hidden.type == HiddenType.VISIBLE) {
      return true;
    } else if (hidden.type == HiddenType.HIDDEN) {
      log.log(Level.WARNING, "Skipping {0} because it is hidden.", doc);
    } else if (hidden.type == HiddenType.HIDDEN_UNDER) {
      log.log(Level.WARNING,
              "Skipping {0} because it is hidden under {1}.", new Object[] {doc, hidden.hiddenBy});
    } else if (hidden.type == HiddenType.NOT_UNDER_STARTPATH) {
      log.log(Level.WARNING, "Skipping {0} because it is not a descendant of a start path.", doc);
    }
    return false;
  }

  private class ShareAcls {
    private final Acl shareAcl;
    private final Acl dfsShareAcl;

    public ShareAcls(Acl shareAcl, Acl dfsShareAcl) {
      Preconditions.checkNotNull(shareAcl, "The share Acl may not be null.");
      this.shareAcl = shareAcl;
      this.dfsShareAcl = dfsShareAcl;
    }
  }

  private static interface FileTimeFilter {
    public boolean excluded(FileTime fileTime);
  }

  private static class AlwaysAllowFileTimeFilter implements FileTimeFilter {
    @Override
    public boolean excluded(FileTime fileTime) {
      return false;
    }
  }

  private static class AbsoluteFileTimeFilter implements FileTimeFilter {
    private final FileTime oldestAllowed;

    public AbsoluteFileTimeFilter(FileTime oldestAllowed) {
      Preconditions.checkArgument(oldestAllowed.compareTo(
          FileTime.fromMillis(System.currentTimeMillis())) < 0,
          oldestAllowed.toString().substring(0, 10) + " is in the future.");
      this.oldestAllowed = oldestAllowed;
    }

    @Override
    public boolean excluded(FileTime fileTime) {
      return fileTime.compareTo(oldestAllowed) < 0;
    }
  }

  private static class ExpiringFileTimeFilter implements FileTimeFilter {
    private static final long MILLIS_PER_DAY = 24 * 60 * 60 * 1000L;
    private final long relativeMillis;

    public ExpiringFileTimeFilter(int daysOld) {
      Preconditions.checkArgument(daysOld > 0, "The number of days old for "
          + "expired content must be greater than zero.");
      this.relativeMillis = daysOld * MILLIS_PER_DAY;
    }

    @Override
    public boolean excluded(FileTime fileTime) {
      FileTime oldestAllowed = FileTime.fromMillis(System.currentTimeMillis() - relativeMillis);
      return fileTime.compareTo(oldestAllowed) < 0;
    }
  }

  @Override
  public CheckpointCloseableIterable<ApiOperation> getChanges(byte[] checkpoint) {
    return null;
  }

  @Override
  public CheckpointCloseableIterable<ApiOperation> getAllDocs(byte[] checkpoint) {
    throw new UnsupportedOperationException("FsRepository doesn't support getAllDocs method");
  }

  @Override
  public boolean exists(Item item) {
    throw new UnsupportedOperationException("Not implemented yet");
  }

  @Override
  public void close() {
    try {
      if (asyncDirectoryPusherService != null) {
        asyncDirectoryPusherService.shutdownNow();
      }
    } finally {
      delegate.destroy();
    }
  }

  static interface RepositoryEventPusher {
    ListenableFuture<List<GenericJson>> push(ApiOperation event);
  }
}
