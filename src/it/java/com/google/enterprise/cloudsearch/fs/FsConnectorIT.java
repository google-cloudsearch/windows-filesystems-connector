/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.enterprise.cloudsearch.fs;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.api.client.util.DateTime;
import com.google.api.services.cloudsearch.v1.model.Item;
import com.google.api.services.cloudsearch.v1.model.ItemMetadata;
import com.google.common.base.Strings;
import com.google.enterprise.cloudsearch.sdk.Util;
import com.google.enterprise.cloudsearch.sdk.config.Configuration.ResetConfigRule;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl;
import com.google.enterprise.cloudsearch.sdk.indexing.CloudSearchService;
import com.google.enterprise.cloudsearch.sdk.indexing.IndexingApplication;
import com.google.enterprise.cloudsearch.sdk.indexing.TestUtils;
import com.google.enterprise.cloudsearch.sdk.indexing.template.ListingConnector;
import com.google.enterprise.cloudsearch.sdk.indexing.template.Repository;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;


/**
 * Tests to check the integration between the Windows File Systems Connector and
 * CloudSearch Indexing API.
 */
@RunWith(JUnit4.class)
public class FsConnectorIT {
  private static final Logger logger = Logger.getLogger(FsConnectorIT.class.getName());

  private static CloudSearchService cloudSearchService;
  private static TestUtils testUtils;
  private static String dataSourceId;
  private static String identitySourceId;
  private static String serviceAccountKeyFile;
  private static Optional<String> rootUrl;
  private static String share;
  private static File shareFolder;
  private static WindowsFileDelegate delegate;

  @Rule public ResetConfigRule resetConfig = new ResetConfigRule();
  @Rule public TemporaryFolder configFolder = new TemporaryFolder();
  @Rule public TemporaryFolder testFolder = new TemporaryFolder(shareFolder);
  private String fsSrc;

  @BeforeClass
  public static void initialize() throws Exception {
    delegate = new WindowsFileDelegate();

    dataSourceId = System.getProperty("api.test.sourceId");
    assertFalse("Missing api.test.sourceId", Strings.isNullOrEmpty(dataSourceId));

    identitySourceId = System.getProperty("api.test.identitySourceId");
    assertFalse("Missing api.test.identitySourceId", Strings.isNullOrEmpty(identitySourceId));

    serviceAccountKeyFile = System.getProperty("api.test.serviceAccountPrivateKeyFile");
    assertFalse("Missing api.test.serviceAccountPrivateKeyFile",
        Strings.isNullOrEmpty(serviceAccountKeyFile));
    Path serviceAccountKeyFilePath = Paths.get(serviceAccountKeyFile);
    assertTrue("No such file: " + serviceAccountKeyFile, Files.exists(serviceAccountKeyFilePath));
    serviceAccountKeyFile = serviceAccountKeyFilePath.toAbsolutePath().toString();

    rootUrl = Optional.ofNullable(System.getProperty("api.test.rootUrl"));

    cloudSearchService = new CloudSearchService(serviceAccountKeyFile, dataSourceId, rootUrl);
    testUtils = new TestUtils(cloudSearchService);

    share = System.getProperty("fs.test.share");
    assertFalse("Missing fs.test.share", Strings.isNullOrEmpty(share));

    String shareFolderName = System.getProperty("fs.test.shareFolder");
    assertFalse("Missing fs.test.shareFolder", Strings.isNullOrEmpty(shareFolderName));
    shareFolder = new File(shareFolderName);
  }

  @Before
  public void setUp() {
    fsSrc = share + "\\" + testFolder.getRoot().getName();
  }

  private String[] setupConfiguration(Properties additionalConfig) throws IOException {
    Properties config = new Properties();
    rootUrl.ifPresent(r -> config.setProperty("api.rootUrl", r));
    config.setProperty("api.sourceId", dataSourceId);
    config.setProperty("api.identitySourceId", identitySourceId);
    config.setProperty("api.serviceAccountPrivateKeyFile", serviceAccountKeyFile);
    config.setProperty("batch.batchSize", "1");
    config.setProperty("traverse.abortAfterException", "1");
    config.setProperty("traverse.threadPoolSize", "1");
    config.setProperty("schedule.pollQueueIntervalSecs", "3");
    config.setProperty("fs.monitorForUpdates", "false");
    config.setProperty("fs.preserveLastAccessTime", "NEVER");
    config.putAll(additionalConfig);
    logger.log(Level.INFO, "Config file properties: {0}", config);
    File file = configFolder.newFile();
    try (FileOutputStream output = new FileOutputStream(file)) {
      config.store(output, "properties file");
      output.flush();
    }
    return new String[] {"-Dconfig=" + file.getAbsolutePath()};
  }

  @Test
  public void basicIndexing_succeeds() throws Exception {
    // c:/.../<share folder>/<tempFolder> etc.
    File localRootFolder = testFolder.getRoot();
    File localTestFile = new File(localRootFolder, "test.txt");

    // \\host\share\<tempFolder> etc.
    Path startPointPath = delegate.getPath(fsSrc);
    String startPointDocId = delegate.newDocId(startPointPath);
    Path filePath = startPointPath.resolve("test.txt");
    String fileDocId = delegate.newDocId(filePath);
    createFile(localTestFile, UTF_8, "test file content");

    BasicFileAttributes shareAttrs = delegate.readBasicAttributes(startPointPath);
    ItemMetadata startPointMetadata = new ItemMetadata()
        .setSourceRepositoryUrl(startPointPath.toUri().toString())
        .setTitle(startPointPath.getFileName().toString())
        .setCreateTime(getRfc3339UtcString(shareAttrs.creationTime()))
        .setUpdateTime(getRfc3339UtcString(shareAttrs.lastModifiedTime()));
    Item expectedStartPointItem = new Item()
        .setName(getFullId(startPointDocId))
        .setItemType("CONTAINER_ITEM")
        .setMetadata(startPointMetadata);
    shareAttrs = delegate.readBasicAttributes(filePath);
    ItemMetadata fileMetadata = new ItemMetadata()
        .setSourceRepositoryUrl(filePath.toUri().toString())
        .setTitle(filePath.getFileName().toString())
        .setContainerName(startPointDocId)
        .setContentLanguage("en")
        .setMimeType("text/plain")
        .setCreateTime(getRfc3339UtcString(shareAttrs.creationTime()))
        .setUpdateTime(getRfc3339UtcString(shareAttrs.lastModifiedTime()));
    Item expectedFileItem = new Item()
        .setName(getFullId(fileDocId))
        .setItemType("CONTENT_ITEM")
        .setMetadata(fileMetadata);

    Properties config = new Properties();
    config.setProperty("fs.src", fsSrc);
    String[] args = setupConfiguration(config);
    TestListingConnector connector = new TestListingConnector(new FsRepository());
    IndexingApplication application = new IndexingApplication.Builder(connector, args).build();
    try {
      CountDownLatch docs = connector.waitFor(startPointDocId, fileDocId);
      application.start();
      assertTrue("Countdown expired", docs.await(60, TimeUnit.SECONDS));

      testUtils.waitUntilEqual(getFullId(startPointDocId), expectedStartPointItem);
      testUtils.waitUntilEqual(getFullId(fileDocId), expectedFileItem);
    } finally {
      application.shutdown("test ended");
      // Deleting the start point container deletes the children, but not the ACL
      // containers associated with the container.
      cloudSearchService.deleteItemsIfExist(
          getFullId(startPointDocId),
          getFullId(Acl.fragmentId(startPointDocId, FsRepository.ALL_FILE_INHERIT_ACL)),
          getFullId(Acl.fragmentId(startPointDocId, FsRepository.ALL_FOLDER_INHERIT_ACL)),
          getFullId(Acl.fragmentId(startPointDocId, FsRepository.CHILD_FILE_INHERIT_ACL)),
          getFullId(Acl.fragmentId(startPointDocId, FsRepository.CHILD_FOLDER_INHERIT_ACL)),
          getFullId(Acl.fragmentId(startPointDocId, FsRepository.SHARE_ACL))
        );
    }
  }

  // Constructing the DateTime without specifying a time zone uses the local machine's
  // zone, giving a string with an offset like "+07:00. The server seems to convert to UTC
  // when returning the ItemMetadata, giving a string with "Z" for the time zone, with so
  // the comparison in TestUtils.waitUntilEqual fails because it's doing a string
  // comparison on the ItemMetadata. Try constructing our expected data to match the
  // server.
  private String getRfc3339UtcString(FileTime fileTime) {
    return new DateTime(new Date(fileTime.toMillis()), TimeZone.getTimeZone("UTC+00:00"))
        .toStringRfc3339();
  }

  private String getFullId(String itemName) {
    return Util.getItemId(dataSourceId, itemName);
  }

  private void createFile(File file, Charset charset, String content) throws IOException {
    try (OutputStreamWriter out = new OutputStreamWriter(new FileOutputStream(file), charset)) {
      out.write(content);
    }
  }

  private static class TestListingConnector extends ListingConnector {
    CountDownLatch docCount = new CountDownLatch(0);
    Set<String> docIds = new HashSet<>();

    TestListingConnector(Repository repository) {
      super(repository);
    }

    CountDownLatch waitFor(String... docIds) {
      this.docIds = Collections.synchronizedSet(new HashSet<>());
      for (String id : docIds) {
        this.docIds.add(id);
      }
      docCount = new CountDownLatch(docIds.length);
      return docCount;
    }

    @Override
    public void process(Item item) throws IOException, InterruptedException {
      super.process(item);
      if (docIds.remove(item.getName())) {
        docCount.countDown();
      }
    }
  }
}
