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

import static com.google.enterprise.cloudsearch.fs.AclView.GenericPermission.GENERIC_READ;
import static com.google.enterprise.cloudsearch.fs.AclView.GenericPermission.GENERIC_WRITE;
import static com.google.enterprise.cloudsearch.fs.AclView.group;
import static com.google.enterprise.cloudsearch.fs.AclView.user;
import static java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.FILE_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.INHERIT_ONLY;
import static java.nio.file.attribute.AclEntryFlag.NO_PROPAGATE_INHERIT;
import static java.nio.file.attribute.AclEntryPermission.READ_ACL;
import static java.nio.file.attribute.AclEntryPermission.READ_DATA;
import static java.nio.file.attribute.AclEntryPermission.READ_NAMED_ATTRS;
import static java.nio.file.attribute.AclEntryType.ALLOW;
import static java.nio.file.attribute.AclEntryType.DENY;
import static org.junit.Assert.assertEquals;

import com.google.api.services.cloudsearch.v1.model.Principal;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.enterprise.cloudsearch.sdk.config.Configuration.ResetConfigRule;
import com.google.enterprise.cloudsearch.sdk.config.Configuration.SetupConfigRule;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl.ResetExternalGroupsRule;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

/** Test cases for {@link AclBuilder}. */
public class AclBuilderTest {
  @Rule public ResetConfigRule resetConfig = new ResetConfigRule();
  @Rule public SetupConfigRule setupConfig = SetupConfigRule.uninitialized();
  @Rule public ResetExternalGroupsRule resetExternalGroups = new ResetExternalGroupsRule();
  @Rule public ExpectedException thrown = ExpectedException.none();
  @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

  private final Path doc = Paths.get("foo", "bar");
  private final Set<String> windowsAccounts =
      ImmutableSet.of(
          "BUILTIN\\Administrators",
          "Everyone",
          "BUILTIN\\Users",
          "BUILTIN\\Guest",
          "NT AUTHORITY\\INTERACTIVE",
          "NT AUTHORITY\\Authenticated Users");
  private final String builtinPrefix = "BUILTIN\\";
  private final AclFileAttributeView aclView =
      new AclView(
          user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
          user("mary")
              .type(ALLOW)
              .perms(GENERIC_READ, GENERIC_WRITE)
              .flags(FILE_INHERIT, DIRECTORY_INHERIT),
          user("mike").type(DENY).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
          group("EVERYONE").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
          group("sales").type(DENY).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT));
  // This is the expected ACL for the above aclView.
  private final Acl expectedAcl = expectedBuilder().build();

  @Test
  public void testConstructorNullPath() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(null, aclView, windowsAccounts, builtinPrefix, "");
  }

  @Test
  public void testConstructorNullAclView() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(doc, null, windowsAccounts, builtinPrefix, "");
  }

  @Test
  public void testConstructorNullAccounts() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(doc, aclView, null, builtinPrefix, "");
  }

  @Test
  public void testConstructorNullPrefix() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(doc, aclView, windowsAccounts, null, "");
  }

  @Test
  public void testGetAcl() throws Exception {
    assertEquals(expectedAcl, newBuilder(aclView).getAcl().build());
  }

  @Test
  public void testGetInheritableByAllDescendentFoldersAcl() throws Exception {
    assertEquals(
        expectedAcl, newBuilder(aclView).getInheritableByAllDescendentFoldersAcl().build());
  }

  @Test
  public void testGetInheritableByAllDescendentFilesAcl() throws Exception {
    assertEquals(expectedAcl, newBuilder(aclView).getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testGetInheritableByChildFoldersOnlyAcl() throws Exception {
    assertEquals(expectedAcl, newBuilder(aclView).getInheritableByChildFoldersOnlyAcl().build());
  }

  @Test
  public void testGetInheritableByChildFilesOnlyAcl() throws Exception {
    assertEquals(expectedAcl, newBuilder(aclView).getInheritableByChildFilesOnlyAcl().build());
  }

  @Test
  public void testFileInheritAcl() throws Exception {
    // "mary" and "sales" are only inheritable by files, not directories.
    AclFileAttributeView aclView =
        new AclView(
            user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("mary").type(ALLOW).perms(GENERIC_READ, GENERIC_WRITE).flags(FILE_INHERIT),
            user("mike").type(DENY).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            group("EVERYONE")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT),
            group("sales").type(DENY).perms(GENERIC_READ).flags(FILE_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // The file inherit ACLs should have all the users and groups.
    assertEquals(expectedAcl, aclBuilder.getInheritableByAllDescendentFilesAcl().build());
    assertEquals(expectedAcl, aclBuilder.getInheritableByChildFilesOnlyAcl().build());

    // The folder inherit ACLs should not include "mary" or "sales".
    List<Principal> readers =
        ImmutableList.of(
            Acl.getGroupPrincipal("EVERYONE"),
            Acl.getUserPrincipal("joe"));
    Acl expected = expectedBuilder().setReaders(readers).setDeniedReaders(users("mike")).build();
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
  }

  @Test
  public void testFolderInheritAcl() throws Exception {
    // "mary" and "sales" are only inheritable by directories, not files.
    AclFileAttributeView aclView =
        new AclView(
            user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("mary").type(ALLOW).perms(GENERIC_READ, GENERIC_WRITE).flags(DIRECTORY_INHERIT),
            user("mike").type(DENY).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            group("EVERYONE")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT),
            group("sales").type(DENY).perms(GENERIC_READ).flags(DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // The folder inherit ACLs should have all the users and groups.
    assertEquals(expectedAcl, aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expectedAcl, aclBuilder.getInheritableByChildFoldersOnlyAcl().build());

    // The file inherit ACLs should not include "mary" or "sales".
    List<Principal> readers =
        ImmutableList.of(
            Acl.getGroupPrincipal("EVERYONE"),
            Acl.getUserPrincipal("joe"));
    Acl expected = expectedBuilder().setReaders(readers).setDeniedReaders(users("mike")).build();
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFilesAcl().build());
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testNoPropagateFolderInheritAcl() throws Exception {
    AclFileAttributeView aclView =
        new AclView(
            user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("mike")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(DIRECTORY_INHERIT, NO_PROPAGATE_INHERIT),
            user("mary").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    Acl acl = aclBuilder.getInheritableByAllDescendentFoldersAcl().build();
    Acl expected = emptyExpectedBuilder().setReaders(users("joe", "mary")).build();
    assertEquals(expected, acl);

    acl = aclBuilder.getInheritableByChildFoldersOnlyAcl().build();
    expected = emptyExpectedBuilder().setReaders(users("joe", "mike", "mary")).build();
    assertEquals(expected, acl);
  }

  @Test
  public void testNoPropagateFileInheritAcl() throws Exception {
    AclFileAttributeView aclView =
        new AclView(
            user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("mike").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, NO_PROPAGATE_INHERIT),
            user("mary").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    Acl acl = aclBuilder.getInheritableByAllDescendentFilesAcl().build();
    Acl expected = emptyExpectedBuilder().setReaders(users("joe", "mary")).build();
    assertEquals(expected, acl);

    acl = aclBuilder.getInheritableByChildFilesOnlyAcl().build();
    expected = emptyExpectedBuilder().setReaders(users("joe", "mike", "mary")).build();
    assertEquals(expected, acl);
  }

  @Test
  public void testInheritOnlyAcl() throws Exception {
    AclFileAttributeView aclView =
        new AclView(
            user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("mike")
                .type(ALLOW)
                .perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT, INHERIT_ONLY),
            user("mary").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // This node's ACL should not include mike.
    Acl expected = emptyExpectedBuilder().setReaders(users("joe", "mary")).build();
    assertEquals(expected, aclBuilder.getAcl().build());

    // However, all of its children should include mike.
    expected = emptyExpectedBuilder().setReaders(users("joe", "mike", "mary")).build();
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testInsufficientReadPerms() throws Exception {
    AclFileAttributeView aclView =
        new AclView(
            user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("mike").type(ALLOW).perms(READ_DATA).flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // This node's ACLs should not include mike.
    Acl expected = emptyExpectedBuilder().setReaders(users("joe")).build();
    assertEquals(expected, aclBuilder.getAcl().build());
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testReadAttributesPermNotNeeded() throws Exception {
    AclFileAttributeView aclView =
        new AclView(
            user("joe").type(ALLOW).perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("mike")
                .type(ALLOW)
                .perms(READ_DATA, READ_ACL, READ_NAMED_ATTRS)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // This node's ACLs should include both joe and mike.
    Acl expected = emptyExpectedBuilder().setReaders(users("joe", "mike")).build();
    assertEquals(expected, aclBuilder.getAcl().build());
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expected, aclBuilder.getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testWindowsBuiltinUsers() throws Exception {
    ArrayList<AclEntry> entries = Lists.newArrayList();
    // Add all the permitted builtin users.
    for (String builtin : windowsAccounts) {
      entries.add(
          user(builtin)
              .type(ALLOW)
              .perms(GENERIC_READ)
              .flags(FILE_INHERIT, DIRECTORY_INHERIT)
              .build());
    }
    String badBuiltin = builtinPrefix + "BACKUP";
    // Now add a builtin user that should be excluded.
    entries.add(
        user(badBuiltin)
            .type(ALLOW)
            .perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT)
            .build());

    AclFileAttributeView aclView = new AclView(entries.toArray(new AclEntry[0]));
    AclBuilder aclBuilder = newBuilder(aclView);

    // The permitted users should contain all of the acceptable builtins.
    // But should not contain the bad builtin.
    Acl expected =
        emptyExpectedBuilder()
            .setReaders(users(Iterables.toArray(windowsAccounts, String.class)))
            .build();
    assertEquals(expected, aclBuilder.getAcl().build());
  }

  @Test
  public void testRemoveDomain() throws Exception {
    AclFileAttributeView aclView =
        new AclView(
            user("domaintoremove\\joe").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT),
            user("domaintokeep\\mike").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder =
        new AclBuilder(doc, aclView, windowsAccounts, builtinPrefix, "DOMAINTOREMOVE");
    Acl result = aclBuilder.getAcl().build();
    Acl expected = emptyExpectedBuilder().setReaders(users("joe")).build();
    assertEquals(expected, result);
  }

  @Test
  public void getAcl_externalGroups_mapped() throws Exception {
    File groupsFile = temporaryFolder.newFile();
    // Group members aren't used when mapping external groups to identity sources.
    createFile(groupsFile, "{\"externalGroups\":["
        + " {\"name\":\"Everyone\", \"members\":[ {\"id\":\"everyoneGroup@example.com\"} ]}"
        + " ]}");
    Properties config = new Properties();
    config.setProperty("externalgroups.filename", groupsFile.toString());
    config.setProperty("externalgroups.identitySourceId", "1234567890");
    // api.identitySourceId is the default identity source for ACL principals but should
    // not be used for groups in the external groups file
    config.setProperty("api.identitySourceId", "abcdefg");
    setupConfig.initConfig(config);

    AclFileAttributeView aclView = new AclView(
        group("Everyone").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder =
        new AclBuilder(doc, aclView, windowsAccounts, builtinPrefix, "");
    Acl result = aclBuilder.getAcl().build();
    // Identity source id in the generated ACL uses the configured external groups
    // identity source.
    Acl expected = emptyExpectedBuilder()
        .setReaders(groups("identitysources/1234567890/groups/Everyone")).build();
    assertEquals(expected, result);
  }

  /** Returns an AclBuilder for the AclFileAttributeView. */
  private AclBuilder newBuilder(AclFileAttributeView aclView) {
    return new AclBuilder(doc, aclView, windowsAccounts, builtinPrefix, "testdomain");
  }

  /**
   * Returns an Acl.Builder representing the aclView field. The caller is expected to overwrite any
   * of thes presets, then call build().
   */
  private Acl.Builder expectedBuilder() {
    List<Principal> readers =
        ImmutableList.of(
            Acl.getGroupPrincipal("EVERYONE"),
            Acl.getUserPrincipal("joe"),
            Acl.getUserPrincipal("mary"));
    List<Principal> deniedReaders =
        ImmutableList.of(
            Acl.getGroupPrincipal("sales"),
            Acl.getUserPrincipal("mike"));
    return emptyExpectedBuilder().setReaders(readers).setDeniedReaders(deniedReaders);
  }

  /** Returns an Acl.Builder with no users or groups. */
  private Acl.Builder emptyExpectedBuilder() {
    return new Acl.Builder();
  }

  /** Returns a Set of UserPrincipals of the named users. */
  private Set<Principal> users(String... users) {
    Set<Principal> principals = Sets.newHashSet();
    for (String user : users) {
      principals.add(Acl.getUserPrincipal(user));
    }
    return principals;
  }

  /** Returns a Set of GroupPrincipals of the named users. */
  private Set<Principal> groups(String... groups) {
    Set<Principal> principals = Sets.newHashSet();
    for (String group : groups) {
      principals.add(new Principal().setGroupResourceName(group));
    }
    return principals;
  }

  private void createFile(File file, String content) throws IOException {
    try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
      pw.write(content);
    }
  }
}
