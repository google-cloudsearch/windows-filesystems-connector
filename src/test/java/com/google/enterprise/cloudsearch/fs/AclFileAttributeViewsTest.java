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

import static com.google.enterprise.cloudsearch.fs.AclView.group;
import static com.google.enterprise.cloudsearch.fs.AclView.user;
import static java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT;
import static java.nio.file.attribute.AclEntryFlag.FILE_INHERIT;
import static java.nio.file.attribute.AclEntryPermission.READ_DATA;
import static java.nio.file.attribute.AclEntryType.ALLOW;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/** Test cases for {@link AclFileAttributeViews}. */
public class AclFileAttributeViewsTest {
  @Rule public ExpectedException thrown = ExpectedException.none();

  private final AclFileAttributeViews aclViews =
      new AclFileAttributeViews(directAclView(), inheritedAclView());

  // Helper methods that create new AclView and List<AclEntry> instances, so
  // that tests for equality go all the way down to the individual AclEntries.

  private AclFileAttributeView directAclView() {
    return new AclView(user("joe").type(ALLOW).perms(READ_DATA));
  }

  private AclFileAttributeView inheritedAclView() {
    return new AclView(
        group("EVERYONE").type(ALLOW).perms(READ_DATA).flags(FILE_INHERIT, DIRECTORY_INHERIT));
  }

  @Test
  public void testConstructorNullDirectAcl() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclFileAttributeViews(null, inheritedAclView());
  }

  @Test
  public void testConstructorNullInheritedAcl() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclFileAttributeViews(directAclView(), null);
  }

  @Test
  public void testGetDirectAclView() throws Exception {
    assertEquals(directAclView().getAcl(), aclViews.getDirectAclView().getAcl());
  }

  @Test
  public void testInheritedAclView() throws Exception {
    assertEquals(inheritedAclView().getAcl(), aclViews.getInheritedAclView().getAcl());
  }

  @Test
  public void testGetCombinedAclView() throws Exception {
    List<AclEntry> acl = aclViews.getCombinedAclView().getAcl();
    assertNotNull(acl);
    assertEquals(2, acl.size());
    assertTrue(acl.contains(directAclView().getAcl().get(0)));
    assertTrue(acl.contains(inheritedAclView().getAcl().get(0)));
  }

  @Test
  public void getCombinedAclViewNoInheritedAcl() throws Exception {
    AclFileAttributeViews aclViews = new AclFileAttributeViews(directAclView(), new AclView());
    assertEquals(directAclView().getAcl(), aclViews.getCombinedAclView().getAcl());
  }

  @Test
  public void getCombinedAclViewNoDirectAcl() throws Exception {
    AclFileAttributeViews aclViews = new AclFileAttributeViews(new AclView(), inheritedAclView());
    assertEquals(inheritedAclView().getAcl(), aclViews.getCombinedAclView().getAcl());
  }
}
