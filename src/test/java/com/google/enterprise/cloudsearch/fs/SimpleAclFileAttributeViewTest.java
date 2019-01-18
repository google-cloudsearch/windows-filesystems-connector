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

import com.google.common.collect.ImmutableList;
import java.io.IOException;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/** Test cases for {@link SimpleAclFileAttributeView}. */
public class SimpleAclFileAttributeViewTest {
  @Rule public ExpectedException thrown = ExpectedException.none();

  private final UserPrincipal user =
      new UserPrincipal() {
        @Override
        public String getName() {
          return "foo";
        }
      };
  private final AclEntry aclEntry =
      AclEntry.newBuilder()
          .setType(AclEntryType.ALLOW)
          .setPrincipal(user)
          .setPermissions(AclEntryPermission.READ_DATA)
          .build();
  private final List<AclEntry> acl = ImmutableList.of(aclEntry);
  private final AclFileAttributeView aclView = new SimpleAclFileAttributeView(acl);

  @Test
  public void testGetAcl() throws IOException {
    assertEquals(acl, aclView.getAcl());
  }

  @Test
  public void testConstructorNullList() {
    thrown.expect(NullPointerException.class);
    new SimpleAclFileAttributeView(null);
  }

  @Test
  public void testSetAcl() throws IOException {
    thrown.expect(UnsupportedOperationException.class);
    aclView.setAcl(acl);
  }

  @Test
  public void testGetOwner() throws IOException {
    thrown.expect(UnsupportedOperationException.class);
    aclView.getOwner();
  }

  @Test
  public void testSetOwner() throws IOException {
    thrown.expect(UnsupportedOperationException.class);
    aclView.setOwner(user);
  }

  @Test
  public void testName() {
    assertEquals("acl", aclView.name());
  }
}
