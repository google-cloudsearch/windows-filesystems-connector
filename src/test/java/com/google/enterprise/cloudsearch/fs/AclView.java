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

import static java.nio.file.attribute.AclEntryPermission.APPEND_DATA;
import static java.nio.file.attribute.AclEntryPermission.EXECUTE;
import static java.nio.file.attribute.AclEntryPermission.READ_ACL;
import static java.nio.file.attribute.AclEntryPermission.READ_ATTRIBUTES;
import static java.nio.file.attribute.AclEntryPermission.READ_DATA;
import static java.nio.file.attribute.AclEntryPermission.READ_NAMED_ATTRS;
import static java.nio.file.attribute.AclEntryPermission.SYNCHRONIZE;
import static java.nio.file.attribute.AclEntryPermission.WRITE_ATTRIBUTES;
import static java.nio.file.attribute.AclEntryPermission.WRITE_DATA;
import static java.nio.file.attribute.AclEntryPermission.WRITE_NAMED_ATTRS;

import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * This convenience class allows creation of an {@link AclFileAttributeView} containing a list of
 * {@link AclEntry AclEntries} that is far less verbose than using {@link
 * java.nio.file.attribute.AclEntry.Builder} multiple times. The static methods {@link
 * #user(String)} and {@link #group(String)} return builders for an AclEntry containing a {@link
 * UserPrincipal} or a {@link GroupPrincipal}, accordingly. The remaining AclEntry fields may then
 * be set using the returned builder. If using the {@code AclView} constructor that takes {@link
 * AclEntryBuilder} parameters, you need not call the {@code build()} method on those builders, as
 * the constructor will do that for you. An example construction of an AclView using this model
 * would look like:<br>
 * <code><pre>
 * import static com.google.enterprise.adaptor.fs.AclView.*;
 * import static java.nio.file.attribute.AclEntryFlag.*;
 * import static java.nio.file.attribute.AclEntryPermission.*;
 * import static java.nio.file.attribute.AclEntryType.*;
 *   ...
 * AclFileAttributeView aclView = new AclView(
 *     user("joe").type(ALLOW).perms(READ_DATA, READ_ATTRIBUTES)
 *         .flags(FILE_INHERIT, DIRECTORY_INHERIT),
 *     group("EVERYONE").type(ALLOW).perms(READ_DATA)
 *         .flags(FILE_INHERIT, DIRECTORY_INHERIT),
 *     user("mary").type(DENY).perms:(READ_DATA));
 * </pre></code>
 */
class AclView extends SimpleAclFileAttributeView {

  /** Compound permissions for easier specification. */
  static enum GenericPermission {
    GENERIC_READ(SYNCHRONIZE, READ_ACL, READ_DATA, READ_ATTRIBUTES,
                 READ_NAMED_ATTRS),
    GENERIC_WRITE(SYNCHRONIZE, READ_ACL, WRITE_DATA, APPEND_DATA,
                  WRITE_ATTRIBUTES, WRITE_NAMED_ATTRS),
    GENERIC_EXECUTE(SYNCHRONIZE, READ_ACL, READ_ATTRIBUTES, EXECUTE),
    GENERIC_ALL(AclEntryPermission.values());

    private final Set<AclEntryPermission> permissions;

    GenericPermission(AclEntryPermission... permissions) {
      this.permissions = Collections.unmodifiableSet(
          EnumSet.copyOf(Arrays.asList(permissions)));
    }

    Set<AclEntryPermission> getPermissions() {
      return permissions;
    }
  }

  AclView() {
    super(Collections.<AclEntry>emptyList());
  }

  AclView(AclEntry... entries) {
    super(Arrays.asList(entries));
  }

  AclView(AclEntryBuilder... entryBuilders) {
    super(buildEntries(entryBuilders));
  }

  /** Return a new AclEntryBuilder for a user entry. */
  static AclEntryBuilder user(String name) {
    return new AclEntryBuilder().user(name);
  }

  /** Return a new AclEntryBuilder for a group entry. */
  static AclEntryBuilder group(String name) {
    return new AclEntryBuilder().group(name);
  }

  /** Build the a List of AclEntries from the accumulated entry builders. */
  private static List<AclEntry> buildEntries(AclEntryBuilder... entryBuilders) {
    ArrayList<AclEntry> entries = new ArrayList<AclEntry>(entryBuilders.length);
    for (AclEntryBuilder builder : entryBuilders) {
      entries.add(builder.build());
    }
    return entries;
  }

  /** An AclEntry builder that is less verbose than AclEntry.Builder. */
  static class AclEntryBuilder {
    private final AclEntry.Builder builder = AclEntry.newBuilder();

    AclEntryBuilder user(String name) {
      builder.setPrincipal(new User(name));
      return this;
    }

    AclEntryBuilder group(String name) {
      builder.setPrincipal(new Group(name));
      return this;
    }

    AclEntryBuilder type(AclEntryType type) {
      builder.setType(type);
      return this;
    }

    AclEntryBuilder perms(AclEntryPermission... permissions) {
      builder.setPermissions(permissions);
      return this;
    }

    AclEntryBuilder perms(GenericPermission... permissions) {
      Set<AclEntryPermission> perms = EnumSet.noneOf(AclEntryPermission.class);
      for (GenericPermission genericPerm : permissions) {
        perms.addAll(genericPerm.getPermissions());
      }
      builder.setPermissions(perms);
      return this;
    }

    AclEntryBuilder flags(AclEntryFlag... flags) {
      builder.setFlags(flags);
      return this;
    }

    AclEntry build() {
      return builder.build();
    }
  }

  private static class User implements UserPrincipal {
    private final String name;

    User(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      return name;
    }

    // This implementation of equals() is a bit unusual, because I may compare
    // instances of two different implementations of the interface and I do not
    // want to match GroupPrincipals (which extend UserPrincipals).
    @Override
    public boolean equals(Object obj) {
      if (obj == null) {
        return false;
      }
      if (!(obj instanceof UserPrincipal) || obj instanceof GroupPrincipal) {
        return false;
      }
      return getName().equals(((UserPrincipal) obj).getName());
    }

    @Override
    public int hashCode() {
      return getName().hashCode();
    }
  }

  private static class Group extends User implements GroupPrincipal {
    Group(String name) {
      super(name);
    }

    // This implementation of equals() is a bit unusual, because I may compare
    // instances of two different implementations of the interface.
    @Override
    public boolean equals(Object obj) {
      if (obj == null) {
        return false;
      }
      if (!(obj instanceof GroupPrincipal)) {
        return false;
      }
      return getName().equals(((GroupPrincipal) obj).getName());
    }

    @Override
    public int hashCode() {
      return getName().hashCode();
    }
  }
}
