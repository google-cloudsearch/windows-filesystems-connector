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

import com.google.api.services.cloudsearch.v1.model.Principal;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Lists;
import com.google.enterprise.cloudsearch.sdk.indexing.Acl;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Build ACL for the file system adaptor.
 * <p>
 * A note about the inheritance behaviours of
 * ACEs, as described by Microsoft.  The original reference used is available at <a
 * href="https://web.archive.org/web/20111202234528/http://support.microsoft.com/kb/220167"
 * target="_blank">https://web.archive.org/web/20111202234528/http://support.microsoft.com/kb/220167</a>.
 * Another description of ACE propagation is at <a
 * href="https://msdn.microsoft.com/en-us/library/ms229747(v=vs.110).aspx"
 * target="_blank">https://msdn.microsoft.com/en-us/library/ms229747(v=vs.110).aspx</a>.

 * <p>
 * "This folder only":
 * <ul>
 *   <li>No ACE flags
 *   <li>No inheritance applies to ACE.
 * </ul>
 *
 * <p>
 * "This folder, subfolders, and files":
 * <ul>
 *   <li>ACE flags: Object Inherit and Container Inherit
 *   <li>All subordinate objects inherit this ACE, unless they are configured to block ACL
 *       inheritance altogether.
 * </ul>
 *
 * <p>
 * "This folder and subfolders":
 * <ul>
 *   <li>ACE flags: Container Inherit
 *   <li>ACE propagates to subfolders of this container, but not to files within this
 *       container.
 * </ul>
 *
 * <p>
 * "This folder and files":
 * <ul>
 *   <li>ACE flags: Object Inherit
 *   <li>ACE propagates to files within this container, but not to subfolders.
 * </ul>
 *
 * <p>
 * "Subfolders and files only":
 * <ul>
 *   <li>ACE flags: Inherit Only, Object Inherit, and Container Inherit
 *   <li>ACE does not apply to this container, but does propagate to both subfolders
 *       and files contained within.
 * </ul>
 *
 * <p>
 * "Subfolders only":
 * <ul>
 *   <li>ACE flags: Inherit Only and Container Inherit
 *   <li>ACE does not apply to this container, but propagates to subfolders.
 *       It does not propagate to contained files.
 * </ul>
 *
 * <p>
 * "Files only":
 * <ul>
 *   <li>ACE flags: Inherit Only and Object Inherit
 *   <li>ACE does not apply to this container, but propagates to the files it
 *       contains. Subfolders do not receive this ACE.
 * </ul>
 *
 * <p>
 * "Apply permissions to objects and/or containers within this container only":
 * <ul>
 *   <li>ACE flags: Any, plus No Propagate
 *   <li>This flag limits inheritance only to those sub-objects that are immediately
 *       subordinate to the current object.  It would be used in combination with other
 *       flags to indicate whether the ACE applies to this container, subordinate
 *       containers, and/or subordinate files.
 * </ul>
 *
 * <p>
 * More information regarding the explicit individual meanings of the ACE flags:
 * <ul>
 *   <li>Inherit Only - This flag indicates that this ACE does not apply to the
 *       current object.
 *   <li>Container Inherit - This flag indicates that subordinate containers
 *       will inherit this ACE.
 *   <li>Object Inherit - This flag indicates that subordinate files will
 *       inherit the ACE.
 *   <li>No Propagate - This flag indicates that the subordinate object will
 *      not propagate the inherited ACE any further.
 * </ul>
 */
public class AclBuilder {
  private static final Logger log
      = Logger.getLogger(AclBuilder.class.getName());

  private Path doc;
  private AclFileAttributeView aclView;
  private Set<String> supportedWindowsAccounts;
  private String builtinPrefix;
  private String supportedDomain;

  public AclBuilder(Path doc, AclFileAttributeView aclView,
      Set<String> supportedWindowsAccounts, String builtinPrefix, String supportedDomain) {
    Preconditions.checkNotNull(doc, "doc may not be null");
    Preconditions.checkNotNull(aclView, "aclView may not be null");
    Preconditions.checkNotNull(supportedWindowsAccounts,
        "supportedWindowsAccounts may not be null");
    Preconditions.checkNotNull(builtinPrefix, "builtinPrefix may not be null");
    Preconditions.checkNotNull(supportedDomain, "supportedDomain may not be null");
    this.doc = doc;
    this.aclView = aclView;
    this.supportedWindowsAccounts = supportedWindowsAccounts;
    this.builtinPrefix = builtinPrefix.toUpperCase();
    this.supportedDomain = supportedDomain.toUpperCase();
  }

  public Acl.Builder getAcl() throws IOException {
    return getAcl(isDirectEntry);
  }

  public Acl.Builder getInheritableByAllDescendentFoldersAcl()
      throws IOException {
    return getAcl(isInheritableByAllDescendentFoldersEntry);
  }

  public Acl.Builder getInheritableByAllDescendentFilesAcl()
      throws IOException {
    return getAcl(isInheritableByAllDescendentFilesEntry);
  }

  public Acl.Builder getInheritableByChildFoldersOnlyAcl() throws IOException {
    return getAcl(isInheritableByChildFoldersOnlyEntry);
  }

  public Acl.Builder getInheritableByChildFilesOnlyAcl() throws IOException {
    return getAcl(isInheritableByChildFilesOnlyEntry);
  }

  Acl.Builder getFlattenedAcl() throws IOException {
    return getAcl(Predicates.<Set<AclEntryFlag>>alwaysTrue());
  }

  @SuppressWarnings("cast")
  private Acl.Builder getAcl(Predicate<Set<AclEntryFlag>> predicate)
      throws IOException {
    List<Principal> permits = Lists.newArrayList();
    List<Principal> denies = Lists.newArrayList();
    for (AclEntry entry : aclView.getAcl()) {
      if (!predicate.apply(entry.flags())) {
        continue;
      }
      if (filterOutAclEntry(entry)) {
        continue;
      }

      Principal principal;
      if (entry.principal() instanceof java.nio.file.attribute.GroupPrincipal) {
        String localGroup = entry.principal().getName();
        principal = Acl.getGroupPrincipal(localGroup);
      } else if (entry.principal() instanceof java.nio.file.attribute.UserPrincipal) {
        String localUser = entry.principal().getName();

        // TODO(gemerson): toUpperCase needs to handle locales for domains
        if (supportedDomain.length() > 0
            && localUser.toUpperCase().startsWith(supportedDomain + "\\")) {
          localUser = localUser.substring(localUser.indexOf('\\') + 1);
          principal = Acl.getUserPrincipal(localUser);
        } else if (isSupportedWindowsAccount(localUser)) {
          principal = Acl.getUserPrincipal(localUser);
        } else if (localUser.indexOf("\\") != -1) {
          log.log(Level.WARNING, "Skipping domain user: {0}", localUser);
          continue;
        } else {
          principal = Acl.getUserPrincipal(localUser);
        }
      } else {
        log.log(Level.WARNING, "Unsupported ACL entry found: {0}", entry);
        continue;
      }

      if (entry.type() == AclEntryType.ALLOW) {
        permits.add(principal);
      } else if (entry.type() == AclEntryType.DENY) {
        denies.add(principal);
      }
    }

    return new Acl.Builder().setReaders(permits).setDeniedReaders(denies);
  }

  /**
   * Returns true if provided {@link AclEntry} should be excluded from ACL.
   *
   * @param entry The AclEntry to check.
   */
  private boolean filterOutAclEntry(AclEntry entry) {
    String principalName = entry.principal().getName();

    if (!isSupportedWindowsAccount(principalName)) {
      if (isBuiltin(principalName)) {
        log.log(Level.FINEST, "Filtering BUILTIN ACE {0} for file {1}.",
            new Object[] { entry, doc });
        return true;
      }
    }

    if (!hasReadPermission(entry.permissions())) {
      log.log(Level.FINEST, "Filtering non-read ACE {0} for file {1}.",
          new Object[] { entry, doc });
      return true;
    }

    return false;
  }

  /**
   * Returns true if the provided set of {@link AclEntryPermission} enables
   * read permission.
   */
  private boolean hasReadPermission(Set<AclEntryPermission> p) {
    return p.contains(AclEntryPermission.READ_DATA)
        && p.contains(AclEntryPermission.READ_ACL)
        && p.contains(AclEntryPermission.READ_NAMED_ATTRS);
  }

  /**
   * Returns true if the passed in user name is a Windows builtin user.
   */
  private boolean isBuiltin(String name) {
    return name.toUpperCase().startsWith(builtinPrefix);
  }

  /**
   * Returns true if the supplied account qualifies for inclusion in an ACL,
   * regardless of the value returned by {@link #isBuiltin(String name)}.
   */
  private final boolean isSupportedWindowsAccount(String user) {
    return supportedWindowsAccounts.contains(user);
  }

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is explicit
   * for this node, not inherited from another node.
   */
  private static final Predicate<Set<AclEntryFlag>> isDirectEntry =
      new Predicate<Set<AclEntryFlag>>() {
        @Override
        public boolean apply(Set<AclEntryFlag> flags) {
          return !flags.contains(AclEntryFlag.INHERIT_ONLY);
        }
      };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by direct children folders only.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByChildFoldersOnlyEntry =
          new Predicate<Set<AclEntryFlag>>() {
            @Override
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.DIRECTORY_INHERIT);
            }
          };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by direct children files only.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByChildFilesOnlyEntry =
          new Predicate<Set<AclEntryFlag>>() {
            @Override
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.FILE_INHERIT);
            }
          };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by all descendent folders.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByAllDescendentFoldersEntry =
          new Predicate<Set<AclEntryFlag>>() {
            @Override
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.DIRECTORY_INHERIT)
                  && !flags.contains(AclEntryFlag.NO_PROPAGATE_INHERIT);
            }
          };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by all descendent files.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByAllDescendentFilesEntry =
          new Predicate<Set<AclEntryFlag>>() {
            @Override
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.FILE_INHERIT)
                  && !flags.contains(AclEntryFlag.NO_PROPAGATE_INHERIT);
            }
          };
}
