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
import java.io.IOException;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;

/**
 * Contains the direct and inherited {@link AclFileAttributeView}s for a file.
 */
public class AclFileAttributeViews {
  private final AclFileAttributeView directAclView;
  private final AclFileAttributeView inheritedAclView;

  public AclFileAttributeViews(AclFileAttributeView directAclView,
                               AclFileAttributeView inheritedAclView) {
    Preconditions.checkNotNull(directAclView, "directAclView may not be null");
    Preconditions.checkNotNull(inheritedAclView, "inheritedAclView may not be null");
    this.directAclView = directAclView;
    this.inheritedAclView = inheritedAclView;
  }

  /**
   * Returns an {@link AclFileAttributeView} that contains the directly
   * applied ACL for the file.  The ACL contains no inherited permissions.
   *
   * @return AclFileAttributeView of direct ACL entries
   */
  public AclFileAttributeView getDirectAclView() {
    return directAclView;
  }

  /**
   * Returns an {@link AclFileAttributeView} that contains the inherited ACL
   * for the file. The ACL contains only permissions inherited from the parent.
   *
   * @return AclFileAttributeView of inherited ACL entries
   */
  public AclFileAttributeView getInheritedAclView() {
    return inheritedAclView;
  }

  /**
   * Returns an {@link AclFileAttributeView} that contains the ACL for the file.
   * The ACL contains directly applied as well as inherited permissions.
   *
   * @return AclFileAttributeView of ACL entries
   * @throws IOException if fails to get either the direct or
   *         inherited ACL.
   */
  public AclFileAttributeView getCombinedAclView() throws IOException {
    ImmutableList.Builder<AclEntry> builder = ImmutableList.builder();
    builder.addAll(directAclView.getAcl());
    builder.addAll(inheritedAclView.getAcl());
    return new SimpleAclFileAttributeView(builder.build());
  }
}
