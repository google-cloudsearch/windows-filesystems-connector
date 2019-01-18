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

import com.google.common.collect.ImmutableList;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;

/**
 * An {@link AclFileAttributeView} implementation that only supports getting
 * the ACL.
 */
class SimpleAclFileAttributeView implements AclFileAttributeView {
  private final List<AclEntry> acl;

  SimpleAclFileAttributeView(List<AclEntry> acl) {
    this.acl = ImmutableList.copyOf(acl);
  }

  @Override
  public List<AclEntry> getAcl() {
      return acl;
  }

  @Override
  public void setAcl(List<AclEntry> acl) throws UnsupportedOperationException {
    throw new UnsupportedOperationException("setAcl is not supported.");
  }

  @Override
  public UserPrincipal getOwner() throws UnsupportedOperationException {
    throw new UnsupportedOperationException("getOwner is not supported.");
  }

  @Override
  public void setOwner(UserPrincipal owner)
      throws UnsupportedOperationException {
    throw new UnsupportedOperationException("setOwner is not supported.");
  }

  @Override
  public String name() {
    return "acl";
  }

  @Override
  public boolean equals(Object object) {
    if (object == null) {
      return false;
    }
    if (!(object instanceof SimpleAclFileAttributeView)) {
      return false;
    }
    return acl.equals(((SimpleAclFileAttributeView) object).acl);
  }
}
