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
import com.google.common.collect.ImmutableMap;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.Map;

class MultiRootMockFileDelegate extends MockFileDelegate {

  final MockFile[] roots;

  private final Map<MockFile, MockFileDelegate> delegates;

  MultiRootMockFileDelegate(MockFile... roots) {
    Preconditions.checkArgument(roots.length > 0,
        "At least one root must be specified.");
    this.roots = roots;
    ImmutableMap.Builder<MockFile, MockFileDelegate> builder = ImmutableMap.builder();
    for (MockFile root : roots) {
      builder.put(root, new MockFileDelegate(root));
    }
    this.delegates = builder.build();
  }

  /**
   * Returns the {@link MockFile} identified by the supplied {@link Path}.
   * @throws FileNotFoundException if the file is not found.
   */
  @Override
  MockFile getFile(Path doc) throws FileNotFoundException {
    for (MockFileDelegate delegate : delegates.values()) {
      try {
        return delegate.getFile(doc);
      } catch (FileNotFoundException e) {
        // Try the next delegate.
      }
    }
    throw new FileNotFoundException("not found: " + doc);
  }
}
