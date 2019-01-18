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

import com.google.common.base.Preconditions;
import com.google.enterprise.cloudsearch.fs.WinApi.Netapi32Ex;
import com.google.enterprise.cloudsearch.fs.WinApi.Shlwapi;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util.Account;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.SID_NAME_USE;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * Base class that provides mechanisms for faking JNA ACL access. Tests that wish to fake JNA calls
 * to access ACLs should extend this.
 */
public class TestWindowsAclViews {

  // Store the SIDs in a map to avoid serializing and deserializing them.
  static HashMap<Long, AccountSid> sidMap = new HashMap<Long, AccountSid>();

  @Rule public final TemporaryFolder temp = new TemporaryFolder();

  protected final Path newTempDir(String name) throws IOException {
    return temp.newFolder(name).toPath().toRealPath();
  }

  protected final Path newTempFile(String name) throws IOException {
    return temp.newFile(name).toPath().toRealPath();
  }

  protected final Path newTempFile(Path parent, String name) throws IOException {
    Preconditions.checkArgument(parent.startsWith(getTempRoot()));
    return Files.createFile(parent.resolve(name));
  }

  protected final Path getTempRoot() throws IOException {
    return temp.getRoot().getCanonicalFile().toPath();
  }

  /**
   * Serializes an WinNT ACEs into a byte buffer representing a DACL. This byte buffer is suitable
   * for reading back via <code>new WinNT.SECURITY_DESCRIPTOR_RELATIVE(Memory)</code>.
   */
  protected static final byte[] buildDaclMemory(WinNT.ACCESS_ACEStructure... aces)
      throws Exception {
    WinNT.ACL acl = new WinNT.ACL();
    WinNT.SECURITY_DESCRIPTOR_RELATIVE securityDescriptor =
        new WinNT.SECURITY_DESCRIPTOR_RELATIVE();
    int totalSize = securityDescriptor.size() + acl.size();
    for (WinNT.ACCESS_ACEStructure ace : aces) {
      totalSize += ace.AceSize;
    }

    // Serialize the structures into a buffer.
    final byte[] buffer = new byte[totalSize];
    int offset = 0;
    // The start of the ACL follows the securityDescriptor in memory.
    securityDescriptor.Dacl = securityDescriptor.size();
    securityDescriptor.write();
    securityDescriptor.getPointer().read(0, buffer, offset, securityDescriptor.size());
    offset += securityDescriptor.size();
    acl.AceCount = (short) aces.length;
    acl.write();
    acl.getPointer().read(0, buffer, offset, acl.size());
    offset += acl.size();
    for (WinNT.ACCESS_ACEStructure ace : aces) {
      ace.write();
      ace.getPointer().read(0, buffer, offset, ace.AceSize);
      offset += ace.AceSize;
    }
    return buffer;
  }

  /** A convenient Ace Builder. Only AccountSid SIDs are supported. */
  public static class AceBuilder {
    private byte type;
    private byte flags;
    private int perms;
    private AccountSid sid;

    public AceBuilder setType(byte type) {
      this.type = type;
      return this;
    }

    public AceBuilder setFlags(byte... flags) {
      for (byte flag : flags) {
        this.flags |= flag;
      }
      return this;
    }

    public AceBuilder setPerms(int... perms) {
      for (int perm : perms) {
        this.perms |= perm;
      }
      return this;
    }

    public AceBuilder setSid(AccountSid sid) {
      this.sid = sid;
      return this;
    }

    public WinNT.ACCESS_ACEStructure build() {
      // Because ACCESS_ACEStructure does not allow me to set the SID
      // directly, I must create a serialized ACE containing a Pointer
      // to my AccountSid, then create a new ACE from that memory.
      WinNT.ACCESS_ACEStructure ace = new Ace();
      ace.AceType = type;
      ace.AceFlags = flags;
      ace.Mask = perms;
      ace.AceSize = (short) (ace.size() + Pointer.SIZE);
      ace.write();
      byte[] buffer = new byte[ace.AceSize];
      ace.getPointer().read(0, buffer, 0, ace.size());
      Memory memory = new Memory(buffer.length);
      memory.write(0, buffer, 0, ace.size());
      sid.write();
      // See ACCESS_ACEStructure(Pointer p) constructor for mystery offsets.
      memory.setPointer(4 + 4, sid.getPointer());
      sidMap.put(Pointer.nativeValue(sid.getPointer()), sid);
      ace = new Ace(memory);
      assertEquals(ace.getSID().sid, sid.getPointer());
      return ace;
    }
  }

  /**
   * A subclass of WinNT.ACCESS_ACEStructure that avoids using Advapi32Util to get the string SID.
   */
  public static class Ace extends WinNT.ACCESS_ACEStructure {
    public Ace() {}

    public Ace(Pointer p) {
      super(p);
    }

    @Override
    public String getSidString() {
      return new AccountSid(getSID().sid).toString();
    }
  }

  /**
   * A SID structure that encapsulates the <code>Advapi32Util.Account</code> information, avoiding
   * network lookups to in <code>getAccountBySid</code>.
   */
  public static class AccountSid extends Structure {

    public static AccountSid user(String name, String domain) {
      return new AccountSid(SID_NAME_USE.SidTypeUser, name, domain);
    }

    public static AccountSid group(String name, String domain) {
      return new AccountSid(SID_NAME_USE.SidTypeGroup, name, domain);
    }

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList(new String[] {"type", "name", "domain"});
    }

    public int type;
    public String name;
    public String domain;

    public AccountSid() {}

    public AccountSid(Pointer p) {
      super(p);
      read();
    }

    public AccountSid(int type, String name, String domain) {
      this.type = type;
      this.name = name;
      this.domain = domain;
    }

    public Account getAccount() throws Win32Exception {
      if (name == null && domain == null) {
        throw new Win32Exception(WinError.ERROR_NONE_MAPPED);
      } else {
        Account account = new Account();
        account.accountType = type;
        account.name = name;
        account.domain = domain;
        return account;
      }
    }

    @Override
    public String toString() {
      if (name == null && domain == null) {
        return "null";
      } else {
        return (domain == null) ? name : domain + "\\" + name;
      }
    }
  }

  /**
   * An subclass of {@link WindowsAclFileAttributeViews} that avoids making actual Windows API calls
   * by using faked JNA implementations.
   */
  public static class TestAclFileAttributeViews extends WindowsAclFileAttributeViews {

    public TestAclFileAttributeViews() {
      super(null, null, null, null, null);
    }

    public TestAclFileAttributeViews(
        Advapi32 advapi32, Kernel32 kernel32, Mpr mpr, Netapi32Ex netapi32, Shlwapi shlwapi) {
      super(advapi32, kernel32, mpr, netapi32, shlwapi);
    }

    @Override
    Account getAccountBySid(WinNT.PSID sid) throws Win32Exception {
      return sidMap.get(Pointer.nativeValue(sid.sid)).getAccount();
    }
  }
}
