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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import com.google.enterprise.cloudsearch.fs.WinApi.Netapi32Ex;
import com.google.enterprise.cloudsearch.fs.WinApi.PathHelper;
import com.google.enterprise.cloudsearch.fs.WinApi.Shlwapi;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Advapi32Util.Account;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.SID_NAME_USE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generate various {@link AclFileAttributeView}s for Windows files.
 */
class WindowsAclFileAttributeViews {

  private static final Logger log =
      Logger.getLogger(WindowsAclFileAttributeViews.class.getName());

  /** This pattern parses a UNC path to get the host and share details. */
  private static final Pattern UNC_PATTERN =
      Pattern.compile("^\\\\\\\\([^\\\\]+)\\\\([^\\\\]+).*");

  /** The set of SID_NAME_USE which are groups and not users. */
  private static final Set<Integer> GROUP_SID_TYPES =
      Collections.unmodifiableSet(Sets.newHashSet(
        SID_NAME_USE.SidTypeAlias, SID_NAME_USE.SidTypeGroup,
            SID_NAME_USE.SidTypeWellKnownGroup));

  /** The set of SID_NAME_USE which are users and not groups. */
  private static final Set<Integer> USER_SID_TYPES =
      Collections.unmodifiableSet(Sets.newHashSet(SID_NAME_USE.SidTypeUser));

  /** Map of NT GENERIC permissions to NT FILE permissions. */
  private static final Map<Integer, Integer> GENERIC_PERMS_MAP =
      Collections.unmodifiableMap(new HashMap<Integer, Integer>() {
          {
            put(WinNT.GENERIC_READ, WinNT.FILE_GENERIC_READ);
            put(WinNT.GENERIC_WRITE, WinNT.FILE_GENERIC_WRITE);
            put(WinNT.GENERIC_EXECUTE, WinNT.FILE_GENERIC_EXECUTE);
            put(WinNT.GENERIC_ALL, WinNT.FILE_ALL_ACCESS);
          }
      });

  /** The map of ACL permissions from NT to AclEntryPermission. */
  private static final Map<Integer, AclEntryPermission> ACL_PERMS_MAP =
      Collections.unmodifiableMap(new HashMap<Integer, AclEntryPermission>() {
          {
            put(WinNT.FILE_READ_DATA, AclEntryPermission.READ_DATA);
            put(WinNT.FILE_READ_ATTRIBUTES,
                AclEntryPermission.READ_ATTRIBUTES);
            put(WinNT.FILE_READ_EA, AclEntryPermission.READ_NAMED_ATTRS);
            put(WinNT.READ_CONTROL, AclEntryPermission.READ_ACL);
            put(WinNT.FILE_WRITE_DATA, AclEntryPermission.WRITE_DATA);
            put(WinNT.FILE_APPEND_DATA, AclEntryPermission.APPEND_DATA);
            put(WinNT.FILE_WRITE_ATTRIBUTES,
                AclEntryPermission.WRITE_ATTRIBUTES);
            put(WinNT.FILE_WRITE_EA, AclEntryPermission.WRITE_NAMED_ATTRS);
            put(WinNT.WRITE_DAC, AclEntryPermission.WRITE_ACL);
            put(WinNT.WRITE_OWNER, AclEntryPermission.WRITE_OWNER);
            put(WinNT.DELETE, AclEntryPermission.DELETE);
            put(WinNT.FILE_DELETE_CHILD, AclEntryPermission.DELETE_CHILD);
            put(WinNT.SYNCHRONIZE, AclEntryPermission.SYNCHRONIZE);
            put(WinNT.FILE_EXECUTE, AclEntryPermission.EXECUTE);
          }
      });

  /** The map of ACL entry flags from NT to AclEntryFlag. */
  private static final Map<Byte, AclEntryFlag> ACL_FLAGS_MAP =
      Collections.unmodifiableMap(new HashMap<Byte, AclEntryFlag>() {
          {
            put(WinNT.OBJECT_INHERIT_ACE, AclEntryFlag.FILE_INHERIT);
            put(WinNT.CONTAINER_INHERIT_ACE, AclEntryFlag.DIRECTORY_INHERIT);
            put(WinNT.INHERIT_ONLY_ACE, AclEntryFlag.INHERIT_ONLY);
            put(WinNT.NO_PROPAGATE_INHERIT_ACE,
                AclEntryFlag.NO_PROPAGATE_INHERIT);
          }
      });

  /** The map of ACL entry type from NT to AclEntryType. */
  private static final Map<Byte, AclEntryType> ACL_TYPE_MAP =
      Collections.unmodifiableMap(new HashMap<Byte, AclEntryType>() {
          {
            put(WinNT.ACCESS_ALLOWED_ACE_TYPE, AclEntryType.ALLOW);
            put(WinNT.ACCESS_DENIED_ACE_TYPE, AclEntryType.DENY);
          }
      });

  private final Advapi32 advapi32;
  private final Kernel32 kernel32;
  private final Mpr mpr;
  private final Netapi32Ex netapi32;
  private final Shlwapi shlwapi;

  /** Cache of AccountsBySid should max out at about 10-12 MB. */
  private Cache<SidKey, Account> accountCache = CacheBuilder
      .newBuilder().initialCapacity(10000).maximumSize(100000)
      .expireAfterWrite(24, TimeUnit.HOURS).build();

  /** Constructor used for production. */
  public WindowsAclFileAttributeViews() {
    this(Advapi32.INSTANCE, Kernel32.INSTANCE, Mpr.INSTANCE,
         Netapi32Ex.INSTANCE, Shlwapi.INSTANCE);
  }

  /** Constructor used by the tests. */
  @VisibleForTesting
  WindowsAclFileAttributeViews(Advapi32 advapi32, Kernel32 kernel32,
      Mpr mpr, Netapi32Ex netapi32, Shlwapi shlwapi) {
    this.advapi32 = advapi32;
    this.kernel32 = kernel32;
    this.mpr = mpr;
    this.netapi32 = netapi32;
    this.shlwapi = shlwapi;
  }

  /**
   * Returns a container for the direct and inherited ACLs for
   * the supplied file.
   *
   * @param path The file/folder to get the {@link AclFileAttributeViews} for
   * @return AclFileAttributeViews of direct and inherited ACL entries
   */
  public AclFileAttributeViews getAclViews(Path path) throws IOException {
    String pathname = path.toRealPath(LinkOption.NOFOLLOW_LINKS).toString();
    WinNT.ACCESS_ACEStructure[] aces = getFileSecurity(pathname,
        WinNT.DACL_SECURITY_INFORMATION
        | WinNT.PROTECTED_DACL_SECURITY_INFORMATION
        | WinNT.UNPROTECTED_DACL_SECURITY_INFORMATION);
    ImmutableList.Builder<AclEntry> inherited = ImmutableList.builder();
    ImmutableList.Builder<AclEntry> direct = ImmutableList.builder();

    for (WinNT.ACCESS_ACEStructure ace : aces) {
      AclEntry aclEntry = newAclEntry(ace);
      if (aclEntry != null) {
        if ((ace.AceFlags & WinNT.INHERITED_ACE) == WinNT.INHERITED_ACE) {
          inherited.add(aclEntry);
        } else {
          direct.add(aclEntry);
        }
      }
    }

    List<AclEntry> inheritedAcl = inherited.build();
    log.log(Level.FINEST, "Inherited ACL for {0}: {1}",
        new Object[] { pathname, inheritedAcl });

    List<AclEntry> directAcl = direct.build();
    log.log(Level.FINEST, "Direct ACL for {0}: {1}",
        new Object[] { pathname, directAcl });

    return new AclFileAttributeViews(
        new SimpleAclFileAttributeView(directAcl),
        new SimpleAclFileAttributeView(inheritedAcl));
  }

  /**
   * Returns the access control list for the file share which contains
   * the supplied file.
   *
   * @param path The file/folder to get the {@link AclFileAttributeView} for
   * @return AclFileAttributeView of ACL entries imposed by the share
   */
  public AclFileAttributeView getShareAclView(Path path)
      throws IOException, UnsupportedOperationException {
    if (shlwapi.PathIsUNC(path.toString())) {
      log.log(Level.FINEST, "Using a UNC path.");
      return getUncShareAclView(path.toString());
    } else if (shlwapi.PathIsNetworkPath(path.toString())) {
      log.log(Level.FINEST, "Using a mapped drive.");
      // Call WNetGetUniversalNameW with the size needed for
      // UNIVERSAL_NAME_INFO. If WNetGetUniversalNameW returns ERROR_MORE_DATA
      // that indicates that a larger buffer is needed. If this happens, make
      // a second call to WNetGetUniversalNameW with a buffer big enough.
      Memory buf = new Memory(1024);
      IntByReference bufSize = new IntByReference((int) buf.size());
      int result = mpr.WNetGetUniversalNameW(path.getRoot().toString(),
          Mpr.UNIVERSAL_NAME_INFO_LEVEL, buf, bufSize);
      if (result == WinNT.ERROR_MORE_DATA) {
        buf = new Memory(bufSize.getValue());
        result = mpr.WNetGetUniversalNameW(path.getRoot().toString(),
            Mpr.UNIVERSAL_NAME_INFO_LEVEL, buf, bufSize);
      }
      if (result != WinNT.NO_ERROR) {
        throw new IOException("Unable to get UNC path for the mapped path "
            + path + ". Result: " + result);
      }

      Mpr.UNIVERSAL_NAME_INFO info = new Mpr.UNIVERSAL_NAME_INFO(buf);
      return getUncShareAclView(info.lpUniversalName);
    } else {
      log.log(Level.FINEST, "Using a local drive.");
      return new SimpleAclFileAttributeView(Collections.<AclEntry>emptyList());
    }
    // TODO(b/119498228): For a local drive, mapped and UNC the share ACL must also
    // include the ACLs from the config point to the root.
  }

  private AclFileAttributeView getUncShareAclView(String uncPath)
      throws IOException {
    Matcher match = UNC_PATTERN.matcher(uncPath);
    if (!match.find()) {
      throw new IOException("The UNC path " + uncPath + " is not valid. "
          + "A UNC path of the form \\\\<host>\\<share> is required.");
    }
    String host = match.group(1);
    String share = match.group(2);
    log.log(Level.FINEST, "UNC: host: {0}, share: {1}.",
        new Object[] { host, share });
    return getShareAclView(host, share);
  }

  private AclFileAttributeView getShareAclView(String host, String share)
      throws IOException {
    PointerByReference buf = new PointerByReference();

    // Call NetShareGetInfo with a 502 to get the security descriptor of the
    // share. The security descriptor contains the ACL details for the share
    // that the adaptor needs.
    int result = netapi32.NetShareGetInfo(host, share, 502, buf);
    if (result != WinError.ERROR_SUCCESS) {
      if (result == WinError.ERROR_ACCESS_DENIED) {
        throw new IOException(
            "The user does not have access to the share Acl information.");
      } else if (result == WinError.ERROR_INVALID_LEVEL) {
        throw new IOException(
            "The value specified for the level parameter is not valid.");
      } else if (result == WinError.ERROR_INVALID_PARAMETER) {
        throw new IOException("A specified parameter is not valid.");
      } else if (result == WinError.ERROR_NOT_ENOUGH_MEMORY) {
        throw new IOException("Insufficient memory is available.");
      } else if (result == LMErr.NERR_NetNameNotFound) {
        throw new IOException("The share name does not exist.");
      } else {
        throw new IOException("Unable to the read share Acl. Error: "
            + result);
      }
    }

    Netapi32Ex.SHARE_INFO_502 info =
        new Netapi32Ex.SHARE_INFO_502(buf.getValue());
    WinNT.SECURITY_DESCRIPTOR_RELATIVE sdr =
        new WinNT.SECURITY_DESCRIPTOR_RELATIVE(info.shi502_security_descriptor);
    netapi32.NetApiBufferFree(buf.getValue());
    WinNT.ACL dacl = sdr.getDiscretionaryACL();

    ImmutableList.Builder<AclEntry> builder = ImmutableList.builder();
    for (WinNT.ACCESS_ACEStructure ace : dacl.getACEStructures()) {
      AclEntry entry = newAclEntry(ace);
      if (entry != null) {
        builder.add(entry);
      }
    }

    List<AclEntry> acl = builder.build();
    if (log.isLoggable(Level.FINEST)) {
      log.log(Level.FINEST, "Share ACL for \\\\{0}\\{1}: {2}",
          new Object[] { host, share, acl.toString() });
    }
    return new SimpleAclFileAttributeView(acl);
  }

  /**
   * Creates an {@link AclEntry} from a {@code WinNT.ACCESS_ACEStructure}.
   *
   * @param ace Windows ACE returned by JNA
   * @return AclEntry representing the ace, or {@code null} if a valid
   *         AclEntry could not be created from the ace.
   */
  public AclEntry newAclEntry(WinNT.ACCESS_ACEStructure ace) {
    // Map the type.
    AclEntryType aclType = ACL_TYPE_MAP.get(ace.AceType);
    if (aclType == null) {
      log.log(Level.FINEST, "Skipping ACE with unsupported access type: {0}.",
          ace.AceType);
      return null;
    }

    // Map the user.
    Account account;
    try {
      account = getAccountBySid(ace.getSID());
    } catch (Win32Exception e) {
      // Only the least significant 16-bits signifies the HR code.
      int errorCode = e.getHR().intValue() & 0xFFFF;
      log.log(Level.FINEST,
          "Skipping ACE with unresolvable SID: {0}  Error: {1} {2}",
          new Object[] { ace.getSidString(), errorCode, e.getMessage() });
      return null;
    }
    String accountName = (account.domain == null)
        ? account.name : account.domain + "\\" + account.name;
    UserPrincipal aclPrincipal;
    String accountType = getSidTypeString(account.accountType);
    if (USER_SID_TYPES.contains(account.accountType)) {
      aclPrincipal = new User(accountName, accountType);
    } else if (GROUP_SID_TYPES.contains(account.accountType)) {
      aclPrincipal = new Group(accountName, accountType);
    } else {
      log.log(Level.FINEST,
          "Skipping ACE with unsupported account type {0} ({1}).",
          new Object[] { accountName, accountType });
      return null;
    }

    // Expand NT GENERIC_* permissions to their FILE_GENERIC_* equivalents.
    int aceMask = ace.Mask;
    for (Map.Entry<Integer, Integer> e : GENERIC_PERMS_MAP.entrySet()) {
      if ((ace.Mask & e.getKey()) == e.getKey()) {
        aceMask |= e.getValue();
      }
    }

    // Map the permissions.
    Set<AclEntryPermission> aclPerms = EnumSet.noneOf(AclEntryPermission.class);
    for (Map.Entry<Integer, AclEntryPermission> e : ACL_PERMS_MAP.entrySet()) {
      if ((aceMask & e.getKey()) == e.getKey()) {
        aclPerms.add(e.getValue());
      }
    }

    // Map the flags.
    Set<AclEntryFlag> aclFlags = EnumSet.noneOf(AclEntryFlag.class);
    for (Map.Entry<Byte, AclEntryFlag> e : ACL_FLAGS_MAP.entrySet()) {
      if ((ace.AceFlags & e.getKey()) == e.getKey()) {
        aclFlags.add(e.getValue());
      }
    }

    return AclEntry.newBuilder()
        .setType(aclType)
        .setPrincipal(aclPrincipal)
        .setPermissions(aclPerms)
        .setFlags(aclFlags)
        .build();
  }

  private static class SidKey {
    private byte[] sidBytes;

    SidKey(byte[] sidBytes) {
      this.sidBytes = sidBytes;
    }

    @Override
    public boolean equals(Object other) {
      if (other instanceof SidKey) {
        return Arrays.equals(sidBytes, ((SidKey) other).sidBytes);
      } else {
        return false;
      }
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(sidBytes);
    }
  }

  @VisibleForTesting
  Account getAccountBySid(final WinNT.PSID sid) throws Win32Exception {
    // PSID made a poor cache key, but the raw bytes work much better.
    Account account = accountCache.getIfPresent(new SidKey(sid.getBytes()));
    if (account == null) {
      account = Advapi32Util.getAccountBySid(sid);
      SidKey key = new SidKey(Arrays.copyOf(account.sid, account.sid.length));
      account.sid = null;       // Reduce cache memory usage by dropping the
      account.sidString = null; // unused sid bytes and sidString.
      accountCache.put(key, account);
    }
    return account;
  }

  // One-to-one corresponance to WinNT.SID_NAME_USE "enumeration".
  private static final List<String> SID_TYPE_NAMES = ImmutableList.of(
      "Unknown", "User", "Group", "Domain", "Alias", "Well-known Group",
      "Deleted", "Invalid", "Computer");

  private static String getSidTypeString(int sidType) {
    if (sidType < 0 || sidType > SID_TYPE_NAMES.size()) {
      return SID_TYPE_NAMES.get(0);
    } else {
      return SID_TYPE_NAMES.get(sidType);
    }
  }

  private static class User implements UserPrincipal {
    private final String accountName;
    private final String accountType;

    User(String accountName, String accountType) {
      this.accountName = accountName;
      this.accountType = accountType;
    }

    @Override
    public String getName() {
      return accountName;
    }

    @Override
    public String toString() {
      return accountName + " (" + accountType + ")";
    }
  }

  private static class Group extends User implements GroupPrincipal {
    Group(String accountName, String accountType) {
      super(accountName, accountType);
    }
  }

  @VisibleForTesting
  public static interface Mpr extends StdCallLibrary {
    Mpr INSTANCE = (Mpr) Native.loadLibrary("Mpr", Mpr.class, W32APIOptions.UNICODE_OPTIONS);

    public final int UNIVERSAL_NAME_INFO_LEVEL = 1;

    int WNetGetUniversalNameW(String lpLocalPath, int dwInfoLevel,
        Pointer lpBuffer, IntByReference lpBufferSize);

    public static class UNIVERSAL_NAME_INFO extends Structure {
      public String lpUniversalName;

      public UNIVERSAL_NAME_INFO() {
        super();
      }

      public UNIVERSAL_NAME_INFO(Pointer memory) {
        useMemory(memory);
        read();
      }

      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList(new String[] { "lpUniversalName" });
      }
    }
  }

  /** Uses JNA to call native Windows {@code GetFileSecurity} function. */
  private WinNT.ACCESS_ACEStructure[] getFileSecurity(String pathname,
      int daclType) throws IOException {
    String uncPath = PathHelper.longPath(pathname);
    IntByReference lengthNeeded = new IntByReference();

    if (advapi32.GetFileSecurity(new WString(uncPath), daclType, null, 0, lengthNeeded)) {
      throw new AssertionError("GetFileSecurity was expected to fail with "
          + "ERROR_INSUFFICIENT_BUFFER");
    }

    int rc = kernel32.GetLastError();
    if (rc != W32Errors.ERROR_INSUFFICIENT_BUFFER) {
      throw new IOException("Failed GetFileSecurity for "
          + uncPath, new Win32Exception(rc));
    }

    Memory memory = new Memory(lengthNeeded.getValue());
    if (!advapi32.GetFileSecurity(new WString(uncPath), daclType, memory, (int) memory.size(),
                                  lengthNeeded)) {
      throw new IOException("Failed GetFileSecurity " + uncPath,
          new Win32Exception(kernel32.GetLastError()));
    }

    WinNT.SECURITY_DESCRIPTOR_RELATIVE securityDescriptor =
        new WinNT.SECURITY_DESCRIPTOR_RELATIVE(memory);
    return securityDescriptor.getDiscretionaryACL().getACEStructures();
  }
}
