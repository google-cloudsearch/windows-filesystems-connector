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

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Netapi32;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import java.util.Arrays;
import java.util.List;

class WinApi {
  private WinApi() {
    // Prevent instantiation.
  }

  /**
  * Helper class for long paths
  * https://msdn.microsoft.com/library/windows/desktop/aa365247.aspx
  */
  public static class PathHelper {
    public static String longPath(String path) {
      if (path.length() < WinNT.MAX_PATH) {
        return path;
      }
      if (Shlwapi.INSTANCE.PathIsUNC(path)) {
        return path.replaceAll("^[^\\w]+",
            "\\\\\\\\?\\\\UNC\\\\").replaceAll("/", "\\\\");
      } else {
        return path.replaceAll("^[^\\w]*",
            "\\\\\\\\?\\\\").replaceAll("/", "\\\\");
      }
    }
  }

  public interface Kernel32Ex extends Kernel32 {
    Kernel32Ex INSTANCE = (Kernel32Ex) Native.loadLibrary("Kernel32",
        Kernel32Ex.class, W32APIOptions.UNICODE_OPTIONS);

    public static final int WAIT_IO_COMPLETION = 0x000000C0;

    int WaitForSingleObjectEx(HANDLE hHandle, int dwMilliseconds,
        boolean bAlertable);
  }

  public interface Shlwapi extends StdCallLibrary {
    Shlwapi INSTANCE = (Shlwapi) Native.loadLibrary("Shlwapi",
        Shlwapi.class, W32APIOptions.UNICODE_OPTIONS);

    boolean PathIsNetworkPath(String pszPath);
    boolean PathIsUNC(String pszPath);
  }

  public interface Netapi32Ex extends Netapi32 {
    Netapi32Ex INSTANCE = (Netapi32Ex) Native.loadLibrary(
        "Netapi32", Netapi32Ex.class, W32APIOptions.UNICODE_OPTIONS);

    public int NetShareGetInfo(String servername, String netname, int level,
        PointerByReference bufptr);

    /**
     * Documentation on SHARE_INFO_502 can be found at:
     * https://msdn.microsoft.com/en-us/library/windows/desktop/bb525410(v=vs.85).aspx
     */
    public static class SHARE_INFO_502 extends Structure {
      public String shi502_netname;
      public int shi502_type;
      public String shi502_remark;
      public int shi502_permissions;
      public int shi502_max_uses;
      public int shi502_current_uses;
      public String shi502_path;
      public String shi502_passwd;
      public int shi502_reserved;
      public Pointer shi502_security_descriptor;

      public SHARE_INFO_502() {
        super();
      }

      public SHARE_INFO_502(Pointer memory) {
        useMemory(memory);
        read();
      }

      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList(new String[] {
            "shi502_netname", "shi502_type", "shi502_remark",
            "shi502_permissions", "shi502_max_uses", "shi502_current_uses",
            "shi502_path", "shi502_passwd", "shi502_reserved",
            "shi502_security_descriptor"
            });
      }
    }

    public int NetDfsGetInfo(String DfsEntryPath, String ServerName,
        String ShareName, int Level, PointerByReference Buffer);

    public int NetDfsEnum(String DfsName, int Level, int PrefMaxLen,
        PointerByReference Buffer, IntByReference EntriesRead,
        IntByReference ResumeHandle);

    public static final int DFS_ROOT_FLAVOR_MASK = 0x00000300;
    public static final int DFS_STORAGE_STATE_ONLINE = 2;

    public static class DFS_INFO_1 extends Structure {
      public WString EntryPath;

      public DFS_INFO_1() {
      }

      public DFS_INFO_1(Pointer m) {
        useMemory(m);
        read();
      }

      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList("EntryPath");
      }
    }

    public static class DFS_INFO_3 extends Structure {
      public WString EntryPath;
      public WString Comment;
      public DWORD State;
      public DWORD NumberOfStorages;
      public Pointer Storage;
      protected DFS_STORAGE_INFO[] StorageInfos;

      public DFS_INFO_3() {
      }

      public DFS_INFO_3(Pointer m) {
        useMemory(m);
        read();
      }

      @Override
      public void read() {
        super.read();

        final int sizeOfInfo = new DFS_STORAGE_INFO().size();
        StorageInfos = new DFS_STORAGE_INFO[NumberOfStorages.intValue()];
        for (int i = 0; i < StorageInfos.length; i++) {
          StorageInfos[i] =
              new DFS_STORAGE_INFO(Storage.share(i * sizeOfInfo));
        }
      }

      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList("EntryPath", "Comment", "State",
            "NumberOfStorages", "Storage");
      }
    }

    public static class DFS_INFO_150 extends Structure {
      public ULONG SdLengthReserved;
      public Pointer pSecurityDescriptor;

      public DFS_INFO_150() {
      }

      public DFS_INFO_150(Pointer m) {
        useMemory(m);
        read();
      }

      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList("SdLengthReserved", "pSecurityDescriptor");
      }
    }

    public static class DFS_STORAGE_INFO extends Structure {
      public ULONG State;
      public WString ServerName;
      public WString ShareName;

      public DFS_STORAGE_INFO() {
      }

      public DFS_STORAGE_INFO(Pointer m) {
        useMemory(m);
        read();
      }

      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList("State", "ServerName", "ShareName");
      }
    }
  }
}
