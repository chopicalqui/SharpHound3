using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Security.AccessControl;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class NetShareEnumTasks
    {
        /// <summary>No error</summary>
        protected const int SUCCESS = 0;
        /// <summary>Access is denied.</summary>
        protected const int ERROR_ACCESS_DENIED = 5;

        #region Enumerate Shares
        internal static async Task<LdapWrapper> ProcessNetShares(LdapWrapper wrapper)
        {
            if (wrapper is Computer computer && computer.IsWindows && !computer.PingFailed)
            {
                //If ExcludeDC is set remove DCs from collection
                if (Options.Instance.ExcludeDomainControllers && computer.IsDomainController)
                {
                    return wrapper;
                }

                //If stealth is set, only do session enum if the computer is marked as a stealth target
                if (Options.Instance.Stealth && !computer.IsStealthTarget)
                    return wrapper;

                var shares = await GetNetShares(computer);
                var temp = computer.Shares.ToList();
                temp.AddRange(shares);
                computer.Shares = temp.Distinct().ToArray();
                await Helpers.DoDelay();
            }

            return wrapper;
        }

        /// <summary>
        /// Wraps the NetShareEnum API call with a timeout and parses the results
        /// </summary>
        /// <param name="computer">The computer object whose shares shall be enumerated</param>
        /// <returns></returns>
        private static async Task<List<Share>> GetNetShares(Computer computer)
        {
            var shareList = new List<Share>();
            int level = 502;
            Type type = typeof(ShareInfo502);
            int resumeHandle = 0;
            IntPtr bufPtr = IntPtr.Zero;
            int entriesRead = 0;
            string computerName = computer.APIName.ToUpper();

            if (!computerName.StartsWith(@"\\"))
                computerName = @"\\" + computerName;

            try
            {
                int totalEntries = 0;

                // Try enumerating network shares with higher privileges
                var task = Task.Run(() => NetShareEnum(computerName,
                    level,
                    out bufPtr,
                    -1,
                    out entriesRead,
                    out totalEntries,
                    ref resumeHandle));

                //10 second timeout
                if (await Task.WhenAny(task, Task.Delay(10000)) != task)
                {
                    if (Options.Instance.DumpComputerStatus)
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = "Timeout",
                            Task = "NetShareEnum"
                        });
                    return shareList;
                }

                if (task.Result == ERROR_ACCESS_DENIED)
                {
                    level = 1;
                    type = typeof(ShareInfo1);
                    // Try enumerating network shares with low privileges
                    task = Task.Run(() => NetShareEnum(computerName,
                        level,
                        out bufPtr,
                        -1,
                        out entriesRead,
                        out totalEntries,
                        ref resumeHandle));
                    
                    //10 second timeout
                    if (await Task.WhenAny(task, Task.Delay(10000)) != task)
                    {
                        if (Options.Instance.DumpComputerStatus)
                            OutputTasks.AddComputerStatus(new ComputerStatus
                            {
                                ComputerName = computer.DisplayName,
                                Status = "Timeout",
                                Task = "NetShareEnum"
                            });
                        return shareList;
                    }
                }

                if (task.Result == SUCCESS)
                {
                    int offset = Marshal.SizeOf(type);

                    for (int i = 0, lpItem = bufPtr.ToInt32(); i < entriesRead; i++, lpItem += offset)
                    {
                        IntPtr pItem = new IntPtr(lpItem);
                        Share share;

                        if (level == 1)
                        {
                            ShareInfo1 shareInfo = (ShareInfo1)Marshal.PtrToStructure(pItem, type);
                            share = new Share(computer, shareInfo.NetName);
                            share.Properties.Add("types", shareInfo.Type.ToString());
                            share.Properties.Add("remark", shareInfo.Remark);
                            shareList.Add(share);
                        }
                        else
                        {
                            ShareInfo502 shareInfo = (ShareInfo502)Marshal.PtrToStructure(pItem, type);
                            var types = (from item in shareInfo.Type.ToString().Split(',') select item.Trim());
                            share = new Share(computer, shareInfo.NetName);
                            share.Properties.Add("path", shareInfo.Path);
                            share.Properties.Add("types", types);
                            share.Properties.Add("remark", shareInfo.Remark);
                            shareList.Add(share);

                            // Obtain share ACEs
                            await GetShareAclInformation(share, shareInfo);
                        }
                        await AnalyzeShare(share);
                    }
                }
                else
                {
                    if (Options.Instance.DumpComputerStatus)
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = ((NetApiStatus)task.Result).ToString(),
                            Task = "NetShareEnum"
                        });
                    return shareList;
                }
            }
            finally
            {
                if (bufPtr != IntPtr.Zero)
                    NetApiBufferFree(bufPtr);
            }
            return shareList;
        }

        #region NetSessionEnum Imports
        /// <summary>
        /// Enum representing the possible share types.
        /// </summary>
        [Flags]
        internal enum ShareType
        {
            Disk = 0,
            Printer = 1,
            Device = 2,
            IPC = 3,
            Special = -2147483648
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        protected struct ShareInfo1
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string NetName;
            public ShareType Type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Remark;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        protected struct ShareInfo502
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string NetName;
            public ShareType Type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Remark;
            public Int32 Permissions;
            public Int32 MaxUses;
            public Int32 CurrentUses;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Path;
            public IntPtr Passwd;
            public Int32 Reserved;
            public IntPtr SecurityDescriptor;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        protected static extern int NetShareEnum(string lpServerName,
            int dwLevel,
            out IntPtr lpBuffer,
            int dwPrefMaxLen,
            out int entriesRead,
            out int totalEntries,
            ref int hResume);

        [DllImport("netapi32.dll")]
        protected static extern int NetApiBufferFree(IntPtr lpBuffer);
        #endregion
        #endregion

        #region Enumerate Share Permissions
        /// <summary>
        /// Wraps the GetSecurityDescriptorDacl API call for enumerating share access permissions with a timeout and parses the results
        /// </summary>
        /// <param name="share">The share object whose ACEs shall be enumerated</param>
        /// <returns></returns>
        private static async Task<List<ACL>> GetShareAclInformation(Share share, ShareInfo502 shareInfo)
        {
            // Obtain the share's file system permissions
            List<ACL> acls = await GetAccessControlInfo(share);
            IntPtr bufPtr = IntPtr.Zero;

            try
            {
                bool bDaclPresent = false;
                bool bDaclDefaulted = false;
                int error = 0;
                IntPtr pAcl = IntPtr.Zero;

                // If there are no DACLs
                if (shareInfo.SecurityDescriptor != IntPtr.Zero)
                {
                    var task = Task.Run(() => GetSecurityDescriptorDacl(shareInfo.SecurityDescriptor, out bDaclPresent, ref pAcl, out bDaclDefaulted));

                    //10 second timeout
                    if (await Task.WhenAny(task, Task.Delay(10000)) != task)
                    {
                        if (Options.Instance.DumpComputerStatus)
                            OutputTasks.AddComputerStatus(new ComputerStatus
                            {
                                ComputerName = share.Computer.DisplayName,
                                Status = "Timeout",
                                Task = "NetShareGetInfo"
                            });
                        return acls;
                    }

                    if (bDaclPresent)
                    {
                        AclSizeInformation aclSize = new AclSizeInformation();
                        GetAclInformation(pAcl, ref aclSize, (uint)Marshal.SizeOf(typeof(AclSizeInformation)), AclInformationClass.AclSizeInformation);
                        for (int i = 0; i < aclSize.AceCount; i++)
                        {
                            IntPtr pAce;
                            error = GetAce(pAcl, i, out pAce);
                            AccessAllowedAce ace = (AccessAllowedAce)Marshal.PtrToStructure(pAce, typeof(AccessAllowedAce));

                            IntPtr iter = (IntPtr)((long)pAce + (long)Marshal.OffsetOf(typeof(AccessAllowedAce), "SidStart"));
                            byte[] bSid = null;
                            int size = (int)GetLengthSid(iter);
                            bSid = new byte[size];
                            Marshal.Copy(iter, bSid, 0, size);
                            IntPtr ptrSid;
                            ConvertSidToStringSid(bSid, out ptrSid);
                            string strSid = Marshal.PtrToStringAuto(ptrSid);

                            // Only add ACLs with relevant SIDs
                            if (IsRelevantSid(strSid))
                            {
                                //Resolve the principal's SID to its type
                                var (finalSid, type) = await ResolutionHelpers.ResolveSidAndGetType(strSid, share.Computer.Domain);

                                if (finalSid == null)
                                    continue;

                                acls.Add(new ACL
                                {
                                    PrincipalSID = finalSid,
                                    RightName = "Share" + ace.Mask.ToString(),
                                    AceType = "",
                                    PrincipalType = type,
                                    IsInherited = false
                                });

                                if (ace.Mask.HasFlag(ShareAceMask.Change) && !ace.Mask.HasFlag(ShareAceMask.FullControl))
                                {
                                    acls.Add(new ACL
                                    {
                                        PrincipalSID = finalSid,
                                        RightName = "Share" + ace.Mask.ToString(),
                                        AceType = "",
                                        PrincipalType = type,
                                        IsInherited = false
                                    });
                                }
                            }
                        }
                        share.Aces = acls.ToArray();
                    }
                }
            }
            finally
            {
                NetApiBufferFree(bufPtr);
            }
            return acls;
        }

        #region  GetSecurityDescriptorDacl Imports

        /// <summary>
        /// Enum representing the possible access control entry masks.
        /// </summary>
        [Flags]
        internal enum ShareAceMask
        {
            FullControl = 0x1F01FF,
            Change = 0x1301BF,
            Read = 0x1200A9
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct AclSizeInformation
        {
            public uint AceCount;
            public uint AclBytesInUse;
            public uint AclBytesFree;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct AceHeader
        {
            public byte AceType;
            public byte AceFlags;
            public short AceSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct AccessAllowedAce
        {
            public AceHeader Header;
            public ShareAceMask Mask;
            public int SidStart;
        }

        enum SidNameUse
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        enum AclInformationClass
        {
            AclRevisionInformation = 1,
            AclSizeInformation
        }
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int NetShareGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            [MarshalAs(UnmanagedType.LPWStr)] string netName,
            Int32 level,
            out IntPtr bufPtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent,
            ref IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetAclInformation(IntPtr pAcl,
            ref AclSizeInformation pAclInformation,
            uint nAclInformationLength,
            AclInformationClass dwAclInformationClass);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetAce(
            IntPtr aclPtr,
            int aceIndex,
            out IntPtr acePtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetLengthSid(
            IntPtr pSID);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
            out IntPtr ptrSid);
        #endregion
        #endregion

        #region Enumerate File System Items via Shares
        private static async Task<List<ACL>> GetAccessControlInfo(Share share, string currentItem = null, bool addToShare = false)
        {
            if (string.IsNullOrEmpty(currentItem))
                currentItem = share.ObjectIdentifier;

            var acls = new List<ACL>();
            try
            {
                var directory = new FileSystemItem(share,
                    FileType.Directory,
                    currentItem);
                if (addToShare)
                    share.FileSystemItems.Add(directory);
                FileSystemSecurity fileSystemSecurity = directory.GetAccessControl();
                if (fileSystemSecurity != null)
                {
                    foreach (FileSystemAccessRule rule in fileSystemSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        // Only add ACLs with relevant SIDs
                        if (IsRelevantSid(rule.IdentityReference.Value))
                        {
                            //Resolve the principal's SID to its type
                            var (finalSid, type) = await ResolutionHelpers.ResolveSidAndGetType(rule.IdentityReference.Value,
                                share.Computer.Domain);
                            foreach (var permission in (from item in rule.FileSystemRights.ToString().Split(',') select item.Trim()))
                            {
                                acls.Add(new ACL
                                {
                                    PrincipalSID = finalSid,
                                    RightName = permission,
                                    AceType = rule.AccessControlType.ToString(),
                                    PrincipalType = type,
                                    IsInherited = rule.IsInherited
                                });
                            }
                        }
                    }
                }
                directory.Aces = acls.ToArray();
            }
            catch (Exception)
            {
            }
            return acls;
        }

        private static async Task<List<FileSystemItem>> AnalyzeShare(Share share, string currentItem = null, int maxDepth = 1, int depth = 1)
        {
            if (string.IsNullOrEmpty(currentItem))
                currentItem = share.ObjectIdentifier;

            if (Directory.Exists(currentItem))
            {
                try
                {
                    // Analyze subdirectories
                    if (maxDepth == 0 || depth <= maxDepth)
                    {
                        foreach (var item in Directory.GetDirectories(currentItem))
                        {
                            await GetAccessControlInfo(share, item, true);
                            await AnalyzeShare(share, currentItem, maxDepth, depth + 1);
                        }
                    }
                }
                catch (Exception)
                {
                }
            }
            return share.FileSystemItems;
        }
        #endregion

        #region Helpers

        private static bool IsRelevantSid(string sid)
        {
            // ignore:
            // - NT AUTHORITY\SYSTEM (S-1-5-18)
            // - CREATOR OWNER (S-1-3-0)
            // - Principal Self (S-1-5-10)
            return sid != "S-1-5-18" && sid != "S-1-3-0" && sid != "S-1-5-10";
        }
        #endregion
    }
}