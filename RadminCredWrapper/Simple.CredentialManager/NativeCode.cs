using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Simple.CredentialManager
{
    // https://github.com/spolnik/Simple.CredentialsManager
    // Some code was modified

    /// <summary>
    ///     Wrapper for advapi32.dll library.
    ///     Advanced Services
    ///     Provide access to functionality additional to the kernel.
    ///     Included are things like the Windows registry, shutdown/restart the system (or abort),
    ///     start/stop/create a Windows service, manage user accounts.
    ///     These functions reside in advapi32.dll on 32-bit Windows.
    /// </summary>
    public class NativeCode
    {
        #region Advapi32.dll
        /// <summary>
        ///     The CredRead function reads a credential from the user's credential set.
        ///     The credential set used is the one associated with the logon session of the current token.
        ///     The token must not have the user's SID disabled.
        /// </summary>
        /// <remarks>
        ///     If the value of the Type member of the CREDENTIAL structure specified by the Credential parameter is
        ///     CRED_TYPE_DOMAIN_EXTENDED, a namespace must be specified in the target name. This function can return only one
        ///     credential of the specified type.
        /// </remarks>
        /// <param name="target">Pointer to a null-terminated string that contains the name of the credential to read.</param>
        /// <param name="type">Type of the credential to read. Type must be one of the CRED_TYPE_* defined types.</param>
        /// <param name="reservedFlag">Currently reserved and must be zero.</param>
        /// <param name="credentialPtr">
        ///     Pointer to a single allocated block buffer to return the credential.
        ///     Any pointers contained within the buffer are pointers to locations within this single allocated block.
        ///     The single returned buffer must be freed by calling CredFree.
        /// </param>
        /// <returns>The function returns TRUE on success and FALSE on failure.</returns>
        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

        /// <summary>
        ///     The CredWrite function creates a new credential or modifies an existing credential in the user's credential set.
        ///     The new credential is associated with the logon session of the current token.
        ///     The token must not have the user's security identifier (SID) disabled.
        /// </summary>
        /// <remarks>
        ///     This function creates a credential if a credential with the specified TargetName and Type does not exist. If a
        ///     credential with the specified TargetName and Type exists, the new specified credential replaces the existing one.
        ///     When this function writes a CRED_TYPE_CERTIFICATE credential, the Credential->CredentialBlob member specifies the
        ///     PIN protecting the private key of the certificate specified by the Credential->UserName member. The credential
        ///     manager does not maintain the PIN. Rather, the PIN is passed to the cryptographic service provider (CSP) indicated
        ///     on the certificate for later use by the CSP and the authentication packages. The CSP defines the lifetime of the
        ///     PIN. Most CSPs flush the PIN when the smart card removal from the smart card reader.
        ///     If the value of the Type member of the CREDENTIAL structure specified by the Credential parameter is
        ///     CRED_TYPE_DOMAIN_EXTENDED, a namespace must be specified in the target name. This function does not support writing
        ///     to target names that contain wildcards.
        /// </remarks>
        /// <param name="userCredential">A pointer to the CREDENTIAL structure to be written.</param>
        /// <param name="flags">Flags that control the function's operation. The following flag is defined.</param>
        /// <returns>If the function succeeds, the function returns TRUE, if the function fails, it returns FALSE. </returns>
        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] UInt32 flags);

        /// <summary>
        ///     The CredFree function frees a buffer returned by any of the credentials management functions.
        /// </summary>
        /// <param name="cred">Pointer to the buffer to be freed.</param>
        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        internal static extern void CredFree([In] IntPtr cred);

        /// <summary>
        ///     The CredDelete function deletes a credential from the user's credential set.
        ///     The credential set used is the one associated with the logon session of the current token.
        ///     The token must not have the user's SID disabled.
        /// </summary>
        /// <param name="target">Pointer to a null-terminated string that contains the name of the credential to delete.</param>
        /// <param name="type">
        ///     Type of the credential to delete. Must be one of the CRED_TYPE_* defined types.
        ///     For a list of the defined types, see the Type member of the CREDENTIAL structure.
        ///     If the value of this parameter is CRED_TYPE_DOMAIN_EXTENDED,
        ///     this function can delete a credential that specifies a user name when there are multiple credentials for the same
        ///     target. The value of the TargetName parameter must specify the user name as Target|UserName.
        /// </param>
        /// <param name="flags">Reserved and must be zero.</param>
        /// <returns>The function returns TRUE on success and FALSE on failure.</returns>
        [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
        internal static extern bool CredDelete(string target, CredentialType type, int flags);

        /// <summary>
        /// Enumerate credentials in the credential store
        /// signature: BOOL CredEnumerate (
        ///  _In_ LPCTSTR     Filter,
        ///  _In_ DWORD       Flags,
        ///  _Out_ DWORD       *Count,
        ///  _Out_ PCREDENTIAL **Credentials
        ///);
        /// <param name="filter">[in] 
        /// Pointer to a null-terminated string that contains the filter for the returned credentials.Only credentials with a TargetName matching the filter will be returned.The filter specifies a name prefix followed by an asterisk.For instance, the filter "FRED*" will return all credentials with a TargetName beginning with the string "FRED".
        /// If NULL is specified, all credentials will be returned.</param>
        /// <param name="flag">[in]        
        /// The value of this parameter can be zero or more of the following values combined with a bitwise-OR operation.
        ///  Value Meaning
        ///  CRED_ENUMERATE_ALL_CREDENTIALS 0x1
        ///  This function enumerates all of the credentials in the user's credential set. The target name of each credential is returned in the "namespace:attribute=target" format. If this flag is set and the Filter parameter is not NULL, the function fails and returns ERROR_INVALID_FLAGS.
        ///  Windows Server 2003 and Windows XP:  This flag is not supported.
        ///</param>
        /// <param name="count">[out] Count of the credentials returned in the Credentials array.</param>
        /// <param name="pCredentials"> [out]      
        ///  Pointer to an array of pointers to credentials.The returned credential is a single allocated block. Any pointers contained within the buffer are pointers to locations within this single allocated block.The single returned buffer must be freed by calling CredFree.
        ///  Return value
        /// </param>
        /// <returns>
        /// The function returns TRUE on success and FALSE on failure. The GetLastError function can be called to get a more specific status code.The following status codes can be returned.
        ///  Return code/value Description
        ///  ERROR_NOT_FOUND
        ///  1168 (0x490)
        ///  No credential exists matching the specified Filter.
        ///  ERROR_NO_SUCH_LOGON_SESSION
        ///  1312 (0x520)
        ///  The logon session does not exist or there is no credential set associated with this logon session. Network logon sessions do not have an associated credential set.
        ///  ERROR_INVALID_FLAGS
        ///  1004 (0x3EC)
        ///  A flag that is not valid was specified for the Flags parameter, or CRED_ENUMERATE_ALL_CREDENTIALS is specified for the Flags parameter and the Filter parameter is not NULL.
        /// </returns>
        /// </summary>
        [DllImport("Advapi32.dll", EntryPoint = "CredEnumerate", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);
        #endregion Advapi32.dll

        #region Credui.dll
        [DllImport("Credui.dll", EntryPoint = "CredUIPromptForWindowsCredentialsW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int CredUIPromptForWindowsCredentials(
            ref CredentialUIInfo creditUR,
            int authError,
            ref uint authPackage,
            IntPtr InAuthBuffer,
            uint InAuthBufferSize,
            out IntPtr refOutAuthBuffer,
            out uint refOutAuthBufferSize,
            ref bool fSave,
            PromptForWindowsCredentialsFlags flags);

        [DllImport("Credui.dll", CharSet = CharSet.Auto)]
        internal static extern bool CredUnPackAuthenticationBuffer(
            int dwFlags,
            IntPtr pAuthBuffer,
            uint cbAuthBuffer,
            StringBuilder pszUserName,
            ref int pcchMaxUserName,
            StringBuilder pszDomainName,
            ref int pcchMaxDomainame,
            StringBuilder pszPassword,
            ref int pcchMaxPassword);

        [DllImport("Credui.dll", EntryPoint = "CredUIParseUserNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern CredentialUIReturnCodes CredUIParseUserName(
            string userName,
            StringBuilder user,
            int userMaxChars,
            StringBuilder domain,
            int domainMaxChars);

        [DllImport("Credui.dll")]
        internal static extern CredentialUIReturnCodes CredUICmdLinePromptForCredentials(
            string targetName,
            IntPtr reserved1,
            int iError,
            StringBuilder userName,
            int maxUserName,
            StringBuilder password,
            int maxPassword,
            [MarshalAs(UnmanagedType.Bool)] ref bool pfSave,
            CredentialUIFlags flags);

        #endregion Credui.dll

        #region Ole32.dll
        [DllImport("Ole32.dll", EntryPoint = "CoTaskMemFree", SetLastError = true)]
        internal static extern void CoTaskMemFree(IntPtr buffer);
        #endregion Ole32.dll

        #region Structures
        /// <summary>
        /// The CREDENTIAL structure contains an individual credential.
        /// 
        /// See CREDENTIAL structure <see href="http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx">documentation.</see>
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CredentialUIInfo
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }
        #endregion Structures

        #region Enums
        [Flags]
        internal enum PromptForWindowsCredentialsFlags : uint
        {
            GenericCredentials = 0x1,
            ShowCheckbox = 0x2,
            AuthpackageOnly = 0x10,
            InCredOnly = 0x20,
            EnumerateAdmins = 0x100,
            EnumerateCurrentUser = 0x200,
            SecurePrompt = 0x1000,
            Pack32Wow = 0x10000000
        }

        internal enum CredentialUIFlags
        {
            IncorrectPassword = 0x1,
            DoNotPersist = 0x2,
            RequestAdministrator = 0x4,
            ExcludeCertificates = 0x8,
            RequireCertificate = 0x10,
            ShowSaveCheckBox = 0x40,
            AlwaysShowUi = 0x80,
            RequireSmartcard = 0x100,
            PasswordOnlyOk = 0x200,
            ValidateUsername = 0x400,
            CompleteUsername = 0x800,
            Persist = 0x1000,
            ServerCredential = 0x4000,
            ExpectConfirmation = 0x20000,
            GenericCredentials = 0x40000,
            UsernameTargetCredentials = 0x80000,
            KeepUsername = 0x100000
        }

        internal enum CredentialUIReturnCodes : uint
        {
            Success = 0,
            Cancelled = 1223,
            NoSuchLogonSession = 1312,
            NotFound = 1168,
            InvalidAccountName = 1315,
            InsufficientBuffer = 122,
            InvalidParameter = 87,
            InvalidFlags = 1004
        }

        #endregion Enums

        internal static IEnumerable<CREDENTIAL> CredEnumerate()
        {
            return CredEnumerate(null);
        }

        internal static IEnumerable<CREDENTIAL> CredEnumerate(string filter)
        {
            int count;
            IntPtr pCredentials;
            var ret = CredEnumerate(filter, 0, out count, out pCredentials);
            int lastError = Marshal.GetLastWin32Error();
            if (!ret && lastError != (int)CredentialUIReturnCodes.NotFound)
                throw new Win32Exception(lastError, $"Failed to enumerate credentials.\nError code: {lastError}");

            var credentials = new IntPtr[count];
            for (var n = 0; n < count; n++)
                credentials[n] = Marshal.ReadIntPtr(pCredentials,
                    n * Marshal.SizeOf(typeof(IntPtr)));

            return credentials.Select(ptr => (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL)));
        }

        internal sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
        {
            // Set the handle.
            internal CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }

            internal CREDENTIAL GetCredential()
            {
                if (!IsInvalid)
                {
                    // Get the Credential from the mem location
                    return (CREDENTIAL) Marshal.PtrToStructure(handle, typeof (CREDENTIAL));
                }

                throw new InvalidOperationException("Invalid CriticalHandle!");
            }

            // Perform any specific actions to release the handle in the ReleaseHandle method.
            // Often, you need to use P/Invoke to make a call into the Win32 API to release the 
            // handle. In this case, however, we can use the Marshal class to release the unmanaged memory.
            protected override bool ReleaseHandle()
            {
                // If the handle was set, free it. Return success.
                if (!IsInvalid)
                {
                    // NOTE: We should also ZERO out the memory allocated to the handle, before free'ing it
                    // so there are no traces of the sensitive data left in memory.
                    CredFree(handle);
                    // Mark the handle as invalid for future users.
                    SetHandleAsInvalid();
                    return true;
                }
                // Return false. 
                return false;
            }
        }
    }
}