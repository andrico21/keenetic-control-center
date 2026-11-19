<#
.SYNOPSIS
Runs a command with a non-elevated token on a Windows CI runner.

.DESCRIPTION
kcc refuses to start with an elevated process token (exit 77, docs/SECURITY.md
"Privilege floor"), and GitHub's Windows runner runs every job elevated. This
script lets CI run `cargo test` the way a user would run kcc: without elevation.
It never touches kcc; it only changes the token of the process it starts.

Modes:
  -CommandLine <cmd> [-Method <name>]
      Starts <cmd> with the method's token, streams its output and exits with its
      exit code. Before that, a pre-check child started the same way reports its
      own token; a method whose child is still elevated, cannot write the build
      dirs or dies is skipped. `auto` tries filtered, then filtered-high, and
      fails when neither passes (the other methods are only for the token probe).
  -GrantAccess
      Grants the current user (by SID, not through Administrators) Modify on the
      checkout, the cargo target dir, CARGO_HOME, RUSTUP_HOME and RUNNER_TEMP, so
      a token whose Administrators group is deny-only can still build there.
  -Report [-Label <name>] [-OutFile <file>]
      Prints one `method=<label> verdict=<v> elevated=<0|1> ...` line about this
      process's own token. Exit 0: not elevated and usable; 1: elevated; 2: not
      elevated but a build dir is not writable or cargo does not run; 3: the
      report itself failed.

Methods (every token but `safer` gets the user SID as owner and a default DACL
of user + SYSTEM, see New-MethodToken):
  medium             a primary duplicate of the own token, integrity lowered to
                     Medium (the MSDN low-integrity launch recipe).
  safer-medium       SaferComputeTokenFromLevel(NORMALUSER), integrity Medium.
  restricted-medium  CreateRestrictedToken(DISABLE_MAX_PRIVILEGE), no deny-only
                     SIDs, integrity Medium.
  filtered           CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) with every
                     group the kernel counts as elevated (RtlIsElevatedRid:
                     Administrators, S-1-5-114, ...) deny-only, integrity Medium;
                     what a UAC filtered token looks like.
  filtered-high      as filtered, integrity left as it is.
  safer              the SAFER token unchanged (what `runas /trustlevel:0x20000`
                     uses); kept for the token probe, not in `auto`.

Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [string] $CommandLine,
    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('auto', 'medium', 'safer-medium', 'restricted-medium', 'filtered', 'filtered-high', 'safer')]
    [string] $Method = 'auto',
    [Parameter(ParameterSetName = 'Grant', Mandatory = $true)]
    [switch] $GrantAccess,
    [Parameter(ParameterSetName = 'Report', Mandatory = $true)]
    [switch] $Report,
    [Parameter(ParameterSetName = 'Report')]
    [string] $Label = 'self',
    [Parameter(ParameterSetName = 'Report')]
    [string] $OutFile = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$AutoOrder = @('filtered', 'filtered-high')

# C# 5 only: Windows PowerShell 5.1 compiles this with the .NET Framework csc.
$source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class KccToken
{
    const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    const int TokenUser = 1;
    const int TokenGroups = 2;
    const int TokenPrivileges = 3;
    const int TokenOwner = 4;
    const int TokenDefaultDacl = 6;
    const int TokenElevationType = 18;
    const int TokenElevation = 20;
    const int TokenIntegrityLevel = 25;
    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;
    const uint DISABLE_MAX_PRIVILEGE = 0x1;
    const uint SAFER_SCOPEID_USER = 2;
    const uint SAFER_LEVELID_NORMALUSER = 0x20000;
    const uint SAFER_LEVEL_OPEN = 1;
    const uint SE_GROUP_ENABLED = 0x4;
    const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x10;
    const uint SE_GROUP_INTEGRITY = 0x20;
    const uint GENERIC_ALL = 0x10000000;
    const int ACL_REVISION = 2;
    const int SECURITY_MAX_SID_SIZE = 68;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const int STARTF_USESTDHANDLES = 0x100;
    const uint HANDLE_FLAG_INHERIT = 1;
    const uint INFINITE = 0xFFFFFFFF;
    const uint WAIT_FAILED = 0xFFFFFFFF;

    // Last RIDs the kernel treats as elevated groups (RtlIsElevatedRid, see the
    // evidence notes), unless the group is deny-only or an integrity label.
    static readonly int[] ElevatedRids = {
        0x72, 0x1F2, 0x200, 0x204, 0x205, 0x206, 0x207, 0x208, 0x209,
        0x220, 0x223, 0x224, 0x225, 0x226, 0x227, 0x229, 0x22A, 0x22C, 0x239
    };

    // Privileges whose presence alone makes TokenElevation report 1.
    static readonly string[] GodPrivileges = {
        "SeCreateTokenPrivilege", "SeTcbPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
        "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege", "SeImpersonatePrivilege",
        "SeRelabelPrivilege", "SeDelegateSessionUserImpersonatePrivilege"
    };

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags;
        public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buffer, int length, out int returned);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetTokenInformation(IntPtr token, int cls, IntPtr buffer, int length);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableCount, SID_AND_ATTRIBUTES[] sidsToDisable,
        uint deleteCount, IntPtr privilegesToDelete, uint restrictCount, IntPtr sidsToRestrict, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr text);
    [DllImport("advapi32.dll")] static extern int GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool InitializeAcl(IntPtr acl, int length, int revision);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AddAccessAllowedAce(IntPtr acl, int revision, uint mask, IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeNameW(string systemName, IntPtr luid, StringBuilder name, ref int length);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SaferCreateLevel(uint scope, uint level, uint flags, out IntPtr handle, IntPtr reserved);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SaferComputeTokenFromLevel(IntPtr level, IntPtr inToken, out IntPtr outToken, uint flags, IntPtr reserved);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SaferCloseLevel(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUserW(IntPtr token, string application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory,
        ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    static Exception Failed(string call, int code)
    {
        return new InvalidOperationException(call + " failed: win32=" + code);
    }

    static Exception Failed(string call)
    {
        return Failed(call, Marshal.GetLastWin32Error());
    }

    static IntPtr OwnToken(uint access)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), access, out token)) { throw Failed("OpenProcessToken"); }
        return token;
    }

    // The token's information of class cls in a buffer the caller frees with FreeHGlobal.
    static IntPtr Query(IntPtr token, int cls)
    {
        int length;
        GetTokenInformation(token, cls, IntPtr.Zero, 0, out length);
        if (length <= 0) { throw Failed("GetTokenInformation(" + cls + " size)"); }
        IntPtr buffer = Marshal.AllocHGlobal(length);
        if (!GetTokenInformation(token, cls, buffer, length, out length))
        {
            int code = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw Failed("GetTokenInformation(" + cls + ")", code);
        }
        return buffer;
    }

    static int QueryInt(int cls)
    {
        IntPtr token = OwnToken(TOKEN_QUERY);
        IntPtr buffer = Marshal.AllocHGlobal(4);
        try
        {
            int returned;
            if (!GetTokenInformation(token, cls, buffer, 4, out returned)) { throw Failed("GetTokenInformation(" + cls + ")"); }
            return Marshal.ReadInt32(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); CloseHandle(token); }
    }

    static string SidText(IntPtr sid)
    {
        IntPtr text;
        if (!ConvertSidToStringSidW(sid, out text)) { throw Failed("ConvertSidToStringSid"); }
        try { return Marshal.PtrToStringUni(text); }
        finally { LocalFree(text); }
    }

    static uint SubAuthority(IntPtr sid, int index)
    {
        return unchecked((uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)index)));
    }

    // TOKEN_GROUPS: a DWORD count, then SID_AND_ATTRIBUTES entries aligned to a pointer.
    static int GroupCount(IntPtr groups) { return Marshal.ReadInt32(groups); }

    static IntPtr GroupSid(IntPtr groups, int index)
    {
        return Marshal.ReadIntPtr(groups, IntPtr.Size + index * Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
    }

    static uint GroupAttributes(IntPtr groups, int index)
    {
        int offset = IntPtr.Size + index * Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)) + IntPtr.Size;
        return unchecked((uint)Marshal.ReadInt32(groups, offset));
    }

    static bool IsElevatedGroup(IntPtr sid, uint attributes)
    {
        if ((attributes & (SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_INTEGRITY)) != 0) { return false; }
        int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
        if (count == 0) { return false; }
        uint first = SubAuthority(sid, 0);
        if (first >= 80 && first <= 111) { return false; }
        return Array.IndexOf(ElevatedRids, (int)SubAuthority(sid, count - 1)) >= 0;
    }

    // The same query as the check_elevation crate behind kcc's refusal:
    // OpenProcessToken(TOKEN_QUERY) + GetTokenInformation(TokenElevation).
    public static int Elevated() { return QueryInt(TokenElevation) != 0 ? 1 : 0; }

    public static int ElevationType() { return QueryInt(TokenElevationType); }

    public static uint IntegrityRid()
    {
        IntPtr token = OwnToken(TOKEN_QUERY);
        IntPtr buffer = IntPtr.Zero;
        try
        {
            buffer = Query(token, TokenIntegrityLevel);
            IntPtr sid = Marshal.ReadIntPtr(buffer);
            return SubAuthority(sid, Marshal.ReadByte(GetSidSubAuthorityCount(sid)) - 1);
        }
        finally { if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); } CloseHandle(token); }
    }

    // enabled, deny-only, disabled or absent: the state of group sid in the own token.
    public static string GroupState(string sid)
    {
        IntPtr token = OwnToken(TOKEN_QUERY);
        IntPtr groups = IntPtr.Zero;
        try
        {
            groups = Query(token, TokenGroups);
            for (int i = 0; i < GroupCount(groups); i++)
            {
                if (!string.Equals(SidText(GroupSid(groups, i)), sid, StringComparison.OrdinalIgnoreCase)) { continue; }
                uint attributes = GroupAttributes(groups, i);
                if ((attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0) { return "deny-only"; }
                return (attributes & SE_GROUP_ENABLED) != 0 ? "enabled" : "disabled";
            }
            return "absent";
        }
        finally { if (groups != IntPtr.Zero) { Marshal.FreeHGlobal(groups); } CloseHandle(token); }
    }

    // The own token's groups that count as elevated, comma-separated, or "none".
    public static string ElevatedGroups()
    {
        IntPtr token = OwnToken(TOKEN_QUERY);
        IntPtr groups = IntPtr.Zero;
        try
        {
            groups = Query(token, TokenGroups);
            List<string> found = new List<string>();
            for (int i = 0; i < GroupCount(groups); i++)
            {
                IntPtr sid = GroupSid(groups, i);
                if (IsElevatedGroup(sid, GroupAttributes(groups, i))) { found.Add(SidText(sid)); }
            }
            return found.Count == 0 ? "none" : string.Join(",", found.ToArray());
        }
        finally { if (groups != IntPtr.Zero) { Marshal.FreeHGlobal(groups); } CloseHandle(token); }
    }

    // The own token's privilege names (present, enabled or not).
    static List<string> PrivilegeNames()
    {
        IntPtr token = OwnToken(TOKEN_QUERY);
        IntPtr privileges = IntPtr.Zero;
        try
        {
            privileges = Query(token, TokenPrivileges);
            List<string> names = new List<string>();
            int count = Marshal.ReadInt32(privileges);
            // TOKEN_PRIVILEGES: a DWORD count, then 12-byte LUID_AND_ATTRIBUTES entries.
            for (int i = 0; i < count; i++)
            {
                IntPtr luid = IntPtr.Add(privileges, 4 + i * 12);
                StringBuilder name = new StringBuilder(64);
                int length = name.Capacity;
                if (!LookupPrivilegeNameW(null, luid, name, ref length)) { throw Failed("LookupPrivilegeName"); }
                names.Add(name.ToString());
            }
            return names;
        }
        finally { if (privileges != IntPtr.Zero) { Marshal.FreeHGlobal(privileges); } CloseHandle(token); }
    }

    public static int PrivilegeCount() { return PrivilegeNames().Count; }

    // The own token's privileges that alone make it elevated, comma-separated, or "none".
    public static string ElevatedPrivileges()
    {
        List<string> found = new List<string>();
        foreach (string name in PrivilegeNames())
        {
            if (Array.IndexOf(GodPrivileges, name) >= 0) { found.Add(name); }
        }
        return found.Count == 0 ? "none" : string.Join(",", found.ToArray());
    }

    static IntPtr OwnTokenForChild()
    {
        return OwnToken(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT);
    }

    static void SetMediumIntegrity(IntPtr token)
    {
        IntPtr medium = IntPtr.Zero;
        IntPtr label = IntPtr.Zero;
        try
        {
            if (!ConvertStringSidToSidW("S-1-16-8192", out medium)) { throw Failed("ConvertStringSidToSid(Medium)"); }
            int size = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            label = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(new SID_AND_ATTRIBUTES { Sid = medium, Attributes = SE_GROUP_INTEGRITY }, label, false);
            if (!SetTokenInformation(token, TokenIntegrityLevel, label, size + GetLengthSid(medium)))
            {
                throw Failed("SetTokenInformation(TokenIntegrityLevel)");
            }
        }
        finally
        {
            if (label != IntPtr.Zero) { Marshal.FreeHGlobal(label); }
            if (medium != IntPtr.Zero) { LocalFree(medium); }
        }
    }

    // An elevated token's owner and default DACL name Administrators. Once that group
    // is deny-only, the child (and the console host it starts with the same token)
    // cannot open the objects it creates, its own process included. Like Chromium's
    // RestrictedToken, give the user SID ownership and GENERIC_ALL in the default DACL.
    static void SetUserDefaults(IntPtr token)
    {
        IntPtr user = IntPtr.Zero;
        IntPtr system = IntPtr.Zero;
        IntPtr owner = IntPtr.Zero;
        IntPtr acl = IntPtr.Zero;
        IntPtr dacl = IntPtr.Zero;
        try
        {
            user = Query(token, TokenUser);
            IntPtr userSid = Marshal.ReadIntPtr(user);
            if (!ConvertStringSidToSidW("S-1-5-18", out system)) { throw Failed("ConvertStringSidToSid(SYSTEM)"); }
            owner = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(owner, userSid);
            if (!SetTokenInformation(token, TokenOwner, owner, IntPtr.Size)) { throw Failed("SetTokenInformation(TokenOwner)"); }
            // ACL header, then two ACCESS_ALLOWED_ACEs: 8 bytes each before the SID.
            int size = 8 + 2 * (8 + SECURITY_MAX_SID_SIZE);
            acl = Marshal.AllocHGlobal(size);
            if (!InitializeAcl(acl, size, ACL_REVISION)) { throw Failed("InitializeAcl"); }
            if (!AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, userSid)) { throw Failed("AddAccessAllowedAce(user)"); }
            if (!AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, system)) { throw Failed("AddAccessAllowedAce(SYSTEM)"); }
            dacl = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(dacl, acl);
            if (!SetTokenInformation(token, TokenDefaultDacl, dacl, IntPtr.Size)) { throw Failed("SetTokenInformation(TokenDefaultDacl)"); }
        }
        finally
        {
            if (dacl != IntPtr.Zero) { Marshal.FreeHGlobal(dacl); }
            if (acl != IntPtr.Zero) { Marshal.FreeHGlobal(acl); }
            if (owner != IntPtr.Zero) { Marshal.FreeHGlobal(owner); }
            if (system != IntPtr.Zero) { LocalFree(system); }
            if (user != IntPtr.Zero) { Marshal.FreeHGlobal(user); }
        }
    }

    // Applies the user defaults and, when medium, the Medium label; closes token on failure.
    static IntPtr Prepare(IntPtr token, bool medium)
    {
        try
        {
            SetUserDefaults(token);
            if (medium) { SetMediumIntegrity(token); }
            return token;
        }
        catch
        {
            CloseHandle(token);
            throw;
        }
    }

    public static IntPtr SaferToken()
    {
        IntPtr level;
        if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, out level, IntPtr.Zero)) { throw Failed("SaferCreateLevel"); }
        try
        {
            IntPtr token;
            if (!SaferComputeTokenFromLevel(level, IntPtr.Zero, out token, 0, IntPtr.Zero)) { throw Failed("SaferComputeTokenFromLevel"); }
            return token;
        }
        finally { SaferCloseLevel(level); }
    }

    public static IntPtr SaferMediumToken() { return Prepare(SaferToken(), true); }

    public static IntPtr MediumToken()
    {
        IntPtr own = OwnTokenForChild();
        try
        {
            IntPtr token;
            if (!DuplicateTokenEx(own, 0, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out token)) { throw Failed("DuplicateTokenEx"); }
            return Prepare(token, true);
        }
        finally { CloseHandle(own); }
    }

    public static IntPtr RestrictedMediumToken()
    {
        IntPtr own = OwnTokenForChild();
        try
        {
            IntPtr token;
            if (!CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE, 0, null, 0, IntPtr.Zero, 0, IntPtr.Zero, out token))
            {
                throw Failed("CreateRestrictedToken");
            }
            return Prepare(token, true);
        }
        finally { CloseHandle(own); }
    }

    public static IntPtr FilteredToken(bool medium)
    {
        IntPtr own = OwnTokenForChild();
        IntPtr groups = IntPtr.Zero;
        try
        {
            groups = Query(own, TokenGroups);
            List<SID_AND_ATTRIBUTES> disable = new List<SID_AND_ATTRIBUTES>();
            for (int i = 0; i < GroupCount(groups); i++)
            {
                IntPtr sid = GroupSid(groups, i);
                if (IsElevatedGroup(sid, GroupAttributes(groups, i))) { disable.Add(new SID_AND_ATTRIBUTES { Sid = sid, Attributes = 0 }); }
            }
            SID_AND_ATTRIBUTES[] sids = disable.Count == 0 ? null : disable.ToArray();
            IntPtr token;
            if (!CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE, (uint)disable.Count, sids, 0, IntPtr.Zero, 0, IntPtr.Zero, out token))
            {
                throw Failed("CreateRestrictedToken");
            }
            return Prepare(token, medium);
        }
        finally
        {
            if (groups != IntPtr.Zero) { Marshal.FreeHGlobal(groups); }
            CloseHandle(own);
        }
    }

    static IntPtr InheritableStdHandle(int which)
    {
        IntPtr handle = GetStdHandle(which);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) { return IntPtr.Zero; }
        if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) { throw Failed("SetHandleInformation(std " + which + ")"); }
        return handle;
    }

    // Starts commandLine with token, sharing this process's stdio handles and
    // environment, and returns its exit code. The child gets its own hidden console
    // (CREATE_NO_WINDOW), inherited by everything it starts, instead of attaching to
    // the elevated parent's one; inherited handles are not access-checked again.
    public static uint Run(IntPtr token, string commandLine, string currentDirectory)
    {
        STARTUPINFO startup = new STARTUPINFO();
        startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = InheritableStdHandle(-10);
        startup.hStdOutput = InheritableStdHandle(-11);
        startup.hStdError = InheritableStdHandle(-12);
        PROCESS_INFORMATION process;
        if (!CreateProcessAsUserW(token, null, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW,
            IntPtr.Zero, currentDirectory, ref startup, out process))
        {
            throw Failed("CreateProcessAsUser");
        }
        try
        {
            if (WaitForSingleObject(process.hProcess, INFINITE) == WAIT_FAILED) { throw Failed("WaitForSingleObject"); }
            uint code;
            if (!GetExitCodeProcess(process.hProcess, out code)) { throw Failed("GetExitCodeProcess"); }
            return code;
        }
        finally { CloseHandle(process.hThread); CloseHandle(process.hProcess); }
    }

    public static void Close(IntPtr handle) { CloseHandle(handle); }
}
'@

if (-not ('KccToken' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp
}

function Get-CargoHome {
    if ($env:CARGO_HOME) { return $env:CARGO_HOME }
    return (Join-Path $env:USERPROFILE '.cargo')
}

function Get-RustupHome {
    if ($env:RUSTUP_HOME) { return $env:RUSTUP_HOME }
    return (Join-Path $env:USERPROFILE '.rustup')
}

function Get-TargetDir {
    if ($env:CARGO_TARGET_DIR) { return $env:CARGO_TARGET_DIR }
    if ($env:GITHUB_WORKSPACE) { return (Join-Path $env:GITHUB_WORKSPACE 'target') }
    return ''
}

# Adds the Win32 message to an "X failed: win32=<code>" error from KccToken; one line.
function Format-Failure([System.Management.Automation.ErrorRecord] $record) {
    $message = $record.Exception.Message
    if ($message -match 'win32=(\d+)') {
        $text = (New-Object System.ComponentModel.Win32Exception([int]$Matches[1])).Message
        $message = "$message ($text)"
    }
    return ($message -replace '\s+', ' ').Trim()
}

function Test-Writable([string] $dir) {
    if (-not $dir) { return 'unset' }
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return 'absent' }
    $probe = Join-Path $dir (".kcc-deelevate-probe-{0}" -f $PID)
    try {
        [System.IO.File]::WriteAllText($probe, 'probe')
        Remove-Item -LiteralPath $probe -Force
        return 'ok'
    } catch {
        $failure = $_.Exception
        if ($failure.InnerException) { $failure = $failure.InnerException }
        return ('denied:' + $failure.GetType().Name)
    }
}

# The report line and its exit code (0 ok, 1 elevated, 2 unusable).
function Get-Report {
    $elevated = [KccToken]::Elevated()
    $typeCode = [KccToken]::ElevationType()
    $type = switch ($typeCode) { 1 { 'default' } 2 { 'full' } 3 { 'limited' } default { "code-$typeCode" } }
    $rid = [KccToken]::IntegrityRid()
    $integrity = switch ($rid) {
        0x0000 { 'untrusted' } 0x1000 { 'low' } 0x2000 { 'medium' } 0x2100 { 'medium-plus' }
        0x3000 { 'high' } 0x4000 { 'system' } default { 'other' }
    }
    $writes = [ordered]@{
        write_workspace   = Test-Writable $env:GITHUB_WORKSPACE
        write_target      = Test-Writable (Get-TargetDir)
        write_cargo_home  = Test-Writable (Get-CargoHome)
        write_rustup_home = Test-Writable (Get-RustupHome)
        write_temp        = Test-Writable ([System.IO.Path]::GetTempPath().TrimEnd('\'))
        write_runner_temp = Test-Writable $env:RUNNER_TEMP
    }
    & cmd.exe /d /c 'cargo --version >nul 2>&1'
    $cargo = if ($LASTEXITCODE -eq 0) { 'ok' } else { "exit-$LASTEXITCODE" }
    $usable = ($cargo -eq 'ok') -and -not ($writes.Values | Where-Object { $_ -like 'denied*' })
    $verdict = if ($elevated -eq 1) { 'elevated' } elseif ($usable) { 'ok' } else { 'unusable' }
    $fields = @(
        "method=$Label", "verdict=$verdict", "elevated=$elevated", "elevation_type=$type",
        "integrity=$integrity", ('integrity_rid=0x{0:x4}' -f $rid),
        "admins=$([KccToken]::GroupState('S-1-5-32-544'))",
        "elevated_groups=$([KccToken]::ElevatedGroups())",
        "elevated_privileges=$([KccToken]::ElevatedPrivileges())",
        "privileges=$([KccToken]::PrivilegeCount())",
        "user=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    )
    foreach ($key in $writes.Keys) { $fields += "$key=$($writes[$key])" }
    $fields += "cargo=$cargo"
    $code = if ($elevated -eq 1) { 1 } elseif (-not $usable) { 2 } else { 0 }
    return @(($fields -join ' '), $code)
}

function Invoke-Report {
    try {
        $line, $code = Get-Report
    } catch {
        $line = "method=$Label verdict=report-error error=$(Format-Failure $_)"
        $code = 3
    }
    Write-Output $line
    if ($OutFile) {
        # Written whole and renamed, so a reader polling for the file never sees half a line.
        $partial = "$OutFile.partial"
        Set-Content -LiteralPath $partial -Value $line -Encoding Ascii
        Move-Item -LiteralPath $partial -Destination $OutFile -Force
    }
    exit $code
}

function Invoke-GrantAccess {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $dirs = @($env:GITHUB_WORKSPACE, (Get-TargetDir), (Get-CargoHome), (Get-RustupHome), $env:RUNNER_TEMP) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
        Select-Object -Unique
    foreach ($dir in $dirs) {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        & icacls.exe $dir /grant "*${sid}:(OI)(CI)M" /T /C /Q
        if ($LASTEXITCODE -ne 0) { throw "icacls $dir exited $LASTEXITCODE" }
        Write-Output ("deelevate: granted {0} Modify on {1} in {2:N1} s" -f $sid, $dir, $watch.Elapsed.TotalSeconds)
    }
}

function New-MethodToken([string] $name) {
    switch ($name) {
        'medium' { return [KccToken]::MediumToken() }
        'safer-medium' { return [KccToken]::SaferMediumToken() }
        'restricted-medium' { return [KccToken]::RestrictedMediumToken() }
        'filtered' { return [KccToken]::FilteredToken($true) }
        'filtered-high' { return [KccToken]::FilteredToken($false) }
        'safer' { return [KccToken]::SaferToken() }
    }
    throw "unknown method $name"
}

function Invoke-WithToken([string] $name, [string] $command) {
    $token = New-MethodToken $name
    try {
        [Console]::Out.Flush()
        $cwd = (Get-Location).ProviderPath
        return [KccToken]::Run($token, $command, $cwd)
    } finally {
        [KccToken]::Close($token)
    }
}

function Invoke-Run {
    $shell = (Get-Process -Id $PID).Path
    $methods = if ($Method -eq 'auto') { $AutoOrder } else { @($Method) }
    $chosen = ''
    $tried = @()
    foreach ($name in $methods) {
        $check = "`"$shell`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Report -Label $name"
        try {
            $code = Invoke-WithToken $name $check
        } catch {
            Write-Output ("method={0} verdict=launch-error error={1}" -f $name, (Format-Failure $_))
            $tried += "$name=launch-error"
            continue
        }
        # The child printed its own method= line for exit codes 0-3.
        $verdict = switch ($code) { 0 { 'ok' } 1 { 'elevated' } 2 { 'unusable' } 3 { 'report-error' } default { '' } }
        if (-not $verdict) {
            $verdict = 'child-died'
            Write-Output ("method={0} verdict=child-died exit=0x{1:X8}" -f $name, $code)
            if (('{0:X8}' -f $code) -eq 'C0000142') {
                Write-Output ('deelevate: 0xC0000142 is STATUS_DLL_INIT_FAILED: a DLL of the child (usually kernelbase ' +
                    'console setup or user32 desktop attach) failed to initialise under this token, before any child code ran')
            }
        }
        $tried += "$name=$verdict"
        if ($code -eq 0) { $chosen = $name; break }
    }
    if (-not $chosen) {
        Write-Output ('::error title=De-elevation failed::No launch method gave a non-elevated, usable token ' +
            '(see the method= lines above). kcc refuses an elevated token by design: fix this launcher, never the check.')
        Write-Output ("deelevate: method={0} verdict=failed tried={1}" -f $Method, ($tried -join ','))
        exit 1
    }
    Write-Output "deelevate: method=$chosen running: $CommandLine"
    $code = Invoke-WithToken $chosen $CommandLine
    Write-Output ("deelevate: method={0} exit=0x{1:X8}" -f $chosen, $code)
    exit ([System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]$code), 0))
}

switch ($PSCmdlet.ParameterSetName) {
    'Report' { Invoke-Report }
    'Grant' { Invoke-GrantAccess }
    'Run' { Invoke-Run }
}
