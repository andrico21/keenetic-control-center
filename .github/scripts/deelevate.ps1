<#
.SYNOPSIS
Runs a command with a non-elevated token on a Windows CI runner.

.DESCRIPTION
kcc refuses to start with an elevated process token (exit 77, docs/SECURITY.md
"Privilege floor"), and GitHub's Windows runner runs every job elevated. This
script lets CI run `cargo test` the way a user would run kcc: without elevation.
It never touches kcc; it only changes the token of the process it starts.

Modes:
  -CommandLine <cmd> [-Method auto|safer|restricted]
      Starts <cmd> with a non-elevated token, streams its output and exits with
      its exit code. Before that, a pre-check child reports its own token and
      fails the run when it is still elevated or cannot write the build dirs.
      `auto` tries `safer` first, then `restricted`.
  -GrantAccess
      Grants the current user (by SID, not through Administrators) Modify on
      the checkout, the cargo target dir, CARGO_HOME and RUSTUP_HOME, so a token
      whose Administrators group is deny-only can still build there.
  -Report [-Label <name>] [-OutFile <file>]
      Prints one `method=<label> elevated=<0|1> ...` line about this process's
      own token. Exit 0: not elevated and usable; 1: elevated; 2: not elevated
      but a build dir is not writable or cargo does not run.

Methods:
  safer       SaferComputeTokenFromLevel(SAFER_LEVELID_NORMALUSER), the token
              `runas /trustlevel:0x20000` uses: Administrators deny-only,
              privileges removed, medium integrity.
  restricted  CreateRestrictedToken(DISABLE_MAX_PRIVILEGE | LUA_TOKEN) with
              Administrators deny-only and the integrity lowered to medium.

Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [string] $CommandLine,
    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('auto', 'safer', 'restricted')]
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

# C# 5 only: Windows PowerShell 5.1 compiles this with the .NET Framework csc.
$source = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class KccToken
{
    const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    const int TokenElevationType = 18;
    const int TokenElevation = 20;
    const int TokenIntegrityLevel = 25;
    const uint DISABLE_MAX_PRIVILEGE = 0x1;
    const uint LUA_TOKEN = 0x4;
    const uint SAFER_SCOPEID_USER = 2;
    const uint SAFER_LEVELID_NORMALUSER = 0x20000;
    const uint SAFER_LEVEL_OPEN = 1;
    const uint SE_GROUP_INTEGRITY = 0x20;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const int STARTF_USESTDHANDLES = 0x100;
    const uint HANDLE_FLAG_INHERIT = 1;
    const uint INFINITE = 0xFFFFFFFF;
    const uint WAIT_FAILED = 0xFFFFFFFF;

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
    static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableCount, SID_AND_ATTRIBUTES[] sidsToDisable,
        uint deleteCount, IntPtr privilegesToDelete, uint restrictCount, IntPtr sidsToRestrict, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);
    [DllImport("advapi32.dll")] static extern int GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
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

    // The same query as the check_elevation crate behind kcc's refusal:
    // OpenProcessToken(TOKEN_QUERY) + GetTokenInformation(TokenElevation).
    public static int Elevated() { return QueryInt(TokenElevation) != 0 ? 1 : 0; }

    public static int ElevationType() { return QueryInt(TokenElevationType); }

    public static uint IntegrityRid()
    {
        IntPtr token = OwnToken(TOKEN_QUERY);
        try
        {
            int length;
            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out length);
            if (length <= 0) { throw Failed("GetTokenInformation(TokenIntegrityLevel size)"); }
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, length, out length)) { throw Failed("GetTokenInformation(TokenIntegrityLevel)"); }
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                return unchecked((uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1))));
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(token); }
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

    public static IntPtr RestrictedToken()
    {
        IntPtr own = OwnToken(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT);
        IntPtr admins = IntPtr.Zero;
        IntPtr medium = IntPtr.Zero;
        IntPtr label = IntPtr.Zero;
        try
        {
            if (!ConvertStringSidToSidW("S-1-5-32-544", out admins)) { throw Failed("ConvertStringSidToSid(Administrators)"); }
            SID_AND_ATTRIBUTES[] disable = new SID_AND_ATTRIBUTES[] { new SID_AND_ATTRIBUTES { Sid = admins, Attributes = 0 } };
            IntPtr token;
            if (!CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 1, disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out token))
            {
                throw Failed("CreateRestrictedToken");
            }
            if (!ConvertStringSidToSidW("S-1-16-8192", out medium)) { int code = Marshal.GetLastWin32Error(); CloseHandle(token); throw Failed("ConvertStringSidToSid(Medium)", code); }
            int size = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            label = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(new SID_AND_ATTRIBUTES { Sid = medium, Attributes = SE_GROUP_INTEGRITY }, label, false);
            if (!SetTokenInformation(token, TokenIntegrityLevel, label, size + GetLengthSid(medium)))
            {
                int code = Marshal.GetLastWin32Error();
                CloseHandle(token);
                throw Failed("SetTokenInformation(TokenIntegrityLevel)", code);
            }
            return token;
        }
        finally
        {
            if (label != IntPtr.Zero) { Marshal.FreeHGlobal(label); }
            if (medium != IntPtr.Zero) { LocalFree(medium); }
            if (admins != IntPtr.Zero) { LocalFree(admins); }
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

    // Starts commandLine with token, sharing this process's stdio and environment, and
    // returns its exit code. The child gets its own hidden console (CREATE_NO_WINDOW)
    // instead of attaching to the elevated parent's one.
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

# Adds the Win32 message to an "X failed: win32=<code>" error from KccToken.
function Format-Failure([System.Management.Automation.ErrorRecord] $record) {
    $message = $record.Exception.Message
    if ($message -match 'win32=(\d+)') {
        $text = (New-Object System.ComponentModel.Win32Exception([int]$Matches[1])).Message
        $message = "$message ($text)"
    }
    return $message
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
        return ('denied:' + $_.Exception.GetType().Name)
    }
}

function Invoke-Report {
    $elevated = [KccToken]::Elevated()
    $typeCode = [KccToken]::ElevationType()
    $type = switch ($typeCode) { 1 { 'default' } 2 { 'full' } 3 { 'limited' } default { "code-$typeCode" } }
    $rid = [KccToken]::IntegrityRid()
    $integrity = switch ($rid) {
        0x0000 { 'untrusted' } 0x1000 { 'low' } 0x2000 { 'medium' } 0x2100 { 'medium-plus' }
        0x3000 { 'high' } 0x4000 { 'system' } default { 'rid-0x{0:x}' -f $rid }
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $adminEnabled = [int]$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $writes = [ordered]@{
        write_workspace   = Test-Writable $env:GITHUB_WORKSPACE
        write_target      = Test-Writable (Get-TargetDir)
        write_cargo_home  = Test-Writable (Get-CargoHome)
        write_rustup_home = Test-Writable (Get-RustupHome)
        write_temp        = Test-Writable ([System.IO.Path]::GetTempPath().TrimEnd('\'))
    }
    & cmd.exe /d /c 'cargo --version >nul 2>&1'
    $cargo = if ($LASTEXITCODE -eq 0) { 'ok' } else { "exit-$LASTEXITCODE" }
    $usable = ($cargo -eq 'ok') -and -not ($writes.Values | Where-Object { $_ -like 'denied*' })
    $verdict = if ($elevated -eq 1) { 'elevated' } elseif ($usable) { 'ok' } else { 'unusable' }
    $fields = @(
        "method=$Label", "verdict=$verdict", "elevated=$elevated", "elevation_type=$type",
        "integrity=$integrity", "admin_enabled=$adminEnabled", "user=$($identity.Name)"
    )
    foreach ($key in $writes.Keys) { $fields += "$key=$($writes[$key])" }
    $fields += "cargo=$cargo"
    $line = $fields -join ' '
    Write-Output $line
    if ($OutFile) { Set-Content -LiteralPath $OutFile -Value $line -Encoding Ascii }
    if ($elevated -eq 1) { exit 1 }
    if (-not $usable) { exit 2 }
    exit 0
}

function Invoke-GrantAccess {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $dirs = @($env:GITHUB_WORKSPACE, (Get-TargetDir), (Get-CargoHome), (Get-RustupHome)) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
        Select-Object -Unique
    foreach ($dir in $dirs) {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        & icacls.exe $dir /grant "*${sid}:(OI)(CI)M" /T /C /Q
        if ($LASTEXITCODE -ne 0) { throw "icacls $dir exited $LASTEXITCODE" }
        Write-Output ("deelevate: granted {0} Modify on {1} in {2:N1} s" -f $sid, $dir, $watch.Elapsed.TotalSeconds)
    }
}

function Invoke-WithToken([string] $name, [string] $command) {
    $token = if ($name -eq 'safer') { [KccToken]::SaferToken() } else { [KccToken]::RestrictedToken() }
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
    $methods = if ($Method -eq 'auto') { @('safer', 'restricted') } else { @($Method) }
    $chosen = ''
    foreach ($name in $methods) {
        $check = "`"$shell`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Report -Label $name"
        try {
            $code = Invoke-WithToken $name $check
        } catch {
            Write-Output ("method={0} verdict=launch-error error={1}" -f $name, (Format-Failure $_))
            continue
        }
        if ($code -eq 0) { $chosen = $name; break }
        Write-Output ("deelevate: pre-check of method {0} exited 0x{1:X8}; trying the next method" -f $name, $code)
    }
    if (-not $chosen) {
        Write-Output ('::error title=De-elevation failed::No launch method gave a non-elevated, usable token ' +
            '(see the method= lines above). kcc refuses an elevated token by design: fix this launcher, never the check.')
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
