param(
    [string]$OutputDirectory,
    [string]$ExpectedCurrentUserSid,
    [int]$ExpectedSessionId = -1,
    [switch]$CaptureCallerContext,
    [string]$CallerContextPath,
    [string]$CallerContextSha256,
    [switch]$Plan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$topics = @('configuration', 'state', 'authority', 'cached_msi', 'agent', 'service', 'hosts', 'dns', 'roots', 'registry')
if ($Plan) {
    $mode = 'read_only_preflight'
    $requires = @('same_user_sid', 'same_session', 'administrator', 'new_protected_directory')
    $plannedTopics = $topics
    if ($CaptureCallerContext) {
        $mode = 'caller_context_capture'
        $requires = @('same_user_sid', 'same_session', 'unelevated', 'new_protected_directory')
        $plannedTopics = @('caller_identity', 'documents', 'roots', 'captured_at')
    }
    [ordered]@{
        mode = $mode
        destination = 'Documents/OpenEMS-Lab/<run>/private'
        requires = $requires
        topics = $plannedTopics
        host_mutations = @()
        rollback_status = 'not_yet_verified'
        context_max_age_seconds = 900
    } | ConvertTo-Json -Depth 4
    exit 0
}

function Assert-PilotIdentity([string]$ExpectedSid, [int]$ExpectedSession, [string]$CurrentSid, [int]$CurrentSession, [bool]$Administrator) {
    if (-not $ExpectedSid -or $ExpectedSid -ne $CurrentSid) { throw 'identity_mismatch' }
    if ($ExpectedSession -lt 1 -or $ExpectedSession -ne $CurrentSession) { throw 'session_mismatch' }
    if (-not $Administrator) { throw 'administrator_required' }
}

function Assert-PilotDelegatedIdentity([int]$ExpectedSession, [int]$CurrentSession, [bool]$Administrator) {
    if ($ExpectedSession -lt 1 -or $ExpectedSession -ne $CurrentSession) { throw 'session_mismatch' }
    if (-not $Administrator) { throw 'administrator_required' }
}

function Assert-PilotCaptureIdentity([string]$ExpectedSid, [int]$ExpectedSession, [string]$CurrentSid, [int]$CurrentSession, [bool]$Administrator) {
    Assert-PilotIdentity -ExpectedSid $ExpectedSid -ExpectedSession $ExpectedSession -CurrentSid $CurrentSid -CurrentSession $CurrentSession -Administrator $true
    if ($Administrator) { throw 'caller_context_requires_unelevated' }
}

function Assert-PilotNoReparse([string]$Path) {
    $ancestor = [IO.Path]::GetFullPath($Path)
    while ($ancestor) {
        if ([IO.File]::Exists($ancestor) -or [IO.Directory]::Exists($ancestor)) {
            if (([IO.File]::GetAttributes($ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'invalid_output_directory'
            }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
}

function Get-PilotDestination([string]$OutputDirectory, [string]$DocumentsDirectory) {
    try {
        if (-not $OutputDirectory -or -not [IO.Path]::IsPathRooted($OutputDirectory) -or -not $DocumentsDirectory) { throw 'invalid_output_directory' }
        $leaf = [IO.Path]::GetFileName($OutputDirectory.TrimEnd('\'))
        if ($leaf -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$' -or $leaf.EndsWith('.') -or $leaf -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') { throw 'invalid_output_directory' }
        $destination = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
        $lab = [IO.Path]::GetFullPath([IO.Path]::Combine($DocumentsDirectory, 'OpenEMS-Lab')).TrimEnd('\')
        if (-not [string]::Equals([IO.Path]::GetDirectoryName($destination), $lab, [StringComparison]::OrdinalIgnoreCase)) { throw 'invalid_output_directory' }
        if ([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) { throw 'invalid_output_directory' }
        Assert-PilotNoReparse $destination
    } catch { throw 'invalid_output_directory' }
    $destination
}

function New-PilotDirectorySecurity([Security.Principal.SecurityIdentifier]$UserSid, [Security.Principal.SecurityIdentifier]$OwnerSid) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($OwnerSid)
    foreach ($sid in @($UserSid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    $security
}

function New-PilotPrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$UserSid, [Security.Principal.SecurityIdentifier]$OwnerSid = $UserSid) {
    if ([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)) { throw 'invalid_output_directory' }
    $security = New-PilotDirectorySecurity -UserSid $UserSid -OwnerSid $OwnerSid
    # Directory creation applies the DACL before any private file can exist.
    $directory = New-Object IO.DirectoryInfo($Path)
    $directory.Create($security)
    $actual = $directory.GetAccessControl()
    $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $allowed = @($UserSid.Value, 'S-1-5-18', 'S-1-5-32-544')
    if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $OwnerSid.Value -or $rules.Count -ne 3) { throw 'directory_acl_invalid' }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($sid -notin $allowed -or $seen.ContainsKey($sid) -or $rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl' -or $rule.InheritanceFlags -ne 'ContainerInherit,ObjectInherit' -or $rule.PropagationFlags -ne 'None') { throw 'directory_acl_invalid' }
        $seen[$sid] = $true
    }
}

function Expand-PilotOriginalPath([string]$Value, [hashtable]$Variables) {
    $expanded = [regex]::Replace($Value, '%([A-Za-z][A-Za-z0-9_]*)%', {
        param($match)
        $name = $match.Groups[1].Value
        if (-not $Variables.ContainsKey($name)) { throw 'original_documents_invalid' }
        [string]$Variables[$name]
    })
    if ($expanded.Contains('%') -or $expanded -notmatch '^[A-Za-z]:[\\/]') { throw 'original_documents_invalid' }
    [IO.Path]::GetFullPath($expanded).TrimEnd('\')
}

function Resolve-PilotOriginalDocuments([string]$ProfileImagePath, [string]$PersonalPath, [string]$ContextDocuments, [hashtable]$OriginalEnvironment = @{}) {
    try {
        $systemDrive = [IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\')
        $profile = Expand-PilotOriginalPath $ProfileImagePath @{ SystemDrive = $systemDrive }
        $variables = @{ USERPROFILE = $profile }
        foreach ($name in @('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer')) {
            if ($OriginalEnvironment.ContainsKey($name)) { $variables[$name] = Expand-PilotOriginalPath $OriginalEnvironment[$name] @{ USERPROFILE = $profile } }
        }
        $documents = Expand-PilotOriginalPath $PersonalPath $variables
        $expected = Expand-PilotOriginalPath $ContextDocuments @{}
        if (-not $documents.StartsWith($profile + '\', [StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($documents, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'original_documents_invalid' }
        Assert-PilotNoReparse $profile
        Assert-PilotNoReparse $documents
    } catch { throw 'original_documents_invalid' }
    $documents
}

function Get-PilotOriginalDocuments([string]$OriginalSid, [string]$ContextDocuments) {
    $machine = $null
    $users = $null
    $profile = $null
    $personal = $null
    $environment = $null
    try {
        $sid = (New-Object Security.Principal.SecurityIdentifier($OriginalSid)).Value
        $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
        $profile = $machine.OpenSubKey(('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid), $false)
        $personal = $users.OpenSubKey(($sid + '\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'), $false)
        $environment = $users.OpenSubKey(($sid + '\Environment'), $false)
        if ($null -eq $profile -or $null -eq $personal) { throw 'original_documents_invalid' }
        $options = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        $originalEnvironment = @{}
        if ($null -ne $environment) {
            foreach ($name in @('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer')) {
                $value = $environment.GetValue($name, $null, $options)
                if ($value -is [string] -and $value) { $originalEnvironment[$name] = $value }
            }
        }
        $result = Resolve-PilotOriginalDocuments -ProfileImagePath $profile.GetValue('ProfileImagePath', $null, $options) -PersonalPath $personal.GetValue('Personal', $null, $options) -ContextDocuments $ContextDocuments -OriginalEnvironment $originalEnvironment
    } catch { throw 'original_documents_invalid' }
    finally {
        foreach ($key in @($environment, $personal, $profile, $users, $machine)) { if ($null -ne $key) { $key.Dispose() } }
    }
    $result
}

function Get-PilotHash([IO.Stream]$Stream) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $result = ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    $result
}

function Read-PilotCallerContext([string]$LiteralPath, [string]$Sha256, [string]$ExpectedSid, [int]$ExpectedSession) {
    $stream = $null
    $reader = $null
    try {
        if ($Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'caller_context_hash_mismatch' }
        if (-not (Test-PilotFilePresent $LiteralPath)) { throw 'caller_context_invalid' }
        $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -le 0 -or $stream.Length -gt 8388608) { throw 'caller_context_invalid' }
        if ((Get-PilotHash $stream) -cne $Sha256) { throw 'caller_context_hash_mismatch' }
        # Keep the same non-writable, non-replaceable handle for hashing and JSON parsing.
        $stream.Position = 0
        $reader = New-Object IO.StreamReader($stream, (New-Object Text.UTF8Encoding($false, $true)), $true, 4096, $true)
        $context = $reader.ReadToEnd() | ConvertFrom-Json
        $fields = @($context.PSObject.Properties.Name)
        if ($fields.Count -ne 6 -or @($fields | Where-Object { $_ -notin @('schema_version', 'captured_at', 'user_sid', 'session_id', 'documents', 'roots') }).Count -ne 0) { throw 'caller_context_invalid' }
        if ($context.schema_version -isnot [int] -or $context.schema_version -ne 1 -or $context.user_sid -isnot [string] -or $context.documents -isnot [string] -or $context.session_id -isnot [int] -or $context.captured_at -isnot [string]) { throw 'caller_context_invalid' }
        if ($context.user_sid -cne $ExpectedSid -or (New-Object Security.Principal.SecurityIdentifier($context.user_sid)).Value -cne $ExpectedSid) { throw 'identity_mismatch' }
        if ($ExpectedSession -lt 1 -or $context.session_id -ne $ExpectedSession) { throw 'session_mismatch' }
        $captured = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact($context.captured_at, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$captured) -or $captured.Offset -ne [TimeSpan]::Zero) { throw 'caller_context_invalid' }
        $age = ([DateTimeOffset]::UtcNow - $captured).TotalSeconds
        if ($age -lt -60 -or $age -gt 900) { throw 'caller_context_stale' }
        $rootFields = @($context.roots.PSObject.Properties.Name)
        if ($rootFields.Count -ne 2 -or 'CurrentUser' -notin $rootFields -or 'LocalMachine' -notin $rootFields) { throw 'caller_context_invalid' }
        foreach ($location in @('CurrentUser', 'LocalMachine')) {
            $rows = $context.roots.$location
            if ($rows -isnot [Array] -or $rows.Count -gt 4096) { throw 'caller_context_invalid' }
            $seen = @{}
            foreach ($row in $rows) {
                $names = @($row.PSObject.Properties.Name)
                if ($names.Count -ne 2 -or 'thumbprint' -notin $names -or 'certificate' -notin $names -or $row.thumbprint -isnot [string] -or $row.certificate -isnot [string] -or $row.thumbprint -notmatch '^[0-9a-fA-F]{40}$' -or $seen.ContainsKey($row.thumbprint)) { throw 'caller_context_invalid' }
                $der = [Convert]::FromBase64String($row.certificate)
                if ([Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($der) -ne [Security.Cryptography.X509Certificates.X509ContentType]::Cert) { throw 'caller_context_invalid' }
                $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)
                try { if ($certificate.Thumbprint -ne $row.thumbprint) { throw 'caller_context_invalid' } }
                finally { $certificate.Dispose() }
                $seen[$row.thumbprint] = $true
            }
        }
    } catch {
        if ($_.Exception.Message -in @('caller_context_hash_mismatch', 'caller_context_stale', 'identity_mismatch', 'session_mismatch')) { throw $_.Exception.Message }
        throw 'caller_context_invalid'
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $context
}

function Get-PilotCanonicalAuthority {
    [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'openems\https\authority.json')
}

function Assert-PilotAuthorityPath([string]$Path) {
    $canonical = Get-PilotCanonicalAuthority
    if (-not [string]::Equals($Path, $canonical, [StringComparison]::OrdinalIgnoreCase)) { throw 'authority_path_untrusted' }
}

function Initialize-PilotBackupInterop {
    if ($null -ne ('OpenEms.PilotAuthorityBackup' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace OpenEms {
    public static class PilotAuthorityBackup {
        const uint GENERIC_READ = 0x80000000, FILE_SHARE_READ = 1, OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint DIRECTORY = 0x10, REPARSE_POINT = 0x400;
        const uint TOKEN_QUERY = 8, TOKEN_ADJUST_PRIVILEGES = 0x20, SE_PRIVILEGE_ENABLED = 2;
        const int ERROR_NOT_ALL_ASSIGNED = 1300;
        [StructLayout(LayoutKind.Sequential)] public struct Luid { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] public struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        public sealed class PrivilegeContext {
            internal SafeFileHandle Token;
            internal TokenPrivileges Previous;
        }
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out SafeFileHandle token);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(SafeFileHandle token, bool disableAll, ref TokenPrivileges value, uint size, out TokenPrivileges previous, out uint returned);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);

        static string Canonical { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"openems\https\authority.json"); } }
        public static PrivilegeContext Enable() {
            SafeFileHandle token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out token))
                throw new InvalidOperationException("authority_backup_privilege_unavailable");
            try {
                Luid luid;
                if (!LookupPrivilegeValue(null, "SeBackupPrivilege", out luid))
                    throw new InvalidOperationException("authority_backup_privilege_unavailable");
                TokenPrivileges requested = new TokenPrivileges { Count = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                TokenPrivileges previous;
                uint returned;
                bool adjusted = AdjustTokenPrivileges(token, false, ref requested, (uint)Marshal.SizeOf(typeof(TokenPrivileges)), out previous, out returned);
                int error = Marshal.GetLastWin32Error();
                if (!adjusted || error == ERROR_NOT_ALL_ASSIGNED || error != 0)
                    throw new InvalidOperationException("authority_backup_privilege_unavailable");
                return new PrivilegeContext { Token = token, Previous = previous };
            } catch { token.Dispose(); throw; }
        }
        public static void Restore(PrivilegeContext context) {
            try {
                TokenPrivileges ignored;
                uint returned;
                bool adjusted = AdjustTokenPrivileges(context.Token, false, ref context.Previous, (uint)Marshal.SizeOf(typeof(TokenPrivileges)), out ignored, out returned);
                int error = Marshal.GetLastWin32Error();
                if (!adjusted || error == ERROR_NOT_ALL_ASSIGNED || error != 0)
                    throw new InvalidOperationException("authority_privilege_restore_failed");
            } finally { context.Token.Dispose(); }
        }
        static void ValidateHandle(SafeFileHandle handle, string expected, bool directory) {
            FileInformation information;
            if (!GetFileInformationByHandle(handle, out information)) throw new IOException("authority_unreadable");
            if ((information.Attributes & REPARSE_POINT) != 0 || ((information.Attributes & DIRECTORY) != 0) != directory)
                throw new IOException("authority_path_untrusted");
            StringBuilder final = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandle(handle, final, (uint)final.Capacity, 0);
            if (length == 0 || length >= final.Capacity) throw new IOException("authority_unreadable");
            string actual = final.ToString();
            if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
            if (!String.Equals(actual.TrimEnd('\\'), expected.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new IOException("authority_path_untrusted");
        }
        static SafeFileHandle OpenChecked(string path, bool directory) {
            SafeFileHandle handle = CreateFileW(path, directory ? 0 : GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (handle.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                if (error == 2 || error == 3) return null;
                throw new IOException("authority_unreadable");
            }
            try { ValidateHandle(handle, path, directory); return handle; }
            catch { handle.Dispose(); throw; }
        }
        public static FileStream OpenAuthority(string path) {
            // Recheck in native interop; no caller can turn this into a general backup reader.
            if (!String.Equals(path, Canonical, StringComparison.OrdinalIgnoreCase))
                throw new IOException("authority_path_untrusted");
            List<SafeFileHandle> parents = new List<SafeFileHandle>();
            SafeFileHandle source = null;
            try {
                List<string> paths = new List<string>();
                for (string parent = Path.GetDirectoryName(path); parent != null; parent = Path.GetDirectoryName(parent)) paths.Add(parent);
                paths.Reverse();
                // Retain non-replaceable parent handles until the leaf's final path is validated.
                foreach (string parent in paths) {
                    SafeFileHandle handle = OpenChecked(parent, true);
                    if (handle == null) return null;
                    parents.Add(handle);
                }
                source = OpenChecked(path, false);
                if (source == null) return null;
                FileStream stream = new FileStream(source, FileAccess.Read);
                source = null;
                return stream;
            } finally {
                if (source != null) source.Dispose();
                foreach (SafeFileHandle parent in parents) parent.Dispose();
            }
        }
    }
}
'@
}

function Enable-PilotBackupPrivilege {
    try { [OpenEms.PilotAuthorityBackup]::Enable() }
    catch { throw $_.Exception.GetBaseException().Message }
}
function Restore-PilotBackupPrivilege($Context) {
    try { [OpenEms.PilotAuthorityBackup]::Restore($Context) }
    catch { throw $_.Exception.GetBaseException().Message }
}
function Open-PilotAuthorityHandle([string]$Path) {
    try { [OpenEms.PilotAuthorityBackup]::OpenAuthority($Path) }
    catch { throw $_.Exception.GetBaseException().Message }
}

function Open-PilotAuthorityRead([string]$Path) {
    Assert-PilotAuthorityPath $Path
    Initialize-PilotBackupInterop
    $context = Enable-PilotBackupPrivilege
    $stream = $null
    try { $stream = Open-PilotAuthorityHandle $Path }
    finally {
        try { Restore-PilotBackupPrivilege $context }
        catch {
            if ($null -ne $stream) { $stream.Dispose() }
            throw
        }
    }
    $stream
}

function Save-PilotAuthority($Config, [string]$Destination) {
    $authority = Get-PilotSetting $Config 'authority_path' (Get-PilotCanonicalAuthority)
    Assert-PilotAuthorityPath $authority
    $stream = Open-PilotAuthorityRead $authority
    if ($null -ne $stream) {
        $stream.Dispose()
        $file = Copy-PilotFile -Source $authority -Destination $Destination -ProtectedAuthority
        return @{ file = $file; absent = $null }
    }
    if ($null -ne $Config.PSObject.Properties['block_page_https'] -and $Config.block_page_https) { throw 'authority_missing' }
    @{ file = $null; absent = $authority }
}

function Assert-PilotAuthorityAbsent([string]$Path) {
    $stream = Open-PilotAuthorityRead $Path
    if ($null -ne $stream) { $stream.Dispose(); throw 'source_changed' }
}

function Copy-PilotFile([string]$Source, [string]$Destination, [switch]$ProtectedAuthority) {
    if (-not [IO.Path]::IsPathRooted($Source)) { throw 'backup_failed' }
    if (-not $ProtectedAuthority) { Assert-PilotNoReparse $Source }
    $inputStream = $null
    $outputStream = $null
    try {
        if ($ProtectedAuthority) {
            $inputStream = Open-PilotAuthorityRead $Source
            if ($null -eq $inputStream) { throw 'source_changed' }
        } else { $inputStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) }
        $size = $inputStream.Length
        if ($size -gt 67108864) { throw 'backup_failed' }
        $before = Get-PilotHash $inputStream
        $inputStream.Position = 0
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $inputStream.CopyTo($outputStream)
        $outputStream.Dispose()
        $outputStream = $null
        $inputStream.Position = 0
        if ($inputStream.Length -ne $size -or (Get-PilotHash $inputStream) -ne $before) { throw 'source_changed' }
        $copy = [IO.File]::OpenRead($Destination)
        try { if ((Get-PilotHash $copy) -ne $before) { throw 'backup_failed' } }
        finally { $copy.Dispose() }
        $result = [ordered]@{ source = $Source; backup = $Destination; sha256 = $before; bytes = $size }
        if ($ProtectedAuthority) { $result.protected_authority = $true }
    } finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
    }
    $result
}

function Test-PilotFilePresent([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'configuration_unreadable' }
    try { $attributes = [IO.File]::GetAttributes($Path) }
    catch [IO.FileNotFoundException] { return $false }
    catch [IO.DirectoryNotFoundException] { return $false }
    if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw 'backup_failed' }
    Assert-PilotNoReparse $Path
    $true
}

function Assert-PilotFilesUnchanged($Files) {
    foreach ($file in $Files) {
        if ($file.Contains('protected_authority') -and $file.protected_authority) {
            $stream = Open-PilotAuthorityRead $file.source
            if ($null -eq $stream) { throw 'source_changed' }
        } else { $stream = [IO.File]::Open($file.source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) }
        try {
            if ($stream.Length -ne $file.bytes -or (Get-PilotHash $stream) -ne $file.sha256) { throw 'source_changed' }
        } finally { $stream.Dispose() }
    }
}

function Write-PilotJson([string]$Path, $Value) {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 100))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) }
    finally { $stream.Dispose() }
}

function Get-PilotSetting($Config, [string]$Name, [string]$Fallback) {
    $property = $Config.PSObject.Properties[$Name]
    if ($null -eq $property) { $value = $Fallback }
    elseif ($property.Value -is [string] -and $property.Value) { $value = $property.Value }
    else { throw 'configuration_unreadable' }
    $value
}

function Read-PilotRegistryTree($Key) {
    $values = [ordered]@{}
    foreach ($name in $Key.GetValueNames()) {
        $values[$name] = @{ kind = $Key.GetValueKind($name).ToString(); value = $Key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    }
    $children = [ordered]@{}
    foreach ($name in $Key.GetSubKeyNames()) {
        $child = $Key.OpenSubKey($name, $false)
        try { $children[$name] = Read-PilotRegistryTree $child }
        finally { if ($null -ne $child) { $child.Dispose() } }
    }
    @{ values = $values; children = $children }
}

function Open-PilotRegistryBase([string]$Hive, [string]$View) {
    [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$Hive, [Microsoft.Win32.RegistryView]::$View)
}

function Get-PilotRegistrySnapshot([string]$OriginalUserSid) {
    # Complete union of direct writers in the current and historical 0.1 agent:
    # browser_policy.rs (browser leaves), agent-usb.ps1 (DeviceInstall), nrpt.rs (local NRPT).
    # Keep the DNS policy store and service keys as conservative recovery coverage.
    # Do not walk all Policies: unrelated protected GPOs (for example IPSec) are outside agent ownership.
    $paths = @(
        'SOFTWARE\Policies\Google\Chrome',
        'SOFTWARE\Policies\Microsoft\Edge',
        'SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS',
        'SOFTWARE\Policies\Mozilla\Firefox\Certificates',
        'SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions',
        'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
        'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig',
        'SYSTEM\CurrentControlSet\Services\openems-agent',
        'SYSTEM\CurrentControlSet\Services\USBSTOR'
    )
    $result = [ordered]@{}
    foreach ($hive in @('LocalMachine', 'CurrentUser')) {
        foreach ($view in @('Registry64', 'Registry32')) {
            $baseHive = if ($hive -eq 'CurrentUser') { [Microsoft.Win32.RegistryHive]::Users } else { [Microsoft.Win32.RegistryHive]::LocalMachine }
            $base = Open-PilotRegistryBase -Hive $baseHive -View $view
            try {
                foreach ($path in $paths) {
                    $lookup = if ($hive -eq 'CurrentUser') { $OriginalUserSid + '\' + $path } else { $path }
                    $key = $base.OpenSubKey($lookup, $false)
                    try {
                        $name = $hive + '/' + $view + '/' + $path
                        $result[$name] = if ($null -eq $key) { $null } else { Read-PilotRegistryTree $key }
                    } finally { if ($null -ne $key) { $key.Dispose() } }
                }
            } finally { $base.Dispose() }
        }
    }
    $result
}

function Get-PilotCachedProduct {
    $products = @()
    foreach ($view in @('Registry64', 'Registry32')) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$view)
        try {
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $false)
            if ($null -ne $uninstall) {
                try {
                    foreach ($name in $uninstall.GetSubKeyNames()) {
                        $key = $uninstall.OpenSubKey($name, $false)
                        try {
                            if ($key.GetValue('DisplayName') -eq 'openems endpoint agent') {
                                $guid = ([guid]$name).ToString('N').ToUpperInvariant()
                                $order = @(7,6,5,4,3,2,1,0,11,10,9,8,15,14,13,12,17,16,19,18,21,20,23,22,25,24,27,26,29,28,31,30)
                                $packed = -join @($order | ForEach-Object { $guid[$_] })
                                $cache = $base.OpenSubKey(('SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\' + $packed + '\InstallProperties'), $false)
                                try {
                                    if ($null -eq $cache -or -not $cache.GetValue('LocalPackage')) { throw 'cached_msi_unavailable' }
                                    $products += @{ product_code = $name; version = [string]$key.GetValue('DisplayVersion'); local_package = [string]$cache.GetValue('LocalPackage') }
                                } finally { if ($null -ne $cache) { $cache.Dispose() } }
                            }
                        } finally { if ($null -ne $key) { $key.Dispose() } }
                    }
                } finally { $uninstall.Dispose() }
            }
        } finally { $base.Dispose() }
    }
    if ($products.Count -ne 1) { throw 'cached_msi_unavailable' }
    $products[0]
}

function Get-PilotRoots([string[]]$Locations = @('CurrentUser', 'LocalMachine')) {
    $result = [ordered]@{}
    foreach ($location in $Locations) {
        $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', $location)
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $result[$location] = @($store.Certificates | ForEach-Object { @{ thumbprint = $_.Thumbprint; certificate = [Convert]::ToBase64String($_.RawData) } } | Sort-Object { $_.thumbprint })
        } finally { $store.Close() }
    }
    $result
}

function Get-PilotEffectiveRoots($CallerContext) {
    if ($null -eq $CallerContext) { $result = Get-PilotRoots }
    else {
        $live = Get-PilotRoots -Locations @('LocalMachine')
        $expected = @($CallerContext.roots.LocalMachine | ForEach-Object { $_.thumbprint.ToUpperInvariant() + ':' + $_.certificate } | Sort-Object)
        $actual = @($live.LocalMachine | ForEach-Object { $_.thumbprint.ToUpperInvariant() + ':' + $_.certificate } | Sort-Object)
        if ($expected.Count -ne $actual.Count) { throw 'machine_roots_changed' }
        for ($index = 0; $index -lt $expected.Count; $index++) {
            if ($expected[$index] -cne $actual[$index]) { throw 'machine_roots_changed' }
        }
        $result = @{ CurrentUser = @($CallerContext.roots.CurrentUser); LocalMachine = @($live.LocalMachine) }
    }
    $result
}

$status = 'preflight_failed'
$complete = [ordered]@{}
foreach ($topic in $topics) { $complete[$topic] = $false }
$files = New-Object 'Collections.Generic.List[object]'
$loopback = $false
$snapshotCreated = $false
$rootCounts = @{ current_user = $null; local_machine = $null }
$identityMode = 'same_user'
$callerContext = $null
$userRootsCapturedAt = $null
try {
    if ([bool]$CallerContextPath -ne [bool]$CallerContextSha256) { throw 'caller_context_pair_required' }
    if ($CaptureCallerContext -and $CallerContextPath) { throw 'caller_context_mode_conflict' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $documents = $null
    if ($CaptureCallerContext) {
        $identityMode = 'caller_context_capture'
        Assert-PilotCaptureIdentity -ExpectedSid $ExpectedCurrentUserSid -ExpectedSession $ExpectedSessionId -CurrentSid $identity.User.Value -CurrentSession $sessionId -Administrator $administrator
        $documents = [Environment]::GetFolderPath('MyDocuments')
    } elseif ($CallerContextPath) {
        $identityMode = 'delegated_administrator'
        Assert-PilotDelegatedIdentity -ExpectedSession $ExpectedSessionId -CurrentSession $sessionId -Administrator $administrator
        $status = 'caller_context_invalid'
        $callerContext = Read-PilotCallerContext -LiteralPath $CallerContextPath -Sha256 $CallerContextSha256 -ExpectedSid $ExpectedCurrentUserSid -ExpectedSession $ExpectedSessionId
        $documents = Get-PilotOriginalDocuments -OriginalSid $callerContext.user_sid -ContextDocuments $callerContext.documents
        # Fail before creating a destination if machine trust changed since caller capture.
        $null = Get-PilotEffectiveRoots -CallerContext $callerContext
        $userRootsCapturedAt = $callerContext.captured_at
    } else {
        Assert-PilotIdentity -ExpectedSid $ExpectedCurrentUserSid -ExpectedSession $ExpectedSessionId -CurrentSid $identity.User.Value -CurrentSession $sessionId -Administrator $administrator
        $documents = [Environment]::GetFolderPath('MyDocuments')
    }
    $originalSid = New-Object Security.Principal.SecurityIdentifier($ExpectedCurrentUserSid)
    $status = 'invalid_output_directory'
    $run = Get-PilotDestination -OutputDirectory $OutputDirectory -DocumentsDirectory $documents
    $lab = [IO.Path]::GetDirectoryName($run)
    if (-not [IO.Directory]::Exists($lab)) { [void][IO.Directory]::CreateDirectory($lab) }
    New-PilotPrivateDirectory -Path $run -UserSid $originalSid -OwnerSid $identity.User
    $snapshotCreated = $true
    $private = [IO.Path]::Combine($run, 'private')
    New-PilotPrivateDirectory -Path $private -UserSid $originalSid -OwnerSid $identity.User

    if ($CaptureCallerContext) {
        $status = 'caller_context_capture_failed'
        $capturedRoots = Get-PilotRoots
        $context = [ordered]@{
            schema_version = 1; captured_at = [DateTime]::UtcNow.ToString('o')
            user_sid = $identity.User.Value; session_id = $sessionId; documents = $documents; roots = $capturedRoots
        }
        $contextPath = [IO.Path]::Combine($private, 'caller-context.json')
        Write-PilotJson $contextPath $context
        $stream = [IO.File]::OpenRead($contextPath)
        try { $contextHash = Get-PilotHash $stream }
        finally { $stream.Dispose() }
        [ordered]@{
            passed = $true; status = 'caller_context_captured'; identity_mode = $identityMode
            backup_complete = $false; snapshot_created = $true; file_count = 1; context_sha256 = $contextHash
            current_user_roots_captured_at = $context.captured_at
            root_counts = @{ current_user = $capturedRoots.CurrentUser.Count; local_machine = $capturedRoots.LocalMachine.Count }
            rollback_status = 'not_yet_verified'
        } | ConvertTo-Json -Depth 5
        exit 0
    }
    if ($null -ne $callerContext) {
        $status = 'caller_context_invalid'
        $contextRecord = Copy-PilotFile $CallerContextPath ([IO.Path]::Combine($private, 'caller-context.json'))
        if ($contextRecord.sha256 -cne $CallerContextSha256) { throw 'caller_context_hash_mismatch' }
        $files.Add($contextRecord)
    }

    $status = 'configuration_unreadable'
    $data = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'openems')
    $configRecord = Copy-PilotFile -Source ([IO.Path]::Combine($data, 'agent.json')) -Destination ([IO.Path]::Combine($private, 'agent.json'))
    $files.Add($configRecord)
    $config = [IO.File]::ReadAllText($configRecord.backup) | ConvertFrom-Json
    $origin = Get-PilotSetting $config 'server' ''
    $device = Get-PilotSetting $config 'devid' ''
    $uri = [Uri]$origin
    if (-not $device -or -not $uri.IsAbsoluteUri -or $uri.Scheme -notin @('http', 'https') -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) { throw 'configuration_unreadable' }
    $loopback = $uri.IsLoopback
    $complete.configuration = $true

    $status = 'backup_failed'
    $state = Get-PilotSetting $config 'state_path' ([IO.Path]::Combine($data, 'state.json'))
    $files.Add((Copy-PilotFile $state ([IO.Path]::Combine($private, 'state.json'))))
    $optionalAbsent = @()
    foreach ($name in @('control-pending.json', 'tamper-pending.json', 'browser-policies.json', 'application-control.json', 'usb-control.json', 'usb-inventory.json', 'uninstall.json', 'session.json')) {
        $source = [IO.Path]::Combine([IO.Path]::GetDirectoryName($state), $name)
        if (Test-PilotFilePresent $source) { $files.Add((Copy-PilotFile $source ([IO.Path]::Combine($private, $name)))) }
        else { $optionalAbsent += $source }
    }
    $complete.state = $true
    $status = 'authority_unreadable'
    $authorityRecord = Save-PilotAuthority -Config $config -Destination ([IO.Path]::Combine($private, 'authority.json'))
    if ($null -ne $authorityRecord.file) { $files.Add($authorityRecord.file) }
    $complete.authority = $true

    $status = 'backup_failed'
    $hosts = Get-PilotSetting $config 'hosts_path' ([IO.Path]::Combine([Environment]::SystemDirectory, 'drivers\etc\hosts'))
    $files.Add((Copy-PilotFile $hosts ([IO.Path]::Combine($private, 'hosts'))))
    if (Test-PilotFilePresent ($hosts + '.openems.bak')) { $files.Add((Copy-PilotFile ($hosts + '.openems.bak') ([IO.Path]::Combine($private, 'hosts.openems.bak')))) }
    $complete.hosts = $true

    $agentDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'openems')
    $agent = [IO.Path]::Combine($agentDirectory, 'openems-agent.exe')
    $files.Add((Copy-PilotFile $agent ([IO.Path]::Combine($private, 'openems-agent.exe'))))
    $session = [IO.Path]::Combine($agentDirectory, 'openems-session.exe')
    if (Test-PilotFilePresent $session) { $files.Add((Copy-PilotFile $session ([IO.Path]::Combine($private, 'openems-session.exe')))) }
    $agentVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($agent).FileVersion
    $complete.agent = $true
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')
    $service = Get-Service -Name 'openems-agent'
    $serviceInfo = @{ status = $service.Status.ToString(); start_type = $service.StartType.ToString() }
    $complete.service = $true

    $roots = Get-PilotEffectiveRoots -CallerContext $callerContext
    if ($null -eq $callerContext) { $userRootsCapturedAt = [DateTime]::UtcNow.ToString('o') }
    $rootCounts = @{ current_user = $roots.CurrentUser.Count; local_machine = $roots.LocalMachine.Count }
    Write-PilotJson ([IO.Path]::Combine($private, 'roots.json')) $roots
    $complete.roots = $true
    Write-PilotJson ([IO.Path]::Combine($private, 'registry.json')) (Get-PilotRegistrySnapshot -OriginalUserSid $originalSid.Value)
    $complete.registry = $true
    Import-Module (Join-Path $PSHOME 'Modules\DnsClient\DnsClient.psd1')
    Import-Module (Join-Path $PSHOME 'Modules\NetSecurity\NetSecurity.psd1')
    $dns = @{
        adapters = @(Get-DnsClientServerAddress | Select-Object InterfaceIndex, InterfaceAlias, AddressFamily, ServerAddresses)
        nrpt = @(Get-DnsClientNrptPolicy -Effective | Select-Object Namespace, NameServers, DnsSecValidationRequired, DnsSecQueryIPsecRequired)
        firewall = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.DisplayName -like '*openems*' -or $_.Name -like '*openems*' } | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile)
    }
    Write-PilotJson ([IO.Path]::Combine($private, 'dns.json')) $dns
    $complete.dns = $true

    $status = 'cached_msi_unavailable'
    $product = Get-PilotCachedProduct
    $files.Add((Copy-PilotFile $product.local_package ([IO.Path]::Combine($private, 'previous-agent.msi'))))
    $complete.cached_msi = $true
    $status = 'source_changed'
    Assert-PilotFilesUnchanged $files
    if ($null -ne $authorityRecord.absent) { Assert-PilotAuthorityAbsent $authorityRecord.absent }
    foreach ($source in $optionalAbsent) { if (Test-PilotFilePresent $source) { throw 'source_changed' } }
    if ($null -ne $callerContext) { $null = Get-PilotEffectiveRoots -CallerContext $callerContext }
    $status = 'backup_failed'
    Write-PilotJson ([IO.Path]::Combine($private, 'snapshot.json')) @{
        user_sid = $originalSid.Value; collector_user_sid = $identity.User.Value; session_id = $ExpectedSessionId; server = $origin; device_identity = $device
        identity_mode = $identityMode; caller_context_sha256 = $CallerContextSha256; current_user_roots_captured_at = $userRootsCapturedAt
        config = $config; service = $serviceInfo; agent_version = $agentVersion; product = $product; files = @($files.ToArray())
        absent_optional_files = @($optionalAbsent) + @($authorityRecord.absent | Where-Object { $null -ne $_ })
        captured_at = [DateTime]::UtcNow.ToString('o'); rollback_status = 'not_yet_verified'
    }
    $status = 'backup_complete'
} catch {
    $safe = @('identity_mismatch', 'session_mismatch', 'administrator_required', 'invalid_output_directory', 'source_changed', 'caller_context_pair_required', 'caller_context_mode_conflict', 'caller_context_requires_unelevated', 'caller_context_hash_mismatch', 'caller_context_stale', 'caller_context_invalid', 'original_documents_invalid', 'machine_roots_changed', 'directory_acl_invalid', 'authority_path_untrusted', 'authority_missing', 'authority_unreadable', 'authority_backup_privilege_unavailable', 'authority_privilege_restore_failed')
    if ($_.Exception.Message -in $safe) { $status = $_.Exception.Message }
}

$passed = $status -eq 'backup_complete'
$report = [ordered]@{
    passed = $passed; status = $status; backup_complete = $passed; snapshot_created = $snapshotCreated
    identity_mode = $identityMode; current_user_roots_captured_at = $userRootsCapturedAt
    origin_loopback = $loopback; topics = $complete; file_count = $files.Count; root_counts = $rootCounts
    file_hashes = @($files.ToArray() | ForEach-Object { @{ sha256 = $_.sha256; bytes = $_.bytes } })
    rollback_status = 'not_yet_verified'
}
# Only sanitized status, hashes and counts leave the private snapshot.
$report | ConvertTo-Json -Depth 6
if (-not $passed) { exit 1 }
