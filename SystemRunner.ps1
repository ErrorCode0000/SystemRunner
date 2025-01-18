# Yönetici yetkisi kontrolü ve yükseltme
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# TrustedInstaller servisini başlat
$service = Get-Service -Name "TrustedInstaller"
if ($service.Status -ne "Running") {
    Start-Service "TrustedInstaller"
    Start-Sleep -Seconds 2
}

# TrustedInstaller process ID'sini al
$trustedInstallerPid = (Get-Process -Name "TrustedInstaller" -ErrorAction SilentlyContinue).Id
if (-not $trustedInstallerPid) {
    Write-Error "TrustedInstaller process'i bulunamadı!"
    Exit
}

$source = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class TokenManipulator
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out IntPtr lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint TOKEN_ALL_ACCESS = 0x000F01FF;
    private const uint TOKEN_DUPLICATE = 0x0002;

    public static void CreateProcessWithToken(int processId, string command)
    {
        IntPtr sourceProcessHandle = IntPtr.Zero;
        IntPtr sourceTokenHandle = IntPtr.Zero;
        IntPtr duplicateTokenHandle = IntPtr.Zero;
        IntPtr processInfo = IntPtr.Zero;

        try
        {
            sourceProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (sourceProcessHandle == IntPtr.Zero) throw new Exception("OpenProcess failed");

            if (!OpenProcessToken(sourceProcessHandle, TOKEN_ALL_ACCESS, out sourceTokenHandle))
                throw new Exception("OpenProcessToken failed");

            if (!DuplicateTokenEx(sourceTokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out duplicateTokenHandle))
                throw new Exception("DuplicateTokenEx failed");

            IntPtr startupInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(STARTUPINFO)));
            Marshal.StructureToPtr(new STARTUPINFO() { cb = Marshal.SizeOf(typeof(STARTUPINFO)) }, startupInfo, false);

            if (!CreateProcessWithTokenW(duplicateTokenHandle, 0, null, command, 0, IntPtr.Zero, null, startupInfo, out processInfo))
                throw new Exception("CreateProcessWithTokenW failed");
        }
        finally
        {
            if (sourceProcessHandle != IntPtr.Zero) CloseHandle(sourceProcessHandle);
            if (sourceTokenHandle != IntPtr.Zero) CloseHandle(sourceTokenHandle);
            if (duplicateTokenHandle != IntPtr.Zero) CloseHandle(duplicateTokenHandle);
            if (processInfo != IntPtr.Zero) CloseHandle(processInfo);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
}
"@

Add-Type -TypeDefinition $source -Language CSharp

try {
    [TokenManipulator]::CreateProcessWithToken($trustedInstallerPid, "powershell.exe")
    Write-Host "PowerShell başarıyla TrustedInstaller yetkisiyle başlatıldı!" -ForegroundColor Green
}
catch {
    Write-Error "Hata oluştu: $_"
}
