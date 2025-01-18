# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    $CommandLine = "-ExecutionPolicy Bypass -File `"" + $MyInvocation.MyCommand.Path + "`""
    Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $CommandLine
    Exit
}

# ExecutionPolicy'yi otomatik ayarla
Set-ExecutionPolicy Bypass -Scope Process -Force

$source = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

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

    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();

    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint TOKEN_ALL_ACCESS = 0x000F01FF;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;

    public static void CreateProcessWithToken(int processId, string command)
    {
        IntPtr sourceProcessHandle = IntPtr.Zero;
        IntPtr sourceTokenHandle = IntPtr.Zero;
        IntPtr duplicateTokenHandle = IntPtr.Zero;
        IntPtr processInfo = IntPtr.Zero;

        try
        {
            sourceProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (sourceProcessHandle == IntPtr.Zero) 
                throw new Exception($"OpenProcess failed with error: {GetLastError()}");

            if (!OpenProcessToken(sourceProcessHandle, TOKEN_ALL_ACCESS, out sourceTokenHandle))
                throw new Exception($"OpenProcessToken failed with error: {GetLastError()}");

            if (!DuplicateTokenEx(sourceTokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out duplicateTokenHandle))
                throw new Exception($"DuplicateTokenEx failed with error: {GetLastError()}");

            IntPtr startupInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(STARTUPINFO)));
            Marshal.StructureToPtr(new STARTUPINFO() { cb = Marshal.SizeOf(typeof(STARTUPINFO)) }, startupInfo, false);

            if (!CreateProcessWithTokenW(duplicateTokenHandle, 0, null, command, CREATE_NEW_CONSOLE, IntPtr.Zero, null, startupInfo, out processInfo))
                throw new Exception($"CreateProcessWithTokenW failed with error: {GetLastError()}");
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

function Start-TrustedProcess {
    try {
        # TrustedInstaller servisini başlat ve bekle
        $service = Get-Service -Name "TrustedInstaller" -ErrorAction Stop
        if ($service.Status -ne "Running") {
            Start-Service "TrustedInstaller" -ErrorAction Stop
            $service.WaitForStatus("Running", "00:00:30")
        }

        # Process'i bulmak için birkaç deneme yap
        $maxAttempts = 5
        $attempt = 0
        $trustedInstallerPid = $null

        while ($attempt -lt $maxAttempts -and -not $trustedInstallerPid) {
            $process = Get-Process -Name "TrustedInstaller" -ErrorAction SilentlyContinue
            if ($process) {
                $trustedInstallerPid = $process.Id
            }
            else {
                Start-Sleep -Seconds 1
            }
            $attempt++
        }

        if (-not $trustedInstallerPid) {
            throw "TrustedInstaller process'i bulunamadı!"
        }

        # C# kodunu yükle
        if (-not ("TokenManipulator" -as [type])) {
            Add-Type -TypeDefinition $source -Language CSharp
        }

        # PowerShell'i TrustedInstaller yetkisiyle başlat
        [TokenManipulator]::CreateProcessWithToken($trustedInstallerPid, "powershell.exe")
        Write-Host "PowerShell başarıyla TrustedInstaller yetkisiyle başlatıldı!" -ForegroundColor Green
    }
    catch {
        Write-Host "Hata oluştu: $_" -ForegroundColor Red
        Start-Sleep -Seconds 3
    }
}

# Ana işlemi başlat
Start-TrustedProcess
