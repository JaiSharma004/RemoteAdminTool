# Windows Reverse SSH C2 Framework

> **⚠️ DISCLAIMER: EDUCATIONAL PURPOSES ONLY**
> This project was created strictly for educational purposes and cybersecurity research. It is designed to simulate an adversary's post-exploitation workflow to better understand Windows persistence mechanisms, firewall traversal, and detection engineering. I am not responsible for any misuse of this code.

##  Project Overview
This is a Proof-of-Concept Command & Control (C2) agent that demonstrates how legitimate system administration tools can be weaponized to bypass standard perimeter defenses.

Unlike traditional malware that relies on custom TCP sockets (which are easily flagged), this tool utilizes **"Living off the Land" (LotL)** techniques by leveraging **OpenSSH** and **PowerShell** to establish encrypted, persistent reverse tunnels.

##  Key Features

* **Reverse SSH Tunneling:** Bypasses inbound firewall rules and NAT by initiating the connection from the victim to the C2 server (EC2).
* **Out-of-Band Signaling:** Integrates with the **Telegram API** to act as a "Dead Drop Resolver," notifying the operator immediately when a target comes online.
* **Persistence Mechanisms:** Maintains access across reboots using:
    * Windows Scheduled Tasks (Startup & Immediate execution).
    * Windows Services.
* **Automated Provisioning:** The installer script automatically manages SSH keys, configures `sshd_config`, and modifies local firewall rules to permit the tunnel.
* **Stealth:** Utilizes standard administrative binaries (`ssh.exe`, `powershell.exe`) to blend in with normal administrator traffic.

##  Architecture

1.  **Staging:** The PowerShell installer downloads the payload and configures the environment.
2.  **Execution:** A Scheduled Task triggers the connection script.
3.  **Signaling:** The C2 agent contacts the Telegram Bot API to report the machine's status.
4.  **Connection:** The agent establishes a Reverse SSH tunnel (`-R`) to the AWS EC2 instance.
5.  **Control:** The operator connects to the EC2 instance via SSH, pivoting through the established tunnel to access the target shell passwordlessly.

##  Setup & Configuration

**Prerequisites:**
* An AWS EC2 instance (Ubuntu/Debian) acting as the C2 Server.
* A Telegram Bot Token and Chat ID.
* A web server (S3 bucket or simple Python server) to host the payloads.

**Installation Steps:**
1.  **Sanitize & Configure:**
    * Review `installer.ps1`, `test.ps1` (Connection Logic), and `key.ps1`.
    * Replace placeholder variables with your infrastructure details.
2.  **Build the Bot:**
    * Compile the `TeleBot.cs` source code to generate the notifier executable.
3.  **Generate Keys:**
    * Generate a new SSH keypair (`id_rsa` / `id_rsa.pub`) for the tunnel authentication.
4.  **Deployment:**
    * Host the modified scripts and public keys on your web server.
    * Execute the `installer.ps1` script on the test VM (requires Admin privileges).

## 🛡️ Blue Team & Detection Engineering
*This section documents the artifacts left by this tool to assist in writing SIEM rules (Wazuh/Splunk).*

**Indicators of Compromise (IoCs):**

* **Network:**
    * Outbound traffic on Port 22 (SSH) to unknown public IPs.
    * DNS queries to `api.telegram.org` from non-browser processes.
* **File System:**
    * Presence of `C:\ProgramData\duckyc2key.pem`.
    * Modifications to `C:\ProgramData\ssh\sshd_config` disabling `StrictModes` or `AuthorizedKeysFile`.
* **Persistence:**
    * Scheduled Task named `SSHTEST` or `SSHTEST_IMMEDIATE`.
    * PowerShell processes running with `-WindowStyle Hidden` and `-ExecutionPolicy Bypass` arguments.

---
