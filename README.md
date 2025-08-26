# SOC Automation Lab

## Introduction
This project provides a guide for implementing an automated Security Operations Center (SOC) workflow in a virtualized, on-premise environment. The system uses open-source tools—**Wazuh**, **The Hive**, and **Shuffle**—to automate the detection, analysis, and response to security incidents. The primary goal is to handle threats like **Mimikatz** with minimal manual effort, improving the efficiency of security operations.

## Objectives
- **Automate Threat Detection and Response**: Enhance operational efficiency and reduce manual workload by automating the processes of incident detection, analysis, and management.  
- **Integrate Core SOC Tools**: Connect Wazuh for monitoring and detection, The Hive for case management, and Shuffle for orchestration.  
- **Implement Real-Time Alerting**: Provide analysts with immediate notifications for critical incidents.  
- **Enrich Incident Data**: Augment security alerts with external threat intelligence using the VirusTotal API.

## Requirements and Tools

| **Category**       | **Tools and Requirements**                                                                 |
|---------------------|---------------------------------------------------------------------------------------------|
| **Virtualization**  | Oracle VM VirtualBox Manager                                                                |
| **Operating Systems** | Microsoft Windows 10, Ubuntu Server 24.04.1 LTS, Ubuntu Server 22.04 LTS                  |
| **Security Tools**  | Wazuh, Sysmon, TheHive, Shuffle, Mimikatz                                                   |
| **Scripting**       | PowerShell, Bash

## Network and VM Setup

### Virtual Machine Installation
Set up three virtual machines (VMs) with the following specifications:

- **Ubuntu 24.04 VM**: 8 GB RAM, 2 processors, 50 GB disk space (for Wazuh dashboard)  
- **Ubuntu 20.04 VM**: 8 GB RAM, 2 processors, 50 GB disk space (for other components)  
- **Windows 10 VM**: 8 GB RAM, 2 processors, 50 GB disk space (as the client endpoint)  

### Network Configuration
Establish a unified network to enable communication between the VMs.

- **Create a NAT Network**: In VirtualBox, create a new NAT network with the IP address range `192.168.20.0/24`. This allows VMs to communicate with each other and access the internet.  
- **Assign Network to VMs**: For each VM, configure its network adapter to use the custom NAT network.  

## Endpoint Installation

### Install Sysmon on Windows 10
Sysmon is a critical tool for detailed logging on the Windows endpoint.

1. **Download Sysmon**: Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and a pre-configured `sysmonconfig.xml` file from [Sysmon Modular](https://github.com/olafhartong/sysmon-modular).  
2. **Navigate to Directory**: In PowerShell (as Administrator), navigate to the Sysmon directory:  

```powershell
cd C:\Users\Downloads\sysmon
```
3. Install Configuration: Install the Sysmon configuration with the following command:
```powershell
.\sysmon64.exe -i sysmonconfig.xml
```
4.Verify Installation: Check if the Sysmon process is running:
```powershell
Get-Process sysmon64
```

## Wazuh Installation and Configuration

### Wazuh Dashboard
Install and configure the Wazuh dashboard on the **Ubuntu 24.04 VM**.

1. Update System Packages:  
```bash
sudo apt-get update && sudo apt-get upgrade -y
```
2. Install Dependencies:
```bash
sudo apt-get install -y curl apt-transport-https lsb-release gnupg
```
3. Install Wazuh Dashboard:
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash wazuh-install.sh -a
```
4. Verify Wazuh Installation:
```bash
sudo systemctl status wazuh-manager
```
5. Configure Firewall Rules:
```bash
sudo ufw allow from [Windows_10_IP_ADDRESS]
```
6. Retrieve Credentials:
The password for the admin user is stored in wazuh-passwords.txt. Extract it with:
```bash
tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```
7. Access the Dashboard:
Open a browser and navigate to:
```
https://<Wazuh_Dashboard_VM_IP>:443
```

