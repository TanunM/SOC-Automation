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

## Network Architecture & Workflow

This diagram outlines the complete network architecture of the automated SOC setup.  
It shows how **Wazuh** gathers logs from the **Windows 10 client**, and how these logs are subsequently forwarded to **Shuffle** for enrichment before being logged as alerts in **The Hive** for incident response.  

---

### Workflow Diagram
This simplified diagram illustrates the **step-by-step flow** of a security incident from its initial detection to its final resolution.  
It specifically highlights the journey of security alerts, showing how they transition:  

- From the detection phase (**Wazuh**)  
- Through the enrichment process (**Shuffle**)  
- Into a centralized case management system (**The Hive**)  

---

### Shuffle Automation Workflow
This detailed visualization of the **Shuffle workflow** provides a closer look at the automated process.  
It shows precisely how security alerts are handled:  

1. Alerts are **collected and processed**  
2. Alerts are **enriched with threat intelligence** via the **VirusTotal API**  
3. Alerts are **forwarded to The Hive** for incident case creation  
4. Analysts are **notified via email** of critical security events  

---

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

## Wazuh Installation

### Wazuh Dashboard
Install the Wazuh dashboard on the **Ubuntu 24.04 VM**.
Wazuh official website provides a [guide](https://documentation.wazuh.com/current/installation-guide/index.html) A simplified, step-by-step guide is outlined below for this process.
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
8. Login using the credential which can be found in the password file.

 ## Wazuh Agent Installation
Install the **Wazuh agent** on the **Windows 10 VM** to enable log collection.  

#### 1. Open PowerShell
Open **PowerShell as Administrator** on the Windows 10 VM.

#### 2. Run the Installation Command
In the Wazuh Dashboard, click **Add Agent** to generate a PowerShell command for agent installation.  
Replace the placeholder `Your IP address here` with the IP address of your **Wazuh Manager**.  

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -Outfile ${env.tmp}\wazuh-agent.msi; msiexec.exe /i ${env.tmp}\wazuh-agent.msi /q WAZUH_MANAGER='Your IP address here' WAZUH_AGENT_NAME='Your cluster name here' WAZUH_REGISTRATION_SERVER='Your IP address here'
```
#### 3. Start the Service
```powershell
net start wazuhsvc
```
Once started Wazuh Dashboard will show 1 active agent.

## TheHive Installation

Install TheHive with necessary dependencies on the Ubuntu 22.04 VM.  
A simplified step-by-step guide is provided below. For full details, refer to the [Strangebee guide](https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/).

### Dependencies & JVM
```bash
sudo apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```
1. Install Amazon Corretto 11
```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
```
2. Set JAVA_HOME
```bash
echo 'JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"' | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```
### Apache Cassandra
1. Add repository
```bash
wget -qO- https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 41x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
```
2. Install Cassandra
```bash
sudo apt update
sudo apt install cassandra
```
### Elasticsearch
1. Add repository
```bash
wget -qO- https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
```
2. Install Elasticsearch
```bash
sudo apt update
sudo apt install elasticsearch
```
### TheHive
1. Download package
```bash
wget -O /tmp/thehive_5.5.7-1_all.deb https://thehive.download.strangebee.com/5.5/deb/thehive_5.5.7-1_all.deb
wget -O /tmp/thehive_5.5.7-1_all.deb.sha256 https://thehive.download.strangebee.com/5.5/sha256/thehive_5.5.7-1_all.deb.sha256
wget -O /tmp/thehive_5.5.7-1_all.deb.asc https://thehive.download.strangebee.com/5.5/asc/thehive_5.5.7-1_all.deb.asc
```
2. Verify integrity and GPG signature
```bash
sha256sum /tmp/thehive_5.5.7-1_all.deb
wget -O /tmp/strangebee.gpg https://keys.download.strangebee.com/latest/gpg/strangebee.gpg
gpg --import /tmp/strangebee.gpg
gpg --verify /tmp/thehive_5.5.7-1_all.deb.asc /tmp/thehive_5.5.7-1_all.deb
```
3. Install TheHive
```bash
sudo apt-get update
sudo apt-get install /tmp/thehive_5.5.7-1_all.deb
```
## Cassandra + Elasticsearch + TheHive configuration

### Cassandra Configuration
1. Navigate to Cassandra configuration directory:
```bash
cd /etc/cassandra/
```
2. Edit cassandra.yaml to configure for TheHive:
```
cluster_name: '<desired name>'
# rpc_address: '<IP address of the Hive server>'
# listen_address: '<IP address of the Hive server>'
# seed_provider: ...
# seeds: '<IP address of the Hive server>:7000'
```
3. Save the changes
4. Delete older files
```bash
rm -rf /var/lib/cassandra/*
```
5. Restart and enable Cassandra service
```bash
sudo systemctl restart cassandra.service
sudo systemctl enable cassandra
```
6. Verify status
```bash
sudo systemctl status cassandra.service
```

### Elasticsearch Configuration
1. Navigate to Elasticsearch config directory
```bash
cd /etc/elasticsearch/
```
2. Edit elasticsearch.yml file with the following changes:
```
cluster.name: 'thehive'
node.name: node-1
network.host: <TheHive_IP>
http.port: 9200
cluster.initial_master_nodes: ["node-1"]
```
3. Save changes
4. Restart and enable Elasticsearch service
```bash
sudo systemctl restart elasticsearch.service
sudo systemctl enable elasticsearch.service
```

### TheHive Configuration
1. Ensure proper file access
```bash
ls -la /opt/thp
```
2. Give thehive user access to /opt/thp
```bash
sudo chown -R thehive:thehive /opt/thp
```
3. Edit TheHive configuration file
```bash
sudo nano /etc/thehive/application.conf
```
 Set the following:
```
application.baseUrl = "http://<IP address of the Hive server>:9000"
In db.janusgraph section:
hostname = ["<IP address of the Hive server>"]
cluster-name = tm
index.search.hostname = ["<IP address of the Hive server>"]
If Elasticsearch requires auth:
index.elasticsearch.auth.username = "<elasticsearch-username>"
index.elasticsearch.auth.password = "<elasticsearch-password>"
```
4. Start and enable TheHive service
```bash
sudo systemctl start thehive
sudo systemctl enable thehive
```
5. Access the web interface at:
```
http://<YOUR_SERVER_ADDRESS>:9000
Default login credentials:
Username: admin@thehive.local
Password: secret
```




