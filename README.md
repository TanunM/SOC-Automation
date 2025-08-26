# **SOC Automation Lab**

## **Introduction**

This project provides a guide for implementing an automated Security Operations Center (SOC) workflow in a virtualized, on-premise environment. The system uses open-source tools—**Wazuh**, **The Hive**, and **Shuffle**—to automate the detection, analysis, and response to security incidents. The primary goal is to handle threats like Mimikatz with minimal manual effort, improving the efficiency of security operations.

## **Objectives**
* **Automate Threat Detection and Response:** Enhance operational efficiency and reduce manual workload by automating the processes of incident detection, analysis, and management.
* **Integrate Core SOC Tools:** Connect **Wazuh** for monitoring and detection, **The Hive** for case management, and **Shuffle** for orchestration.
* **Implement Real-Time Alerting:** Provide analysts with immediate notifications for critical incidents.
* **Enrich Incident Data:** Augment security alerts with external threat intelligence using the VirusTotal API.

## **Requirements and Tools**
| Category | Tools and Requirements |
 | ----- | ----- |
| Virtualization | Oracle VM VirtualBox Manager |
| Operating Systems | Microsoft Windows 10, Ubuntu Server 24.04.1 LTS, Ubuntu Server 22.04 LTS |
| Security Tools | Wazuh, Sysmon, TheHive, Shuffle, Mimikatz |
| Scripting | PowerShell, Bash |
| Threat Intelligence | VirusTotal API Key |

## **Network Architecture & Workflow**

**Network Architecture Diagram:**
This diagram outlines the complete network architecture of the automated SOC setup. It shows how Wazuh gathers logs from the Windows 10 client, and how these logs are subsequently forwarded to Shuffle for enrichment before being logged as alerts in The Hive for incident response.

  <img width="555" height="489" alt="Architecture" src="https://github.com/user-attachments/assets/16edcbea-12b8-425a-8e9a-bbb6cbb5e564" />

**Workflow Diagram:**
This simplified diagram illustrates the step-by-step flow of a security incident from its initial detection to its final resolution. It specifically highlights the journey of security alerts, showing how they transition:
* From the detection phase (**Wazuh**)
* Through the enrichment process (**Shuffle**)
* Into a centralized case management system (**The Hive**)

  <img width="885" height="124" alt="workflow" src="https://github.com/user-attachments/assets/79cad15a-d973-4d8e-a11e-93f7a9aed007" />

**Shuffle Automation Workflow:**
This detailed visualization of the Shuffle workflow provides a closer look at the automated process. It shows precisely how security alerts are handled:
* Alerts are collected and processed
* Alerts are enriched with threat intelligence via the VirusTotal API
* Alerts are forwarded to The Hive for incident case creation
* Analysts are notified via email of critical security events

  <img width="1388" height="477" alt="Shuffle" src="https://github.com/user-attachments/assets/4f8a7e43-7593-40dc-a1a0-4a725b60f405" />

## **Network and VM Setup**

### **Virtual Machine Installation**
Set up three virtual machines (VMs) with the following specifications. **Note:** These are recommended minimums and can be adjusted based on available host machine resources.
* **Ubuntu 24.04 VM:** 8 GB RAM, 2 processors, 50 GB disk space (for Wazuh dashboard)
* **Ubuntu 22.04 VM:** 8 GB RAM, 2 processors, 50 GB disk space (for other components)
* **Windows 10 VM:** 8 GB RAM, 2 processors, 50 GB disk space (as the client endpoint)

### **Network Configuration**
Establish a unified network to enable communication between the VMs.
1. **Create a NAT Network:** In VirtualBox, create a new NAT network with the IP address range `192.168.20.0/24`. This allows VMs to communicate with each other and access the internet.
2. **Assign Network to VMs:** For each VM, configure its network adapter to use the custom NAT network.

## **Endpoint Installation**

### **Install Sysmon on Windows 10**
Sysmon is a critical tool for detailed logging on the Windows endpoint.
1. **Download Sysmon:** Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and a pre-configured `sysmonconfig.xml` file from 1. **Download Sysmon:** Download  [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) from Microsoft Sysinternals and a pre-configured `sysmonconfig.xml` file from Sysmon Modular..
2. **Navigate to Directory:** In PowerShell (as Administrator), navigate to the directory where you downloaded the files. For example, `cd C:\Users\YourUsername\Downloads\sysmon`.
3. **Install Configuration:** Install the Sysmon configuration with the following command:
   ```
   .\Sysmon64.exe -i sysmonconfig.xml   
   ```
4. **Verify Installation:** Check if the Sysmon process is running:
   ```
   Get-Process sysmon64   
   ```
   To verify Sysmon is logging correctly, open the Windows Event Viewer and check the **Applications and Services Logs > Microsoft > Windows > Sysmon > Operational** log for new events.

## **Wazuh Installation**

### **Wazuh Dashboard**
Install the Wazuh dashboard on the Ubuntu 24.04 VM. The Wazuh official website provides a [guide](https://documentation.wazuh.com/current/installation-guide/index.html), and a simplified, step-by-step guide is outlined below for this process.
1. **Update System Packages:**
   ```
   sudo apt-get update && sudo apt-get upgrade -y   
   ```
2. **Install Dependencies:**
   ```
   sudo apt-get install -y curl apt-transport-https lsb-release gnupg 
   ```
3. **Install Wazuh Dashboard:**
   ```
   curl -sO [https://packages.wazuh.com/4.12/wazuh-install.sh](https://packages.wazuh.com/4.12/wazuh-install.sh) && sudo bash wazuh-install.sh -a   
   ```
4. **Verify Wazuh Installation:**
   ```
   sudo systemctl status wazuh-manager  
   ```
5. **Configure Firewall Rules:**
   ```
   sudo ufw allow from [Windows_10_IP_ADDRESS]   
   ```
6. **Retrieve Credentials:** The password for the admin user is stored in `wazuh-passwords.txt`. From the directory where you ran the installation script, extract it with:
   ```
   tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt   
   ```
7. **Access the Dashboard:** Open a browser and navigate to:
   ```
   https://<Wazuh_Dashboard_VM_IP>:443  
   ```
   Login using the credential which can be found in the password file.

### **Wazuh Agent Installation**
Install the Wazuh agent on the Windows 10 VM to enable log collection.
1. **Open PowerShell:** Open PowerShell as Administrator on the Windows 10 VM.
2. **Run the Installation Command:** In the Wazuh Dashboard, click **Add Agent** and fill in the information to generate a PowerShell command for agent installation.
   * **Action Required:** Replace the placeholder `Your IP address here` with the IP address of your Wazuh Manager.
   * **Action Required:** Replace `Your cluster name here` with a unique name for the agent (e.g., `Windows10-Endpoint`).
   ```
   Invoke-WebRequest -Uri [https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi) -Outfile ${env.tmp}\wazuh-agent.msi; msiexec.exe /i ${env.tmp}\wazuh-agent.msi /q WAZUH_MANAGER='Your IP address here' WAZUH_AGENT_NAME='Your cluster name here' WAZUH_REGISTRATION_SERVER='Your IP address here' 
   ```
3. **Start the Service:**
   ```
   net start wazuhsvc
   
   ```
   Once started, the Wazuh Dashboard will show 1 active agent.

   <img width="824" height="578" alt="Active agent" src="https://github.com/user-attachments/assets/e8433467-f948-46aa-84c4-9f510e15f9e5" />

## **TheHive Installation**
Install TheHive with necessary dependencies on the Ubuntu 22.04 VM. A simplified step-by-step guide is provided below. For full details, refer to the [Strangebee guide](https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/).

### **Dependencies & JVM**
```
sudo apt install wget gnupg apt-transport-https ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```
**Install Amazon Corretto 11**
```
wget -qO- [https://apt.corretto.aws/corretto.key](https://apt.corretto.aws/corretto.key) | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] [https://apt.corretto.aws](https://apt.corretto.aws) stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
```
**Set JAVA_HOME**
```
echo 'JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"' | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

### **Apache Cassandra**
**Add repository**
```
wget -qO- [https://downloads.apache.org/cassandra/KEYS](https://downloads.apache.org/cassandra/KEYS) | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] [https://debian.cassandra.apache.org](https://debian.cassandra.apache.org) 41x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
```
**Install Cassandra**
```
sudo apt update
sudo apt install cassandra
```

### **Elasticsearch**
**Add repository**
```
wget -qO- [https://artifacts.elastic.co/GPG-KEY-elasticsearch](https://artifacts.elastic.co/GPG-KEY-elasticsearch) | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] [https://artifacts.elastic.co/packages/7.x/apt](https://artifacts.elastic.co/packages/7.x/apt) stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
```
**Install Elasticsearch**
```
sudo apt update
sudo apt install elasticsearch
```

### **TheHive**
**Download package**
```
wget -O /tmp/thehive_5.5.7-1_all.deb [https://thehive.download.strangebee.com/5.5/deb/thehive_5.5.7-1_all.deb](https://thehive.download.strangebee.com/5.5/deb/thehive_5.5.7-1_all.deb)
wget -O /tmp/thehive_5.5.7-1_all.deb.sha256 [https://thehive.download.strangebee.com/5.5/sha256/thehive_5.5.7-1_all.deb.sha256](https://thehive.download.strangebee.com/5.5/sha256/thehive_5.5.7-1_all.deb.sha256)
wget -O /tmp/thehive_5.5.7-1_all.deb.asc [https://thehive.download.strangebee.com/5.5/asc/thehive_5.5.7-1_all.deb.asc](https://thehive.download.strangebee.com/5.5/asc/thehive_5.5.7-1_all.deb.asc)
```
**Verify integrity and GPG signature**
```
sha256sum /tmp/thehive_5.5.7-1_all.deb
wget -O /tmp/strangebee.gpg [https://keys.download.strangebee.com/latest/gpg/strangebee.gpg](https://keys.download.strangebee.com/latest/gpg/strangebee.gpg)
gpg --import /tmp/strangebee.gpg
gpg --verify /tmp/thehive_5.5.7-1_all.deb.asc /tmp/thehive_5.5.7-1_all.deb
```
**Install TheHive**
```
sudo apt-get update
sudo apt-get install /tmp/thehive_5.5.7-1_all.deb
```

## **Cassandra + Elasticsearch + TheHive configuration**

**Cassandra Configuration**
1. **Navigate to Cassandra configuration directory:**
   ```
   cd /etc/cassandra/   
   ```
2. **Edit `cassandra.yaml` to configure for TheHive:**
   ```
   sudo nano cassandra.yaml   
   ```
   * **Action Required:** Uncomment and set the following, replacing `<IP address of the Hive server>` with your Ubuntu 22.04 VM's IP address.
   ```
   cluster_name: 'TheHive_Cluster'
   rpc_address: '<IP address of the Hive server>'
   listen_address: '<IP address of the Hive server>'
   seed_provider: ...
   seeds: '<IP address of the Hive server>:7000'   
   ```
3. **Save the changes.**
4. **Delete older files:**
   ```
   sudo rm -rf /var/lib/cassandra/*   
   ```
5. **Restart and enable Cassandra service:**
   ```
   sudo systemctl restart cassandra.service
   sudo systemctl enable cassandra  
   ```
6. **Verify status:**
   ```
   sudo systemctl status cassandra.service 
   ```

**Elasticsearch Configuration**
1. **Navigate to Elasticsearch config directory:**
   ```
   cd /etc/elasticsearch/  
   ```
2. **Edit `elasticsearch.yml` file with the following changes:**
   ```
   sudo nano elasticsearch.yml  
   ```
   * **Action Required:** Replace `<TheHive_IP>` with your Ubuntu 22.04 VM's IP address.
   ```
   cluster.name: 'thehive'
   node.name: node-1
   network.host: <TheHive_IP>
   http.port: 9200
   cluster.initial_master_nodes: ["node-1"]   
   ```
3. **Save changes.**
4. **Restart and enable Elasticsearch service:**
   ```
   sudo systemctl restart elasticsearch.service
   sudo systemctl enable elasticsearch.service 
   ```

**TheHive Configuration**
1. **Ensure proper file access:**
   ```
   sudo chown -R thehive:thehive /opt/thp  
   ```
2. **Edit TheHive configuration file:**
   ```
   sudo nano /etc/thehive/application.conf   
   ```
3. **Set the following:**
   * **Action Required:** Replace `<IP address of the Hive server>` with your Ubuntu 22.04 VM's IP address.
   ```
   application.baseUrl = "http://<IP address of the Hive server>:9000"   
   ```
   * **Action Required:** In the `db.janusgraph` section, update the hostnames.
   ```
   db.janusgraph {
     hostname = ["<IP address of the Hive server>"]
     cluster-name = tm
     index.search.hostname = ["<IP address of the Hive server>"]
     ...
   }   
   ```
   * **Note:** If Elasticsearch requires authentication, uncomment and set the username and password.
   ```
   index.elasticsearch.auth.username = "<elasticsearch-username>"
   index.elasticsearch.auth.password = "<elasticsearch-password>"   
   ```
4. **Start and enable TheHive service:**
   ```
   sudo systemctl start thehive
   sudo systemctl enable thehive   
   ```
5. **Access the web interface at:**
   ```
   http://<YOUR_SERVER_ADDRESS>:9000   
   ```
   Default login credentials:
   Username: `admin@thehive.local`
   Password: `secret`

## **Wazuh Agent Configuration (Sysmon and Mimikatz Log Collection)**

### **Configure Agent on Windows 10 for Sysmon**
1. Navigate to the Wazuh agent installation directory on the Windows 10 machine.
2. Locate the configuration file: `ossec.conf`.
3. Make a backup of the file before editing.
4. Add the following section **inside** the `<ossec_config>` tags:
   ```
   <localfile>
       <location>Microsoft-Windows-Sysmon/Operational</location>
       <log_format>eventchannel</log_format>
   </localfile>   
   ```
5. Save changes.
6. Restart the Wazuh service using PowerShell or Service Manager.
7. In the Wazuh Dashboard, search for "sysmon" under events. If configured correctly, you should now see Sysmon logs being generated.

   <img width="923" height="592" alt="wazuh-sysmon" src="https://github.com/user-attachments/assets/29d4a4e7-888f-4446-8e4e-421d9dd76c7b" />

### **Wazuh Configuration for Mimikatz Activity Detection**
This section configures the Wazuh Manager to collect and visualize logs from a simulated Mimikatz attack. It also includes creating a custom rule to generate alerts when Mimikatz is executed on the Windows endpoint.

## **Preparing Windows Endpoint**
1. **Exclude Download Folder in Windows Defender:** Before downloading Mimikatz, create an exclusion to prevent Defender from deleting it.
   * Open Windows Security.
   * Go to **Virus & threat protection**.
   * Under **Virus & threat protection settings**, click **Manage settings**.
   * Scroll to **Exclusions** → **Add or remove exclusions**.
   * Click **+ Add an exclusion** → **Folder**, and select the folder where Mimikatz will be downloaded (e.g., `C:\downloads`).
2. **Download Mimikatz:** Download [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases) to the excluded folder.
### **Running Mimikatz**
Open PowerShell as Administrator and execute Mimikatz:
```
cd C:\downloads\mimikatz_trunk\x64
.\mimikatz.exe
```

  <img width="585" height="240" alt="mimikatz" src="https://github.com/user-attachments/assets/bf9a1db1-db6b-4e7d-b23a-c467cef560eb" />

### **Configure Wazuh Manager for Full Logging**
On the Ubuntu machine running Wazuh Manager navigate to:
```
cd /var/ossec/etc/
sudo cp ossec.conf ossec.conf.bak    # Backup
sudo nano ossec.conf
```
Inside the `<ossec_config>` block, modify:
```
<logall>yes</logall>
<logall_json>yes</logall_json>
```
Save and restart the manager:
```
sudo systemctl restart wazuh-manager.service
```

### **Create Wazuh Archive Index in Dashboard**
The `wazuh-install.sh -a` script automatically sets up Filebeat and the `wazuh-archives-*` index pattern, so no manual configuration is needed here.
1. Log into Wazuh Dashboard.
2. Go to **Discover** and select the `wazuh-archives-*` index to view the full log stream (including Mimikatz events).

  <img width="766" height="342" alt="index-pattern" src="https://github.com/user-attachments/assets/4d09b7e6-0ab5-46f2-9b6b-2860f31e79fe" />

  <img width="256" height="352" alt="Discovery" src="https://github.com/user-attachments/assets/fc49d67e-8755-4909-abc5-fa6a7fa6383c" />

### **Custom Rule for Mimikatz Detection**
In the Wazuh Manager ruleset, add a custom rule to detect process creation events (Sysmon Event ID 1) for Mimikatz.
```
<ruleset>
  <rule id="100002" level="15">
    <if_sid>60001</if_sid>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Alert</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</ruleset>
```
* **Note:** I've changed `<if_group>` to `<if_sid>` with the Sysmon rule ID 60001 for better specificity. You can also use `if_group` if the rule is part of a specific Sysmon group.

Restart Wazuh Manager
```
sudo systemctl restart wazuh-manager.service
```

### **Verification**
Run Mimikatz again on the Windows endpoint.
In Wazuh Dashboard → Discover, search for `mimikatz`.
You should now see:
* Raw Sysmon process creation logs.
* A high-level alert tagged “Mimikatz Alert” (with MITRE technique T1003).

  <img width="931" height="608" alt="wazuh-mimikatz" src="https://github.com/user-attachments/assets/0a5311fc-b39e-45ba-91af-4e76e18d6a20" />

## **Workflow Configuration**

### **Establish Wazuh-Shuffle Connection:**
1. In the Shuffle dashboard, create a new workflow.
2. Add a **Webhook** trigger to the workflow canvas. This will generate a unique URL for receiving alerts.
3. Copy the Webhook URI.
4. On the Wazuh Manager VM, edit the `ossec.conf` file and go to the `<integration>` tag.
5. **Action Required:** Paste the copied Webhook URL into the `hook_url` field.
   ```
   <integration>
       <name>shuffle</name>
       <hook_url>http://<YOUR_SHUFFLE_URL>/api/v1/hooks/<HOOK_ID></hook_url>
       <rule_id>100002</rule_id>
       <alert_format>json</alert_format>
   </integration>   
   ```
6. Save the file and restart the Wazuh Manager service to apply the changes.

   <img width="1065" height="589" alt="webhook-url" src="https://github.com/user-attachments/assets/ba18aa9f-1cf4-461a-8d75-51fdcdab0c42" />

### **Parse data**
After an alert is received, Shuffle must parse the data to extract the SHA256 hash of the malicious file. This is accomplished using a **Regex Capture Group** action.
1. Click on the "Change ME" icon and change **Find Actions** to **Repeat back to me**.
2. Add the following Regex:
   ```
   SHA256=([A-Fa-f0-9]{64})  
   ```

  <img width="1066" height="589" alt="shuffletools-conf" src="https://github.com/user-attachments/assets/42e72589-45df-496f-8936-6ad2751d5d01" />

  <img width="296" height="607" alt="regex" src="https://github.com/user-attachments/assets/15d79a58-1047-4bea-9106-51d103d90a66" />

### **Enrich Alerts:**
1. Create a VirusTotal account and integrate the **VirusTotal v3** application into the workflow.
2. Click on the VirusTotal icon and set **Find Actions** to **Get a hash report**.
3. Authenticate using the API key (copied from your VirusTotal account).
4. Configure the action to **Get a hash report** using the SHA256 value extracted from the previous step.

    <img width="263" height="560" alt="virustools" src="https://github.com/user-attachments/assets/387240aa-6a2e-4c00-b1bc-49a0453fce4a" />

### **Create Cases in The Hive**
1. Add **The Hive** app to the workflow.
2. Before configuration, go to The Hive dashboard:
   * Add an organization.
   * Add 1 normal user as analyst.
   * Add 1 service user as analyst.
  
     <img width="1050" height="676" alt="thehive" src="https://github.com/user-attachments/assets/efcbcd27-59de-47fe-bfca-f30222fca2ad" />
    
3. Log in with the normal user account and extract the API key.
4. Go back to Shuffle and authenticate using:
   * The API key
   * The Hive IP address in the URL
  
    <img width="333" height="562" alt="hive" src="https://github.com/user-attachments/assets/684b1e8a-df17-4bd8-9844-a1658deb1beb" />
     
5. Click on The Hive icon, go to **Advanced**, and update the JSON with:
   ```
   {
     "body": {
       "title": "Mimikatz Alert: $sha256_hash",
       "description": "Alert detected by Wazuh and analyzed via VirusTotal.",
       "type": "external",
       "source": "Wazuh",
       "severity": 3,
       "tlp": 2,
       "tags": ["T1003", "Mimikatz"],
       "artifacts": [
         {
           "dataType": "hash",
           "data": "$sha256_hash",
           "message": "SHA256 hash of the suspicious file."
         },
         {
           "dataType": "ip",
           "data": "$exec.alert.source_ip",
           "message": "Source IP of detected activity."
         }
       ]
     }
   }
   ```
   * **Note:** Ensure the JSON payload is correctly formatted and that the variables (`$sha256_hash`, `$exec.alert.source_ip`) are correctly mapped to your workflow's output.

#### **Configure Email Notifications:**
1. Add the **Email** app to the workflow.
2. For **Find Actions**, select **Send email (Shuffle)**.
3. Configure the recipient’s email address and a custom message template.
4. Customize the email to include essential alert details such as:
   * Host
   * Event title
   * Timestamp

*Now run the Workflow and you will see alerts and mail generating.

  <img width="1114" height="598" alt="thehive-alert" src="https://github.com/user-attachments/assets/601fe1a1-8091-4760-a2c9-76bd29fb13dc" />

  <img width="490" height="390" alt="email" src="https://github.com/user-attachments/assets/b56ce94b-85c4-4c7b-88ed-9ff3d35ac969" />

## **Conclusion**
This guide successfully outlines a robust, automated SOC workflow that integrates key open-source tools to detect, enrich, and manage security incidents. By automating the response to a simulated Mimikatz attack, the setup demonstrates how organizations can significantly reduce manual effort and improve their security posture. This automated pipeline frees up security analysts to focus on more complex, high-impact tasks.
