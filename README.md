# SOAR-Human-In-The-Loop-Automation
Automated Incident Response playbook using a 3B SOAR workflow, LimaCharlie EDR, VirusTotal, and ServiceNow, featuring Human-in-the-Loop analyst approval gates, endpoint containment, and dynamic ITSM ticket logging.

![Category](https://img.shields.io/badge/Domain-SOC%20Automation%20%26%20IR-blue)

![SOAR](https://img.shields.io/badge/SOAR-Tines%203B-purple)

![Architecture](https://img.shields.io/badge/Architecture-Human--in--the--Loop%20(HITL)-orange)

![EDR](https://img.shields.io/badge/EDR-LimaCharlie-green)

![ITSM](https://img.shields.io/badge/ITSM-ServiceNow-brightgreen)

---

## 📌 Overview
When a Windows endpoint runs the credential-dumping tool **LaZagne**, LimaCharlie detects it and sends the alert to the SOAR workflow. The workflow checks the file hash on VirusTotal, alerts the SOC on Slack and Gmail, and asks an analyst to approve or decline containment.

* A **Yes** decision isolates the host and requests process termination.
* A **No** decision sends the alert to manual investigation. 
* Either way, a ServiceNow incident ticket is dynamically logged.
  
### 🎯 MITRE ATT&CK Mapping
* **Tactics:** [TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006/)
* **Technique:** [T1555: Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
* **Sub-techniques:** [T1555.003: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
  
## 🗺️ Architecture & Workflow

The end-to-end incident response playbook is orchestrated through **Tines 3B**, linking EDR telemetry, threat enrichment, analyst decision gates, and ITSM ticketing.

<img width="928" height="237" alt="Screenshot_15-10-2026_14433_copper-quinoa 3b dev" src="https://github.com/user-attachments/assets/e7050635-07d9-45fe-874a-225020272bbe" />

##  ⚙️ How it works
1.Detect: a LimaCharlie D&R rule fires when LaZagne runs.

2.Enrich: the file hash is looked up on VirusTotal.

3.Notify: Slack and Gmail receive the alert, the VirusTotal score and the approval link.

4.Decide: a signed-in analyst chooses Yes or No on the approval page.

5.Respond: on Yes, the incident is created and host isolation and process termination are requested through the LimaCharlie API. On No, no containment runs, and a ServiceNow ticket is created to track the manual investigation (it can later be closed as a false positive or escalated).

---
## 🛡️ Detection Engineering (LimaCharlie D&R Rule)

To catch credential-harvesting activity before LaZagne can exfiltrate passwords, a custom **Detection and Response (D&R) rule** was authored in LimaCharlie. 

The rule evaluates Windows process creation events against file paths, command-line parameters, and known bad file hashes, triggering a report alert and tagging the sensor for tracking.

### 📄 LimaCharlie D&R Rule (YAML)

```yaml
# Detect Rule Logic
detect:
  events:
    - NEW_PROCESS
    - EXISTING_PROCESS
  op: and
  rules:
    - op: is windows
    - op: or
      rules:
        - case sensitive: false
          op: ends with
          path: event/FILE_PATH
          value: lazagne.exe
        - case sensitive: false
          op: ends with
          path: event/COMMAND_LINE
          value: all
        - case sensitive: false
          op: contains
          path: event/COMMAND_LINE
          value: lazagne
        - case sensitive: false
          op: is
          path: event/HASH
          value: '3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05'

# Response Rule Logic
respond:
  - action: report
    name: MyDFIR - HackTool - Lazagne (SOAR-EDR)
  - action: add tag
    tag: saved credential stealer
```
 ## 🖼️ Demo



### 1. Detection in LimaCharlie
LaZagne execution caught by the D&R rule.

<img width="1868" height="680" alt="Screenshot_15-10-2026_144024_app limacharlie io" src="https://github.com/user-attachments/assets/e8e25dc4-61b6-45ce-90cd-a0c85d7aa0f3" />



### 2. Slack and Gmail alert
The alert with the VirusTotal score and the approval link.

<img width="1511" height="502" alt="Screenshot_15-10-2026_141847_mail google com" src="https://github.com/user-attachments/assets/27342f54-d063-491c-a1f8-6b28a2c11567" />


<img width="1279" height="260" alt="Screenshot_15-10-2026_141942_app slack com" src="https://github.com/user-attachments/assets/a7e96962-22b0-48f0-b04e-b60aebb4a428" />



### 3. Analyst approval
The Human-In-The-Loop decision page (Yes or No).

<img width="1619" height="1067" alt="Screenshot_15-10-2026_142511_forprojeccts--copper-quinoa 3b run" src="https://github.com/user-attachments/assets/fc505f8e-2148-460a-b754-c4c7762c6f07" />



### 4. Host isolation
The endpoint isolated from the network after the analyst approved.

<img width="1283" height="458" alt="image" src="https://github.com/user-attachments/assets/bca52bb5-e832-4711-af71-097ae4c6a5e1" />




### 5. ServiceNow tickets
Yes path (true positive) and No path (manual investigation).

<img width="1886" height="736" alt="image" src="https://github.com/user-attachments/assets/125ee604-b1e4-47cf-97bd-20928466524e" />

<img width="1748" height="220" alt="Screenshot_15-10-2026_143919_dev374125 service-now com" src="https://github.com/user-attachments/assets/47bd1d8a-41f6-4513-b124-92813c64686f" />

**If the analyst chooses No**, no containment runs. The ticket stays In Progress, and the work note says **manual investigation going on**.

<img width="1744" height="151" alt="Screenshot_15-10-2026_143444_dev374125 service-now com" src="https://github.com/user-attachments/assets/81d0fb1f-6763-4178-af4e-b01d7a9a786c" />

---

## 🛠️ Setup

> Lab use only. Never run credential-dumping tools on machines you do not own.

### Prerequisites
- A Windows VM for the endpoint (this project used Windows Server 2022 on AWS EC2)
- Free accounts: LimaCharlie, VirusTotal, Slack, Gmail, ServiceNow developer instance
- A SOAR platform account

### 1. Endpoint
1. Launch the Windows VM and give it a corporate-style hostname (for example `corp-windows-client01`).
2. Allow RDP (TCP 3389) only from your own IP.

### 2. LimaCharlie (EDR)
1. Create an organization and an installation key.
2. Install the sensor on the VM with that key, and confirm it shows online under **Sensors**.
3. Add a D&R rule that detects LaZagne execution, and confirm a detection appears when you run the tool.

### 3. Connections in the SOAR platform
Keep every secret in the platform's connection store, never in workflow code.

| Service | What you need |
|---------|---------------|
| LimaCharlie | Organization ID and an API key with only the permissions needed to task sensors. Allowed URLs: `*.limacharlie.io` |
| VirusTotal | API key. Allowed URL: `https://www.virustotal.com/*` |
| Slack | A bot app with the `chat:write` scope, installed to the workspace and invited to the alert channel |
| Gmail | SMTP with a Google app password (2-Step Verification must be on) |
| ServiceNow | An OAuth application registry entry and an integration user with the `itil` role |

### 4. Workflow
1. Build the workflow: receive alert, VirusTotal check, Slack and Gmail notifications, analyst approval, response and ServiceNow ticket.
2. Test each step with sample data.
3. Push the workflow live.

### 5. Connect LimaCharlie to the workflow
1. Copy the live webhook URL from the **Receive alert** step.
2. In LimaCharlie, add an **Output** with the **Detections** stream and a **Webhook** destination, and paste the URL.
3. Treat the URL as a secret, and never commit it to this repo.

### 6. Run the test
1. On the VM, run `LaZagne.exe all`.
2. Check the detection in LimaCharlie, then the Slack and Gmail alerts.
3. Open the approval page as the analyst. On a first run, choose **No** so nothing is isolated.
4. Run it again and choose **Yes** to test containment.
5. Check the ServiceNow ticket for each path.

### 7. Clean up
- In LimaCharlie, release the host (**Network Isolation → Rejoin Network**).
- Close the test tickets in ServiceNow.
- Stop or terminate the VM.

---
---

## 👤 Author

**Your Name**
* **GitHub:** (https://github.com/ridaabbas000000/cloud)


