# Threat-Hunt-Report-Unauthorized-TOR-Usage-

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

On 2025-11-11T07:43:11Z , user adamalme was observed downloading a Tor installer, resulting in multiple Tor-related files being copied to the desktop. A file named “tor-shopping-list.txt” was also created. These events were identified by searching the DeviceFileEvents table in Microsoft Defender for Endpoint for any file containing the string “tor”

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "Alme-Window-203"
| where InitiatingProcessAccountName == "adamalme"
| where FileName startswith "tor"
| where Timestamp >= datetime(2025-11-11T07:43:11.4085219Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine entries containing the string "tor-browser-windows-x86_64-portable-15.0.exe". Based on the logs returned, at 2025-11-11T07:24:38.0563663Z, the user adamalme on the device Alme-Windows-203 executed the file tor-browser-windows-x86_64-portable-15.0.exe from their Downloads folder (C:\Users\Adamalme\Downloads) using a command that initiated a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName contains "Alme-Window-203"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.exe"
| project Timestamp, AccountName, FileName, ProcessCommandLine,SHA256,FolderPath
```

--------

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "Alme-Window-203"
| where InitiatingProcessAccountName == "adamalme"
| where FileName startswith "tor"
| where Timestamp >= datetime(2025-11-11T07:43:11.4085219Z)
| order by Timestamp desc
| project Timestamp , DeviceName, FileName, FolderPath , SHA256 , accout=InitiatingProcessAccountName
```


---
Searched the DeviceProcessEvents table for indications that user “adam” executed the Tor Browser. Evidence shows the browser was launched at 2025-11-11T07:25:57.2928976Z . Additional instances of firefox.exe (associated with Tor Browser) and tor.exe were observed subsequently, indicating multiple Tor-related processes were spawned.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "alme-Window-203"
| where FileName in ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,SHA256, ProcessCommandLine
| order by Timestamp desc
```



### 5. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "alme-Window-203"
| where InitiatingProcessAccountName != "system" 
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443") 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  

```

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer
-**Timestamp:** '2025-11-10T23:24:38Z'
- **Event:** The user "adamalme" downloaded a file named tor-browser-windows-x86_64-portable-15.0.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:** 'C:\Users\Adamalme\Downloads\tor-browser-windows-x86_64-portable-15.0.exe'
- **File Hash** '(SHA256): fd022504bb6e57e379668ed4b82966f284f19508dd88d76eaaf33e505add4f43'

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** '2025-11-10T23:25:57Z'
- **Event:** The user "adamalme" executed tor-browser-windows-x86_64-portable-15.0.exe, initiating the installation of the TOR Browser bundle.
- **Action:** Process creation detected.
- **File Path:** C:\Users\Adamalme\Downloads\tor-browser-windows-x86_64-portable-15.0.exe

### 3. Process Execution - TOR Browser Launch

- ** Process Execution :TOR Browser Installation
- ** Timestamp: ** 2025-11-10T23:25:57Z
- ** Event:**  The user "adamalme" executed tor-browser-windows-x86_64-portable-15.0.exe, initiating the installation of the TOR Browser bundle.
- ** Action:**  Process creation detected.
- ** File Path:  ** C:\Users\Adamalme\Downloads\tor-browser-windows-x86_64-portable-15.0.exe

### 4. Network Connection - TOR Network

- ** Process Continuation - Active TOR Browser Usage
- ** Timestamps:**  2025-11-10T23:33Z – 2025-11-10T23:38Z
- ** Event:**  Continuous execution of firefox.exe and tor.exe processes observed, confirming the TOR Browser remained active.
- ** Action:**  Persistent process execution detected.

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamp: - 2025-11-10T23:27:14Z - connected to "150.171.28.11" , on port "443"
- 2025-11-11T07:27:23.2379657Z - local connection to 27.0.0.1' on port '9150'
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "adam" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-11-10T23:43:11Z`
- **Event:** The user "employee" created a file named `tor-shopping-list”` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Adamalme\Desktop\tor-shopping-list.txt`
  
### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-11-11T20:03Z – 2025-11-11T20:04Z`
- **Event:** The user "employee" created a file named `tor-shopping-list”` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File modification detected..
---

## Summary

The user "adamalme." on the "Alme-Window-203" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `Alme-Window-203` by the user `adamalme.`. The device was isolated, and the user's direct manager was notified.

---

