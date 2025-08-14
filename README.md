# Chia Monitor

Simple autostart and checking for Chia farming in Windows / Python script.

## Overview

**Chia Monitor** is a Python tool designed to automate and monitor Chia farming on Windows. It provides real-time status via a graphical interface and manages farm services, credentials, and network drives for both local and remote plot directories (initializes remote/UNC drive access on startup).

---

## Features

- **Autostart Chia Farmer**: Automatically starts the Chia farmer process.
- **Farm Status Monitoring**: Periodically checks farming status and plot file count.
- **GUI Dashboard**: Displays farming status, plot summary, plot counts, error logs, and lets you edit directories and expected plots.
- **Credential Management**: Securely retrieves Chia wallet and network share credentials from Windows Credential Manager.
- **Network Drive Handling**: Maps/checks local and UNC network directories; retries on failures.
- **Plot Count Alerting**: Launches Chia GUI if plot count doesn't match expected value after several checks.
- **Rotating Logging**: Keeps activity logs with rotation to avoid large log files.
- **Graceful Shutdown**: Stops Chia farmer services and saves config on exit.

---

## Installation & Setup
1. **Prerequisites**
   - Python 3.x installed on Windows.
   - Chia client installed (CLI and GUI paths set in config).

2. **Clone the Repository**
   ```sh
   git clone https://github.com/alewir/chia_monitor.git C:\chia_monitor
   cd chia_monitor

### Configure Credentials
- Save your Chia wallet password in Windows Credential Manager:
  - Service Name: chia_wallet_password
  - Username: chia_farmer
  - Password: (your wallet password)
- (Optional) Save network share credentials if scanning network drives:
  - Service Name: chia_network_shares
  - Username: username
  - Password: password

### Edit Configuration
Modify chia_monitor_config.json for paths, expected plots, directories, and other parameters.
Example (assuming repo cloned and Chia GUI - https://www.chia.net/downloads/ - installed on drive C):

```json
{
  "chia_path": "c:\\<path_to_chia_gui_installation>\\resources\\app.asar.unpacked\\daemon\\chia.exe",
  "chia_gui_path": "c:\\<path_to_chia_gui_installation>\\chia.exe",
  "keyring_service_name": "chia_wallet_password",
  "keyring_username": "chia_farmer",
  "network_share_service_name": "chia_network_shares",
  "log_file_path": "C:\\chia_monitor\\harvest.log",
  "max_log_bytes": 1048576,
  "backup_count": 5,
  "summary_check_interval_seconds": 30,
  "network_drive_retry_attempts": 3,
  "network_drive_retry_delay_seconds": 10,
  "plot_filename_pattern_str": "plot-k32-\\d{4}-\\d{2}-\\d{2}-\\d{2}-\\d{2}-.{64}\\.plot",
  "plot_directories": [
    "D:\\\\",
    "E:\\\\",
    "F:\\\\",
    "M:\\\\NAS-SYS02\\ChiaFarmNFS02\\\\",
    "N:\\\\NAS-SYS01\\ChiaFarmNFS01\\\\"
  ],
  "expected_plots": 123
}
```
---

## Usage
Start the Monitor:
- Windows Scheduler
  - General: ```"Run only when user is logged in."```
  - Triggers: ```"At log on" - "At log on of any user```
  - Actions: ```Start a program```
    - Program script: ```C:\Windows\System32\cmd.exe``` 
    - Add arguments (...):```/c "c:\<path_to_python_installation>\python.exe C:\chia_monitor\harvest.py"```
 - Conitions: ```"Start only if the following network connection is available" - "Any connection"```

- WSL/2 (Ubuntu)
```bash
sh
python harvest.py
```

### Interact with GUI
- View farming status, plot summary, and logs.
- Edit plot directories and expected plot count directly in the GUI.
- Quit to stop farmer services and save changes.

---

### How It Works
- Loads configuration from chia_monitor_config.json.
- Retrieves credentials from Windows Credential Manager.
- Maps/checks all plot directories (local and network).
- Scans for plot files using regex pattern.
- Periodically checks farm status and plot count.
- If a mismatch is detected, launches Chia GUI for manual inspection.
- Logs all activity to a rotating log file and GUI console.
- On exit, stops farmer and saves configuration.

## Troubleshooting
- Missing Executable: Ensure chia_path and chia_gui_path in config are correct.
- Credential Errors: Store correct credentials in Windows Credential Manager.
- Network Issues: Check UNC paths, network drive mappings, and permissions.
- Configuration Errors: Invalid config will fall back to defaults; check log for warnings.

---

## License
See LICENSE.

Contributing
Feel free to open issues or submit pull requests for improvements.

