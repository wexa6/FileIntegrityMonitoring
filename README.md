# Basic File Integrity Monitoring (FIM) Tool 

A simple, command-line File Integrity Monitoring (FIM) tool built with Python, optimized for use on Windows systems. This tool establishes a baseline of critical file hashes and periodically scans for any additions, modifications, or deletions, sending detailed email alerts when changes are detected.

## Features

- **Baseline Creation**: Generates a secure hash (SHA-256) for every file in specified directories to create a trusted baseline.
- **Automated Email Alerts**: Sends detailed email notifications when file changes are detected, perfect for unattended monitoring.
- **Robust Configuration**: All settings, including paths, log files, and SMTP server details, are managed in a central `config.ini` file.
- **Secure Password Handling**: Does not store sensitive passwords in configuration files. Instead, it securely reads the SMTP password from an environment variable.
- **Configurable**: Easily specify which Windows directories to monitor through a simple configuration file.

---

## How It Works

The tool operates using two main commands:

1.  **`baseline`**: The script recursively scans the files and directories defined in `config.ini`. It calculates a hash for each file and saves this data into a `baseline.json` file. This baseline represents the "known good" state of the system and includes metadata like the creation date and hash algorithm used.
2.  **`scan`**: The script re-scans the target paths and compares the current file hashes against the baseline. If any discrepancy is found (a changed, new, or missing file), it constructs a detailed report and sends it as an **email alert** to the configured recipient.
---

## Getting Started

### Prerequisites

- Python 3.6+ installed on Windows.
- Git for Windows (for cloning the repository).

### Installation

1.  Clone the repository to your local machine using Command Prompt or PowerShell:
    ```cmd
    git clone https://github.com/wexa6/FileIntegrityMonitoring.git
    ```
    *(Replace with your actual repository URL)*

2.  Navigate to the project directory:
    ```cmd
    cd FileIntegrityMonitoring
    ```
---
### Usage

**Step 1: Configure Directories to Monitor**

Open the `config.ini` file in a text editor. Add the full paths of the Windows directories you wish to monitor. Use commas to separate multiple directories and ensure there are no trailing spaces.

*Example for Windows:*
```ini
monitor_paths = C:\Windows\System32,
                C:\Users\YourUser\Documents,
                C:\Program Files\CriticalApp
```
_And change the following email configuration:_
```ini
smtp_user = sender_emailgmail.com
recipient_email = recipient_email@gmail.com
```

---
**Step 2: Set the SMTP Password Environment Variable**

For security, your email password must be set as an environment variable named FIM_SMTP_PASSWORD. Do not write it in the code or config file.

**On Windows (Command Prompt - Temporary):**

This command sets the variable for your current terminal session only.

```ini
set FIM_SMTP_PASSWORD=your_app_password
```

**On Windows (Permanent):**

1. Search for "Edit the system environment variables" in the Start Menu and open it.

2. Click the "Environment Variables..." button.

3. In the "User variables" section, click "New...".

4. Variable name: FIM_SMTP_PASSWORD

5. Variable value: your_app_password

6. Click OK on all windows. You will need to restart your terminal or IDE for the change to take effect.

*Gmail Users: You will need to generate an "App Password" from your Google Account security settings instead of using your regular password.*

---
**Step 3: Create the Initial Baseline**

Run the following command in your terminal. It will prompt you before overwriting an existing baseline.
```ini
python FIM.py baseline
```
This will create the baseline file specified in your config.ini.

---
**Step 4: Run an Integrity Scan**

To check for any changes and trigger email alerts, run the scan command.
```ini
python FIM.py scan
```
If no changes are found, it will be logged. If changes are found, an email alert will be dispatched.

---

## Automation with Windows Task Scheduler

You can run the scan automatically, using Windows Task Scheduler with those steps:
1. Open Task Scheduler.
2. Create a new task.
3. Set the Action to "Start a program".
4. Configure the action:
* * **Program/script:** C:\path\to\your\pythonw.exe (using pythonw.exe runs it without a console window)
* * **Add arguments:** FIM.py scan
* * **Start in:** D:\path\to\your\project\ (This is crucial so it can find the script and config file!)

This will execute python FIM.py scan from the correct directory on your schedule.