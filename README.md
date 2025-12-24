# SecMon — Security Monitoring System

A Windows-focused desktop application (Tkinter GUI) for security monitoring. SecMon periodically captures screenshots, scans installed software against a blacklist, bundles reports, and emails them automatically. It also provides a user-facing VirusTotal file scanner.

> Built with Python, Tkinter, pyautogui, and VirusTotal API.

## Features

- Admin and user roles with a modern Tkinter UI
- Periodic screenshots at a configurable interval
- Daily software scan at a specified hour (Windows Registry query)
- Blacklist management (add/remove/save from the UI)
- Email reports with zipped screenshots and software lists
- On-demand quick scan report from the admin panel
- User panel to upload a file and scan it via VirusTotal API
- Local data directory for screenshots and generated reports

## Project Structure

- `main.py` — Application entry point and all UI/logic
- `monitor_data/` — App data directory, created on first run
  - `screenshots/` — Captured screenshots
  - `blacklist.txt` — Saved blacklist terms
  - `soft_names.txt` — Installed software list
  - `soft_report.txt` — Full software report
  - `Alldata.zip` — Bundled report archive (generated)

## Requirements

- Windows 10/11 (uses `reg query` and takes desktop screenshots)
- Python 3.9+
- Internet access for emailing and VirusTotal

Python packages:
- `pyautogui`
- `requests`

Optional transitive dependencies are installed automatically.

### Quick setup

```powershell
# From the project root (f:\Projects\SecMon)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
# Optional: create a requirements file for later reuse
pip freeze | Out-File -Encoding utf8 requirements.txt
# Optional: pin exact versions currently installed
pip freeze | Out-File -Encoding utf8 requirements.lock.txt
```

## Configuration (secrets & settings)

Open `main.py` and locate the CONFIG section near the top. Replace these constants with your values:

```python
SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "your_app_password"   # Gmail App Password (with 2FA)
VT_API_KEY = "your_virustotal_api_key"
RECIPIENT_EMAIL = "recipient@example.com"
```

Notes:
- Use a Gmail App Password (requires enabling 2FA). Regular account passwords won’t work with SMTP.
- Get a free VirusTotal API key by creating an account at virustotal.com.
- Do not commit real secrets to version control. Consider using environment variables and updating the code to read them with `os.getenv()` if you plan to distribute this.

Other defaults (adjust in the Admin UI or edit constants):
- Screenshot interval (minutes)
- Daily scan hour (0–23)
- Work hours (used to batch screenshots per email)

## Running

```powershell
# Ensure your venv is activated and deps installed
python main.py
```

- Log in with demo credentials shown on the login screen:
  - Admin: `admin / admin123`
  - User: `user / user123`
- As Admin, configure intervals and start monitoring. The app will:
  - Take screenshots periodically and email them in batches
  - At the chosen hour, scan installed software names (from the Windows registry)
  - Compare names against your blacklist and email a report if hits are found
- As User, open the VirusTotal scanner, select a file, and run a scan. The result is displayed and optionally emailed.

## How it works (high level)

- Screenshots: `pyautogui.screenshot()` saves images under `monitor_data/screenshots/`.
- Zipping: All screenshots and `soft_names.txt` are zipped into `Alldata.zip` for email reports.
- Daily scan: Queries `HKLM\SOFTWARE` via `reg query`, parses entries into a list, and compares to blacklist terms (case-insensitive substring match).
- Email: SMTP (Gmail) with TLS on port 587; HTML bodies and optional attachment.
- VirusTotal: Uploads a file, polls analysis status, summarizes verdict (malicious/suspicious/clean).

## Limitations

- Windows-only implementation (uses registry queries and desktop screenshot APIs)
- Requires a signed-in desktop session for screenshots (won’t work headless)
- Basic parsing of registry output may include noise; tune blacklist terms accordingly
- Emailing relies on external SMTP; network/firewall policies may block it
- VirusTotal free API has rate limits

## Troubleshooting

- SMTP login fails:
  - Ensure you’re using a Gmail App Password with 2FA enabled
  - Check that less secure app restrictions/policies aren’t blocking SMTP
- Screenshots are blank/error:
  - Ensure the session is unlocked and a display is available
  - Verify `pyautogui` is installed and no UAC/policy is blocking screenshots
- Daily scan finds nothing:
  - Confirm `blacklist.txt` contains the terms you expect (UI: Add → Save)
  - Try running the app with elevated privileges if registry access is limited
- VirusTotal errors/timeouts:
  - Verify the API key; watch for rate limits; try again later

## Security and ethics

- This tool captures screenshots and inventories installed software. Use only on systems you own or where you have explicit authorization.
- Protect your credentials (email/app password, API key). Do not commit them publicly.
