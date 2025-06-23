# Offline Internet Outage Reporter

A Python desktop application to report, store, and share internet outage statuses offline.  
Designed for use during internet shutdowns to help users track and share connectivity status securely.

---

## Features

- Add reports with reporter name, status (up/down), and location  
- Stores reports locally in SQLite database  
- Export reports as **encrypted** JSON files (password-protected)  
- Import encrypted reports and merge without duplicates  
- Simple and user-friendly GUI built with Tkinter

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/internet-outage-map.git
cd internet-outage-map

    (Optional) Create and activate a virtual environment:

python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

    Install dependencies:

pip install cryptography

Usage

Run the app with:

python main.py

    Use the GUI to add new reports

    Export and import encrypted reports to share with others

    View all collected reports in the app
