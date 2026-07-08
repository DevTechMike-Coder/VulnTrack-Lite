# VulnTrack Lite 🛡️

A lightweight, standalone security vulnerability tracker designed to serve as an agile, low-resource dashboard for security engineers.

> [!NOTE]
> **AI-Assisted Build:** This project was designed, coded, and verified by **Antigravity**, an AI coding assistant developed by Google DeepMind, in collaboration with the user.

---

## ✨ Features

- **Metric Overview Grid:** Real-time summary counts of total, Critical, High, and Medium/Low threats.
- **Dynamic Data Table:** Interactive table with glowing CVSS indicators, severity badges, and inspect options.
- **Search & Filters:** Real-time query filtering for CVE IDs, titles, or descriptions, plus severity tab filtering.
- **Manual Input Modal:** Wizard to manually log new CVE entries with validation checks.
- **Zero Heavy ORMs:** Built directly on top of Python's standard `sqlite3` driver.

---

## 🛠️ Architecture

- **Backend (`main.py`):** Single FastAPI backend serving static HTML, endpoints, database migrations, and payload validation.
- **Frontend (`index.html`):** Clean HTML5 structure styled via Tailwind CSS CDN with pure vanilla JavaScript state handling and Lucide icons.
- **Database (`vulntrack.db`):** Lightweight SQLite database initialized on startup.

---

## 🚀 Getting Started

### 1. Installation

Clone or copy this folder structure, navigate to it in your terminal, and install the FastAPI environment dependencies:

```bash
pip install fastapi uvicorn pydantic
```

### 2. Launch the Application

Run the local uvicorn server:

```bash
python -m uvicorn main:app --reload
```

Navigate to **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

### 3. Run Automated Tests

Execute the local integration tests using:

```bash
python run_tests.py
```

---

## 📂 Project Structure

- `main.py` - FastAPI app, database routing, and payload validation.
- `index.html` - Core HTML dashboard & Tailwind styling.
- `run_tests.py` - Unit integration test client.
- `LICENSE` - Project license terms.
- `vulntrack.db` - SQLite database file (created on startup).

---

## 📄 License

This project is licensed under the terms of the MIT License. See [LICENSE](file:///C:/Users/personal/Documents/VulnTrack_Lite/LICENSE) for details.
