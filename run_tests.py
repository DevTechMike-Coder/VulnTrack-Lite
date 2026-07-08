import unittest
import os
import sqlite3
from fastapi.testclient import TestClient

# Import the application and db setup from main.py
try:
    from main import app, DB_FILE, init_db
except ImportError:
    print("Could not import app. Installing fastapi and uvicorn if necessary...")
    import sys
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn", "pydantic"])
    from main import app, DB_FILE, init_db

class TestVulnTrackLite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Clear or delete existing test db if any
        if os.path.exists(DB_FILE):
            try:
                os.remove(DB_FILE)
            except PermissionError:
                pass
        
        # Manually initialize the database for testing context (starts empty)
        init_db()
        cls.client = TestClient(app)

    def test_01_index_html(self):
        """Test that the index.html page is served properly"""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("VulnTrack", response.text)

    def test_02_get_vulnerabilities_empty(self):
        """Test fetching vulnerabilities from an empty database"""
        response = self.client.get("/api/vulnerabilities")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 0)

    def test_03_add_vulnerability(self):
        """Test adding vulnerabilities manually"""
        # Add critical vuln
        vuln1 = {
            "cve_id": "CVE-2026-9999",
            "title": "Custom Vulnerability Test Critical",
            "severity": "Critical",
            "score": 9.9,
            "description": "This is a custom test vulnerability description that meets length requirements."
        }
        response1 = self.client.post("/api/vulnerabilities", json=vuln1)
        self.assertEqual(response1.status_code, 201)
        data1 = response1.json()
        self.assertEqual(data1["cve_id"], vuln1["cve_id"])
        self.assertEqual(data1["score"], vuln1["score"])

        # Add low vuln
        vuln2 = {
            "cve_id": "CVE-2026-1111",
            "title": "Custom Vulnerability Test Low",
            "severity": "Low",
            "score": 2.0,
            "description": "This is a low severity test description."
        }
        response2 = self.client.post("/api/vulnerabilities", json=vuln2)
        self.assertEqual(response2.status_code, 201)

    def test_04_get_vulnerabilities_populated(self):
        """Test fetching vulnerabilities when database is populated"""
        response = self.client.get("/api/vulnerabilities")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["cve_id"], "CVE-2026-9999") # Ordered by score DESC
        self.assertEqual(data[1]["cve_id"], "CVE-2026-1111")

    def test_05_filter_severity(self):
        """Test severity filtering endpoints"""
        # Fetch Critical ones
        response_crit = self.client.get("/api/vulnerabilities?severity=Critical")
        self.assertEqual(response_crit.status_code, 200)
        data_crit = response_crit.json()
        self.assertEqual(len(data_crit), 1)
        self.assertEqual(data_crit[0]["cve_id"], "CVE-2026-9999")

        # Fetch Low ones
        response_low = self.client.get("/api/vulnerabilities?severity=Low")
        self.assertEqual(response_low.status_code, 200)
        data_low = response_low.json()
        self.assertEqual(len(data_low), 1)
        self.assertEqual(data_low[0]["cve_id"], "CVE-2026-1111")

        # Fetch High ones (should be empty)
        response_high = self.client.get("/api/vulnerabilities?severity=High")
        self.assertEqual(response_high.status_code, 200)
        data_high = response_high.json()
        self.assertEqual(len(data_high), 0)

    def test_06_add_vulnerability_validation(self):
        """Test validation rules for manual adding"""
        # Duplicate CVE
        new_vuln = {
            "cve_id": "CVE-2026-9999",
            "title": "Duplicate Vulnerability Test",
            "severity": "Critical",
            "score": 9.9,
            "description": "This is a custom test vulnerability description that meets length requirements."
        }
        response = self.client.post("/api/vulnerabilities", json=new_vuln)
        self.assertEqual(response.status_code, 400)
        self.assertIn("already exists", response.json()["detail"])

        # Invalid CVE format
        bad_cve = {
            "cve_id": "BAD-CVE-FORMAT",
            "title": "Invalid CVE ID Test",
            "severity": "High",
            "score": 8.0,
            "description": "Validation testing description for format matching."
        }
        response = self.client.post("/api/vulnerabilities", json=bad_cve)
        self.assertEqual(response.status_code, 422)

        # Mismatched score / severity range (pydantic validates 0-10)
        bad_score = {
            "cve_id": "CVE-2026-8888",
            "title": "Invalid Score Test",
            "severity": "Low",
            "score": 11.5,
            "description": "Validation testing for score range out of bound."
        }
        response = self.client.post("/api/vulnerabilities", json=bad_score)
        self.assertEqual(response.status_code, 422)

if __name__ == "__main__":
    unittest.main()
