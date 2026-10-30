import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import feeds
import main

H = {"X-Requested-With": "VulnTrack"}
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def body(cve="CVE-2026-1000", **kw):
    d = {"cve_id": cve, "title": "Test vulnerability", "description": "A description long enough to pass.", "score": 5.0}
    d.update(kw)
    return d


class ApiCase(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._p = mock.patch.object(main, "DB_FILE", self.path)
        self._p.start()
        main.init_db()
        main.limiter.hits.clear()
        self.c = TestClient(main.app, base_url="http://127.0.0.1:8000")

    def tearDown(self):
        self._p.stop()
        os.remove(self.path)

    def post(self, payload, **kw):
        return self.c.post("/api/vulnerabilities", json=payload, headers=H, **kw)


class CrudAndDerivation(ApiCase):
    def test_index_and_security_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("VulnTrack", r.text)
        self.assertIn("script-src 'self'", r.headers["content-security-policy"])
        self.assertNotIn("unsafe-inline", r.headers["content-security-policy"])
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")

    def test_empty_list(self):
        self.assertEqual(self.c.get("/api/vulnerabilities").json(), [])

    def test_severity_derived_from_score(self):
        r = self.post(body(score=9.9))
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["severity"], "Critical")

    def test_vector_computes_score(self):
        r = self.post(body(cvss_vector=V31, score=None))
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["score"], 9.8)
        self.assertEqual(r.json()["cvss_version"] if r.json()["cvss_version"] else "3.1", "3.1")

    def test_vector_score_mismatch_rejected(self):
        self.assertEqual(self.post(body(cvss_vector=V31, score=5.0)).status_code, 422)

    def test_v40_requires_score(self):
        self.assertEqual(self.post(body(cvss_vector=V40, score=None)).status_code, 422)
        self.assertEqual(self.post(body(cvss_vector=V40, score=9.3)).status_code, 201)

    def test_severity_mismatch_and_missing_score(self):
        self.assertEqual(self.post(body(score=9.0, severity="Low")).status_code, 422)
        d = body(); del d["score"]
        self.assertEqual(self.post(d).status_code, 422)

    def test_validation(self):
        for bad in (body(cve="BAD"), body(score=11.5), body(title="x"), body(extra="field"), body(cvss_vector="CVSS:3.1/AV:N")):
            self.assertEqual(self.post(bad).status_code, 422, bad)

    def test_duplicate_is_409(self):
        self.assertEqual(self.post(body()).status_code, 201)
        r = self.post(body())
        self.assertEqual(r.status_code, 409)
        self.assertIn("already exists", r.json()["detail"])

    def test_filter_sort_and_get_one(self):
        self.post(body("CVE-2026-0001", score=2.0))
        self.post(body("CVE-2026-0002", score=9.9))
        ids = [v["cve_id"] for v in self.c.get("/api/vulnerabilities").json()]
        self.assertEqual(ids, ["CVE-2026-0002", "CVE-2026-0001"])
        self.assertEqual(len(self.c.get("/api/vulnerabilities?severity=critical").json()), 1)
        self.assertEqual(self.c.get("/api/vulnerabilities?severity=Bogus").status_code, 400)
        self.assertEqual(self.c.get("/api/vulnerabilities?priority=9").status_code, 422)
        self.assertEqual(self.c.get("/api/vulnerabilities/CVE-2026-0001").status_code, 200)
        self.assertEqual(self.c.get("/api/vulnerabilities/CVE-2026-0404").status_code, 404)
        self.assertEqual(self.c.get("/api/vulnerabilities/not-a-cve").status_code, 422)

    def test_sqli_and_xss_payloads_are_inert(self):
        self.assertEqual(self.c.get("/api/vulnerabilities", params={"severity": "High' OR '1'='1"}).status_code, 400)
        payload = '<img src=x onerror=alert(1)>'
        r = self.post(body(title=payload))
        self.assertEqual(r.json()["title"], payload)  # stored verbatim; the UI escapes on render

    def test_delete_one_and_clear(self):
        self.post(body("CVE-2026-0001")); self.post(body("CVE-2026-0002"))
        self.assertEqual(self.c.delete("/api/vulnerabilities/CVE-2026-0001", headers=H).status_code, 200)
        self.assertEqual(self.c.delete("/api/vulnerabilities/CVE-2026-0001", headers=H).status_code, 404)
        self.assertEqual(self.c.delete("/api/vulnerabilities", headers=H).status_code, 400)
        r = self.c.delete("/api/vulnerabilities", headers={**H, "X-Confirm-Clear": "delete-all"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.c.get("/api/vulnerabilities").json(), [])

    def test_legacy_clear_route_removed(self):
        self.assertIn(self.c.post("/api/clear", headers=H).status_code, (404, 405))


class Migration(unittest.TestCase):
    def test_legacy_schema_is_upgraded_and_severity_repaired(self):
        fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE vulnerabilities (cve_id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, score REAL NOT NULL, description TEXT NOT NULL)")
        conn.execute("INSERT INTO vulnerabilities VALUES ('CVE-2020-0001','t','Low',9.8,'legacy row with wrong severity')")
        conn.commit(); conn.close()
        with mock.patch.object(main, "DB_FILE", path):
            main.init_db(); main.init_db()  # idempotent
            c = TestClient(main.app, base_url="http://127.0.0.1")
            row = c.get("/api/vulnerabilities").json()[0]
        os.remove(path)
        self.assertEqual(row["severity"], "Critical")
        self.assertFalse(row["kev"])
        self.assertEqual(row["source"], "manual")


class RequestGate(ApiCase):
    def test_csrf_header_required_for_writes(self):
        self.assertEqual(self.c.post("/api/vulnerabilities", json=body()).status_code, 403)
        self.assertEqual(self.c.delete("/api/vulnerabilities", headers={"X-Confirm-Clear": "delete-all"}).status_code, 403)

    def test_cross_origin_write_refused(self):
        r = self.c.post("/api/vulnerabilities", json=body(), headers={**H, "Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)
        ok = self.c.post("/api/vulnerabilities", json=body(), headers={**H, "Origin": "http://127.0.0.1:8000"})
        self.assertEqual(ok.status_code, 201)

    def test_dns_rebinding_host_rejected(self):
        r = self.c.get("/api/vulnerabilities", headers={"Host": "evil.example"})
        self.assertEqual(r.status_code, 400)

    def test_body_size_limit(self):
        r = self.c.post("/api/vulnerabilities", content=b"x" * (main.MAX_BODY + 1), headers={**H, "Content-Type": "application/json"})
        self.assertEqual(r.status_code, 413)

    def test_token_auth(self):
        with mock.patch.dict(os.environ, {"VULNTRACK_TOKEN": "s3cret-token-value-123"}):
            self.assertEqual(self.c.get("/api/vulnerabilities").status_code, 401)
            self.assertEqual(self.c.get("/api/vulnerabilities", headers={"Authorization": "Bearer wrong"}).status_code, 401)
            ok = self.c.get("/api/vulnerabilities", headers={"Authorization": "Bearer s3cret-token-value-123"})
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(self.c.get("/").status_code, 200)  # shell is public; data is not

    def test_feed_rate_limit(self):
        with mock.patch.object(feeds, "fetch_nvd_cve", return_value=None):
            codes = [self.c.post("/api/vulnerabilities/import", json={"cve_id": "CVE-2026-0001"}, headers=H).status_code for _ in range(12)]
        self.assertEqual(codes.count(429), 2)

    def test_errors_do_not_leak_internals(self):
        quiet = TestClient(main.app, base_url="http://127.0.0.1", raise_server_exceptions=False)
        self.post(body("CVE-2026-0001"))
        with mock.patch.object(main, "to_response", side_effect=RuntimeError("secret path /etc/x")):
            r = quiet.get("/api/vulnerabilities/CVE-2026-0001")
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json(), {"detail": "Internal server error"})


NVD_RECORD = {
    "cve_id": "CVE-2021-44228", "title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
    "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    "score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "cvss_version": "3.1",
    "published": "2021-12-10T10:15:09.143", "last_modified": "2024-01-01T00:00:00.000",
}
KEV = {"CVE-2021-44228": {"kev_date_added": "2021-12-10", "kev_due_date": "2021-12-24", "kev_ransomware": "Known"}}
EPSS = {"CVE-2021-44228": {"epss": 0.97, "epss_percentile": 0.999, "epss_date": "2026-10-29"}}


class Enrichment(ApiCase):
    def test_import_enriches_and_prioritises(self):
        with mock.patch.object(feeds, "fetch_nvd_cve", return_value=NVD_RECORD), \
             mock.patch.object(feeds, "fetch_kev", return_value=KEV), \
             mock.patch.object(feeds, "fetch_epss", return_value=EPSS):
            r = self.c.post("/api/vulnerabilities/import", json={"cve_id": "CVE-2021-44228"}, headers=H)
        self.assertEqual(r.status_code, 201, r.text)
        v = r.json()
        self.assertTrue(v["kev"]); self.assertEqual(v["priority"], 0); self.assertEqual(v["source"], "nvd")
        self.assertEqual(v["kev_ransomware"], "Known"); self.assertEqual(v["epss"], 0.97)

    def test_import_failures(self):
        with mock.patch.object(feeds, "fetch_nvd_cve", return_value=None):
            self.assertEqual(self.c.post("/api/vulnerabilities/import", json={"cve_id": "CVE-2021-44228"}, headers=H).status_code, 404)
        with mock.patch.object(feeds, "fetch_nvd_cve", side_effect=feeds.FeedError("Could not reach services.nvd.nist.gov")):
            r = self.c.post("/api/vulnerabilities/import", json={"cve_id": "CVE-2021-44228"}, headers=H)
        self.assertEqual(r.status_code, 502)
        self.assertEqual(self.c.post("/api/vulnerabilities/import", json={"cve_id": "nope"}, headers=H).status_code, 422)

    def test_import_survives_enrichment_outage(self):
        err = feeds.FeedError("down")
        with mock.patch.object(feeds, "fetch_nvd_cve", return_value=NVD_RECORD), \
             mock.patch.object(feeds, "fetch_kev", side_effect=err), mock.patch.object(feeds, "fetch_epss", side_effect=err):
            r = self.c.post("/api/vulnerabilities/import", json={"cve_id": "CVE-2021-44228"}, headers=H)
        self.assertEqual(r.status_code, 201)
        self.assertIsNone(r.json()["epss"]); self.assertEqual(r.json()["priority"], 1)

    def test_enrich_all_reports_warnings_and_keeps_kev_on_outage(self):
        self.post(body("CVE-2021-44228", score=10.0))
        with mock.patch.object(feeds, "fetch_kev", return_value=KEV), mock.patch.object(feeds, "fetch_epss", return_value=EPSS):
            r = self.c.post("/api/enrich", headers=H).json()
        self.assertEqual((r["updated"], r["kev_hits"], r["warnings"]), (1, 1, []))
        with mock.patch.object(feeds, "fetch_kev", side_effect=feeds.FeedError("down")), mock.patch.object(feeds, "fetch_epss", return_value={}):
            r = self.c.post("/api/enrich", headers=H).json()
        self.assertEqual(len(r["warnings"]), 1)
        self.assertTrue(self.c.get("/api/vulnerabilities/CVE-2021-44228").json()["kev"])  # not wiped by outage

    def test_priority_filters(self):
        self.post(body("CVE-2021-44228", score=10.0)); self.post(body("CVE-2026-0002", score=3.0))
        with mock.patch.object(feeds, "fetch_kev", return_value=KEV), mock.patch.object(feeds, "fetch_epss", return_value=EPSS):
            self.c.post("/api/enrich", headers=H)
        self.assertEqual([v["cve_id"] for v in self.c.get("/api/vulnerabilities?kev=true").json()], ["CVE-2021-44228"])
        self.assertEqual([v["cve_id"] for v in self.c.get("/api/vulnerabilities?priority=3").json()], ["CVE-2026-0002"])
        self.assertEqual(self.c.get("/api/vulnerabilities").json()[0]["cve_id"], "CVE-2021-44228")


class FeedParsing(unittest.TestCase):
    PAYLOAD = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-44228", "published": "2021-12-10T10:15:09.143", "lastModified": "2024-01-01T00:00:00.000",
        "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Log4j2 JNDI features do not protect against attacker controlled LDAP. More text."}],
        "metrics": {
            "cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "baseScore": 5.3}},
                {"type": "Primary", "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0}}],
        }}}]}

    def test_parse_prefers_primary_english(self):
        r = feeds.parse_nvd(self.PAYLOAD, "CVE-2021-44228")
        self.assertEqual(r["score"], 10.0); self.assertEqual(r["cvss_version"], "3.1")
        self.assertTrue(r["title"].startswith("Log4j2 JNDI")); self.assertTrue(r["title"].endswith("LDAP."))

    def test_parse_missing_and_unscored(self):
        self.assertIsNone(feeds.parse_nvd({"vulnerabilities": []}, "CVE-2021-44228"))
        unscored = {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "descriptions": [], "metrics": {}}}]}
        with self.assertRaises(feeds.FeedError):
            feeds.parse_nvd(unscored, "CVE-2021-44228")

    def test_parse_rejects_bad_vector(self):
        p = {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "descriptions": [{"lang": "en", "value": "x" * 20}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"vectorString": "garbage", "baseScore": 5.0}}]}}}]}
        with self.assertRaises(feeds.FeedError):
            feeds.parse_nvd(p, "CVE-2021-44228")

    def test_http_client_blocks_unlisted_hosts_and_http(self):
        for url in ("https://evil.example/x", "http://services.nvd.nist.gov/x", "https://169.254.169.254/latest"):
            with self.assertRaises(feeds.FeedError):
                feeds._http_get_json(url)

    def test_cve_id_validated_before_request(self):
        with self.assertRaises(feeds.FeedError):
            feeds.fetch_nvd_cve("CVE-1-2")


if __name__ == "__main__":
    unittest.main()
