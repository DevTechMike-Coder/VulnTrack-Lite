import unittest

from cvss import CvssError, base_score, parse_vector, severity_for
from triage import priority

V31_VECTORS = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 7.8,
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 4.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
}
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class CvssTests(unittest.TestCase):
    def test_v3_scores(self):
        for vector, expected in V31_VECTORS.items():
            with self.subTest(vector=vector):
                self.assertEqual(base_score(vector), expected)

    def test_v4_validates_but_does_not_score(self):
        self.assertEqual(parse_vector(V40).version, "4.0")
        with self.assertRaises(CvssError):
            base_score(V40)

    def test_rejects_malformed(self):
        bad = [
            "", "garbage", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Z",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            "CVSS:3.1/" + "A" * 400,
        ]
        for v in bad:
            with self.subTest(vector=v[:40]):
                with self.assertRaises(CvssError):
                    parse_vector(v)

    def test_severity_bands(self):
        got = [severity_for(s) for s in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)]
        self.assertEqual(got, ["None", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"])
        for bad in (-0.1, 10.1):
            with self.assertRaises(CvssError):
                severity_for(bad)


class TriageTests(unittest.TestCase):
    def test_kev_always_p0(self):
        self.assertEqual(priority(2.0, 0.0001, True)[0], 0)

    def test_epss_thresholds(self):
        self.assertEqual(priority(5.0, 0.25, False)[0], 1)
        self.assertEqual(priority(9.5, 0.06, False)[0], 1)
        self.assertEqual(priority(7.5, 0.01, False)[0], 2)
        self.assertEqual(priority(3.0, 0.06, False)[0], 2)
        self.assertEqual(priority(3.0, 0.01, False)[0], 3)

    def test_without_epss_falls_back_to_cvss(self):
        self.assertEqual(priority(9.9, None, False)[0], 1)
        self.assertEqual(priority(7.0, None, False)[0], 2)
        self.assertEqual(priority(6.9, None, False)[0], 3)


if __name__ == "__main__":
    unittest.main()
