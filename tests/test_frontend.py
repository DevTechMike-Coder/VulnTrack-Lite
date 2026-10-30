"""Regression guards that keep the strict CSP (no unsafe-inline) workable."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class FrontendCspGuards(unittest.TestCase):
    def test_index_has_no_inline_handlers_styles_or_scripts(self):
        html = read("index.html")
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html), "inline event handler found")
        self.assertIsNone(re.search(r"\sstyle\s*=", html), "inline style attribute found")
        self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script> found")
        self.assertNotIn("<style", html)
        self.assertNotRegex(html, r"https?://")  # no third-party origins

    def test_app_js_has_no_html_injection_sinks(self):
        code = re.sub(r"//.*", "", read("static", "app.js"))
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(sink, code)

    def test_static_assets_are_served(self):
        from fastapi.testclient import TestClient
        import main
        c = TestClient(main.app, base_url="http://127.0.0.1")
        for path in ("/static/app.js", "/static/app.css", "/static/tailwind.css",
                     "/static/vendor/lucide-0.469.0.min.js", "/static/fonts/inter-latin-wght-normal.woff2"):
            self.assertEqual(c.get(path).status_code, 200, path)


if __name__ == "__main__":
    unittest.main()
