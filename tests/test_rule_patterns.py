"""Pattern tests for the rules that will be changed first.

Each rule gets short texts that it names itself (must be caught) and harmless near-misses taken from false alarms
seen on real, legitimate tools (must not be caught). These are one-line patterns, not attack code: nothing here is
written to disk or run.

The near-misses are marked expectedFailure while the rules still raise them, so the record of the false alarm is
kept. When a rule is fixed its near-miss tests start to pass, unittest reports "unexpected success", and the marker
must be removed in the same change.

Run from the repository root:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from skillaudit.engine import ContentEngine  # noqa: E402
from skillaudit.model import TextUnit  # noqa: E402
from skillaudit.rules import all_rules  # noqa: E402

# Rules with no malicious demo sample that are covered by pattern tests instead (read by benchmark/run.py).
# FS-NAME-HIDDEN-CHARS is tested in memory in test_skillaudit.py.
PATTERN_TESTED = {"CRED-BROWSER", "EXEC-JS-REMOTE-EXEC", "OBF-DECODE-EXEC", "FS-NAME-HIDDEN-CHARS"}

ENGINE = ContentEngine(all_rules())


def rule_ids(text, kind):
    """Rule ids the full content engine reports for this text (validators, kinds and hints included)."""
    return {f.rule_id for f in ENGINE.scan(TextUnit("sample", text, kind))}


class PatternCase(unittest.TestCase):
    def caught(self, rule, text, kind):
        self.assertIn(rule, rule_ids(text, kind), "%s should be caught in: %s" % (rule, text))

    def not_caught(self, rule, text, kind):
        self.assertNotIn(rule, rule_ids(text, kind), "%s should not be raised on: %s" % (rule, text))


class BrowserCredentialStore(PatternCase):
    """CRED-BROWSER: a browser profile's credential or cookie store."""

    def test_chrome_profile_login_data(self):
        self.caught("CRED-BROWSER", 'p = base + "/Google/Chrome/User Data/Default/Login Data"\n', "python")

    def test_firefox_logins_file(self):
        self.caught("CRED-BROWSER", 'p = "~/.mozilla/firefox/abcd.default-release/logins.json"\n', "python")

    def test_safari_cookie_file(self):
        self.caught("CRED-BROWSER", 'p = "~/Library/Cookies/Cookies.binarycookies"\n', "python")

    @unittest.expectedFailure  # false alarm on Chrome DevTools MCP and Playwright (link to Chromium's bug tracker)
    def test_near_miss_chromium_bug_link(self):
        self.not_caught("CRED-BROWSER", "// see https://bugs.chromium.org/p/chromium/issues/detail?id=1439785\n",
                        "javascript")

    @unittest.expectedFailure  # false alarm on Playwright (where the browser program is installed)
    def test_near_miss_browser_install_path(self):
        self.not_caught("CRED-BROWSER", 'const exe = "/opt/google/chrome/chrome";\n', "javascript")

    @unittest.expectedFailure  # false alarm on Playwright (name of a bundled file)
    def test_near_miss_bundled_file_name(self):
        self.not_caught("CRED-BROWSER", "// node_modules/electron-to-chromium/versions.js\n", "javascript")


class JsRemoteCodeExecution(PatternCase):
    """EXEC-JS-REMOTE-EXEC: eval / Function applied to text fetched from the network."""

    def test_eval_of_response_text(self):
        self.caught("EXEC-JS-REMOTE-EXEC", "eval(xhr.responseText);\n", "javascript")

    def test_function_constructor_of_fetched_text(self):
        self.caught("EXEC-JS-REMOTE-EXEC", "const run = Function(await response.text());\n", "javascript")

    @unittest.expectedFailure  # false alarm on Playwright: the keyword "function" is not the Function constructor
    def test_near_miss_function_keyword_then_fetch(self):
        self.not_caught("EXEC-JS-REMOTE-EXEC", 'setInterval(function(){fetch("ping")},1e4);\n', "javascript")

    @unittest.expectedFailure  # same cause, ordinary promise code
    def test_near_miss_promise_callback(self):
        self.not_caught("EXEC-JS-REMOTE-EXEC", "return fetch(url).then(function(r){return r.text()});\n",
                        "javascript")


class DecodeThenExecute(PatternCase):
    """OBF-DECODE-EXEC: decoded data handed straight to an interpreter."""

    def test_js_eval_of_atob(self):
        self.caught("OBF-DECODE-EXEC", "eval(atob(payload));\n", "javascript")

    def test_python_exec_of_b64decode(self):
        self.caught("OBF-DECODE-EXEC", "exec(base64.b64decode(blob))\n", "python")

    @unittest.expectedFailure  # false alarm on impeccable and Playwright: a function that decodes, nothing executed
    def test_near_miss_function_that_decodes(self):
        self.not_caught("OBF-DECODE-EXEC", "function dt(e){const i=window.atob(e);return new Uint8Array(i.length)}\n",
                        "javascript")


if __name__ == "__main__":
    unittest.main()
