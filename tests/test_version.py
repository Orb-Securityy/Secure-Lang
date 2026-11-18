"""Keep the published project version synchronized across entry-point metadata and docs."""

import pathlib
import re
import unittest

from securec import VERSION


ROOT = pathlib.Path(__file__).resolve().parents[1]


class VersionConsistencyTests(unittest.TestCase):
    def test_readme_uses_the_compiler_version(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"(v{VERSION}, bootstrap)", readme.splitlines()[0])

    def test_changelog_has_a_matching_release_heading(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        pattern = rf"^## {re.escape(VERSION)} — "
        self.assertRegex(changelog, pattern, msg="CHANGELOG.md must describe VERSION")


if __name__ == "__main__":
    unittest.main()
