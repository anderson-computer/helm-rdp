import os
import unittest
from pathlib import Path

from tests.helpers import ROOT

from helm_rdp import help_content


class HelpTest(unittest.TestCase):
    def test_help_md_in_sync(self):
        path = os.path.join(ROOT, "HELP.md")
        if not os.path.isfile(path):
            self.skipTest("HELP.md not shipped here")
        self.assertEqual(Path(path).read_text(encoding="utf-8"), help_content.markdown())

    def test_topics(self):
        names = [h for h, _b in help_content.HELP_TOPICS]
        for n in ("General tab", "Display tab", "Local Resources tab", "Experience tab", "Advanced tab",
                  "Credentials and saved passwords"):
            self.assertIn(n, names)
