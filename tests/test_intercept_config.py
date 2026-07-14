import json
import os
import tempfile
import unittest

from src.core.config import InterceptConfig


class InterceptConfigTest(unittest.TestCase):
    def test_update_rule_preserves_enabled_status(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = os.path.join(directory, "intercept_config.json")
            config = InterceptConfig(config_path)
            success, _ = config.add_rule("example.com", "/app-data", "users.0.id", "7", "response")
            self.assertTrue(success)
            config.rules[0]["enabled"] = False

            success, _ = config.update_rule(
                0, "example.com", "/app-data", "users.0.role", "admin", "response"
            )

            self.assertTrue(success)
            self.assertEqual(config.rules[0]["param_name"], "users.0.role")
            self.assertFalse(config.rules[0]["enabled"])
            with open(config_path, encoding="utf-8") as config_file:
                self.assertFalse(json.load(config_file)["rules"][0]["enabled"])


if __name__ == "__main__":
    unittest.main()
