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

    def test_intercept_responses_are_delivered_to_the_matching_request(self):
        with tempfile.TemporaryDirectory() as directory:
            config = InterceptConfig(os.path.join(directory, "intercept_config.json"))
            first_id = config.add_to_intercept_queue({'url': 'https://example.com/first'})
            second_id = config.add_to_intercept_queue({'url': 'https://example.com/second'})

            self.assertTrue(config.add_intercept_response({'intercept_id': second_id, 'action': 'drop'}))
            self.assertTrue(config.add_intercept_response({'intercept_id': first_id, 'action': 'forward'}))

            self.assertEqual(config.get_intercept_response(first_id)['action'], 'forward')
            self.assertEqual(config.get_intercept_response(second_id)['action'], 'drop')

    def test_disabling_intercept_releases_pending_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            config = InterceptConfig(os.path.join(directory, "intercept_config.json"))
            config.toggle_intercept()
            intercept_id = config.add_to_intercept_queue({'url': 'https://example.com/pending'})

            self.assertFalse(config.toggle_intercept())
            self.assertEqual(config.get_intercept_response(intercept_id)['action'], 'forward')


if __name__ == "__main__":
    unittest.main()
