import unittest

from src.core.json_path import parse_json_value, set_json_path


class JsonPathTest(unittest.TestCase):
    def test_updates_object_inside_array(self):
        body = {"processes": [{"id": 4}, {"id": 5}]}

        set_json_path(body, "processes.1.id", 999)

        self.assertEqual(body["processes"][1]["id"], 999)

    def test_updates_nested_array(self):
        body = {"processes": [{"locomotions": [{"estimated_amount": "35.70"}]}]}

        set_json_path(body, "processes.0.locomotions.0.estimated_amount", "500.00")

        self.assertEqual(
            body["processes"][0]["locomotions"][0]["estimated_amount"],
            "500.00",
        )

    def test_creates_first_object_in_empty_array(self):
        body = {"users": []}

        set_json_path(body, "users.0.id", 7)

        self.assertEqual(body, {"users": [{"id": 7}]})

    def test_expands_array_for_requested_index(self):
        body = {"users": []}

        set_json_path(body, "users.2.role", "admin")

        self.assertEqual(body["users"], [{}, {}, {"role": "admin"}])

    def test_parses_rule_value_types(self):
        self.assertIs(parse_json_value("true"), True)
        self.assertEqual(parse_json_value("999"), 999)
        self.assertEqual(parse_json_value('"fechado"'), "fechado")
        self.assertEqual(parse_json_value("fechado"), "fechado")


if __name__ == "__main__":
    unittest.main()
