import unittest

from src.core.multipart import upsert_multipart_form_field


class MultipartTest(unittest.TestCase):
    def test_replaces_requested_field_without_changing_other_fields(self):
        boundary = "----WebKitFormBoundarybjZ0uhHam2NXXn6S"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="user_id"\r\n\r\n'
            "7\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="process_type_id"\r\n\r\n'
            "2\r\n"
            f"--{boundary}--\r\n"
        )

        rewritten, replacements = upsert_multipart_form_field(
            body, boundary, "process_type_id", "1"
        )

        self.assertEqual(replacements, 1)
        self.assertIn('name="user_id"\r\n\r\n7', rewritten)
        self.assertIn('name="process_type_id"\r\n\r\n1', rewritten)
        self.assertNotIn('name="process_type_id"\r\n\r\n2', rewritten)

    def test_appends_missing_field_before_final_boundary(self):
        boundary = "example"
        body = '--example\r\nContent-Disposition: form-data; name="user_id"\r\n\r\n7\r\n--example--\r\n'

        rewritten, replacements = upsert_multipart_form_field(body, boundary, "title", "Teste injetado")

        self.assertEqual(replacements, 1)
        self.assertIn('name="user_id"\r\n\r\n7', rewritten)
        self.assertIn('name="title"\r\n\r\nTeste injetado', rewritten)
        self.assertTrue(rewritten.endswith('--example--\r\n'))


if __name__ == "__main__":
    unittest.main()
