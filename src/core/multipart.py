import re


def upsert_multipart_form_field(body, boundary, field_name, value):
    """Replace a multipart field or append it when it is not present."""
    if not boundary:
        raise ValueError("Boundary multipart ausente")

    escaped_field = re.escape(field_name)
    escaped_boundary = re.escape(boundary)
    pattern = re.compile(
        rf'(Content-Disposition:\s*form-data;\s*name="{escaped_field}"\r?\n'
        rf'(?:[^\r\n]*\r?\n)*?\r?\n).*?(?=\r?\n--{escaped_boundary})',
        re.DOTALL | re.IGNORECASE,
    )
    rewritten, replacements = pattern.subn(rf'\g<1>{value}', body, count=1)
    if replacements:
        return rewritten, replacements

    closing_boundary = f"--{boundary}--"
    closing_index = body.rfind(closing_boundary)
    if closing_index == -1:
        raise ValueError("Delimitador final multipart não encontrado")

    line_break = "\r\n" if "\r\n" in body else "\n"
    new_part = (
        f"--{boundary}{line_break}"
        f'Content-Disposition: form-data; name="{field_name}"{line_break}{line_break}'
        f"{value}{line_break}"
    )
    return body[:closing_index] + new_part + body[closing_index:], 1
