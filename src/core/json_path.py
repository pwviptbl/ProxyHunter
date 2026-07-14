import json


def parse_json_value(value):
    """Convert a rule value to its JSON type when possible."""
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


def set_json_path(document, key_path, value):
    """Set a value using dot notation, creating missing objects and list items."""
    keys = key_path.split('.')
    if not key_path or any(key == '' for key in keys):
        raise ValueError("Caminho JSON vazio ou invalido")

    current = document
    for position, key in enumerate(keys):
        is_last = position == len(keys) - 1

        if isinstance(current, list):
            if not key.isdigit():
                raise ValueError(f"O segmento '{key}' deve ser um indice numerico")
            index = int(key)
            if is_last:
                while len(current) <= index:
                    current.append(None)
                current[index] = value
                return

            next_key = keys[position + 1]
            while len(current) <= index:
                current.append([] if next_key.isdigit() else {})
            current = current[index]
            continue

        if not isinstance(current, dict):
            raise ValueError(
                f"Nao e possivel acessar '{key}' dentro de {type(current).__name__}"
            )

        if is_last:
            current[key] = value
            return

        if key not in current:
            next_key = keys[position + 1]
            current[key] = [] if next_key.isdigit() else {}
        current = current[key]
