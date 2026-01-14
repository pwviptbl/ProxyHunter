import re

# Lista de padrões de regex para detecção de segredos.
# Cada entrada é um dicionário contendo:
# 'Name': O nome do tipo de segredo.
# 'Pattern': A expressão regular para detectar o segredo.

SECRET_PATTERNS = [
    {
        "Name": "Google API Key",
        "Pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    },
    {
        "Name": "AWS Access Key ID",
        "Pattern": re.compile(r"AKIA[0-9A-Z]{16}")
    },
    {
        "Name": "GitHub Token",
        "Pattern": re.compile(r"ghp_[0-9a-zA-Z]{36}")
    },
                    {
                        "Name": "Generic API Key",
                        "Pattern": re.compile(r"""(?i)api[_-]?key[\s:=]+['"]?([a-zA-Z0-9_\-]{16,128})""")
                    },    {
        "Name": "JWT Token",
        "Pattern": re.compile(r"ey[J][A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*")
    },
    {
        "Name": "Test Secret Key",
        "Pattern": re.compile(r"SECRET_KEY_FOR_TESTING_[a-zA-Z0-9_\-]+")
    }
]
