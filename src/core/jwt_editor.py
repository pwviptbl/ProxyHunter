import jwt
import json
import base64
from typing import Dict, Optional, Tuple

class JWTEditor:
    """
    Uma classe para decodificar, manipular e testar a segurança de JSON Web Tokens (JWT).
    """
    def __init__(self, token: str):
        self.original_token = token
        self.header: Dict = {}
        self.payload: Dict = {}
        self.signature: bytes = b''
        self.decode()

    def _b64_decode(self, data: str) -> bytes:
        """Decodifica uma string base64url, adicionando padding se necessário."""
        padding = '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

    def decode(self) -> Tuple[bool, str]:
        """Decodifica o token em header, payload e assinatura."""
        try:
            parts = self.original_token.split('.')
            if len(parts) != 3:
                return False, "Token JWT inválido: O token deve ter 3 partes."

            self.header = json.loads(self._b64_decode(parts[0]))
            self.payload = json.loads(self._b64_decode(parts[1]))
            self.signature = self._b64_decode(parts[2])
            return True, "Token decodificado com sucesso."
        except (json.JSONDecodeError, TypeError, IndexError) as e:
            self.header = {}
            self.payload = {}
            self.signature = b''
            return False, f"Erro ao decodificar o token: {e}"

    def update_header(self, new_header: Dict):
        """Atualiza o cabeçalho do token."""
        self.header = new_header

    def update_payload(self, new_payload: Dict):
        """Atualiza o payload do token."""
        self.payload = new_payload

    def sign(self, secret: str = '', algorithm: Optional[str] = None) -> str:
        """
        Assina o header e o payload atuais para gerar um novo token.
        Se o algoritmo for None, usa o do cabeçalho.
        """
        alg = algorithm if algorithm is not None else self.header.get('alg', 'HS256')

        # O algoritmo 'none' não precisa de chave
        if alg.lower() == 'none':
            secret = ''

        try:
            new_token = jwt.encode(
                self.payload,
                secret,
                algorithm=alg,
                headers=self.header
            )
            return new_token
        except Exception as e:
            return f"Erro ao assinar o token: {e}"

    def apply_alg_none_attack(self) -> str:
        """Aplica o ataque 'alg: none' ao modificar o header e remover a assinatura."""
        self.header['alg'] = 'none'

        # O encode com alg 'none' lida com a assinatura vazia
        unsigned_token = self.sign(algorithm='none')

        # jwt.encode retorna a string completa, mas queremos garantir que termina com um '.'
        parts = unsigned_token.split('.')
        if len(parts) == 3 and parts[2] == '':
             return f"{parts[0]}.{parts[1]}."

        return unsigned_token

    def get_header_str(self) -> str:
        """Retorna o header como uma string JSON formatada."""
        return json.dumps(self.header, indent=4)

    def get_payload_str(self) -> str:
        """Retorna o payload como uma string JSON formatada."""
        return json.dumps(self.payload, indent=4)
