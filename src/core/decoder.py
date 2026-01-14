import base64
import urllib.parse
import html
import binascii
import hashlib

class Decoder:
    @staticmethod
    def b64_encode(input_text: str) -> str:
        """Codifica uma string para Base64."""
        return base64.b64encode(input_text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def b64_decode(input_text: str) -> str:
        """Decodifica uma string de Base64.
        
        Raises:
            binascii.Error: Se a entrada não for um Base64 válido.
            UnicodeDecodeError: Se o resultado decodificado não for um UTF-8 válido.
        """
        return base64.b64decode(input_text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def url_encode(input_text: str) -> str:
        """Codifica uma string para o formato URL."""
        return urllib.parse.quote(input_text)

    @staticmethod
    def url_decode(input_text: str) -> str:
        """Decodifica uma string do formato URL."""
        return urllib.parse.unquote(input_text)

    @staticmethod
    def html_encode(input_text: str) -> str:
        """Codifica caracteres especiais de HTML (e.g., '<' para '&lt;')."""
        return html.escape(input_text)

    @staticmethod
    def html_decode(input_text: str) -> str:
        """Decodifica entidades HTML (e.g., '&lt;' para '<')."""
        return html.unescape(input_text)

    @staticmethod
    def hex_encode(input_text: str) -> str:
        """Codifica uma string para sua representação hexadecimal."""
        return binascii.hexlify(input_text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def hex_decode(input_text: str) -> str:
        """Decodifica uma string de sua representação hexadecimal.
        
        Raises:
            binascii.Error: Se a entrada contiver caracteres não-hexadecimais.
            UnicodeDecodeError: Se o resultado decodificado não for um UTF-8 válido.
        """
        return binascii.unhexlify(input_text).decode('utf-8')

    @staticmethod
    def hash_md5(input_text: str) -> str:
        """Calcula o hash MD5 de uma string."""
        return hashlib.md5(input_text.encode('utf-8')).hexdigest()

    @staticmethod
    def hash_sha1(input_text: str) -> str:
        """Calcula o hash SHA-1 de uma string."""
        return hashlib.sha1(input_text.encode('utf-8')).hexdigest()

    @staticmethod
    def hash_sha256(input_text: str) -> str:
        """Calcula o hash SHA-256 de uma string."""
        return hashlib.sha256(input_text.encode('utf-8')).hexdigest()
