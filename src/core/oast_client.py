import requests
import secrets

class OASTClient:
    """
    Cliente para interagir com o servidor OAST (Out-of-Band Application Security Testing).
    """

    def __init__(self, config):
        """
        Inicializa o cliente OAST.

        :param config: Objeto de configuração que contém as configurações do OAST.
        """
        self.api_url = getattr(config, 'oast_api_url', None)
        self.api_key = getattr(config, 'oast_api_key', None)
        self.base_domain = getattr(config, 'oast_base_domain', None)

    def generate_interaction_id(self, type_prefix="gen"):
        """
        Gera um ID de interação único e o domínio de payload correspondente.

        :param type_prefix: Um prefixo para ajudar a identificar o tipo de teste.
        :return: Uma tupla contendo (interaction_id, payload_domain).
        """
        random_string = secrets.token_hex(8)
        interaction_id = f"pxh-{type_prefix}-{random_string}"
        payload_domain = f"{interaction_id}.{self.base_domain}"
        return interaction_id, payload_domain

    def check_hit(self, interaction_id: str) -> dict:
        """
        Verifica se uma interação (hit) ocorreu para um determinado ID.

        :param interaction_id: O ID da interação a ser verificado.
        :return: Um dicionário com a resposta da API.
        """
        if not self.api_url or not self.api_key:
            return {"hit": False, "data": [], "error": "OAST client não configurado."}

        params = {'id': interaction_id}
        headers = {'X-ProxyHunter-Key': self.api_key}

        try:
            response = requests.get(self.api_url, params=params, headers=headers, timeout=5)
            response.raise_for_status()  # Lança exceção para status de erro HTTP (4xx ou 5xx)

            # Tenta decodificar o JSON, mesmo que a resposta esteja vazia
            try:
                return response.json()
            except requests.exceptions.JSONDecodeError:
                # Retorna um hit falso se o corpo da resposta não for um JSON válido
                return {"hit": False, "data": [], "error": f"Resposta não-JSON recebida (Status: {response.status_code})"}

        except requests.exceptions.RequestException as e:
            return {"hit": False, "data": [], "error": f"Falha na requisição: {e}"}
