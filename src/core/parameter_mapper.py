import json
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree as ET

class ParameterMapper:
    def find_injection_points(self, flow):
        """
        Analisa um objeto de fluxo do mitmproxy e retorna uma lista de pontos de injeção.
        """
        points = []
        points.extend(self._from_query(flow))
        points.extend(self._from_body(flow))
        points.extend(self._from_headers(flow))
        points.extend(self._from_cookies(flow))
        points.extend(self._from_path(flow))
        return points

    def _from_query(self, flow):
        """ Extrai parâmetros da query string. """
        query_params = flow.request.query
        return [
            {'location': 'QUERY', 'name': name, 'value': value}
            for name, value in query_params.items()
        ]

    def _from_body(self, flow):
        """ Extrai parâmetros do corpo da requisição. """
        content_type = flow.request.headers.get('Content-Type', '')
        body = flow.request.get_text()
        if not body:
            return []

        points = []
        if 'application/x-www-form-urlencoded' in content_type:
            params = parse_qs(body)
            for name, values in params.items():
                for value in values:
                    points.append({'location': 'BODY_FORM', 'name': name, 'value': value})
        elif 'application/json' in content_type:
            try:
                data = json.loads(body)
                points.extend(self._from_json(data))
            except json.JSONDecodeError:
                pass # Body inválido
        elif 'application/xml' in content_type:
            points.extend(self._from_xml(body))

        return points

    def _from_json(self, data, parent_key=''):
        """ Recursivamente extrai chaves e valores de um objeto JSON. """
        points = []
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{parent_key}.{key}" if parent_key else key
                if isinstance(value, (dict, list)):
                    points.extend(self._from_json(value, new_key))
                else:
                    points.append({'location': 'BODY_JSON', 'name': new_key, 'value': str(value)})
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_key = f"{parent_key}[{i}]"
                if isinstance(item, (dict, list)):
                    points.extend(self._from_json(item, new_key))
                else:
                    points.append({'location': 'BODY_JSON', 'name': new_key, 'value': str(item)})
        return points

    def _from_xml(self, body):
        """ Extrai parâmetros de um corpo XML (heurística). """
        points = []
        try:
            root = ET.fromstring(body)
            for elem in root.iter():
                # Valores de atributos
                for name, value in elem.attrib.items():
                    points.append({'location': 'BODY_XML', 'name': f"{elem.tag}@{name}", 'value': value})
                # Conteúdo de texto da tag
                if elem.text and elem.text.strip():
                    points.append({'location': 'BODY_XML', 'name': elem.tag, 'value': elem.text.strip()})
        except ET.ParseError:
            pass # XML inválido
        return points

    def _from_headers(self, flow):
        """ Extrai parâmetros dos cabeçalhos. """
        # Headers que geralmente não são interessantes para scan
        exclude_headers = {'content-length', 'host', 'connection', 'accept', 'accept-encoding', 'accept-language', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'upgrade-insecure-requests', 'cache-control'}

        return [
            {'location': 'HEADER', 'name': name, 'value': value}
            for name, value in flow.request.headers.items()
            if name.lower() not in exclude_headers
        ]

    def _from_cookies(self, flow):
        """ Extrai parâmetros dos cookies. """
        return [
            {'location': 'COOKIE', 'name': name, 'value': value}
            for name, value in flow.request.cookies.items()
        ]

    def _from_path(self, flow):
        """ Extrai parâmetros numéricos do path da URL. """
        path_segments = urlparse(flow.request.url).path.split('/')
        points = []
        for i, segment in enumerate(path_segments):
            if segment.isdigit():
                points.append({'location': 'PATH', 'name': f'path_segment_{i}', 'value': segment})
        return points
