from datetime import datetime
from typing import List, Dict, Optional


import queue


class WebSocketHistory:
    """Gerencia o histórico de conexões e mensagens WebSocket"""

    def __init__(self):
        self.connections = {}  # {flow_id: connection_info}
        self.messages = {}  # {flow_id: [messages]}
        self.current_id = 0
        self.ui_queue = None

    def set_ui_queue(self, ui_queue: queue.Queue):
        """Define a fila para notificações da UI."""
        self.ui_queue = ui_queue

    def add_connection(self, flow_id: str, url: str, host: str):
        """Registra uma nova conexão WebSocket"""
        self.current_id += 1
        self.connections[flow_id] = {
            'id': self.current_id,
            'flow_id': flow_id,
            'url': url,
            'host': host,
            'start_time': datetime.now(),
            'end_time': None,
            'status': 'active',
            'message_count': 0,
        }
        self.messages[flow_id] = []

        # Notifica a UI
        if self.ui_queue:
            self.ui_queue.put({"type": "update_websocket_list", "data": self.get_connections()})

    def add_message(self, flow_id: str, message: bytes, from_client: bool):
        """Adiciona uma mensagem WebSocket ao histórico"""
        if flow_id not in self.messages:
            return

        # Tenta decodificar como texto UTF-8 válido
        try:
            content = message.decode('utf-8')
            # Verifica se contém caracteres não-imprimíveis (exceto espaços em branco comuns)
            is_binary = any(ord(c) < 32 and c not in '\n\r\t' for c in content)
            if is_binary:
                # Se for binário, usa representação hexadecimal
                content = message.hex()
        except UnicodeDecodeError:
            # Não é UTF-8 válido, trata como binário
            content = message.hex()
            is_binary = True

        msg_entry = {
            'timestamp': datetime.now(),
            'from_client': from_client,
            'content': content,
            'is_binary': is_binary,
            'size': len(message),
        }
        
        self.messages[flow_id].append(msg_entry)
        
        # Atualiza contador de mensagens
        if flow_id in self.connections:
            self.connections[flow_id]['message_count'] += 1

        # Notifica a UI
        if self.ui_queue:
            self.ui_queue.put({"type": "update_websocket_list", "data": self.get_connections()})

    def close_connection(self, flow_id: str):
        """Marca uma conexão WebSocket como fechada"""
        if flow_id in self.connections:
            self.connections[flow_id]['end_time'] = datetime.now()
            self.connections[flow_id]['status'] = 'closed'

            # Notifica a UI
            if self.ui_queue:
                self.ui_queue.put({"type": "update_websocket_list", "data": self.get_connections()})

    def get_connections(self) -> List[Dict]:
        """Retorna todas as conexões WebSocket"""
        return list(self.connections.values())

    def get_messages(self, flow_id: str) -> List[Dict]:
        """Retorna todas as mensagens de uma conexão específica"""
        return self.messages.get(flow_id, [])

    def get_connection_info(self, flow_id: str) -> Optional[Dict]:
        """Retorna informações sobre uma conexão específica"""
        return self.connections.get(flow_id)

    def clear_history(self):
        """Limpa todo o histórico de WebSocket"""
        self.connections = {}
        self.messages = {}
        self.current_id = 0
