import sqlite3
import json
import hashlib
import os
from urllib.parse import urlparse
import threading

class DatabaseManager:
    def __init__(self, db_path='data/target.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        # Permite uso seguro entre threads do proxy e da UI
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._initialize_db()

    def _initialize_db(self):
        cursor = self.conn.cursor()

        # Tabela para os "moldes" das requisições
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS RequestNodes (
                id INTEGER PRIMARY KEY,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                request_headers_json TEXT,
                request_body_blob BLOB,
                response_hash TEXT,
                response_time_ms INTEGER,
                UNIQUE(host, method, path)
            )
        ''')

        # Tabela para os pontos de injeção identificados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS InjectionPoints (
                id INTEGER PRIMARY KEY,
                request_node_id INTEGER,
                location TEXT NOT NULL,
                name TEXT,
                original_value TEXT,
                status TEXT DEFAULT 'PENDING',
                FOREIGN KEY(request_node_id) REFERENCES RequestNodes(id)
            )
        ''')

        self.conn.commit()

    def get_or_create_request_node(self, flow):
        parsed_url = urlparse(flow.request.url)
        host = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path

        with self.lock:
            cursor = self.conn.cursor()

            # Tenta encontrar um nó existente
            cursor.execute(
                "SELECT id FROM RequestNodes WHERE host = ? AND method = ? AND path = ?",
                (host, flow.request.method, path)
            )
            row = cursor.fetchone()

            if row:
                return row['id']
            else:
                # Cria um novo nó
                headers = {k: v for k, v in flow.request.headers.items()}
                try:
                    response_hash = hashlib.sha256(flow.response.content).hexdigest() if flow.response and flow.response.content else None
                except Exception:
                    response_hash = None
                try:
                    response_time_ms = int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000) if flow.response else 0
                except Exception:
                    response_time_ms = 0

                cursor.execute(
                    """
                    INSERT INTO RequestNodes (host, method, path, request_headers_json, request_body_blob, response_hash, response_time_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        host,
                        flow.request.method,
                        path,
                        json.dumps(headers),
                        flow.request.content,
                        response_hash,
                        response_time_ms
                    )
                )
                self.conn.commit()
                return cursor.lastrowid

    def add_injection_points(self, request_node_id, injection_points):
        if not injection_points:
            return

        with self.lock:
            cursor = self.conn.cursor()

            points_to_insert = [
                (request_node_id, p['location'], p.get('name'), p.get('value'))
                for p in injection_points
            ]

            cursor.executemany(
                """
                INSERT INTO InjectionPoints (request_node_id, location, name, original_value)
                VALUES (?, ?, ?, ?)
                """,
                points_to_insert
            )
            self.conn.commit()

    def clear_all(self):
        """Remove todos os registros das tabelas principais."""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM InjectionPoints')
            cursor.execute('DELETE FROM RequestNodes')
            self.conn.commit()

    def close(self):
        self.conn.close()
