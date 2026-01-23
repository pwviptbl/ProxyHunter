import sqlite3
import jwt
import os
from flask import Flask, request, Response, g, render_template_string, redirect, url_for, make_response

# --- App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_that_is_not_at_all_secret'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'database.db')
FILES_DIR = os.path.join(BASE_DIR, 'files')

# --- Database Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- Routes ---

@app.route('/')
def index():
    """Página inicial com links para outras seções."""
    return render_template_string("""
    <h1>Bem-vindo ao Servidor Vulnerável</h1>
    <p>Use os links abaixo para testar as funcionalidades do ProxyHunter.</p>
    <ul>
        <li><a href="/login">Login (SQLi, Brute Force)</a></li>
        <li><a href="/search">Search (XSS Refletido)</a></li>
        <li><a href="/profile">Profile (Cookie, JWT)</a></li>
        <li><a href="/admin">Admin (JWT Bypass)</a></li>
        <li><a href="/view-file?name=welcome.txt">File Viewer (Path Traversal)</a></li>
    </ul>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login vulnerável a SQL Injection e Brute Force."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        
        # VULNERABILIDADE: SQL Injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor = db.execute(query)
        user = cursor.fetchone()

        if user:
            # Geração de Cookie e JWT
            resp = make_response(redirect(url_for('profile')))
            resp.set_cookie('session_id', str(user['id']))
            
            # VULNERABILIDADE: JWT com segredo fraco e sem algoritmo especificado
            encoded_jwt = jwt.encode({'user': user['username'], 'role': 'user'}, app.config['SECRET_KEY'])
            resp.set_cookie('jwt_token', encoded_jwt)
            return resp
        else:
            return 'Login falhou. <a href="/login">Tente novamente</a>.'
            
    return render_template_string("""
    <h2>Login</h2>
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    <p>Tente usar ' or '1'='1' -- no campo de usuário.</p>
    """)

@app.route('/search')
def search():
    """Página de pesquisa vulnerável a XSS Refletido."""
    query = request.args.get('q', '')
    # VULNERABILIDADE: XSS Refletido
    return render_template_string(f"""
    <h2>Pesquisa</h2>
    <form method="get">
        <input type="text" name="q" value="{query}">
        <input type="submit" value="Search">
    </form>
    <h3>Resultados para: {query}</h3>
    """)

@app.route('/profile')
def profile():
    """Página de perfil que usa cookies e exibe um JWT."""
    session_id = request.cookies.get('session_id')
    jwt_token = request.cookies.get('jwt_token')
    
    if not session_id:
        return 'Não autenticado. Faça <a href="/login">login</a> primeiro.'

    return render_template_string("""
    <h2>Perfil do Usuário</h2>
    <p>Você está logado!</p>
    <p>Seu cookie de sessão é: {{ session_id }}</p>
    <p>Seu token JWT é: {{ jwt_token }}</p>
    <p>Use este token para tentar acessar a <a href="/admin">página de admin</a>.</p>
    """, session_id=session_id, jwt_token=jwt_token)

@app.route('/admin')
def admin():
    """Página de admin que valida um JWT."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return 'Acesso negado. Token JWT não fornecido no cabeçalho Authorization: Bearer [token].', 403

    token = auth_header.split(' ')[1]
    try:
        # VULNERABILIDADE: Validação fraca, vulnerável a ataques como 'none' algorithm
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded_token.get('role') == 'admin':
            return '<h1>Painel do Administrador</h1><p>Bem-vindo, admin!</p>'
        else:
            return 'Acesso negado. Você não é um admin.', 403
    except jwt.ExpiredSignatureError:
        return 'Token expirado.', 403
    except jwt.InvalidTokenError:
        return 'Token inválido.', 403

@app.route('/view-file')
def view_file():
    """Visualizador de arquivos vulnerável a Path Traversal."""
    filename = request.args.get('name')
    
    # VULNERABILIDADE: Path Traversal
    file_path = os.path.join(FILES_DIR, filename)
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return Response(content, mimetype='text/plain')
    except FileNotFoundError:
        return "Arquivo não encontrado.", 404
    except Exception as e:
        return f"Erro: {e}", 500

@app.route('/api/config')
def api_config():
    """Endpoint que expõe segredos para teste do scanner."""
    config_data = {
        "service": "internal-config-service",
        "version": "1.2.3",
        "keys": {
            "google_api_key": "AIzaSyC_this_is_a_fake_google_key_12345",
            "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "custom_auth_token": "SECRET_KEY_FOR_TESTING_abcdef-123456-xyz"
        }
    }
    return config_data

# --- Main Execution ---
if __name__ == '__main__':
    # Criar diretórios e arquivos necessários
    if not os.path.exists(FILES_DIR):
        os.makedirs(FILES_DIR)
    with open(os.path.join(FILES_DIR, 'welcome.txt'), 'w') as f:
        f.write('Este é um arquivo de boas-vindas.')
    with open(os.path.join(FILES_DIR, 'secret.txt'), 'w') as f:
        f.write('Esta é a informação secreta que o Path Traversal pode encontrar.')

    # Configurar o banco de dados
    conn = sqlite3.connect(DATABASE)
    conn.execute('DROP TABLE IF EXISTS users')
    conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
    conn.execute("INSERT INTO users (username, password) VALUES ('user', 'password')")
    conn.commit()
    conn.close()
    
    print("Servidor vulnerável iniciado em http://127.0.0.1")
    print("Use Ctrl+C para parar o servidor.")
    app.run(debug=True, port=5000)