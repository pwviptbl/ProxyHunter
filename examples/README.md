# 📁 Examples - Payload Files

Esta pasta contém arquivos de exemplo com payloads para diferentes tipos de testes de segurança.

## 📋 Arquivos Disponíveis

### Arquivos Existentes
- `directories.txt` - Lista de diretórios comuns para fuzzing
- `passwords.txt` - Senhas comuns para testes de autenticação
- `sqli_payloads.txt` - Payloads de SQL Injection
- `usernames.txt` - Nomes de usuário comuns
- `xss_payloads.txt` - Payloads de Cross-Site Scripting

## 🆕 Novos Arquivos Sugeridos

Você pode criar os seguintes arquivos nesta pasta para expandir suas capacidades de teste:

### 1. `path_traversal_payloads.txt`
Payloads para testes de Path Traversal (já implementados no scanner):
```
../
../../
../../../
../../../../
../../../../../etc/passwd
../../../../../../../../windows/win.ini
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### 2. `command_injection_payloads.txt`
Payloads para Command Injection:
```
; whoami
| whoami
& whoami
; ls -la
| cat /etc/passwd
; sleep 5
& timeout /t 5
```

### 3. `api_keys_wordlist.txt`
Padrões de API keys para buscar em respostas:
```
api_key
apikey
api-key
secret_key
access_token
auth_token
```

### 4. `sensitive_files.txt`
Arquivos sensíveis comuns:
```
.env
.git/config
config.php
database.yml
web.config
wp-config.php
.htaccess
.htpasswd
backup.sql
dump.sql
```

### 5. `subdomain_wordlist.txt`
Subdomínios comuns para enumeração:
```
www
api
admin
dev
test
staging
beta
mail
ftp
```

### 6. `http_methods.txt`
Métodos HTTP para testar:
```
GET
POST
PUT
DELETE
PATCH
OPTIONS
HEAD
TRACE
CONNECT
PROPFIND
```

### 7. `parameter_names.txt`
Nomes de parâmetros comuns para fuzzing:
```
id
user
username
password
email
token
api_key
search
q
query
page
limit
```

### 8. `file_extensions.txt`
Extensões de arquivo para testes:
```
.php
.asp
.aspx
.jsp
.cgi
.pl
.py
.rb
.sh
.bat
.bak
.old
.backup
.sql
.zip
.tar.gz
```

### 9. `user_agents.txt`
User-Agents diversos para testes:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)
curl/7.64.1
Googlebot/2.1
nikto/2.1.6
sqlmap/1.0
```

### 10. `encoding_variations.txt`
Variações de encoding para bypass:
```
%2e%2e%2f
%252e%252e%252f
..%c0%af
..%ef%bc%8f
%c0%ae%c0%ae%c0%af
```

## 📊 Como Usar

### No Scanner Ativo
Os payloads já estão integrados no código do `active_scanner.py`. Você pode:

1. Usar os payloads padrão (já implementados)
2. Adicionar payloads customizados editando `config/custom_payloads.example.yml`
3. Criar seus próprios arquivos de payload nesta pasta

### No Attacker Tab
Use estes arquivos na aba "Attacker" do ProxyHunter:

1. Selecione o tipo de ataque
2. Escolha o arquivo de payload apropriado desta pasta
3. Configure os parâmetros de ataque
4. Execute o fuzzing

### Exemplo de Uso Programático

```python
# Carregar payloads de um arquivo
def load_payloads(filename):
    with open(f'examples/{filename}', 'r') as f:
        return [line.strip() for line in f if line.strip()]

# Usar no seu código
sqli_payloads = load_payloads('sqli_payloads.txt')
xss_payloads = load_payloads('xss_payloads.txt')
```

## 🔒 Segurança

⚠️ **IMPORTANTE**: 
- Use estes payloads apenas em ambientes de teste autorizados
- Nunca teste em sistemas sem permissão explícita
- Alguns payloads podem causar danos se usados incorretamente
- Sempre tenha backups antes de realizar testes destrutivos

## 📚 Fontes de Payloads

Os payloads implementados são baseados em:

1. **SecLists** (Daniel Miessler)
   - https://github.com/danielmiessler/SecLists

2. **PayloadsAllTheThings** (swisskyrepo)
   - https://github.com/swisskyrepo/PayloadsAllTheThings

3. **OWASP Testing Guide**
   - https://owasp.org/www-project-web-security-testing-guide/

4. **PortSwigger Web Security Academy**
   - https://portswigger.net/web-security

5. **Pesquisa própria e CVEs**

## 🔄 Atualizações

Para manter seus payloads atualizados:

1. **Automaticamente**: Use o script `update_payloads.py` (a ser criado)
2. **Manualmente**: Baixe as listas mais recentes dos links acima
3. **Custom**: Adicione seus próprios payloads baseados em suas descobertas

## 📝 Contribuindo

Se você descobrir novos payloads efetivos, considere:

1. Adicionar ao arquivo apropriado
2. Documentar o contexto de uso
3. Compartilhar com a comunidade (se apropriado)

## 🎯 Melhores Práticas

1. **Organize seus payloads**: Separe por tipo e severidade
2. **Documente**: Adicione comentários explicando payloads complexos
3. **Teste gradualmente**: Comece com payloads menos invasivos
4. **Monitore**: Sempre observe as respostas do sistema alvo
5. **Rate limiting**: Use delays para não sobrecarregar o alvo

## 📊 Estatísticas dos Payloads Implementados

| Tipo | Quantidade | Arquivo |
|------|------------|---------|
| SQL Injection | 100+ | Integrado no scanner |
| XSS | 70+ | Integrado no scanner |
| Path Traversal | 70+ | Integrado no scanner |
| Command Injection | 50+ | Integrado no scanner |
| Pastas comuns | ~50 | directories.txt |
| Senhas | ~100 | passwords.txt |
| Usuários | ~50 | usernames.txt |

---

**Última atualização**: 26 de outubro de 2025  
**Versão**: 2.0
