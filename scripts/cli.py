import sys
import os
import json
import click
import threading
import time
import asyncio

# Adiciona o diretório raiz do projeto ao path para importações corretas
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.core.config import InterceptConfig
from src.core.auto_navigator import AutoNavigator, PlaywrightAutoNavigator
from src.core.agent import AutonomousAgent, LLMConfig


@click.group()
def cli():
    """
    Iniciando CLI - Ferramenta de linha de comando para gerenciar
    regras de interceptação e executar o proxy.
    """
    pass


# Para que o comando scan funcione, precisamos de acesso ao addon e ao histórico.
# Em um cenário real, isso poderia vir de um estado compartilhado ou de um proxy em execução.
# Aqui, vamos instanciá-los para permitir a chamada.
config_instance = InterceptConfig()
from src.core.history import RequestHistory
history_instance = RequestHistory()
from src.core.spider import Spider
spider_instance = Spider()
from src.core.addon import InterceptAddon
addon_instance = InterceptAddon(config_instance, history_instance, spider=spider_instance)




@cli.command('list')
def list_rules():
    """Lista todas as regras de interceptação configuradas."""
    config = InterceptConfig()
    rules = config.get_rules()

    if not rules:
        click.echo("Nenhuma regra configurada.")
        return

    click.echo(click.style(f"{'#':<3} {'STATUS':<8} {'HOST':<25} {'CAMINHO':<20} {'PARÂMETRO':<20} {'VALOR'}", bold=True))
    click.echo("-" * 100)

    for i, rule in enumerate(rules):
        status = "Ativo" if rule.get('enabled', True) else "Inativo"
        status_color = "green" if status == "Ativo" else "red"

        click.echo(
            f"{i+1:<3} "
            f"{click.style(status, fg=status_color):<8} "
            f"{rule['host']:<25} "
            f"{rule['path']:<20} "
            f"{rule['param_name']:<20} "
            f"{rule['param_value']}"
        )


@cli.command('add')
@click.option('--host', required=True, help="Host/domínio a ser interceptado.")
@click.option('--path', required=True, help="Caminho da rota (ex: /contato).")
@click.option('--param', 'param_name', required=True, help="Nome do parâmetro a ser modificado.")
@click.option('--value', 'param_value', required=True, help="Novo valor para o parâmetro.")
def add_rule(host, path, param_name, param_value):
    """Adiciona uma nova regra de interceptação."""
    config = InterceptConfig()
    success, message = config.add_rule(host, path, param_name, param_value)

    if success:
        click.echo(click.style(f"✓ {message}", fg="green"))
    else:
        click.echo(click.style(f"✗ {message}", fg="red"))


@cli.command('remove')
@click.argument('index', type=int)
def remove_rule(index):
    """Remove uma regra pelo seu número de índice."""
    config = InterceptConfig()
    rule_index = index - 1  # Converte para índice baseado em zero

    if 0 <= rule_index < len(config.get_rules()):
        if config.remove_rule(rule_index):
            click.echo(click.style(f"✓ Regra #{index} removida com sucesso!", fg="green"))
        else:
            click.echo(click.style(f"✗ Erro ao remover regra #{index}.", fg="red"))
    else:
        click.echo(click.style(f"✗ Erro: Índice #{index} é inválido.", fg="red"))


from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options
from src.core.logger_config import log
from src.core.scanner import VulnerabilityScanner
from src.core.active_scanner import ActiveScanner
from src.core.oast_client import OASTClient


@cli.command('toggle')
@click.argument('index', type=int)
def toggle_rule(index):
    """Ativa ou desativa uma regra pelo seu número de índice."""
    config = InterceptConfig()
    rule_index = index - 1  # Converte para índice baseado em zero

    if 0 <= rule_index < len(config.get_rules()):
        if config.toggle_rule(rule_index):
            new_status = "Ativa" if config.get_rules()[rule_index]['enabled'] else "Inativa"
            click.echo(click.style(f"✓ Status da regra #{index} alterado para: {new_status}", fg="green"))
        else:
            click.echo(click.style(f"✗ Erro ao alterar status da regra #{index}.", fg="red"))
    else:
        click.echo(click.style(f"✗ Erro: Índice #{index} é inválido.", fg="red"))


@cli.command('set-port')
@click.argument('port', type=int)
def set_port(port):
    """Define a porta do proxy."""
    config = InterceptConfig()
    success, message = config.set_port(port)
    
    if success:
        click.echo(click.style(f"✓ {message}", fg="green"))
    else:
        click.echo(click.style(f"✗ {message}", fg="red"))


@cli.command('get-port')
def get_port():
    """Mostra a porta configurada do proxy."""
    config = InterceptConfig()
    port = config.get_port()
    click.echo(click.style(f"Porta configurada: {port}", fg="cyan"))


@cli.command('run')
@click.option('--port', type=int, default=None, help="Porta para o proxy escutar (padrão: configuração salva ou 9507)")
def run_proxy(port):
    """Inicia o proxy em modo headless."""
    config = InterceptConfig()
    
    # Se uma porta foi especificada via CLI, usa ela; caso contrário usa a configuração salva
    if port is not None:
        config.port = port
    
    actual_port = config.get_port()
    rules = config.get_rules()

    if not rules:
        click.echo(click.style("\n⚠️ Nenhuma regra configurada. Adicione uma com 'add' primeiro.", fg="yellow"))
        return

    click.echo(click.style("=" * 60, fg="cyan"))
    click.echo(click.style("🚀 Iniciando Iniciando em modo headless...", bold=True, fg="cyan"))
    click.echo(click.style("=" * 60, fg="cyan"))

    log.info(f"Proxy (CLI) iniciando na porta {actual_port}...")
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_proxy_headless(config, actual_port))
    except KeyboardInterrupt:
        click.echo("\n✓ Proxy encerrado pelo usuário.")
        log.info("Proxy (CLI) encerrado pelo usuário.")
    except Exception as e:
        click.echo(click.style(f"\n❌ Erro ao executar proxy: {e}", fg="red"))
        log.error(f"Erro ao executar proxy (CLI): {e}", exc_info=True)


async def start_proxy_headless(config, port):
    """Função assíncrona para iniciar o mitmdump."""
    proxy_options = options.Options(listen_host='127.0.0.1', listen_port=port)
    master = DumpMaster(proxy_options, with_termlog=True, with_dumper=False)
    master.addons.add(InterceptAddon(config))

    click.echo(click.style(f"\nProxy escutando em http://127.0.0.1:{port}", fg="green"))
    click.echo("Pressione Ctrl+C para parar.")

    await master.run()


def _start_proxy_background(config, port, history=None, spider=None):
    proxy_options = options.Options(listen_host='127.0.0.1', listen_port=port)
    state = {"master": None}
    ready = threading.Event()

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            async def _main():
                master = DumpMaster(proxy_options, with_termlog=False, with_dumper=False)
                master.addons.add(InterceptAddon(config, history=history, spider=spider))
                state["master"] = master
                ready.set()
                await master.run()

            loop.run_until_complete(_main())
        finally:
            try:
                loop.close()
            except Exception:
                pass

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    ready.wait(timeout=3)
    return state["master"], thread


def _serialize_history(history: RequestHistory):
    entries = history.get_history()
    for entry in entries:
        ts = entry.get("timestamp")
        try:
            entry["timestamp"] = ts.isoformat()
        except Exception:
            entry["timestamp"] = str(ts)
    return entries


def _save_json(path: str, data):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _find_entry(entries, request_id: int):
    for item in entries:
        if item.get("id") == request_id:
            return item
    return None

def _merge_vulns(entry, new_vulns):
    if not new_vulns:
        return 0
    existing = entry.get("vulnerabilities") or []
    existing_set = {str(v) for v in existing}
    added = 0
    for v in new_vulns:
        if str(v) not in existing_set:
            existing.append(v)
            existing_set.add(str(v))
            added += 1
    entry["vulnerabilities"] = existing
    return added

def _extract_vulns(entries, domain: str | None = None):
    items = []
    for entry in entries:
        url = str(entry.get("url", ""))
        if domain and domain.lower() not in url.lower():
            continue
        for vuln in entry.get("vulnerabilities") or []:
            items.append(vuln)
    return items

def _group_vulns(vulns):
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    groups = {k: [] for k in severity_order}
    for v in vulns:
        sev = v.get("severity") or "Info"
        if sev not in groups:
            groups[sev] = []
        groups[sev].append(v)
    return groups, severity_order

def _write_text(path: str, content: str):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _load_ai_config() -> dict:
    """Carrega configuração de IA do arquivo unificado config/ai_config.json"""
    config_path = os.path.join(project_root, "config", "ai_config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


@cli.command('crawl')
@click.option('--url', 'start_urls', multiple=True, required=True, help="URL(s) iniciais para navegacao.")
@click.option('--depth', default=2, show_default=True, type=int, help="Profundidade maxima do crawl.")
@click.option('--max-pages', default=200, show_default=True, type=int, help="Maximo de paginas GET a visitar.")
@click.option('--max-forms', default=200, show_default=True, type=int, help="Maximo de formularios a submeter.")
@click.option('--delay', default=0.2, show_default=True, type=float, help="Delay entre requisicoes.")
@click.option('--timeout', default=10, show_default=True, type=int, help="Timeout por requisicao (s).")
@click.option('--port', default=None, type=int, help="Porta do proxy (padrao: configuracao salva).")
@click.option('--no-submit-forms', is_flag=True, default=False, help="Nao submeter formularios.")
@click.option('--browser', is_flag=True, default=False, help="Usar Playwright (renderiza JS).")
@click.option('--headful', is_flag=True, default=False, help="Abrir navegador visivel (Playwright).")
@click.option('--probe-common-paths', is_flag=True, default=False, help="Tentar caminhos comuns (ex: /login, /register).")
@click.option('--common-paths', default="login,register,signup,signin,admin,dashboard,auth,users,user,api,health,status", show_default=True, help="Lista separada por virgula de caminhos para testar.")
@click.option('--history-out', default="logs/cli_history.json", show_default=True, help="Arquivo de saida do historico.")
@click.option('--spider-out', default="logs/cli_spider.json", show_default=True, help="Arquivo de saida do spider.")
def crawl(start_urls, depth, max_pages, max_forms, delay, timeout, port, no_submit_forms, browser, headful, probe_common_paths, common_paths, history_out, spider_out):
    """Navega automaticamente e registra historico/spider para consulta."""
    config = InterceptConfig()
    if port is not None:
        config.port = port
    actual_port = config.get_port()

    history = RequestHistory()
    spider = Spider()
    spider.start(target_urls=list(start_urls), max_depth=depth, max_urls=max_pages)

    seed_paths = []
    if probe_common_paths:
        seed_paths = [p.strip() for p in (common_paths or "").split(",") if p.strip()]

    click.echo(f"Iniciando proxy em 127.0.0.1:{actual_port}...")
    master, thread = _start_proxy_background(config, actual_port, history=history, spider=spider)
    time.sleep(0.8)

    if browser:
        navigator = PlaywrightAutoNavigator(
            start_urls=list(start_urls),
            spider=spider,
            proxy_port=actual_port,
            max_depth=depth,
            max_pages=max_pages,
            max_forms=max_forms,
            delay=delay,
            timeout=timeout,
            submit_forms=not no_submit_forms,
            headless=not headful,
            seed_paths=seed_paths,
        )
    else:
        navigator = AutoNavigator(
            start_urls=list(start_urls),
            spider=spider,
            proxy_port=actual_port,
            max_depth=depth,
            max_pages=max_pages,
            max_forms=max_forms,
            delay=delay,
            timeout=timeout,
            submit_forms=not no_submit_forms,
            seed_paths=seed_paths,
        )

    try:
        if browser:
            stats = asyncio.run(navigator.crawl())
        else:
            stats = navigator.crawl()
    except KeyboardInterrupt:
        click.echo("\nCrawl interrompido pelo usuário.")
        stats = {
            "pages_fetched": 0,
            "total_requests": 0,
            "forms_submitted": 0,
            "visited": 0,
            "elapsed_sec": 0,
        }
    finally:
        try:
            if master is not None:
                master.shutdown()
        except Exception:
            pass
        thread.join(timeout=3)
        spider.stop()

    history_payload = _serialize_history(history)
    spider_payload = {
        "stats": spider.get_stats(),
        "urls": spider.get_discovered_urls(),
        "forms": spider.get_forms(),
    }
    _save_json(history_out, history_payload)
    _save_json(spider_out, spider_payload)

    click.echo("\nResumo do crawl:")
    click.echo(f"- Paginas visitadas: {stats.get('pages_fetched', 0)}")
    click.echo(f"- Requisicoes totais: {stats.get('total_requests', 0)}")
    click.echo(f"- Formularios submetidos: {stats.get('forms_submitted', 0)}")
    click.echo(f"- Historico salvo em: {history_out}")
    click.echo(f"- Spider salvo em: {spider_out}")


@cli.group('history')
def history_group():
    """Comandos de consulta ao historico salvo."""
    pass


@history_group.command('list')
@click.option('--file', 'history_file', default="logs/cli_history.json", show_default=True, help="Arquivo de historico.")
@click.option('--limit', default=20, show_default=True, type=int, help="Limite de entradas.")
def history_list(history_file, limit):
    try:
        entries = _load_json(history_file)
    except FileNotFoundError:
        click.echo(f"Arquivo nao encontrado: {history_file}")
        return

    if not entries:
        click.echo("Historico vazio.")
        return

    click.echo(click.style(f"{'#':<4} {'METODO':<8} {'STATUS':<6} {'URL'}", bold=True))
    for entry in entries[:max(1, limit)]:
        click.echo(
            f"{entry.get('id', ''):<4} "
            f"{entry.get('method', ''):<8} "
            f"{entry.get('status', ''):<6} "
            f"{entry.get('url', '')}"
        )


@cli.command('scan-passive')
@click.argument('request_id', type=int)
@click.option('--file', 'history_file', default="logs/cli_history.json", show_default=True, help="Arquivo de historico.")
def scan_passive(request_id, history_file):
    """Executa o scanner passivo em uma entrada do historico salvo."""
    try:
        entries = _load_json(history_file)
    except FileNotFoundError:
        click.echo(f"Arquivo nao encontrado: {history_file}")
        return

    entry = _find_entry(entries, request_id)

    if not entry:
        click.echo(f"ID {request_id} nao encontrado no historico.")
        return

    scanner = VulnerabilityScanner()
    vulns = scanner.scan_entry(entry)
    if vulns:
        _merge_vulns(entry, vulns)
        _save_json(history_file, entries)
        click.echo(click.style(f"✓ {len(vulns)} vulnerabilidades detectadas:", fg="green"))
        for v in vulns:
            click.echo(f"  - [{v.get('severity')}] {v.get('type')} em {v.get('url')}")
    else:
        click.echo(click.style("✓ Nenhuma vulnerabilidade detectada.", fg="green"))


@cli.command('scan-active')
@click.argument('request_id', type=int)
@click.option('--file', 'history_file', default="logs/cli_history.json", show_default=True, help="Arquivo de historico.")
def scan_active(request_id, history_file):
    """Executa o scanner ativo em uma entrada do historico salvo."""
    try:
        entries = _load_json(history_file)
    except FileNotFoundError:
        click.echo(f"Arquivo nao encontrado: {history_file}")
        return

    entry = _find_entry(entries, request_id)
    if not entry:
        click.echo(f"ID {request_id} nao encontrado no historico.")
        return

    config = InterceptConfig()
    active = ActiveScanner(
        oast_client=OASTClient(config),
        enabled_modules=config.get_active_scan_modules()
    )
    base_request = {
        'method': entry.get('method', ''),
        'url': entry.get('url', ''),
        'headers': entry.get('request_headers', {}) or {},
        'body': entry.get('request_body', '') or '',
    }
    vulns = active.scan_request(base_request)
    if vulns:
        _merge_vulns(entry, vulns)
        _save_json(history_file, entries)
        click.echo(click.style(f"✓ {len(vulns)} vulnerabilidades detectadas:", fg="green"))
        for v in vulns:
            click.echo(f"  - [{v.get('severity')}] {v.get('type')} em {v.get('url')}")
    else:
        click.echo(click.style("✓ Nenhuma vulnerabilidade detectada.", fg="green"))


@cli.command('scan-both')
@click.argument('request_id', type=int)
@click.option('--file', 'history_file', default="logs/cli_history.json", show_default=True, help="Arquivo de historico.")
def scan_both(request_id, history_file):
    """Executa scanner passivo e ativo na mesma entrada."""
    try:
        entries = _load_json(history_file)
    except FileNotFoundError:
        click.echo(f"Arquivo nao encontrado: {history_file}")
        return

    entry = _find_entry(entries, request_id)
    if not entry:
        click.echo(f"ID {request_id} nao encontrado no historico.")
        return

    total = 0
    scanner = VulnerabilityScanner()
    passive = scanner.scan_entry(entry)
    if passive:
        total += _merge_vulns(entry, passive)

    config = InterceptConfig()
    active = ActiveScanner(
        oast_client=OASTClient(config),
        enabled_modules=config.get_active_scan_modules()
    )
    base_request = {
        'method': entry.get('method', ''),
        'url': entry.get('url', ''),
        'headers': entry.get('request_headers', {}) or {},
        'body': entry.get('request_body', '') or '',
    }
    active_vulns = active.scan_request(base_request)
    if active_vulns:
        total += _merge_vulns(entry, active_vulns)

    if total:
        _save_json(history_file, entries)
        click.echo(click.style(f"✓ {total} vulnerabilidades detectadas:", fg="green"))
        for v in (passive or []) + (active_vulns or []):
            click.echo(f"  - [{v.get('severity')}] {v.get('type')} em {v.get('url')}")
    else:
        click.echo(click.style("✓ Nenhuma vulnerabilidade detectada.", fg="green"))


@cli.command('scan-both-domain')
@click.argument('domain', type=str)
@click.option('--file', 'history_file', default="logs/cli_history.json", show_default=True, help="Arquivo de historico.")
@click.option('--limit', default=None, type=int, help="Limite de entradas a escanear.")
def scan_both_domain(domain, history_file, limit):
    """Executa scanner passivo e ativo em todas as entradas de um dominio."""
    try:
        entries = _load_json(history_file)
    except FileNotFoundError:
        click.echo(f"Arquivo nao encontrado: {history_file}")
        return

    domain = domain.strip().lower()
    if not domain:
        click.echo("Dominio invalido.")
        return

    matches = []
    for item in entries:
        url = str(item.get("url", ""))
        if domain in url.lower():
            matches.append(item)

    if not matches:
        click.echo(f"Nenhuma entrada encontrada para o dominio: {domain}")
        return

    if limit is not None:
        matches = matches[:max(1, limit)]

    scanner = VulnerabilityScanner()
    config = InterceptConfig()
    active = ActiveScanner(
        oast_client=OASTClient(config),
        enabled_modules=config.get_active_scan_modules()
    )

    total_added = 0
    for entry in matches:
        passive = scanner.scan_entry(entry)
        total_added += _merge_vulns(entry, passive)

        base_request = {
            'method': entry.get('method', ''),
            'url': entry.get('url', ''),
            'headers': entry.get('request_headers', {}) or {},
            'body': entry.get('request_body', '') or '',
        }
        active_vulns = active.scan_request(base_request)
        total_added += _merge_vulns(entry, active_vulns)

    _save_json(history_file, entries)
    click.echo(click.style(f"✓ Scan concluido para {len(matches)} entradas. Novas vulnerabilidades: {total_added}.", fg="green"))


@cli.command('report-md')
@click.option('--domain', default=None, help="Filtra vulnerabilidades por dominio/host.")
@click.option('--file', 'history_file', default="logs/cli_history.json", show_default=True, help="Arquivo de historico.")
@click.option('--out', 'out_file', default="logs/report.md", show_default=True, help="Arquivo de saida do relatorio.")
def report_md(domain, history_file, out_file):
    """Gera relatorio em Markdown a partir do historico."""
    try:
        entries = _load_json(history_file)
    except FileNotFoundError:
        click.echo(f"Arquivo nao encontrado: {history_file}")
        return

    vulns = _extract_vulns(entries, domain=domain)
    if not vulns:
        click.echo("Nenhuma vulnerabilidade encontrada para relatorio.")
        return

    groups, order = _group_vulns(vulns)
    total = sum(len(v) for v in groups.values())

    lines = []
    lines.append("# Relatorio de Vulnerabilidades (CLI)")
    if domain:
        lines.append(f"- Dominio: {domain}")
    lines.append(f"- Total: {total}")
    lines.append("")
    lines.append("## Resumo por Severidade")
    for sev in order:
        lines.append(f"- {sev}: {len(groups.get(sev, []))}")
    lines.append("")

    lines.append("## Detalhes")
    for sev in order:
        items = groups.get(sev, [])
        if not items:
            continue
        lines.append(f"### {sev}")
        for v in items:
            vtype = v.get("type", "N/A")
            url = v.get("url", "N/A")
            method = v.get("method", "")
            desc = v.get("description", "")
            evidence = v.get("evidence", "")
            lines.append(f"- **{vtype}**")
            lines.append(f"  - URL: {url}")
            if method:
                lines.append(f"  - Metodo: {method}")
            if desc:
                lines.append(f"  - Descricao: {desc}")
            if evidence:
                lines.append(f"  - Evidencia: `{str(evidence)[:200]}`")
        lines.append("")

    _write_text(out_file, "\n".join(lines).strip() + "\n")
    click.echo(click.style(f"✓ Relatorio gerado em: {out_file}", fg="green"))


@cli.group('spider')
def spider_group():
    """Comandos de consulta ao spider salvo."""
    pass


@spider_group.command('list')
@click.option('--file', 'spider_file', default="logs/cli_spider.json", show_default=True, help="Arquivo do spider.")
@click.option('--limit', default=50, show_default=True, type=int, help="Limite de URLs.")
def spider_list(spider_file, limit):
    try:
        payload = _load_json(spider_file)
    except FileNotFoundError:
        click.echo(f"Arquivo nao encontrado: {spider_file}")
        return

    urls = payload.get("urls", []) if isinstance(payload, dict) else []
    if not urls:
        click.echo("Spider sem URLs.")
        return

    for url in urls[:max(1, limit)]:
        click.echo(url)


@cli.command('info')
def system_info():
    """Exibe informações do sistema, como o número de núcleos de CPU."""
    cpu_cores = os.cpu_count() or 1
    max_recommended_threads = cpu_cores * 5
    click.echo(click.style("======= Informações do Sistema =======", bold=True))
    click.echo(f"- Número de núcleos de CPU lógicos: {cpu_cores}")
    click.echo(f"- Máximo de threads recomendadas: ~{max_recommended_threads}")
    click.echo("\nUse o número de núcleos como uma base para definir a quantidade de threads.")
    click.echo("Um valor comum e seguro é (núcleo * 5).")


@cli.command('agent')
@click.argument('url')
@click.option('--objective', '-o', default="explorar site e mapear rotas", help="Objetivo da navegação.")
@click.option('--username', '-u', default=None, help="Usuário para login (opcional).")
@click.option('--password', '-p', default=None, help="Senha para login (opcional).")
@click.option('--headful', is_flag=True, default=False, help="Abrir navegador visível.")
def agent_navigate(url, objective, username, password, headful):
    """
    Navegação autônoma inteligente com LLM.
    
    O agente explora o site automaticamente, preenche formulários,
    e registra TODAS as requisições e rotas descobertas.
    
    Configuração do LLM: config/ai_config.json
    
    Exemplos:
    
        proxyhunter agent https://example.com
        
        proxyhunter agent https://app.com -o "fazer login" -u admin -p secret
        
        proxyhunter agent https://site.com --headful
    """
    # Carrega configuração do arquivo unificado
    ai_config = _load_ai_config()
    
    # Resolve provider do config
    provider = ai_config.get("provider", "gemini")
    
    # Resolve API key (env > config)
    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY") or ai_config.get("api_key")
    elif provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY") or ai_config.get("api_key")
    else:
        api_key = ai_config.get("api_key", "")
    
    # Valida API key para providers que precisam
    if provider in ("gemini", "openai") and not api_key:
        click.echo(click.style("❌ API key não encontrada!", fg="red"))
        click.echo("Configure em config/ai_config.json")
        return
    
    # Resolve modelo do config
    model = ai_config.get("model")
    if not model:
        defaults = {"gemini": "gemini-2.5-flash-lite", "openai": "gpt-4", "ollama": "llama3"}
        model = defaults.get(provider, "gemini-2.5-flash-lite")
    
    # Resolve configurações do agente
    max_steps = ai_config.get("max_steps", 50)
    
    # Configura LLM
    llm_config = LLMConfig(
        provider=provider,
        api_key=api_key or "",
        model=model,
        temperature=ai_config.get("temperature", 0.3),
    )
    
    # Credenciais
    credentials = None
    if username and password:
        credentials = (username, password)
    
    # Caminhos de saída
    history_out = "logs/cli_history.json"
    spider_out = "logs/cli_spider.json"
    
    click.echo(click.style("=" * 60, fg="cyan"))
    click.echo(click.style("🤖 Iniciando Agente Autônomo Inteligente", bold=True, fg="cyan"))
    click.echo(click.style("=" * 60, fg="cyan"))
    click.echo(f"  Alvo: {url}")
    click.echo(f"  Objetivo: {objective}")
    click.echo(f"  LLM: {provider}/{model}")
    if credentials:
        click.echo(f"  Credenciais: {username}/****")
    click.echo()
    
    # Cria agente (captura requisições via Playwright hooks)
    agent = AutonomousAgent(
        target_url=url,
        objective=objective,
        llm_config=llm_config,
        credentials=credentials,
        proxy_port=None,
        max_steps=max_steps,
        max_depth=3,
        headless=not headful,
    )
    
    # Executa
    result = {}
    try:
        result = asyncio.run(agent.run())
    except KeyboardInterrupt:
        click.echo("\n⚠️ Agente interrompido pelo usuário.")
        result = {"status": "interrupted", "actions_count": 0, "captured_requests": [], "routes": []}
    except Exception as e:
        click.echo(click.style(f"\n❌ Erro: {e}", fg="red"))
        result = {"status": "error", "error": str(e), "captured_requests": [], "routes": []}
    
    # Extrai dados capturados
    captured_requests = result.get("captured_requests", [])
    routes = result.get("routes", [])
    
    # Salva histórico (formato compatível com scan-passive/active)
    _save_json(history_out, captured_requests)
    
    # Salva spider com rotas descobertas
    spider_data = {
        "target_url": url,
        "urls": [r.get("url") for r in routes if r.get("url")],
        "routes_count": len(routes),
        "requests_count": len(captured_requests),
    }
    _save_json(spider_out, spider_data)
    
    # Exibe resultado
    click.echo()
    click.echo(click.style("=" * 60, fg="cyan"))
    click.echo(click.style("📊 Resultado da Navegação", bold=True, fg="cyan"))
    click.echo(click.style("=" * 60, fg="cyan"))
    click.echo(f"  Status: {result.get('status', 'N/A')}")
    click.echo(f"  Ações executadas: {result.get('actions_count', 0)}")
    click.echo(f"  Páginas visitadas: {result.get('pages_visited', 0)}")
    click.echo(f"  Rotas descobertas: {len(routes)}")
    click.echo(f"  Requisições capturadas: {len(captured_requests)}")
    click.echo(f"  Duração: {result.get('duration_seconds', 0)}s")
    click.echo()
    click.echo(f"  Histórico: {history_out}")
    click.echo(f"  Spider: {spider_out}")
    
    # Lista rotas
    if routes:
        click.echo()
        click.echo(click.style("Rotas descobertas:", bold=True))
        for route in routes[:10]:
            click.echo(f"  - {route.get('url', 'N/A')}")
        if len(routes) > 10:
            click.echo(f"  ... e mais {len(routes) - 10} rotas")
    
    click.echo()
    click.echo("Para scans use:")
    click.echo(f"  proxyhunter scan-passive <ID> --file {history_out}")
    click.echo(f"  proxyhunter scan-active <ID> --file {history_out}")


if __name__ == "__main__":
    cli()

