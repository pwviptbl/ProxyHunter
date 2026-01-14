import sys
import os
import click

# Adiciona o diretório raiz do projeto ao path para importações corretas
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.core.config import InterceptConfig


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
from src.core.addon import InterceptAddon
addon_instance = InterceptAddon(config_instance, history_instance)


@cli.command('scan')
@click.argument('request_id', type=int)
def scan_request(request_id):
    """
    Executa o Scanner Ativo em uma requisição do histórico.

    Nota: O proxy precisa ter capturado requisições na sessão atual
    para que o histórico contenha itens a serem escaneados.
    """
    click.echo(f"Executando varredura ativa na requisição ID: {request_id}...")

    # Simula a captura de alguns dados para que o histórico não esteja vazio
    if not history_instance.get_history():
        click.echo(click.style("Histórico vazio. O proxy precisa capturar tráfego primeiro.", fg="yellow"))
        click.echo("Para fins de demonstração, o histórico não é persistido entre execuções.")
        return

    addon_instance.run_active_scan_on_request(request_id)

    entry = history_instance.get_entry_by_id(request_id)
    if entry and entry['vulnerabilities']:
        click.echo(click.style("✓ Varredura concluída. Novas vulnerabilidades encontradas:", fg="green"))
        for vuln in entry['vulnerabilities']:
            click.echo(f"  - [{vuln['severity']}] {vuln['type']} em {vuln['description']}")
    else:
        click.echo(click.style("✓ Varredura concluída. Nenhuma nova vulnerabilidade encontrada.", fg="green"))


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


import asyncio
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options
from src.core.addon import InterceptAddon
from src.core.logger_config import log


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


if __name__ == "__main__":
    cli()
