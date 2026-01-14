import logging
import sys

def setup_logger():
    """
    Configura e retorna um logger para a aplicação.
    """
    # Cria um logger
    logger = logging.getLogger('ProxyHunterLogger')

    # Evita adicionar múltiplos handlers se a função for chamada várias vezes
    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.INFO)

    # Define o formato da mensagem
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Handler para salvar logs em um arquivo
    file_handler = logging.FileHandler('proxy.log', mode='a', encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Handler para mostrar logs no console (opcional, mas bom para debug)
    # Mostra apenas INFO e níveis superiores no console, para não poluir
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    return logger

# Instância única do logger para ser importada por outros módulos
log = setup_logger()
