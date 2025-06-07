#!/usr/bin/env python3
"""
Script para atualização automática de tweets de protocolos
Deve ser executado diariamente via cron job ou task scheduler
"""

import sys
import os
from datetime import datetime

# Adicionar o diretório atual ao path para importar os módulos
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from twitter_service import TwitterService
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('twitter_updates.log'),
        logging.StreamHandler()
    ]
)

def main():
    """Função principal do script"""
    logging.info("=== Iniciando atualização automática de tweets ===")
    
    try:
        with app.app_context():
            # Criar instância do serviço
            twitter_service = TwitterService()
            
            # Atualizar todos os protocolos
            result = twitter_service.update_all_protocols_tweets()
            
            # Log dos resultados
            logging.info(f"Atualização concluída:")
            logging.info(f"  - Sucessos: {result['updated']}")
            logging.info(f"  - Falhas: {result['failed']}")
            logging.info(f"  - Total: {result['total']}")
            
            if result['failed'] > 0:
                logging.warning(f"Houve {result['failed']} falha(s) na atualização")
            
            return 0
            
    except Exception as e:
        logging.error(f"Erro crítico na atualização automática: {str(e)}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 