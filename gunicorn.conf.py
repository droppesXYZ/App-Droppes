import os

# Configuração otimizada do Gunicorn para diversos provedores
bind = f"0.0.0.0:{os.environ.get('PORT', 8080)}"

# Configuração otimizada para recursos limitados
workers = 1  # Adequado para a maioria dos provedores gratuitos
worker_class = "sync"  # Removendo gevent para compatibilidade
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100

# Timeouts otimizados
timeout = 120
keepalive = 5
graceful_timeout = 30

# Performance
preload_app = True
max_worker_memory = 200  # MB
worker_tmp_dir = "/tmp"  # Funciona na maioria dos ambientes

# Logging otimizado
accesslog = "-"
errorlog = "-"
loglevel = "warning"

# Health check
def when_ready(server):
    server.log.info("🚀 Servidor Droppes pronto para receber requisições!")

def on_starting(server):
    server.log.info("🔧 Iniciando servidor Gunicorn...")

def on_reload(server):
    server.log.info("🔄 Recarregando servidor...") 