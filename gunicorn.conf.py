import os

# Configuração otimizada do Gunicorn para Render
bind = f"0.0.0.0:{os.environ.get('PORT', 8080)}"

# Otimizações para Render (plano gratuito tem 0.5 CPU cores)
workers = 1  # Render free tier tem recursos limitados
worker_class = "gevent"  # Async workers para melhor performance
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100

# Timeouts otimizados
timeout = 120  # Aumentado para evitar timeouts em cold start
keepalive = 5  # Mantém conexões vivas por mais tempo
graceful_timeout = 30

# Performance
preload_app = True
max_worker_memory = 200  # MB - evita memory leaks
worker_tmp_dir = "/dev/shm"  # Usar RAM para temp files

# Logging otimizado
accesslog = "-"
errorlog = "-"
loglevel = "warning"  # Menos verbose em produção

# Health check
def when_ready(server):
    server.log.info("🚀 Servidor Droppes pronto para receber requisições!")

def worker_exit(server, worker):
    server.log.info(f"🔄 Worker {worker.pid} reiniciado") 