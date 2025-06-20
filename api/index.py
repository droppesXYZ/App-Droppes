import os
import sys

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configurar ambiente Vercel
os.environ['VERCEL'] = '1'

try:
    # Importar app principal
    from app import app
    print("✅ App importado com sucesso!")
    
except Exception as e:
    print(f"❌ Erro ao importar app: {e}")
    # Criar app de fallback
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def hello():
        return f'<h1>Erro de Import</h1><p>{str(e)}</p>'

# Exportar app diretamente
application = app

# Para desenvolvimento local
if __name__ == "__main__":
    app.run(debug=True) 