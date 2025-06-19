import sys
import os

# Adiciona o diretório atual ao path do Python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app
    print("✅ App importado com sucesso!")
except Exception as e:
    print(f"❌ Erro ao importar app: {e}")
    # Cria uma app Flask simples como fallback
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def hello():
        return f"<h1>Erro de Import</h1><p>Erro: {str(e)}</p>"

# Export app for Vercel
application = app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
