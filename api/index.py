import os
import sys

# Adiciona o diretório raiz ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
    print("✅ App importado com sucesso!")
except Exception as e:
    print(f"❌ Erro ao importar app: {e}")
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return f"<h1>Erro de Import</h1><p>{str(e)}</p>"

# Para o Vercel
def handler(request):
    return app(request.environ, lambda status, headers: None)

if __name__ == "__main__":
    app.run(debug=True) 