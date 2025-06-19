import sys
import os

# Adiciona o diretório atual ao path do Python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app
    print("✅ App principal importado com sucesso!")
except Exception as e:
    print(f"❌ Erro ao importar app principal: {e}")
    # Fallback para app simples
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error_page():
        return f"""
        <h1>❌ Erro de Import</h1>
        <p><strong>Erro:</strong> {str(e)}</p>
        <p><strong>Solução:</strong> Verificar dependências e arquivos</p>
        <a href="/test">Teste de Rota</a>
        """
    
    @app.route('/test')
    def test():
        return "<h1>✅ Rota de teste funcionando!</h1>"

# Export app for Vercel
application = app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
