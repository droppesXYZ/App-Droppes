import sys
import os
import traceback

# Adiciona o diretório atual ao path do Python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("🔧 Iniciando main.py...")
print(f"📍 Python path: {sys.path[0]}")
print(f"🌍 Environment: {'Vercel' if os.getenv('VERCEL') else 'Local'}")

try:
    print("📦 Tentando importar app...")
    from app import app
    print("✅ App principal importado com sucesso!")
except Exception as e:
    error_msg = str(e)
    print(f"❌ Erro ao importar app principal: {error_msg}")
    print(f"📋 Traceback completo:")
    traceback.print_exc()
    
    # Fallback para app simples
    print("🔄 Criando app de fallback...")
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error_page():
        return f"""
        <h1>❌ Erro de Import</h1>
        <p><strong>Erro:</strong> {str(error_msg)}</p>
        <p><strong>Traceback:</strong> {traceback.format_exc()}</p>
        <p><strong>Environment:</strong> {'Render' if os.getenv('RENDER') else 'Local'}</p>
        <p><strong>Python Path:</strong> {sys.path[0]}</p>
        <a href="/test">Teste de Rota</a>
        """
    
    @app.route('/test')
    def test():
        return "<h1>✅ Rota de teste funcionando!</h1>"
    
    print("✅ App de fallback criado!")

# Export app for Vercel
application = app

if __name__ == '__main__':
    print("🚀 Iniciando servidor Flask...")
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
