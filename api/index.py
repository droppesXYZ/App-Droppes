import os
import sys

# Adiciona o diretório raiz ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configurar ambiente Vercel
os.environ['VERCEL'] = '1'

try:
    from app import app
    print("✅ App importado com sucesso no Vercel!")
    
    # Exportar app para Vercel
    application = app
    
except Exception as e:
    print(f"❌ Erro ao importar app: {e}")
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return f'''
        <h1>❌ Erro de Import</h1>
        <p><strong>Erro:</strong> {str(e)}</p>
        <p><strong>Ambiente:</strong> Vercel</p>
        <a href="/test">Teste de Rota</a>
        '''
    
    @app.route('/test')
    def test():
        return "<h1>✅ Rota de teste funcionando no Vercel!</h1>"
    
    application = app

# Handler para Vercel (serverless)
def handler(request, context):
    return application

if __name__ == "__main__":
    application.run(debug=True) 