import os
from flask import Flask

# Cria uma aplicação Flask simples e independente
app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h1>🎉 APLICAÇÃO FUNCIONANDO NO VERCEL!</h1>
    <h2>✅ Status: ONLINE</h2>
    <h3>🔧 Informações de Debug:</h3>
    <ul>
        <li><strong>Python Path:</strong> Funcionando</li>
        <li><strong>Flask:</strong> Funcionando</li>
        <li><strong>Vercel:</strong> Funcionando</li>
    </ul>
    <h3>🌐 Variáveis de Ambiente:</h3>
    <ul>
        <li><strong>SUPABASE_URL:</strong> {'✅ Configurada' if os.getenv('SUPABASE_URL') else '❌ Não configurada'}</li>
        <li><strong>SUPABASE_KEY:</strong> {'✅ Configurada' if os.getenv('SUPABASE_KEY') else '❌ Não configurada'}</li>
        <li><strong>SECRET_KEY:</strong> {'✅ Configurada' if os.getenv('SECRET_KEY') else '❌ Não configurada'}</li>
    </ul>
    <p><a href="/test">🧪 Teste de Rota</a></p>
    """

@app.route('/test')
def test():
    return """
    <h1>🧪 Página de Teste</h1>
    <p>✅ Roteamento funcionando!</p>
    <p><a href="/">🏠 Voltar ao início</a></p>
    """

@app.route('/health')
def health():
    return {"status": "ok", "message": "Aplicação funcionando no Vercel!"}

# Export app for Vercel
application = app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
