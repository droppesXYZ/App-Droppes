# 🚀 App Droppes - Gerenciador de Airdrops de Criptomoedas

Uma aplicação web Flask para gerenciar protocolos de criptomoedas e seus airdrops, com integração ao Twitter para monitoramento de tweets.

## ✨ Funcionalidades

- **👤 Sistema de Login/Registro** com autenticação segura
- **🔗 Gerenciamento de Protocolos** (adicionar, editar, remover)
- **💰 Controle de Investimentos** por protocolo
- **🐦 Integração com Twitter** para buscar tweets dos protocolos
- **📊 Dashboard** com informações dos protocolos
- **🎨 Interface moderna** e responsiva

## 🛠️ Tecnologias

- **Backend:** Flask + SQLAlchemy
- **Database:** Supabase (PostgreSQL)
- **Frontend:** HTML/CSS/JavaScript com Bootstrap
- **API:** Twitter API v2 (via Tweepy)
- **Autenticação:** Session-based + OAuth Twitter

## 📋 Pré-requisitos

- Python 3.8+
- Conta no Twitter Developer Portal
- Banco de dados Supabase (ou PostgreSQL)

## 🚀 Instalação

### 1. Clone o repositório
```bash
git clone <seu-repositorio>
cd App-Droppes-main
```

### 2. Crie e ative o ambiente virtual
```bash
# Windows
python -m venv .venv
.venv\\Scripts\\activate

# Linux/Mac
python -m venv .venv
source .venv/bin/activate
```

### 3. Instale as dependências
```bash
pip install -r requirements.txt
```

### 4. Configure as variáveis de ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
# Twitter API Credentials
TWITTER_BEARER_TOKEN=seu_bearer_token_aqui
TWITTER_CONSUMER_KEY=sua_consumer_key_aqui
TWITTER_CONSUMER_SECRET=sua_consumer_secret_aqui
TWITTER_ACCESS_TOKEN=seu_access_token_aqui
TWITTER_ACCESS_TOKEN_SECRET=seu_access_token_secret_aqui
TWITTER_CLIENT_ID=seu_client_id_aqui
TWITTER_CLIENT_SECRET=seu_client_secret_aqui

# Database (opcional - padrão já configurado para Supabase)
DATABASE_URL=postgresql://usuario:senha@host:porta/database

# Session Secret (opcional - padrão já configurado)
SESSION_SECRET=sua_chave_secreta_aqui
```

### 5. Execute a aplicação
```bash
python main.py
```

A aplicação estará disponível em:
- **Local:** http://127.0.0.1:8000
- **Rede:** http://192.168.x.x:8000

## 🔧 Configuração do Twitter

### Obter Credenciais da API do Twitter:

1. Acesse [Twitter Developer Portal](https://developer.twitter.com/)
2. Crie um novo App
3. Obtenha as seguintes credenciais:
   - **Bearer Token** (para busca de tweets)
   - **Consumer Key/Secret** (OAuth 1.0a)
   - **Access Token/Secret** (OAuth 1.0a)
   - **Client ID/Secret** (OAuth 2.0)

### Configurar Permissões:
- **Read** (para buscar tweets)
- **Users** (para autenticação)

## 📁 Estrutura do Projeto

```
App-Droppes-main/
├── app.py              # Aplicação Flask principal
├── models.py           # Modelos do banco de dados
├── simple_twitter.py   # Serviço de integração Twitter
├── main.py            # Ponto de entrada
├── requirements.txt   # Dependências Python
├── .env              # Variáveis de ambiente (criar)
├── templates/        # Templates HTML
├── static/          # Arquivos CSS/JS/Images
└── .venv/           # Ambiente virtual
```

## 🎯 Uso

### 1. Criar Conta
- Acesse a página de login
- Clique em "Registrar nova conta"
- Preencha os dados e crie sua conta

### 2. Adicionar Protocolos
- Faça login na aplicação
- Vá para "Adicionar Protocolo"
- Preencha as informações do protocolo
- Inclua o handle do Twitter (sem @)

### 3. Buscar Tweets
- Acesse "Buscar Tweets"
- Selecione os protocolos desejados
- Clique em "Buscar Tweets"
- Visualize os últimos 3 tweets originais

### 4. Gerenciar Investimentos
- Acesse cada protocolo
- Adicione investimentos (entrada/retirada)
- Acompanhe o histórico

## 🔒 Segurança

- Senhas criptografadas com bcrypt
- Sessions seguras com timeout
- Proteção CSRF em formulários
- Validação de dados de entrada

## 🌐 Rate Limits

A aplicação **não possui limitações artificiais**. Os únicos limites são os da API do Twitter:
- **300 requests por 15 minutos** (Bearer Token)
- Resets automaticamente após o período

## 🛠️ Desenvolvimento

### Estrutura de Desenvolvimento:
1. **app.py** - Rotas e lógica principal
2. **models.py** - Estrutura do banco de dados
3. **simple_twitter.py** - Integração com Twitter
4. **templates/** - Interface do usuário

### Debug Mode:
A aplicação roda em modo debug por padrão, com auto-reload ativado.

## 📝 Logs

Logs são exibidos no console durante execução:
- ✅ Conexões bem-sucedidas
- ❌ Erros de API/Database
- 🔍 Informações de debug

## 🤝 Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📄 Licença

Este projeto é de código aberto. Use livremente para seus projetos.

## 🆘 Suporte

Para dúvidas ou problemas:
1. Verifique se todas as dependências estão instaladas
2. Confirme se as credenciais do Twitter estão corretas
3. Verifique os logs no console para detalhes de erro

---

**🎉 Pronto! Sua aplicação de gerenciamento de airdrops está funcionando!** 