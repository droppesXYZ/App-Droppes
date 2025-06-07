# 🐦 Configuração da Funcionalidade de Tweets

## 📋 Resumo

Esta funcionalidade permite mostrar os 3 últimos tweets de cada protocolo dentro do cartão de detalhes. A atualização pode ser feita manualmente ou automaticamente 1 vez por dia.

## 🔑 Configuração da API do Twitter

### 1. Criar App no Twitter Developer Portal

1. Acesse [developer.twitter.com](https://developer.twitter.com)
2. Faça login e vá para o Dashboard
3. Clique em "Create App" 
4. Preencha as informações do app:
   - **App name**: "Crypto Airdrop Manager"
   - **Description**: "App para gerenciar protocolos de airdrop de criptomoedas"
   - **Website URL**: Sua URL da aplicação
   - **Terms of Service**: (opcional)
   - **Privacy Policy**: (opcional)

### 2. Configurar Permissões

1. Vá para "App Settings" → "User authentication settings"
2. Clique em "Set up"
3. Configure:
   - **App permissions**: Read only
   - **Type of App**: Web App
   - **Callback URI**: `http://localhost:8000/callback` (para desenvolvimento)
   - **Website URL**: Sua URL da aplicação

### 3. Obter Bearer Token

1. Na aba "Keys and tokens"
2. Em "Bearer Token", clique em "Generate"
3. **COPIE E GUARDE** o Bearer Token (só aparece uma vez!)

### 4. Configurar Variável de Ambiente

Adicione ao seu arquivo `.env`:

```bash
TWITTER_BEARER_TOKEN=seu_bearer_token_aqui
```

## 🚀 Como Usar

### 1. Configurar Twitter no Protocolo

1. Ao criar ou editar um protocolo, preencha o campo "Twitter"
2. Formatos aceitos:
   - `@username`
   - `username`
   - `https://twitter.com/username`

### 2. Atualizar Tweets Manualmente

1. Acesse os detalhes de um protocolo
2. Clique na aba "Tweets"
3. Clique no botão "Update" para buscar os últimos tweets

### 3. Atualização Automática Diária

#### Windows (Task Scheduler)

1. Abra o "Agendador de Tarefas"
2. Clique em "Criar Tarefa Básica"
3. Configure:
   - **Nome**: "Atualizar Tweets Protocolos"
   - **Disparador**: Diariamente às 08:00
   - **Ação**: Iniciar programa
   - **Programa**: `python`
   - **Argumentos**: `update_tweets_cron.py`
   - **Iniciar em**: Caminho da sua aplicação

#### Linux/macOS (Cron)

1. Abra o terminal
2. Execute: `crontab -e`
3. Adicione a linha:
```bash
0 8 * * * cd /caminho/para/sua/aplicacao && python update_tweets_cron.py
```

## 📊 Limites da API Gratuita

### Twitter API v2 Free Tier
- **500.000 tweets por mês**
- **300 requests por 15 minutos**
- Perfeitamente suficiente para uso pessoal

### Cálculo do Consumo
- 3 tweets por protocolo
- 2 requests por protocolo (1 para buscar user_id, 1 para tweets)
- Exemplo: 50 protocolos = 100 requests por dia = 3.000 requests por mês

## 🔧 Solução de Problemas

### Erro: "Twitter Bearer Token não configurado"
- Verifique se a variável `TWITTER_BEARER_TOKEN` está no arquivo `.env`
- Certifique-se que o Bearer Token está correto

### Erro: "Erro ao buscar tweets para username"
- Verifique se o username está correto (sem espaços, caracteres especiais)
- Certifique-se que a conta existe e é pública
- Verifique se não excedeu os limites da API

### Erro: "401 Unauthorized"
- Bearer Token inválido ou expirado
- Gere um novo Bearer Token no Twitter Developer Portal

### Nenhum tweet aparece
- A conta pode não ter tweets públicos
- A conta pode estar privada
- Verifique se o username está no formato correto

## 💡 Dicas

1. **Teste primeiro manualmente** antes de configurar a atualização automática
2. **Use usernames simples** (prefira @username ao invés de URLs completas)
3. **Monitore os logs** em `twitter_updates.log`
4. **Não abuse da API** - respeite os limites

## 🆓 Alternativas Gratuitas (Futuras)

Se preferir não usar a API oficial:

1. **RSS Feeds de terceiros** (limitado)
2. **Nitter instances** (instável)
3. **Web scraping** (contra ToS)

A API oficial é a opção mais confiável e legal.

## 📞 Suporte

Se encontrar problemas:

1. Verifique os logs em `twitter_updates.log`
2. Teste manualmente primeiro
3. Verifique as configurações da API
4. Consulte a documentação oficial do Twitter 