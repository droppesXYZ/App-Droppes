import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from functools import wraps, lru_cache
from werkzeug.security import check_password_hash, generate_password_hash
from authlib.integrations.flask_client import OAuth
from models import db, User, Protocol, Investment, Task, Airdrop, Tweet, Payment, InvestmentType, TaskStatus, ProtocolStatus, AirdropStatus, AirdropType, PaymentStatus, SubscriptionPlan
# Carregar variáveis de ambiente do arquivo .env se existir (apenas localmente)
try:
    # Só tenta carregar .env se não estivermos no Vercel
    if not os.getenv('VERCEL'):
        from dotenv import load_dotenv
        load_dotenv()
except (ImportError, UnicodeDecodeError, Exception) as e:
    # Ignora erros de .env - usa variáveis de ambiente do sistema
    print(f"⚠️ Aviso: Não foi possível carregar .env ({e}), usando variáveis de ambiente do sistema")
    pass

# Import do serviço Twitter com fallback
try:
    from simple_twitter import twitter_service
    print("✅ Serviço Twitter importado com sucesso!")
except ImportError as e:
    print(f"⚠️ Aviso: Não foi possível importar simple_twitter ({e}), criando fallback")
    # Cria um serviço twitter simples como fallback
    class TwitterServiceFallback:
        def search_tweets_by_username(self, username, count=3):
            return []
        def is_configured(self):
            return False
    twitter_service = TwitterServiceFallback()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# ===============================================
# SISTEMA DE INTERNACIONALIZAÇÃO (i18n)
# ===============================================

# Dicionários de tradução
TRANSLATIONS = {
    'en': {
        # Navigation
        'calendar': 'Calendar',
        'search_tweets': 'Search Tweets',
        'my_account': 'My Account',
        'analytics': 'Analytics',
        'logout': 'Logout',
        'add_protocol': 'Add Protocol',
        
        # Calendar page
        'airdrop_calendar': 'Airdrop Calendar',
        'visualize_airdrops': 'Visualize your received and expected airdrops',
        'received_this_month': 'Received This Month',
        'airdrops_received': 'Airdrops Received',
        'expected_airdrops': 'Expected Airdrops',
        'no_protocols_found': 'No protocols found',
        'add_protocols_message': 'Add some protocols and airdrops to see the calendar.',
        'airdrop_details': 'Airdrop Details',
        'add_airdrop': 'Add Airdrop',
        'add_expected_airdrop': 'Add Expected Airdrop',
        'protocol': 'Protocol',
        'select_protocol': 'Select a protocol',
        'token_name': 'Token Name',
        'expected_date': 'Expected Date',
        'airdrop_type': 'Airdrop Type',
        'notes': 'Notes',
        'additional_info': 'Additional information about the airdrop (optional)',
        'tip_edit_later': 'You can edit or mark as received later through the protocol details.',
        'cancel': 'Cancel',
        'received': 'Received',
        'expected': 'Expected',
        'pending': 'Pending',
        'sold': 'Sold',
        'edit': 'Edit',
        'delete': 'Delete',
        
        # Twitter search
        'search_protocol_tweets': 'Search Protocol Tweets',
        'no_protocols_twitter': 'No protocols with Twitter configured.',
        'add_twitter_message': 'To use this functionality, add Twitter accounts to your protocols on the edit page.',
        'search_tweets_by_protocol': 'Search Tweets by Protocol',
        'latest_tweets_info': 'The search returns the latest 3 original tweets from each protocol.',
        'api_limits_info': 'Limited only by Twitter API rate limits.',
        'search_tweets': 'Search Tweets',
        'recent_tweets': 'Recent Tweets',
        'no_tweets_found': 'No tweets found yet',
        'use_buttons_search': 'Use the buttons above to search for tweets from your protocols.',
        'how_search_works': 'How does tweet search work?',
        'no_artificial_limits': 'No artificial limitations: You can search as many times as you want',
        'quantity_info': 'Quantity: Returns the latest 3 original tweets (no retweets)',
        'config_required': 'Configuration: The protocol must have the Twitter field filled',
        'accepted_formats': 'Accepted formats: @username, username, or full Twitter URL',
        'rate_limits': 'Rate limits: We respect Twitter API limits',
        'connect_twitter': 'Connect your Twitter for better experience!',
        'twitter_benefits': 'By connecting your Twitter account, you\'ll have:',
        'personalized_access': 'Personalized access: View tweets using your own credentials',
        'more_features': 'More features: Advanced search and interaction features',
        'better_performance': 'Better performance: Individual rate limits',
        'twitter_connected': 'Twitter Connected Successfully!',
        'view_on_twitter': 'View on Twitter',
        
        # Account page
        'account_info': 'Account Information',
        'protocols': 'Protocols',
        'free_plan': 'Free Plan',
        'limit_protocols': 'Limit of {limit} protocols',
        'subscription_status': 'Subscription Status',
        'language': 'Language',
        'change_language': 'Change Language',
        'portuguese': 'Portuguese (Brazil)',
        'english': 'English',
        
        # General
        'home': 'Home',
        'date': 'Date',
        'network': 'Network',
        'value': 'Value',
        'status': 'Status',
        'actions': 'Actions',
        'type': 'Type',
        'save': 'Save',
        'close': 'Close',
        'confirm': 'Confirm',
        'loading': 'Loading...',
        'error': 'Error',
        'success': 'Success',
        'warning': 'Warning',
        'info': 'Information',
        
        # Flash messages
        'language_changed': 'Language changed successfully!',
        'protocol_not_found': 'Protocol not found.',
        'airdrop_added_success': 'Airdrop added successfully!',
        'airdrop_updated_success': 'Airdrop updated successfully!',
        'airdrop_deleted_success': 'Airdrop deleted successfully!',
        'error_loading_calendar': 'Error loading airdrop calendar.',
        'error_adding_airdrop': 'Error adding airdrop. Please try again.',
        'tweets_found_saved': 'new tweets found and saved!',
        'search_completed': 'Search completed! No new tweets found.',
        'error_searching_tweets': 'Error searching for tweets.',
        
        # Days of the week
        'sunday': 'Sun',
        'monday': 'Mon',
        'tuesday': 'Tue', 
        'wednesday': 'Wed',
        'thursday': 'Thu',
        'friday': 'Fri',
        'saturday': 'Sat',
        
        # Calendar navigation
        'previous': 'Previous',
        'today': 'Today',
        'next': 'Next',
        
        # Calendar legend
        'legend': 'Legend',
        'token': 'TOKEN',
        'received_airdrop': 'Received airdrop',
        'expected_airdrop': 'Expected airdrop',
        'not_informed': 'Not informed',
        'airdrop': 'airdrop',
        
        # Analytics
        'analytics_overview': 'Complete analysis of your airdrop portfolio',
        
        # Quick actions
        'quick_actions': 'Quick Actions',
        'upgrade_premium': 'Upgrade Premium',
        
        # Upgrade page
        'choose_premium_plan': 'Choose Your Premium Plan',
        'unlock_unlimited_protocols': 'Unlock unlimited protocols with our flexible subscription',
        'premium_benefits': 'Premium Plan Benefits',
        'unlimited_protocols': 'Unlimited Protocols',
        'add_as_many_as_you_want': 'Add as many as you want',
        'priority_support': 'Priority Support',
        'preferential_service': 'Preferential service',
        'advanced_tools': 'Advanced Tools',
        'exclusive_features': 'Exclusive features',
        'no_commitment': 'No Commitment',
        'cancel_anytime': 'Cancel anytime',
        'most_popular': 'MOST POPULAR',
        'best_value': 'BEST VALUE',
        'per_month': 'per month',
        'one_time_payment_for': 'one-time payment for {months} months',
        'discount': '{discount}% discount',
        'save_amount': 'Save ${amount}',
        'unlimited_protocols_feature': 'Unlimited protocols',
        'priority_support_feature': 'Priority support',
        'all_features': 'All features',
        'months_access': '{months} months of access',
        'choose_plan': 'Choose {plan}',
        'finalize_payment': 'Finalize Payment',
        'how_to_pay': 'How to Pay',
        'send_exact_amount': 'Send the <strong>exact amount in USDC or USDT</strong> via Solana to the address below',
        'copy_transaction_hash': 'Copy the transaction hash',
        'fill_form_submit': 'Fill out the form and submit for verification',
        'await_confirmation': 'Await confirmation (usually within 24 hours)',
        'payment_address_solana': 'Payment Address (Solana)',
        'accepted_only_usdc_usdt': 'Only USDC or USDT accepted on Solana network',
        'token_used': 'Token Used *',
        'your_wallet_address': 'Your Wallet Address *',
        'wallet_placeholder': 'Your Solana address that made the payment',
        'wallet_help_text': 'The wallet address from which you sent the payment',
        'transaction_hash': 'Transaction Hash *',
        'transaction_placeholder': 'Paste the transaction hash here',
        'transaction_help_text': 'You can find the hash in your wallet or on',
        'submit_for_verification': 'Submit for Verification',
        'back_to_account': 'Back to My Account',
        'need_help': 'Need Help?',
        'how_to_get_usdc_usdt': 'How to get USDC/USDT on Solana?',
        'use_exchanges': 'Use exchanges like Binance, Coinbase or FTX',
        'buy_and_withdraw': 'Buy USDC/USDT and withdraw to your Solana wallet',
        'use_bridges': 'Use bridges like Wormhole to transfer from other networks',
        'recommended_wallets': 'Recommended wallets:',
        'phantom_wallet': 'Phantom Wallet',
        'solflare': 'Solflare',
        'backpack': 'Backpack',
        'important_warning': 'Important:',
        'verify_address_warning': 'Always verify the address before sending. Cryptocurrency transactions are irreversible.',
        'selected_plan': 'Selected',
        'plan_info': 'Plan {plan} - ${price}',
        'select_plan_first': 'Please select a plan before continuing.',
    },
    'pt': {
        # Navigation
        'calendar': 'Calendário',
        'search_tweets': 'Buscar Tweets',
        'my_account': 'Minha Conta',
        'analytics': 'Análises',
        'logout': 'Sair',
        'add_protocol': 'Adicionar Protocolo',
        
        # Calendar page
        'airdrop_calendar': 'Calendário de Airdrops',
        'visualize_airdrops': 'Visualize seus airdrops recebidos e esperados',
        'received_this_month': 'Recebido este Mês',
        'airdrops_received': 'Airdrops Recebidos',
        'expected_airdrops': 'Airdrops Esperados',
        'no_protocols_found': 'Nenhum protocolo encontrado',
        'add_protocols_message': 'Adicione alguns protocolos e airdrops para ver o calendário.',
        'airdrop_details': 'Detalhes dos Airdrops',
        'add_airdrop': 'Adicionar Airdrop',
        'add_expected_airdrop': 'Adicionar Airdrop Esperado',
        'protocol': 'Protocolo',
        'select_protocol': 'Selecione um protocolo',
        'token_name': 'Nome do Token',
        'expected_date': 'Data Esperada',
        'airdrop_type': 'Tipo de Airdrop',
        'notes': 'Observações',
        'additional_info': 'Informações adicionais sobre o airdrop (opcional)',
        'tip_edit_later': 'Você pode editar ou marcar como recebido depois através dos detalhes do protocolo.',
        'cancel': 'Cancelar',
        'received': 'Recebido',
        'expected': 'Esperado',
        'pending': 'Pendente',
        'sold': 'Vendido',
        'edit': 'Editar',
        'delete': 'Deletar',
        
        # Twitter search
        'search_protocol_tweets': 'Buscar Tweets dos Protocolos',
        'no_protocols_twitter': 'Nenhum protocolo com Twitter configurado.',
        'add_twitter_message': 'Para usar esta funcionalidade, adicione o Twitter dos seus protocolos na página de edição.',
        'search_tweets_by_protocol': 'Buscar Tweets por Protocolo',
        'latest_tweets_info': 'A busca retorna os últimos 3 tweets originais de cada protocolo.',
        'api_limits_info': 'Limitado apenas pelos rate limits da API do Twitter.',
        'search_tweets': 'Buscar Tweets',
        'recent_tweets': 'Tweets Recentes',
        'no_tweets_found': 'Nenhum tweet encontrado ainda',
        'use_buttons_search': 'Use os botões acima para buscar tweets dos seus protocolos.',
        'how_search_works': 'Como funciona a busca de tweets?',
        'no_artificial_limits': 'Sem limitação artificial: Pode buscar quantas vezes quiser',
        'quantity_info': 'Quantidade: Retorna os últimos 3 tweets originais (sem retweets)',
        'config_required': 'Configuração: O protocolo deve ter o campo Twitter preenchido',
        'accepted_formats': 'Formatos aceitos: @username, username, ou URL completa do Twitter',
        'rate_limits': 'Rate limits: Respeitamos os limites da API do Twitter',
        'connect_twitter': 'Conecte seu Twitter para melhor experiência!',
        'twitter_benefits': 'Ao conectar sua conta do Twitter, você terá:',
        'personalized_access': 'Acesso personalizado: Visualize tweets usando suas próprias credenciais',
        'more_features': 'Mais funcionalidades: Recursos avançados de busca e interação',
        'better_performance': 'Melhor performance: Rate limits individuais',
        'twitter_connected': 'Twitter Conectado com Sucesso!',
        'view_on_twitter': 'Ver no Twitter',
        
        # Account page
        'account_info': 'Informações da Conta',
        'protocols': 'Protocolos',
        'free_plan': 'Plano Gratuito',
        'limit_protocols': 'Limite de {limit} protocolos',
        'subscription_status': 'Status da Assinatura',
        'language': 'Idioma',
        'change_language': 'Alterar Idioma',
        'portuguese': 'Português (Brasil)',
        'english': 'Inglês',
        
        # General
        'home': 'Início',
        'date': 'Data',
        'network': 'Rede',
        'value': 'Valor',
        'status': 'Status',
        'actions': 'Ações',
        'type': 'Tipo',
        'save': 'Salvar',
        'close': 'Fechar',
        'confirm': 'Confirmar',
        'loading': 'Carregando...',
        'error': 'Erro',
        'success': 'Sucesso',
        'warning': 'Aviso',
        'info': 'Informação',
        
        # Flash messages
        'language_changed': 'Idioma alterado com sucesso!',
        'protocol_not_found': 'Protocolo não encontrado.',
        'airdrop_added_success': 'Airdrop adicionado com sucesso!',
        'airdrop_updated_success': 'Airdrop atualizado com sucesso!',
        'airdrop_deleted_success': 'Airdrop deletado com sucesso!',
        'error_loading_calendar': 'Erro ao carregar calendário de airdrops.',
        'error_adding_airdrop': 'Erro ao adicionar airdrop. Tente novamente.',
        'tweets_found_saved': 'novos tweets encontrados e salvos!',
        'search_completed': 'Busca realizada! Nenhum tweet novo encontrado.',
        'error_searching_tweets': 'Erro ao buscar tweets.',
        
        # Days of the week
        'sunday': 'Dom',
        'monday': 'Seg',
        'tuesday': 'Ter', 
        'wednesday': 'Qua',
        'thursday': 'Qui',
        'friday': 'Sex',
        'saturday': 'Sáb',
        
        # Calendar navigation
        'previous': 'Anterior',
        'today': 'Hoje',
        'next': 'Próximo',
        
        # Calendar legend
        'legend': 'Legenda',
        'token': 'TOKEN',
        'received_airdrop': 'Airdrop recebido',
        'expected_airdrop': 'Airdrop esperado',
        'not_informed': 'Não informado',
        'airdrop': 'airdrop',
        
        # Analytics
        'analytics_overview': 'Análise completa do seu portfólio de airdrops',
        
        # Quick actions
        'quick_actions': 'Ações Rápidas',
        'upgrade_premium': 'Upgrade Premium',
        
        # Upgrade page
        'choose_premium_plan': 'Escolha seu Plano Premium',
        'unlock_unlimited_protocols': 'Desbloqueie protocolos ilimitados com nossa assinatura flexível',
        'premium_benefits': 'Benefícios do Plano Premium',
        'unlimited_protocols': 'Protocolos Ilimitados',
        'add_as_many_as_you_want': 'Adicione quantos quiser',
        'priority_support': 'Suporte Prioritário',
        'preferential_service': 'Atendimento preferencial',
        'advanced_tools': 'Ferramentas Avançadas',
        'exclusive_features': 'Funcionalidades exclusivas',
        'no_commitment': 'Sem Compromisso',
        'cancel_anytime': 'Cancele quando quiser',
        'most_popular': 'MAIS POPULAR',
        'best_value': 'MELHOR VALOR',
        'per_month': 'por mês',
        'one_time_payment_for': 'pagamento único para {months} meses',
        'discount': '{discount}% de desconto',
        'save_amount': 'Economize ${amount}',
        'unlimited_protocols_feature': 'Protocolos ilimitados',
        'priority_support_feature': 'Suporte prioritário',
        'all_features': 'Todas as funcionalidades',
        'months_access': '{months} meses de acesso',
        'choose_plan': 'Escolher {plan}',
        'finalize_payment': 'Finalizar Pagamento',
        'how_to_pay': 'Como Pagar',
        'send_exact_amount': 'Envie o <strong>valor exato em USDC ou USDT</strong> via Solana para o endereço abaixo',
        'copy_transaction_hash': 'Copie o hash da transação',
        'fill_form_submit': 'Preencha o formulário e envie para verificação',
        'await_confirmation': 'Aguarde confirmação (geralmente em até 24 horas)',
        'payment_address_solana': 'Endereço para Pagamento (Solana)',
        'accepted_only_usdc_usdt': 'Aceito apenas USDC ou USDT na rede Solana',
        'token_used': 'Token Utilizado *',
        'your_wallet_address': 'Seu Endereço da Carteira *',
        'wallet_placeholder': 'Seu endereço Solana que fez o pagamento',
        'wallet_help_text': 'O endereço da carteira de onde você enviou o pagamento',
        'transaction_hash': 'Hash da Transação *',
        'transaction_placeholder': 'Cole aqui o hash da transação',
        'transaction_help_text': 'Você pode encontrar o hash na sua carteira ou no',
        'submit_for_verification': 'Enviar para Verificação',
        'back_to_account': 'Voltar para Minha Conta',
        'need_help': 'Precisa de Ajuda?',
        'how_to_get_usdc_usdt': 'Como obter USDC/USDT na Solana?',
        'use_exchanges': 'Use exchanges como Binance, Coinbase ou FTX',
        'buy_and_withdraw': 'Compre USDC/USDT e retire para sua carteira Solana',
        'use_bridges': 'Use pontes como Wormhole para transferir de outras redes',
        'recommended_wallets': 'Carteiras recomendadas:',
        'phantom_wallet': 'Phantom Wallet',
        'solflare': 'Solflare',
        'backpack': 'Backpack',
        'important_warning': 'Importante:',
        'verify_address_warning': 'Verifique sempre o endereço antes de enviar. Transações de criptomoedas são irreversíveis.',
        'selected_plan': 'Selecionado',
        'plan_info': 'Plano {plan} - ${price}',
        'select_plan_first': 'Por favor, selecione um plano antes de continuar.',
    }
}

def get_current_language():
    """Obtém o idioma atual da sessão ou padrão"""
    return session.get('language', 'en')

def set_language(lang_code):
    """Define o idioma na sessão"""
    if lang_code in TRANSLATIONS:
        session['language'] = lang_code
        session.permanent = True
        return True
    return False

def translate(key, **kwargs):
    """Traduz uma chave para o idioma atual"""
    lang = get_current_language()
    translation = TRANSLATIONS.get(lang, {}).get(key, key)
    
    # Suporte para formatação de strings
    if kwargs:
        try:
            return translation.format(**kwargs)
        except (KeyError, ValueError):
            return translation
    
    return translation

def get_available_languages():
    """Retorna lista de idiomas disponíveis"""
    return [
        {'code': 'en', 'name': 'English'},
        {'code': 'pt', 'name': 'Português (Brasil)'}
    ]

# ===============================================
# FLASK APP CONFIGURATION
# ===============================================

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "crypto_airdrop_manager_secret_key_2025")

# Configure session
app.permanent_session_lifetime = timedelta(days=7)  # Remember me for 7 days
app.config['SESSION_COOKIE_SECURE'] = False  # Para desenvolvimento local
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'



def get_client_ip():
    """Get client IP address from request"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        # If behind a proxy
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP'):
        # If behind nginx
        return request.environ['HTTP_X_REAL_IP']
    else:
        # Direct connection
        return request.environ.get('REMOTE_ADDR')

# Adicionar funções de tradução ao contexto global dos templates
@app.context_processor
def inject_language_functions():
    return {
        'translate': translate,
        'get_current_language': get_current_language,
        'get_available_languages': get_available_languages
    }

# Configure OAuth
oauth = OAuth(app)

# Twitter OAuth configuration
twitter = oauth.register(
    name='twitter',
    client_id=os.environ.get("TWITTER_CLIENT_ID"),
    client_secret=os.environ.get("TWITTER_CLIENT_SECRET"),
    authorize_url='https://twitter.com/i/oauth2/authorize',
    access_token_url='https://api.twitter.com/2/oauth2/token',
    client_kwargs={
        'scope': 'tweet.read users.read offline.access',
        'code_challenge_method': 'S256'
    }
)

# Configure the database with smart fallback
def setup_database():
    """Setup database connection with automatic fallback to SQLite"""
    database_url = os.environ.get("DATABASE_URL")
    
    if not database_url:
        # Default to Supabase connection
        database_url = "postgresql://postgres.ejyxvigvakzmqebmcuiw:PjmdV3ZlrY1MV6Z3@aws-0-sa-east-1.pooler.supabase.com:5432/postgres"
    
    # Try to connect to the specified database
    if database_url.startswith('postgresql://'):
        print("🔄 Tentando conectar ao Supabase...")
        try:
            # Test connection with a simple socket check first
            import socket
            import urllib.parse
            
            parsed = urllib.parse.urlparse(database_url)
            host = parsed.hostname
            port = parsed.port or 5432
            
            # Quick connectivity test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Reduced timeout for faster fallback
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result != 0:
                raise ConnectionError(f"Não foi possível conectar ao host {host}:{port}")
            
            print("✅ Conectividade testada com sucesso!")
            app.config["SQLALCHEMY_DATABASE_URI"] = database_url
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
                "pool_recycle": 300,
                "pool_pre_ping": True,
                "connect_args": {
                    "connect_timeout": 5,  # Reduced timeout
                    "application_name": "crypto_airdrop_manager"
                }
            }
            
        except Exception as e:
            print(f"❌ Supabase indisponível: {str(e)}")
            print("🔄 Usando SQLite local como fallback...")
            database_url = "sqlite:///app.db"
            app.config["SQLALCHEMY_DATABASE_URI"] = database_url
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
    else:
        # Already SQLite or other database
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
    
    return database_url

# Setup database configuration
db_url = setup_database()

# Initialize the app with the extension
db.init_app(app)

# Medidas de segurança do banco de dados
def check_database_exists(url):
    """Verifica se o banco de dados já tem dados importantes"""
    try:
        import sqlalchemy
        engine = sqlalchemy.create_engine(url, connect_args={"connect_timeout": 5})
        with engine.connect() as conn:
            # Verificar se existem tabelas com dados
            result = conn.execute(sqlalchemy.text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
                if url.startswith('sqlite://') else
                "SELECT table_name FROM information_schema.tables WHERE table_name='users'"
            ))
            tables = result.fetchall()
            
            if tables:
                # Verificar se há usuários no banco
                try:
                    result = conn.execute(sqlalchemy.text("SELECT COUNT(*) FROM users"))
                    user_count = result.scalar()
                    if user_count > 0:
                        print(f"🛡️ Banco protegido: {user_count} usuários encontrados")
                        return True
                except:
                    pass
        engine.dispose()
    except:
        pass
    return False

def safe_create_tables():
    """Cria tabelas apenas se não existirem dados importantes"""
    try:
        # Primeiro tenta conectar e verificar se há dados
        current_url = app.config["SQLALCHEMY_DATABASE_URI"]
        
        # Se há dados existentes, NÃO recriar as tabelas
        if check_database_exists(current_url):
            print("✅ Banco de dados protegido - usando dados existentes")
            return True
        
        # Se não há dados, é seguro criar/recriar as tabelas
        print("🔧 Criando esquema do banco de dados...")
        db.create_all()
        print("✅ Esquema criado com sucesso!")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao criar esquema: {str(e)}")
        return False

# Sistema de inicialização seguro do banco
def init_database_with_fallback():
    """Inicialização segura do banco com proteção contra perda de dados"""
    global db_url
    
    with app.app_context():
        try:
            # Testar conexão principal (Supabase)
            if db_url.startswith('postgresql://'):
                import sqlalchemy
                engine = sqlalchemy.create_engine(
                    db_url, 
                    connect_args={"connect_timeout": 5},
                    pool_pre_ping=True
                )
                
                try:
                    with engine.connect() as conn:
                        conn.execute(sqlalchemy.text("SELECT 1"))
                    engine.dispose()
                    
                    # Conexão bem-sucedida, criar tabelas com segurança
                    if safe_create_tables():
                        print("✅ Conectado ao Supabase com sucesso!")
                        return True
                        
                except Exception as e:
                    print(f"⚠️ Problemas com Supabase: {str(e)}")
                    engine.dispose()
                    
                    # Fallback para SQLite local
                    print("🔄 Usando SQLite local como backup...")
                    db_url = "sqlite:///backup_app.db"
                    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
                    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
            
            # Para SQLite (backup ou principal)
            if safe_create_tables():
                print("✅ Conectado ao SQLite local com sucesso!")
                return True
            
        except Exception as e:
            print(f"❌ Erro crítico: {str(e)}")
            # Último recurso - criar banco de emergência
            emergency_db = "sqlite:///emergency_backup.db"
            app.config["SQLALCHEMY_DATABASE_URI"] = emergency_db
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
            
            try:
                db.create_all()
                print("🚨 Usando banco de emergência!")
                return True
            except Exception as final_error:
                print(f"💥 Falha total: {str(final_error)}")
                raise final_error
        
        return False

# Inicializar sistema de backup automático
try:
    from backup_manager import BackupManager
    backup_manager = BackupManager()
    
    # Verificar se há backups ou criar um backup inicial
    current_db = app.config["SQLALCHEMY_DATABASE_URI"]
    if current_db.startswith('sqlite:///'):
        db_file = current_db.replace('sqlite:///', '')
        backup_manager.auto_backup_if_needed(db_file)
        print("🛡️ Sistema de backup ativo!")
    
except Exception as e:
    print(f"⚠️ Sistema de backup não pôde ser inicializado: {str(e)}")

# Initialize database
init_database_with_fallback()

# Inicializar serviço simples do Twitter
print("🔧 Inicializando serviço simples do Twitter...")
print("✅ Serviço Twitter inicializado!")

# Authentication configuration removed - now using database

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def is_authenticated():
    """Check if user is authenticated"""
    auth_status = 'user_id' in session
    if not auth_status:
        logging.debug(f"Usuário não autenticado. Sessão: {dict(session)}")
    return auth_status

def get_current_user():
    """Get current logged in user with enhanced security checks"""
    if 'user_id' in session:
        user_id = session['user_id']
        username = session.get('username')
        
        # 🔒 SECURITY CHECK: Validate session integrity
        if not user_id or not isinstance(user_id, int):
            logging.warning(f"⚠️ SECURITY: Invalid user_id in session: {user_id}")
            session.clear()
            return None
            
        user = User.query.get(user_id)
        if not user:
            logging.warning(f"⚠️ SECURITY: User ID {user_id} not found in database, clearing session")
            session.clear()
            return None
            
        # 🔒 SECURITY CHECK: Verify session username matches database
        if username and user.username != username:
            logging.warning(f"⚠️ SECURITY: Session username mismatch! Session: '{username}' vs DB: '{user.username}' for user ID {user_id}")
            session.clear()
            return None
            
        # 🔒 SECURITY CHECK: Log user access for audit trail
        logging.debug(f"✅ SECURITY: Valid user session - ID: {user.id}, Username: {user.username}")
        
        return user
    return None

def verify_protocol_ownership(protocol_id, current_user):
    """
    🔒 SECURITY FUNCTION: Verify that the current user owns the specified protocol
    Returns the protocol if owned by user, None otherwise
    """
    if not current_user:
        logging.warning(f"⚠️ SECURITY: Protocol access attempt without authentication - Protocol ID: {protocol_id}")
        return None
        
    protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first()
    
    if not protocol:
        # Check if protocol exists at all (to differentiate between non-existent and unauthorized)
        protocol_exists = Protocol.query.get(protocol_id)
        if protocol_exists:
            logging.warning(f"⚠️ SECURITY: User {current_user.id} ({current_user.username}) attempted to access protocol {protocol_id} owned by user {protocol_exists.user_id}")
        else:
            logging.warning(f"⚠️ SECURITY: User {current_user.id} ({current_user.username}) attempted to access non-existent protocol {protocol_id}")
        return None
        
    logging.debug(f"✅ SECURITY: Protocol ownership verified - User {current_user.id} owns protocol {protocol_id} ({protocol.name})")
    return protocol

def get_user_protocols_secure(current_user):
    """
    🔒 SECURITY FUNCTION: Get all protocols for current user with extra verification
    """
    if not current_user:
        logging.warning(f"⚠️ SECURITY: Protocol list request without authentication")
        return []
        
    protocols = Protocol.query.filter_by(user_id=current_user.id).all()
    
    # 🔒 SECURITY CHECK: Verify all returned protocols actually belong to the user
    verified_protocols = []
    for protocol in protocols:
        if protocol.user_id == current_user.id:
            verified_protocols.append(protocol)
        else:
            logging.error(f"🚨 CRITICAL SECURITY ISSUE: Protocol {protocol.id} has user_id {protocol.user_id} but was returned for user {current_user.id}")
            
    logging.debug(f"✅ SECURITY: Returned {len(verified_protocols)} verified protocols for user {current_user.id}")
    return verified_protocols

# Make authentication status available in templates
@app.context_processor
def inject_auth():
    return dict(is_authenticated=is_authenticated(), current_user=get_current_user())

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        action = request.form.get('action', 'login')
        
        if action == 'register':
            return handle_register()
        else:
            return handle_login()
    
    # If user is already logged in, redirect to index (but avoid infinite loops)
    if is_authenticated():
        next_page = request.args.get('next')
        if next_page and next_page != url_for('login'):
            return redirect(next_page)
        return redirect(url_for('index'))
    
    return render_template('login.html')

def handle_login():
    """Handle login form submission"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    remember = 'remember' in request.form
    
    logging.info(f"Tentativa de login para usuário: {username}")
    
    if not username or not password:
        flash('Por favor, insira usuário e senha.', 'error')
        return render_template('login.html')
    
    # Check credentials in database
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        logging.warning(f"Falha no login para usuário: {username}")
        flash('Usuário ou senha inválidos.', 'error')
        return render_template('login.html')
    
    # Login successful - create session
    session['user_id'] = user.id
    session['username'] = user.username
    session.permanent = remember
    
    # Update login information
    client_ip = get_client_ip()
    user.update_login_info(client_ip)
    db.session.commit()
    
    logging.info(f"Login bem-sucedido para usuário: {username} (ID: {user.id}) from IP: {client_ip}")
    logging.info(f"Sessão criada: user_id={session.get('user_id')}")
    
    flash(f'Bem-vindo de volta, {user.username}!', 'success')
    
    # Redirect to next page if specified, otherwise go to index
    next_page = request.args.get('next')
    if next_page and next_page != url_for('login'):
        logging.info(f"Redirecionando para: {next_page}")
        return redirect(next_page)
    
    logging.info("Redirecionando para index")
    return redirect(url_for('index'))

def handle_register():
    """Handle registration form submission"""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Validation
    if not username or not email or not password:
        flash('All fields are required.', 'error')
        return render_template('login.html')
    
    if len(username) < 3:
        flash('Username must be at least 3 characters long.', 'error')
        return render_template('login.html')
    
    if len(password) < 6:
        flash('Password must be at least 6 characters long.', 'error')
        return render_template('login.html')
    
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return render_template('login.html')
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return render_template('login.html')
    
    if User.query.filter_by(email=email).first():
        flash('Email already registered.', 'error')
        return render_template('login.html')
    
    try:
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Log in the new user
        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = True
        
        flash(f'Account created successfully! Welcome, {user.username}!', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating user: {str(e)}")
        flash('An error occurred while creating your account. Please try again.', 'error')
        return render_template('login.html')

@app.route('/logout')
def logout():
    """Handle user logout"""
    username = session.get('username', 'User')
    session.clear()
    flash(f'You have been logged out successfully, {username}.', 'info')
    return redirect(url_for('login'))

# Twitter OAuth routes
@app.route('/auth/twitter/test')
def twitter_test():
    """Test Twitter API connection"""
    try:
        # Try to make a simple API call to test rate limits
        import requests
        
        token = os.environ.get('TWITTER_BEARER_TOKEN')
        if not token:
            return jsonify({'status': 'error', 'message': 'TWITTER_BEARER_TOKEN not configured'})
        
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get('https://api.twitter.com/2/users/by/username/twitter', headers=headers)
        
        if response.status_code == 200:
            return jsonify({'status': 'success', 'message': 'Twitter API is working normally'})
        elif response.status_code == 429:
            reset_time = response.headers.get('x-rate-limit-reset')
            if reset_time:
                from datetime import datetime
                reset_datetime = datetime.fromtimestamp(int(reset_time))
                time_until_reset = reset_datetime - datetime.now()
                minutes_left = int(time_until_reset.total_seconds() / 60)
                return jsonify({
                    'status': 'rate_limited', 
                    'message': f'Rate limit active. Resets in {minutes_left} minutes',
                    'minutes_left': minutes_left
                })
            else:
                return jsonify({'status': 'rate_limited', 'message': 'Rate limit active. Wait ~15 minutes'})
        else:
            return jsonify({'status': 'error', 'message': f'Twitter API error: {response.status_code}'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/auth/twitter/status')
def twitter_status():
    """Status page for Twitter OAuth - NO API CALLS to avoid rate limits"""
    return render_template('twitter_status.html', 
                         status='ready', 
                         message='🚀 Sistema Twitter OAuth otimizado e pronto para uso!',
                         can_login=True,
                         info='Login funciona mesmo com rate limits na API')

@app.route('/auth/twitter')
def twitter_login():
    """Initiate Twitter OAuth"""
    try:
        # Verificar se as credenciais do Twitter estão configuradas
        client_id = os.environ.get("TWITTER_CLIENT_ID")
        client_secret = os.environ.get("TWITTER_CLIENT_SECRET")
        
        if not client_id or not client_secret or client_id == "your_twitter_client_id_here":
            flash('❌ Twitter OAuth não configurado! Configure as credenciais TWITTER_CLIENT_ID e TWITTER_CLIENT_SECRET.', 'error')
            return render_template('oauth_error.html', 
                                 error_type='config_missing',
                                 error_message='Credenciais do Twitter não configuradas. Configure TWITTER_CLIENT_ID e TWITTER_CLIENT_SECRET nas variáveis de ambiente.')
        
        # Limpar qualquer sessão OAuth anterior
        session.pop('oauth_state', None)
        session.pop('oauth_code_verifier', None)
        
        redirect_uri = url_for('twitter_callback', _external=True)
        print(f"🔗 Iniciando OAuth Twitter com callback: {redirect_uri}")
        return twitter.authorize_redirect(redirect_uri)
    except Exception as e:
        logging.error(f"Twitter OAuth initiation error: {str(e)}")
        flash('❌ Erro ao iniciar login com Twitter. Tente novamente.', 'error')
        return redirect(url_for('login'))

@app.route('/auth/twitter/reset')
def twitter_reset():
    """Reset Twitter OAuth session"""
    try:
        # Limpar toda a sessão OAuth
        session.pop('oauth_state', None)
        session.pop('oauth_code_verifier', None)
        session.pop('_flashes', None)
        
        flash('🔄 Sessão OAuth resetada. Tente fazer login novamente.', 'info')
        return redirect(url_for('login'))
    except Exception as e:
        logging.error(f"OAuth reset error: {str(e)}")
        flash('❌ Erro ao resetar sessão OAuth.', 'error')
        return redirect(url_for('login'))

@app.route('/auth/twitter/callback')
def twitter_callback():
    """Handle Twitter OAuth callback"""
    try:
        # Verificar se há código de erro na query string
        error = request.args.get('error')
        error_description = request.args.get('error_description', '')
        
        if error:
            if error == 'access_denied':
                logging.warning(f"Twitter OAuth access denied by user")
                return render_template('oauth_error.html', 
                                     error_type='access_denied',
                                     error_message='Você cancelou a autorização. Para usar todas as funcionalidades, é necessário autorizar o acesso ao Twitter.')
            else:
                logging.error(f"Twitter OAuth error: {error} - {error_description}")
                return render_template('oauth_error.html', 
                                     error_type='oauth_error',
                                     error_message=f'Erro de autorização: {error} - {error_description}')
        
        # Get the authorization token
        try:
            token = twitter.authorize_access_token()
        except Exception as oauth_error:
            logging.error(f"OAuth token error: {str(oauth_error)}")
            return render_template('oauth_error.html', 
                                 error_type='token_error',
                                 error_message=f'Erro ao obter token de autorização: {str(oauth_error)}')
        
        # Verificar se o token foi obtido com sucesso
        if not token or 'access_token' not in token:
            logging.error(f"Invalid token received: {token}")
            return render_template('oauth_error.html', 
                                 error_type='invalid_token',
                                 error_message='Token de acesso inválido recebido do Twitter')
        
        # Obter dados do usuário da API do Twitter
        try:
            resp = twitter.get('https://api.twitter.com/2/users/me?user.fields=id,username,name,profile_image_url', 
                              token=token, timeout=10)
            user_info = resp.json()
            
            logging.info(f"Twitter API response: {user_info}")
            
            # Verificar se conseguiu obter dados válidos da API
            if 'data' not in user_info or 'id' not in user_info['data']:
                if 'title' in user_info and user_info['title'] == 'Too Many Requests':
                    logging.error("Rate limit atingido na API do Twitter")
                    return render_template('oauth_error.html', 
                                         error_type='rate_limit',
                                         error_message='Rate limit da API do Twitter atingido. Tente novamente em alguns minutos.')
                else:
                    logging.error(f"Resposta inválida da API do Twitter: {user_info}")
                    return render_template('oauth_error.html', 
                                         error_type='api_error',
                                         error_message='Não foi possível obter dados do usuário da API do Twitter.')
            
            twitter_user_data = user_info['data']
            twitter_id = str(twitter_user_data['id'])
            logging.info("✅ Dados obtidos da API do Twitter com sucesso")
                
        except Exception as api_error:
            logging.error(f"Erro na API do Twitter: {api_error}")
            return render_template('oauth_error.html', 
                                 error_type='api_error',
                                 error_message=f'Erro ao acessar a API do Twitter: {str(api_error)}. Tente novamente em alguns minutos.')
        
        # Check if user already exists
        user = User.query.filter_by(twitter_id=twitter_id).first()
        
        if user:
            # Update existing user data
            user.update_twitter_data(twitter_user_data)
            # Salvar tokens OAuth para MCP individual
            user.twitter_access_token = token.get('access_token')
            user.twitter_access_token_secret = token.get('access_token_secret', '')
            # Usar as credenciais da aplicação (necessárias para API calls)
            user.twitter_consumer_key = os.environ.get('TWITTER_CONSUMER_KEY')
            user.twitter_consumer_secret = os.environ.get('TWITTER_CONSUMER_SECRET')
            
            db.session.commit()
            
            # Log in the user
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            flash(f'🎉 Welcome back, {user.display_name}! Login successful.', 'success')
        else:
            # Create new user
            user = User.create_from_twitter(twitter_user_data)
            # Salvar tokens OAuth para MCP individual
            user.twitter_access_token = token.get('access_token')
            user.twitter_access_token_secret = token.get('access_token_secret', '')
            # Usar as credenciais da aplicação (necessárias para API calls)
            user.twitter_consumer_key = os.environ.get('TWITTER_CONSUMER_KEY')
            user.twitter_consumer_secret = os.environ.get('TWITTER_CONSUMER_SECRET')
            
            db.session.add(user)
            db.session.commit()
            
            # Log in the new user
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            flash(f'🎉 Account created successfully! Welcome, {user.display_name}!', 'success')
        
        return redirect(url_for('index'))
        
    except Exception as e:
        logging.error(f"Twitter OAuth error: {str(e)}")
        return render_template('oauth_error.html', 
                             error_type='unexpected_error',
                             error_message=f'Erro inesperado durante o login: {str(e)}')

@app.route('/')
@login_required
def index():
    """Display all protocols on the homepage with filters"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Get filter parameters
        status_filter = request.args.get('status', 'all')
        network_filter = request.args.get('network', 'all')
        
        # Start with base query for current user
        query = Protocol.query.filter(Protocol.user_id == current_user.id)
        
        # Apply status filter
        if status_filter != 'all':
            if status_filter == 'active':
                query = query.filter(Protocol.status == ProtocolStatus.ACTIVE)
            elif status_filter == 'ended':
                query = query.filter(Protocol.status == ProtocolStatus.ENDED)
        
        # Apply network filter
        if network_filter != 'all':
            query = query.filter(Protocol.network == network_filter)
        
        # Order by start_date (newest first), then by created_at as fallback
        protocols = query.order_by(
            Protocol.start_date.desc().nulls_last(),
            Protocol.created_at.desc()
        ).all()
        
        # Get unique networks for filter dropdown (only for current user)
        networks = db.session.query(Protocol.network).filter(Protocol.user_id == current_user.id).distinct().all()
        networks = [network[0] for network in networks]
        
        return render_template('index.html', 
                             protocols=protocols, 
                             networks=networks,
                             current_status=status_filter,
                             current_network=network_filter)
    except Exception as e:
        logging.error(f"Error loading protocols: {str(e)}")
        flash('Error loading protocols. Please try again.', 'error')
        return render_template('index.html', protocols=[], networks=[])

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_protocol():
    """Add a new protocol"""
    if request.method == 'POST':
        try:
            current_user = get_current_user()
            if not current_user:
                return redirect(url_for('login'))
            
            # Check protocol limit for free users
            if not current_user.can_add_protocol():
                flash(f'Limite atingido! Usuários gratuitos podem adicionar apenas {current_user.get_protocol_limit()} protocolos. Faça upgrade para Premium e tenha protocolos ilimitados!', 'warning')
                return render_template('add_protocol.html', show_upgrade=True)
            
            # Get form data
            name = request.form.get('name', '').strip()
            network = request.form.get('network', '').strip()
            website = request.form.get('website', '').strip()
            twitter = request.form.get('twitter', '').strip()
            start_date_str = request.form.get('start_date', '').strip()
            daily_missions = 'daily_missions' in request.form
            
            # Validate required fields
            if not name:
                flash('Protocol name is required.', 'error')
                return render_template('add_protocol.html')
            
            if not network:
                flash('Network is required.', 'error')
                return render_template('add_protocol.html')
            
            # Check if protocol already exists for this user
            existing_protocol = Protocol.query.filter_by(user_id=current_user.id, name=name).first()
            if existing_protocol:
                flash('You already have a protocol with this name.', 'error')
                return render_template('add_protocol.html')
            
            # Parse start date
            start_date_obj = None
            if start_date_str:
                try:
                    start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                except ValueError:
                    flash('Invalid date format. Please use YYYY-MM-DD.', 'error')
                    return render_template('add_protocol.html')
            
            # Validate URLs
            if website and not (website.startswith('http://') or website.startswith('https://')):
                website = 'https://' + website
            
            # Clean Twitter handle
            if twitter:
                if twitter.startswith('@'):
                    twitter = twitter[1:]
                if twitter.startswith('https://twitter.com/'):
                    twitter = twitter.replace('https://twitter.com/', '')
                if twitter.startswith('https://x.com/'):
                    twitter = twitter.replace('https://x.com/', '')
            
            # Get visual customization fields
            logo_url = request.form.get('logo_url', '').strip()
            background_image_url = request.form.get('background_image_url', '').strip()
            primary_color = request.form.get('primary_color', '').strip()
            
            # Validate visual URLs
            if logo_url and not (logo_url.startswith('http://') or logo_url.startswith('https://')):
                logo_url = 'https://' + logo_url
            if background_image_url and not (background_image_url.startswith('http://') or background_image_url.startswith('https://')):
                background_image_url = 'https://' + background_image_url
            
            # Validate color format
            if primary_color and not primary_color.startswith('#'):
                primary_color = '#' + primary_color
            
            # 🔒 SECURITY: Create new protocol with explicit user verification
            protocol = Protocol(
                user_id=current_user.id,
                name=name,
                network=network,
                website=website,
                twitter=twitter,
                start_date=start_date_obj,
                daily_missions=daily_missions,
                logo_url=logo_url if logo_url else None,
                background_image_url=background_image_url if background_image_url else None,
                primary_color=primary_color if primary_color else None
            )
            
            db.session.add(protocol)
            db.session.commit()
            
            # 🔒 SECURITY: Log protocol creation for audit trail
            logging.info(f"✅ SECURITY: Protocol '{name}' created successfully by user {current_user.id} ({current_user.username})")
            
            flash(f'Protocol "{name}" added successfully!', 'success')
            return redirect(url_for('index'))
                
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error adding protocol: {str(e)}")
            
            # Check for specific error types
            error_message = str(e)
            if 'duplicate key value violates unique constraint' in error_message:
                if 'protocols_name_key' in error_message or 'unique_user_protocol' in error_message:
                    flash(f'Você já possui um protocolo com o nome "{name}". Escolha um nome diferente.', 'error')
                else:
                    flash('Este protocolo já existe. Escolha um nome diferente.', 'error')
            else:
                flash('Ocorreu um erro ao adicionar o protocolo. Tente novamente.', 'error')
            
            return render_template('add_protocol.html')
    
    # Pass user info to template for upgrade prompts
    current_user = get_current_user()
    return render_template('add_protocol.html', current_user=current_user)

@app.route('/edit/<int:protocol_id>', methods=['GET', 'POST'])
@login_required
def edit_protocol(protocol_id):
    """Edit a protocol"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first_or_404()
        
        if request.method == 'POST':
            # Get form data
            name = request.form.get('name', '').strip()
            network = request.form.get('network', '').strip()
            website = request.form.get('website', '').strip()
            twitter = request.form.get('twitter', '').strip()
            start_date_str = request.form.get('start_date', '').strip()
            daily_missions = 'daily_missions' in request.form
            
            # Validate required fields
            if not name:
                flash('Protocol name is required.', 'error')
                return render_template('edit_protocol.html', protocol=protocol)
            
            if not network:
                flash('Network is required.', 'error')
                return render_template('edit_protocol.html', protocol=protocol)
            
            # Check if name is unique (excluding current protocol)
            existing_protocol = Protocol.query.filter_by(
                user_id=current_user.id, 
                name=name
            ).filter(Protocol.id != protocol_id).first()
            
            if existing_protocol:
                flash('You already have a protocol with this name.', 'error')
                return render_template('edit_protocol.html', protocol=protocol)
            
            # Parse start date
            start_date_obj = None
            if start_date_str:
                try:
                    start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                except ValueError:
                    flash('Invalid date format. Please use YYYY-MM-DD.', 'error')
                    return render_template('edit_protocol.html', protocol=protocol)
            
            # Validate URLs
            if website and not (website.startswith('http://') or website.startswith('https://')):
                website = 'https://' + website
            
            # Clean Twitter handle
            if twitter:
                if twitter.startswith('@'):
                    twitter = twitter[1:]
                if twitter.startswith('https://twitter.com/'):
                    twitter = twitter.replace('https://twitter.com/', '')
                if twitter.startswith('https://x.com/'):
                    twitter = twitter.replace('https://x.com/', '')
            
            # Get visual customization fields
            logo_url = request.form.get('logo_url', '').strip()
            background_image_url = request.form.get('background_image_url', '').strip()
            primary_color = request.form.get('primary_color', '').strip()
            
            # Validate visual URLs
            if logo_url and not (logo_url.startswith('http://') or logo_url.startswith('https://')):
                logo_url = 'https://' + logo_url
            if background_image_url and not (background_image_url.startswith('http://') or background_image_url.startswith('https://')):
                background_image_url = 'https://' + background_image_url
            
            # Validate color format
            if primary_color and not primary_color.startswith('#'):
                primary_color = '#' + primary_color
            
            # Update protocol
            protocol.name = name
            protocol.network = network
            protocol.website = website
            protocol.twitter = twitter
            protocol.start_date = start_date_obj
            protocol.daily_missions = daily_missions
            protocol.logo_url = logo_url if logo_url else None
            protocol.background_image_url = background_image_url if background_image_url else None
            protocol.primary_color = primary_color if primary_color else None
            
            db.session.commit()
            
            flash(f'Protocol "{name}" updated successfully!', 'success')
            return redirect(url_for('index'))
        
        return render_template('edit_protocol.html', protocol=protocol)
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing protocol: {str(e)}")
        flash('An error occurred while editing the protocol.', 'error')
        return redirect(url_for('index'))

@app.route('/account')
@login_required
def my_account():
    """Show user account information"""
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for('login'))
    
    # Create user stats object
    user_stats = {
        'protocol_count': len(current_user.protocols),
        'limit': current_user.get_protocol_limit()
    }
    
    return render_template('my_account.html', 
                         user=current_user,
                         user_stats=user_stats,
                         protocols_count=len(current_user.protocols),
                         limit=current_user.get_protocol_limit())

@app.route('/account/update_email', methods=['POST'])
@login_required
def update_email():
    """Update user email"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        new_email = request.form.get('email', '').strip()
        
        # Validar email
        if new_email:
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, new_email):
                flash('Email inválido. Por favor, digite um email válido.', 'error')
                return redirect(url_for('my_account'))
            
            # Verificar se email já está em uso por outro usuário
            existing_user = User.query.filter(
                User.email == new_email,
                User.id != current_user.id
            ).first()
            
            if existing_user:
                flash('Este email já está em uso por outro usuário.', 'error')
                return redirect(url_for('my_account'))
        
        # Atualizar email
        current_user.email = new_email if new_email else None
        db.session.commit()
        
        if new_email:
            flash(f'Email atualizado com sucesso para: {new_email}', 'success')
        else:
            flash('Email removido com sucesso.', 'success')
            
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating email: {str(e)}")
        flash('Erro ao atualizar email. Tente novamente.', 'error')
    
    return redirect(url_for('my_account'))

@app.route('/account/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validações
        if not current_password or not new_password or not confirm_password:
            flash('Todos os campos são obrigatórios.', 'error')
            return redirect(url_for('my_account'))
        
        # Verificar senha atual
        if not current_user.check_password(current_password):
            flash('Senha atual incorreta.', 'error')
            return redirect(url_for('my_account'))
        
        # Verificar se as novas senhas coincidem
        if new_password != confirm_password:
            flash('A nova senha e confirmação não coincidem.', 'error')
            return redirect(url_for('my_account'))
        
        # Verificar comprimento mínimo
        if len(new_password) < 6:
            flash('A nova senha deve ter pelo menos 6 caracteres.', 'error')
            return redirect(url_for('my_account'))
        
        # Verificar se a nova senha é diferente da atual
        if current_user.check_password(new_password):
            flash('A nova senha deve ser diferente da senha atual.', 'error')
            return redirect(url_for('my_account'))
        
        # Atualizar senha
        current_user.set_password(new_password)
        db.session.commit()
        
        flash('Senha alterada com sucesso!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error changing password: {str(e)}")
        flash('Erro ao alterar senha. Tente novamente.', 'error')
    
    return redirect(url_for('my_account'))



@app.route('/upgrade')
@login_required
def upgrade_page():
    """Premium upgrade page"""
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for('login'))
    
    # Endereço fixo para receber pagamentos
    PAYMENT_ADDRESS = "Dm5ThWMqJ6HgroFJuaw7EhWq9ZmctuDSf5DAuaPvfp73"
    
    # Calcular preços dos planos
    monthly_price = 2.99
    quarterly_price = round(monthly_price * 3 * 0.9, 2)  # 10% desconto
    biannual_price = round(monthly_price * 6 * 0.75, 2)  # 25% desconto
    
    plans = {
        'monthly': {
            'name': 'Mensal',
            'price': monthly_price,
            'months': 1,
            'discount': 0,
            'plan_enum': SubscriptionPlan.MONTHLY
        },
        'quarterly': {
            'name': 'Trimestral',
            'price': quarterly_price,
            'months': 3,
            'discount': 10,
            'plan_enum': SubscriptionPlan.QUARTERLY,
            'savings': round((monthly_price * 3) - quarterly_price, 2)
        },
        'biannual': {
            'name': 'Semestral',
            'price': biannual_price,
            'months': 6,
            'discount': 25,
            'plan_enum': SubscriptionPlan.BIANNUAL,
            'savings': round((monthly_price * 6) - biannual_price, 2)
        }
    }
    
    return render_template('upgrade.html', 
                         user=current_user, 
                         payment_address=PAYMENT_ADDRESS,
                         plans=plans)

@app.route('/upgrade/payment', methods=['POST'])
@login_required
def process_payment():
    """Process crypto payment for premium upgrade"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Get form data
        wallet_address = request.form.get('wallet_address', '').strip()
        transaction_hash = request.form.get('transaction_hash', '').strip()
        token_symbol = request.form.get('token_symbol', 'USDC')
        selected_plan = request.form.get('plan', 'monthly')
        
        if not wallet_address or not transaction_hash or not selected_plan:
            flash('Todos os campos são obrigatórios.', 'error')
            return redirect(url_for('upgrade_page'))
        
        # Definir preços e planos
        monthly_price = 2.99
        plans_config = {
            'monthly': {
                'price': monthly_price,
                'months': 1,
                'plan_enum': SubscriptionPlan.MONTHLY
            },
            'quarterly': {
                'price': round(monthly_price * 3 * 0.9, 2),
                'months': 3,
                'plan_enum': SubscriptionPlan.QUARTERLY
            },
            'biannual': {
                'price': round(monthly_price * 6 * 0.75, 2),
                'months': 6,
                'plan_enum': SubscriptionPlan.BIANNUAL
            }
        }
        
        if selected_plan not in plans_config:
            flash('Plano inválido selecionado.', 'error')
            return redirect(url_for('upgrade_page'))
        
        plan_info = plans_config[selected_plan]
        
        # Check if payment already exists
        existing_payment = Payment.query.filter_by(
            user_id=current_user.id,
            transaction_hash=transaction_hash
        ).first()
        
        if existing_payment:
            flash('Esta transação já foi enviada para verificação.', 'warning')
            return redirect(url_for('my_account'))
        
        # Create payment record
        payment = Payment(
            user_id=current_user.id,
            amount_usd=plan_info['price'],
            wallet_address=wallet_address,
            payment_address="Dm5ThWMqJ6HgroFJuaw7EhWq9ZmctuDSf5DAuaPvfp73",
            transaction_hash=transaction_hash,
            token_symbol=token_symbol,
            network='solana',
            expected_amount=plan_info['price'],
            subscription_plan=plan_info['plan_enum'],
            plan_months=plan_info['months']
        )
        
        db.session.add(payment)
        db.session.commit()
        
        flash(f'Pagamento do plano {plan_info["plan_enum"].value} enviado para verificação! Você será notificado quando for confirmado.', 'success')
        return redirect(url_for('my_account'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error processing payment: {str(e)}")
        flash('Erro ao processar pagamento. Tente novamente.', 'error')
        return redirect(url_for('upgrade_page'))

@app.route('/admin/payments')
@login_required
def admin_payments():
    """Admin page to verify payments (apenas para administradores)"""
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for('login'))
    
    # Verificar se o usuário é admin
    if not current_user.is_admin():
        flash('Acesso negado. Apenas administradores podem acessar esta página.', 'error')
        return redirect(url_for('index'))
    
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    
    return render_template('admin_payments.html', payments=payments)

@app.route('/admin/payment/<int:payment_id>/verify', methods=['POST'])
@login_required
def verify_payment(payment_id):
    """Manually verify a payment (admin function)"""
    try:
        current_user = get_current_user()
        if not current_user or not current_user.is_admin():
            flash('Acesso negado. Apenas administradores podem verificar pagamentos.', 'error')
            return redirect(url_for('index'))
            
        payment = Payment.query.get_or_404(payment_id)
        
        if payment.status == PaymentStatus.VERIFIED:
            flash('Pagamento já foi verificado.', 'info')
            return redirect(url_for('admin_payments'))
        
        # Mark payment as verified
        payment.mark_verified("Verificado manualmente")
        db.session.commit()
        
        flash(f'Payment #{payment.id} verified successfully! User {payment.user.username} is now Premium.', 'success')
        return redirect(url_for('admin_payments'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error verifying payment: {str(e)}")
        flash('Erro ao verificar pagamento.', 'error')
        return redirect(url_for('admin_payments'))

@app.route('/admin/payment/<int:payment_id>/reject', methods=['POST'])
@login_required
def reject_payment(payment_id):
    """Manually reject a payment (admin function)"""
    try:
        current_user = get_current_user()
        if not current_user or not current_user.is_admin():
            flash('Acesso negado. Apenas administradores podem rejeitar pagamentos.', 'error')
            return redirect(url_for('index'))
            
        payment = Payment.query.get_or_404(payment_id)
        notes = request.form.get('notes', '').strip()
        
        payment.mark_failed(notes or "Rejeitado manualmente")
        db.session.commit()
        
        flash(f'Pagamento #{payment.id} rejeitado.', 'warning')
        return redirect(url_for('admin_payments'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error rejecting payment: {str(e)}")
        flash('Erro ao rejeitar pagamento.', 'error')
        return redirect(url_for('admin_payments'))

@app.route('/delete/<int:protocol_id>')
@login_required
def delete_protocol(protocol_id):
    """Delete a protocol"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first_or_404()
        protocol_name = protocol.name
        
        db.session.delete(protocol)
        db.session.commit()
        
        flash(f'Protocol "{protocol_name}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting protocol: {str(e)}")
        flash('An error occurred while deleting the protocol.', 'error')
    
    return redirect(url_for('index'))

@app.route('/protocol/<int:protocol_id>')
@login_required
def protocol_details(protocol_id):
    """Show protocol details with investments and tasks"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first_or_404()
        
        # Get investments ordered by date (newest first)
        investments = Investment.query.filter_by(protocol_id=protocol_id).order_by(Investment.date.desc()).all()
        
        # Get tasks ordered by status (pending first) then by creation date
        tasks = Task.query.filter_by(protocol_id=protocol_id).order_by(
            Task.status.asc(), Task.created_at.desc()
        ).all()
        
        return render_template('protocol_details.html', 
                             protocol=protocol, 
                             investments=investments,
                             tasks=tasks)
    except Exception as e:
        logging.error(f"Error loading protocol details: {str(e)}")
        flash('Error loading protocol details.', 'error')
        return redirect(url_for('index'))

@app.route('/protocol/<int:protocol_id>/toggle_status', methods=['POST'])
@login_required
def toggle_protocol_status(protocol_id):
    """Toggle protocol status between active and ended"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first_or_404()
        
        if protocol.status == ProtocolStatus.ACTIVE:
            protocol.status = ProtocolStatus.ENDED
            flash(f'Protocol "{protocol.name}" marked as ended.', 'success')
        else:
            protocol.status = ProtocolStatus.ACTIVE
            flash(f'Protocol "{protocol.name}" marked as active.', 'success')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error toggling protocol status: {str(e)}")
        flash('An error occurred while updating the protocol status.', 'error')
    
    return redirect(url_for('protocol_details', protocol_id=protocol_id))

# Investment routes
@app.route('/protocol/<int:protocol_id>/add_investment', methods=['POST'])
@login_required
def add_investment(protocol_id):
    """Add investment to a protocol"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first_or_404()
        
        amount = float(request.form.get('amount', 0))
        investment_type = request.form.get('type')
        date_str = request.form.get('date')
        description = request.form.get('description', '').strip()
        
        if amount <= 0:
            flash('Investment amount must be greater than 0.', 'error')
            return redirect(url_for('index'))
        
        if investment_type not in ['entrada', 'retirada']:
            flash('Invalid investment type.', 'error')
            return redirect(url_for('index'))
        
        # Parse date
        if not date_str:
            flash('Date is required.', 'error')
            return redirect(url_for('index'))
        investment_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        # Create investment
        investment = Investment(
            protocol_id=protocol_id,
            amount=amount,
            type=InvestmentType.ENTRY if investment_type == 'entrada' else InvestmentType.WITHDRAWAL,
            date=investment_date,
            description=description
        )
        
        db.session.add(investment)
        db.session.commit()
        
        flash(f'Investment of ${amount:.2f} added to {protocol.name}!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding investment: {str(e)}")
        flash('An error occurred while adding the investment.', 'error')
    
    return redirect(url_for('index'))

@app.route('/protocol/<int:protocol_id>/add_task', methods=['POST'])
@login_required
def add_task(protocol_id):
    """Add task to a protocol"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first_or_404()
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        
        if not title:
            flash('Task title is required.', 'error')
            return redirect(url_for('index'))
        
        # Create task
        task = Task(
            protocol_id=protocol_id,
            title=title,
            description=description,
            status=TaskStatus.PENDING
        )
        
        db.session.add(task)
        db.session.commit()
        
        flash(f'Task "{title}" added to {protocol.name}!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding task: {str(e)}")
        flash('An error occurred while adding the task.', 'error')
    
    return redirect(url_for('index'))

@app.route('/task/<int:task_id>/toggle', methods=['POST'])
@login_required
def toggle_task(task_id):
    """Toggle task completion status"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        task = Task.query.join(Protocol).filter(Task.id == task_id, Protocol.user_id == current_user.id).first_or_404()
        
        if task.status == TaskStatus.PENDING:
            task.mark_completed()
            flash(f'Task "{task.title}" marked as completed!', 'success')
        else:
            task.mark_pending()
            flash(f'Task "{task.title}" marked as pending!', 'success')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error toggling task: {str(e)}")
        flash('An error occurred while updating the task.', 'error')
    
    return redirect(url_for('index'))

@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    """Delete a task"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        task = Task.query.join(Protocol).filter(Task.id == task_id, Protocol.user_id == current_user.id).first_or_404()
        task_title = task.title
        
        db.session.delete(task)
        db.session.commit()
        
        flash(f'Task "{task_title}" deleted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting task: {str(e)}")
        flash('An error occurred while deleting the task.', 'error')
    
    return redirect(url_for('index'))

@app.route('/investment/<int:investment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_investment(investment_id):
    """Edit an investment"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        investment = Investment.query.join(Protocol).filter(Investment.id == investment_id, Protocol.user_id == current_user.id).first_or_404()
        
        if request.method == 'POST':
            amount = float(request.form.get('amount', 0))
            investment_type = request.form.get('type')
            date_str = request.form.get('date')
            description = request.form.get('description', '').strip()
            
            if amount <= 0:
                flash('Investment amount must be greater than 0.', 'error')
                return redirect(url_for('protocol_details', protocol_id=investment.protocol_id))
            
            if investment_type not in ['entrada', 'retirada']:
                flash('Invalid investment type.', 'error')
                return redirect(url_for('protocol_details', protocol_id=investment.protocol_id))
            
            if not date_str:
                flash('Date is required.', 'error')
                return redirect(url_for('protocol_details', protocol_id=investment.protocol_id))
            
            # Update investment
            investment.amount = amount
            if investment_type == 'entrada':
                investment.type = InvestmentType.ENTRY
            else:
                investment.type = InvestmentType.WITHDRAWAL
            investment.date = datetime.strptime(date_str, '%Y-%m-%d').date()
            investment.description = description
            
            db.session.commit()
            flash('Investment updated successfully!', 'success')
            return redirect(url_for('protocol_details', protocol_id=investment.protocol_id))
        
        return render_template('edit_investment.html', investment=investment)
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing investment: {str(e)}")
        flash('An error occurred while editing the investment.', 'error')
        return redirect(url_for('index'))

@app.route('/investment/<int:investment_id>/delete', methods=['POST'])
@login_required
def delete_investment(investment_id):
    """Delete an investment"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        investment = Investment.query.join(Protocol).filter(Investment.id == investment_id, Protocol.user_id == current_user.id).first_or_404()
        protocol_id = investment.protocol_id
        
        db.session.delete(investment)
        db.session.commit()
        
        flash('Investment deleted successfully!', 'success')
        return redirect(url_for('protocol_details', protocol_id=protocol_id))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting investment: {str(e)}")
        flash('An error occurred while deleting the investment.', 'error')
        return redirect(url_for('index'))

@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    """Edit a task"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        task = Task.query.join(Protocol).filter(Task.id == task_id, Protocol.user_id == current_user.id).first_or_404()
        
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            
            if not title:
                flash('Task title is required.', 'error')
                return redirect(url_for('protocol_details', protocol_id=task.protocol_id))
            
            # Update task
            task.title = title
            task.description = description
            
            db.session.commit()
            flash('Task updated successfully!', 'success')
            return redirect(url_for('protocol_details', protocol_id=task.protocol_id))
        
        return render_template('edit_task.html', task=task)
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing task: {str(e)}")
        flash('An error occurred while editing the task.', 'error')
        return redirect(url_for('index'))

# Airdrop routes
@app.route('/protocol/<int:protocol_id>/add_airdrop', methods=['POST'])
@login_required
def add_airdrop(protocol_id):
    """Add airdrop to a protocol"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first_or_404()
        
        token_name = request.form.get('token_name', '').strip()
        tokens_received = request.form.get('tokens_received')
        price_per_token = request.form.get('price_per_token')
        status = request.form.get('status', 'pendente')
        received_date_str = request.form.get('received_date')
        notes = request.form.get('notes', '').strip()
        
        if not token_name:
            flash('Token name is required.', 'error')
            return redirect(url_for('protocol_details', protocol_id=protocol_id))
        
        # Convert values
        tokens_received_float = float(tokens_received) if tokens_received else None
        price_per_token_float = float(price_per_token) if price_per_token else None
        received_date_obj = None
        
        if received_date_str:
            received_date_obj = datetime.strptime(received_date_str, '%Y-%m-%d').date()
        
        # Create airdrop
        airdrop = Airdrop(
            protocol_id=protocol_id,
            token_name=token_name,
            tokens_received=tokens_received_float,
            price_per_token=price_per_token_float,
            status=AirdropStatus.PENDING if status == 'pendente' else 
                   AirdropStatus.RECEIVED if status == 'recebido' else 
                   AirdropStatus.SOLD,
            received_date=received_date_obj,
            notes=notes
        )
        
        db.session.add(airdrop)
        db.session.commit()
        
        flash(f'Airdrop {token_name} added to {protocol.name}!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding airdrop: {str(e)}")
        flash('An error occurred while adding the airdrop.', 'error')
    
    return redirect(url_for('protocol_details', protocol_id=protocol_id))

@app.route('/airdrop/<int:airdrop_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_airdrop(airdrop_id):
    """Edit an airdrop"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        airdrop = Airdrop.query.join(Protocol).filter(Airdrop.id == airdrop_id, Protocol.user_id == current_user.id).first_or_404()
        
        if request.method == 'POST':
            token_name = request.form.get('token_name', '').strip()
            tokens_received = request.form.get('tokens_received')
            price_per_token = request.form.get('price_per_token')
            status = request.form.get('status', 'pendente')
            received_date_str = request.form.get('received_date')
            notes = request.form.get('notes', '').strip()
            
            if not token_name:
                flash('Token name is required.', 'error')
                return redirect(url_for('protocol_details', protocol_id=airdrop.protocol_id))
            
            # Update airdrop
            airdrop.token_name = token_name
            airdrop.tokens_received = float(tokens_received) if tokens_received else None
            airdrop.price_per_token = float(price_per_token) if price_per_token else None
            airdrop.status = AirdropStatus.PENDING if status == 'pendente' else \
                           AirdropStatus.RECEIVED if status == 'recebido' else \
                           AirdropStatus.SOLD
            airdrop.received_date = datetime.strptime(received_date_str, '%Y-%m-%d').date() if received_date_str else None
            airdrop.notes = notes
            
            db.session.commit()
            flash('Airdrop updated successfully!', 'success')
            return redirect(url_for('protocol_details', protocol_id=airdrop.protocol_id))
        
        return render_template('edit_airdrop.html', airdrop=airdrop)
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing airdrop: {str(e)}")
        flash('An error occurred while editing the airdrop.', 'error')
        return redirect(url_for('index'))

@app.route('/airdrop/<int:airdrop_id>/delete', methods=['POST'])
@login_required
def delete_airdrop(airdrop_id):
    """Delete an airdrop"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        airdrop = Airdrop.query.join(Protocol).filter(Airdrop.id == airdrop_id, Protocol.user_id == current_user.id).first_or_404()
        protocol_id = airdrop.protocol_id
        token_name = airdrop.token_name
        
        db.session.delete(airdrop)
        db.session.commit()
        
        flash(f'Airdrop {token_name} deleted successfully!', 'success')
        return redirect(url_for('protocol_details', protocol_id=protocol_id))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting airdrop: {str(e)}")
        flash('An error occurred while deleting the airdrop.', 'error')
        return redirect(url_for('index'))


@app.route('/protocol/<int:protocol_id>/update_tweets', methods=['POST'])
@login_required
def update_protocol_tweets(protocol_id):
    """Busca os últimos 3 tweets de um protocolo (máximo 1x por dia)"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        protocol = Protocol.query.get_or_404(protocol_id)
        
        # Check permission
        if protocol.user_id != current_user.id:
            flash('You do not have permission to update tweets for this protocol.', 'error')
            return redirect(url_for('index'))
        
        if not protocol.twitter:
            flash('This protocol does not have Twitter configured.', 'warning')
            return redirect(url_for('protocol_details', protocol_id=protocol_id))
        
        # Usar o serviço simples do Twitter
        result = twitter_service.search_protocol_tweets(protocol_id)
        
        if result.get('success'):
            tweets_count = result.get('tweets_saved', 0)
            if tweets_count > 0:
                flash(f'✅ {tweets_count} {translate("tweets_found_saved")}', 'success')
            else:
                flash(f'✅ {translate("search_completed")}', 'info')
        else:
            error_msg = result.get('error', 'Erro desconhecido')
            flash(f'❌ {error_msg}', 'error')
                
    except Exception as e:
        logging.error(f"Error updating tweets: {str(e)}")
        flash(translate('error_searching_tweets'), 'error')
    
    return redirect(url_for('protocol_details', protocol_id=protocol_id))


@app.route('/admin/update_all_tweets', methods=['POST'])
@login_required
def update_all_tweets():
    """Buscar tweets de todos os protocolos (admin only)"""
    try:
        current_user = get_current_user()
        if not current_user or not current_user.is_admin():
            flash('Access denied. Only administrators can update all tweets.', 'error')
            return redirect(url_for('index'))
        
        # Buscar todos os protocolos com Twitter configurado
        protocols = Protocol.query.filter(Protocol.twitter.isnot(None)).all()
        updated = 0
        failed = 0
        
        for protocol in protocols:
            try:
                result = twitter_service.search_protocol_tweets(protocol.id)
                if result.get('success'):
                    updated += 1
                else:
                    failed += 1
            except:
                failed += 1
        
        flash(f'Update completed: {updated} successes, {failed} failures from {len(protocols)} protocols.', 'info')
        
    except Exception as e:
        logging.error(f"Error updating all tweets: {str(e)}")
        flash('Error updating all tweets.', 'error')
    
    return redirect(url_for('index'))

def safe_string(value):
    """Safely convert value to string, handling encoding issues"""
    if value is None:
        return ""
    
    if isinstance(value, bytes):
        # Handle bytes data that might be corrupted
        try:
            return value.decode('utf-8', errors='replace')
        except:
            try:
                return value.decode('latin-1', errors='replace')
            except:
                return str(value, errors='replace')
    
    if isinstance(value, str):
        # Try to encode/decode to clean any problematic characters
        try:
            # First try to encode to bytes and back to clean the string
            cleaned = value.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            # Remove any null bytes or other problematic characters
            cleaned = cleaned.replace('\x00', '').replace('\ufffd', '')
            return cleaned
        except Exception:
            try:
                return str(value).replace('\x00', '').replace('\ufffd', '')
            except:
                return ""
    
    try:
        result = str(value)
        # Clean the result of any problematic characters
        return result.replace('\x00', '').replace('\ufffd', '')
    except Exception:
        return ""

# Analytics route removed - functionality disabled

# Removed old analytics API endpoint - no longer needed

# Removed old calculate_analytics_data function - no longer needed

# Removed old calculate_protocol_cumulative_data function - no longer needed

# ===============================================
# ROTAS MCP TWITTER - INTEGRAÇÃO AVANÇADA
# ===============================================

# Funcionalidade Twitter simplificada - apenas busca de tweets

@app.route('/twitter/search')
@login_required
def twitter_search():
    """🔒 SECURE: Página para buscar tweets dos protocolos do usuário autenticado"""
    try:
        current_user = get_current_user()
        if not current_user:
            logging.warning("⚠️ SECURITY: Twitter search access attempt without authentication")
            return redirect(url_for('login'))
        
        # 🔒 SECURITY: Use secure function to get user protocols
        all_user_protocols = get_user_protocols_secure(current_user)
        
        # Verificar se o usuário tem Twitter conectado
        has_twitter_connected = bool(current_user.twitter_access_token and current_user.twitter_id)
        
        # Filtrar protocolos que têm Twitter configurado
        protocols_with_twitter = [p for p in all_user_protocols if p.twitter and p.twitter.strip()]
        
        logging.info(f"✅ SECURITY: User {current_user.id} ({current_user.username}) accessing Twitter search - {len(protocols_with_twitter)} protocols with Twitter")
        
        # Buscar tweets recentes de todos os protocolos (apenas dos protocolos do usuário)
        recent_tweets = []
        for protocol in protocols_with_twitter:
            # 🔒 SECURITY: Double-check protocol ownership before accessing tweets
            if protocol.user_id != current_user.id:
                logging.error(f"🚨 CRITICAL SECURITY ISSUE: Protocol {protocol.id} ownership mismatch in twitter_search")
                continue
                
            tweets = twitter_service.get_protocol_tweets(protocol.id, limit=3)
            for tweet in tweets:
                tweet['protocol_name'] = protocol.name
                tweet['protocol_id'] = protocol.id
                recent_tweets.append(tweet)
        
        # Ordenar tweets por data (mais recentes primeiro)
        recent_tweets.sort(key=lambda x: x['created_at'], reverse=True)
        
        return render_template('twitter_search.html', 
                             protocols_with_twitter=protocols_with_twitter,
                             recent_tweets=recent_tweets[:10],  # Mostrar apenas os 10 mais recentes
                             has_twitter_connected=has_twitter_connected,
                             current_user=current_user)
        
    except Exception as e:
        logging.error(f"Erro na página de busca Twitter para usuário {current_user.id if current_user else 'None'}: {e}")
        flash('Erro ao carregar página de busca de tweets.', 'error')
        return redirect(url_for('index'))

@app.route('/twitter/search/<int:protocol_id>', methods=['POST'])
@login_required
def search_protocol_tweets(protocol_id):
    """🔒 SECURE: Buscar tweets de um protocolo específico do usuário autenticado"""
    try:
        current_user = get_current_user()
        if not current_user:
            logging.warning(f"⚠️ SECURITY: Protocol tweet search attempt without authentication - Protocol ID: {protocol_id}")
            return redirect(url_for('login'))
        
        # 🔒 SECURITY: Use secure protocol ownership verification
        protocol = verify_protocol_ownership(protocol_id, current_user)
        
        if not protocol:
            flash('Protocol not found or access denied.', 'error')
            return redirect(url_for('twitter_search'))
        
        if not protocol.twitter:
            flash('This protocol does not have Twitter configured.', 'error')
            return redirect(url_for('twitter_search'))
        
        logging.info(f"✅ SECURITY: User {current_user.id} ({current_user.username}) searching tweets for protocol {protocol_id} ({protocol.name})")
        
        # Usar o serviço simples do Twitter
        result = twitter_service.search_protocol_tweets(protocol_id)
        
        if result.get('success'):
            tweets_count = result.get('tweets_saved', 0)
            if tweets_count > 0:
                flash(f'✅ {tweets_count} new tweets found for {protocol.name}!', 'success')
                logging.info(f"✅ SECURITY: {tweets_count} tweets found for protocol {protocol_id} by user {current_user.id}")
            else:
                flash(f'✅ Search completed for {protocol.name}! No new tweets found.', 'info')
        else:
            error_msg = result.get('error', 'Erro desconhecido')
            flash(f'❌ {error_msg}', 'error')
            logging.warning(f"⚠️ Tweet search error for protocol {protocol_id} by user {current_user.id}: {error_msg}")
        
        return redirect(url_for('twitter_search'))
        
    except Exception as e:
        logging.error(f"Erro ao buscar tweets do protocolo {protocol_id} para usuário {current_user.id if current_user else 'None'}: {e}")
        flash('Error searching for tweets.', 'error')
        return redirect(url_for('twitter_search'))

@app.route('/analytics')
@login_required
def analytics_dashboard():
    """Dashboard de análises e métricas avançadas"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Buscar todos os protocolos do usuário
        protocols = Protocol.query.filter_by(user_id=current_user.id).all()
        
        if not protocols:
            return render_template('analytics.html', 
                                 protocols=[], 
                                 analytics_data={},
                                 current_user=current_user)
        
        # Calcular métricas gerais
        analytics_data = calculate_analytics_data(protocols)
        
        return render_template('analytics.html', 
                             protocols=protocols,
                             analytics_data=analytics_data,
                             current_user=current_user)
        
    except Exception as e:
        logging.error(f"Erro no dashboard de analytics: {e}")
        flash('Erro ao carregar dashboard de analytics.', 'error')
        return redirect(url_for('index'))

def calculate_analytics_data(protocols):
    """Calcular dados de analytics avançados"""
    from collections import defaultdict
    from datetime import datetime, timedelta
    
    # Inicializar dados
    data = {
        'totals': {
            'total_protocols': len(protocols),
            'total_investment': 0,
            'total_airdrop_value': 0,
            'total_airdrops': 0,
            'total_tasks': 0,
            'completed_tasks': 0,
            'roi_percentage': 0
        },
        'by_network': defaultdict(lambda: {
            'protocols': 0,
            'investment': 0,
            'airdrop_value': 0,
            'airdrops': 0,
            'roi': 0
        }),
        'by_status': {
            'pending': 0,
            'received': 0,
            'sold': 0
        },
        'timeline': [],
        'top_protocols': [],
        'recent_airdrops': [],
        'monthly_stats': defaultdict(lambda: {
            'airdrops': 0,
            'value': 0,
            'investment': 0
        })
    }
    
    # Processar cada protocolo
    for protocol in protocols:
        investment = protocol.get_total_investment()
        airdrop_value = protocol.get_total_airdrop_value()
        
        # Totais gerais
        data['totals']['total_investment'] += investment
        data['totals']['total_airdrop_value'] += airdrop_value
        data['totals']['total_airdrops'] += len(protocol.airdrops)
        data['totals']['total_tasks'] += len(protocol.tasks)
        data['totals']['completed_tasks'] += protocol.get_completed_tasks_count()
        
        # Por rede
        network = protocol.network
        data['by_network'][network]['protocols'] += 1
        data['by_network'][network]['investment'] += investment
        data['by_network'][network]['airdrop_value'] += airdrop_value
        data['by_network'][network]['airdrops'] += len(protocol.airdrops)
        
        # Por status de airdrop
        for airdrop in protocol.airdrops:
            status = airdrop.status.value
            # Status já está em inglês após a migração
            if status not in ['pending', 'received', 'sold']:
                status = 'pending'  # fallback para status desconhecidos
            
            data['by_status'][status] += 1
            
            # Timeline de airdrops
            if airdrop.received_date:
                data['timeline'].append({
                    'date': airdrop.received_date,
                    'protocol': protocol.name,
                    'token': airdrop.token_name,
                    'value': airdrop.total_value_usd,
                    'network': protocol.network
                })
            
            # Stats mensais
            if airdrop.received_date:
                month_key = airdrop.received_date.strftime('%Y-%m')
                data['monthly_stats'][month_key]['airdrops'] += 1
                data['monthly_stats'][month_key]['value'] += airdrop.total_value_usd
        
        # Airdrops recentes
        for airdrop in protocol.airdrops:
            if airdrop.received_date:
                data['recent_airdrops'].append({
                    'date': airdrop.received_date,
                    'protocol': protocol.name,
                    'token': airdrop.token_name,
                    'value': airdrop.total_value_usd,
                    'network': protocol.network,
                    'status': airdrop.status.value
                })
    
    # Calcular ROI geral
    if data['totals']['total_investment'] > 0:
        data['totals']['roi_percentage'] = (
            (data['totals']['total_airdrop_value'] / data['totals']['total_investment']) * 100
        )
    
    # Calcular ROI por rede
    for network in data['by_network']:
        if data['by_network'][network]['investment'] > 0:
            data['by_network'][network]['roi'] = (
                (data['by_network'][network]['airdrop_value'] / 
                 data['by_network'][network]['investment']) * 100
            )
    
    # Top protocolos por ROI
    protocol_roi = []
    for protocol in protocols:
        investment = protocol.get_total_investment()
        airdrop_value = protocol.get_total_airdrop_value()
        if investment > 0:
            roi = (airdrop_value / investment) * 100
            protocol_roi.append({
                'protocol': protocol,
                'investment': investment,
                'airdrop_value': airdrop_value,
                'roi': roi,
                'airdrops_count': len(protocol.airdrops)
            })
    
    data['top_protocols'] = sorted(protocol_roi, key=lambda x: x['roi'], reverse=True)[:10]
    
    # Ordenar timeline por data
    data['timeline'] = sorted(data['timeline'], key=lambda x: x['date'], reverse=True)[:20]
    data['recent_airdrops'] = sorted(data['recent_airdrops'], key=lambda x: x['date'], reverse=True)[:10]
    
    # Converter defaultdicts para dicts normais
    data['by_network'] = dict(data['by_network'])
    data['monthly_stats'] = dict(data['monthly_stats'])
    
    return data

@app.route('/calendar')
@login_required
def airdrop_calendar():
    """Airdrop calendar"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Obter parâmetros de data (mês/ano)
        from datetime import datetime, date
        now = datetime.now()
        year = int(request.args.get('year', now.year))
        month = int(request.args.get('month', now.month))
        
        # Buscar todos os protocolos do usuário
        protocols = Protocol.query.filter_by(user_id=current_user.id).all()
        
        # Preparar dados do calendário
        calendar_data = prepare_calendar_data(protocols, year, month)
        
        return render_template('calendar.html', 
                             protocols=protocols,
                             calendar_data=calendar_data,
                             current_year=year,
                             current_month=month,
                             current_user=current_user)
        
    except Exception as e:
        logging.error(f"Error in airdrop calendar: {e}")
        flash('Error loading airdrop calendar.', 'error')
        return redirect(url_for('index'))

@app.route('/calendar/add_airdrop', methods=['POST'])
@login_required
def add_calendar_airdrop():
    """Add airdrop with expected date via calendar"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Obter dados do formulário
        protocol_id = request.form.get('protocol_id')
        token_name = request.form.get('token_name')
        expected_date = request.form.get('expected_date')
        airdrop_type = request.form.get('airdrop_type', 'tge')
        notes = request.form.get('notes', '')
        
        # Validações
        if not protocol_id or not token_name or not expected_date:
            flash('Todos os campos obrigatórios devem ser preenchidos.', 'error')
            return redirect(url_for('airdrop_calendar'))
        
        # Verificar se o protocolo pertence ao usuário
        protocol = Protocol.query.filter_by(id=protocol_id, user_id=current_user.id).first()
        if not protocol:
            flash(translate('protocol_not_found'), 'error')
            return redirect(url_for('airdrop_calendar'))
        
        # Converter data
        from datetime import datetime
        try:
            expected_date = datetime.strptime(expected_date, '%Y-%m-%d').date()
        except ValueError:
            flash('Data inválida.', 'error')
            return redirect(url_for('airdrop_calendar'))
        
        # Verificar se já existe airdrop com mesmo token para este protocolo
        existing_airdrop = Airdrop.query.filter_by(
            protocol_id=protocol.id,
            token_name=token_name
        ).first()
        
        if existing_airdrop:
            flash(f'An airdrop for token {token_name} already exists for protocol {protocol.name}.', 'warning')
            return redirect(url_for('airdrop_calendar'))
        
        # Criar novo airdrop
        airdrop = Airdrop(
            protocol_id=protocol.id,
            token_name=token_name,
            expected_date=expected_date,
            airdrop_type=AirdropType(airdrop_type),
            notes=notes,
            status=AirdropStatus.PENDING
        )
        
        db.session.add(airdrop)
        db.session.commit()
        
        flash(f'Airdrop {token_name} added successfully for {expected_date.strftime("%Y-%m-%d")}!', 'success')
        
        # Redirecionar para o mês do airdrop
        return redirect(url_for('airdrop_calendar', year=expected_date.year, month=expected_date.month))
        
    except Exception as e:
        logging.error(f"Error adding airdrop via calendar: {e}")
        flash(translate('error_adding_airdrop'), 'error')
        
    except Exception as e:
        logging.error(f"Error in add_calendar_airdrop: {e}")
        flash(translate('error_loading_calendar'), 'error')
        return redirect(url_for('index'))

@app.route('/calendar/edit_airdrop/<int:airdrop_id>', methods=['POST'])
@login_required
def edit_calendar_airdrop(airdrop_id):
    """Editar airdrop via calendário"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Buscar o airdrop
        airdrop = Airdrop.query.join(Protocol).filter(
            Airdrop.id == airdrop_id,
            Protocol.user_id == current_user.id
        ).first()
        
        if not airdrop:
            flash('Airdrop não encontrado.', 'error')
            return redirect(url_for('airdrop_calendar'))
        
        # Obter dados do formulário
        token_name = request.form.get('token_name')
        expected_date = request.form.get('expected_date')
        received_date = request.form.get('received_date')
        airdrop_type = request.form.get('airdrop_type')
        tokens_received = request.form.get('tokens_received')
        price_per_token = request.form.get('price_per_token')
        status = request.form.get('status')
        notes = request.form.get('notes', '')
        
        # Validações
        if not token_name:
            flash('Token name is required.', 'error')
            return redirect(url_for('airdrop_calendar'))
        
        # Atualizar campos
        airdrop.token_name = token_name
        airdrop.notes = notes
        
        if airdrop_type:
            airdrop.airdrop_type = AirdropType(airdrop_type)
        
        if expected_date:
            from datetime import datetime
            try:
                airdrop.expected_date = datetime.strptime(expected_date, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        if received_date:
            from datetime import datetime
            try:
                airdrop.received_date = datetime.strptime(received_date, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        if tokens_received:
            try:
                airdrop.tokens_received = float(tokens_received)
                airdrop.amount_received = float(tokens_received)
            except ValueError:
                pass
        
        if price_per_token:
            try:
                airdrop.price_per_token = float(price_per_token)
            except ValueError:
                pass
        
        if status:
            airdrop.status = AirdropStatus(status)
        
        db.session.commit()
        
        flash(f'Airdrop {token_name} updated successfully!', 'success')
        
        # Redirecionar para o mês apropriado
        redirect_date = airdrop.received_date or airdrop.expected_date
        if redirect_date:
            return redirect(url_for('airdrop_calendar', year=redirect_date.year, month=redirect_date.month))
        else:
            return redirect(url_for('airdrop_calendar'))
        
    except Exception as e:
        logging.error(f"Erro ao editar airdrop no calendário: {e}")
        flash('Erro ao editar airdrop. Tente novamente.', 'error')
        db.session.rollback()
        return redirect(url_for('airdrop_calendar'))

@app.route('/calendar/delete_airdrop/<int:airdrop_id>', methods=['POST'])
@login_required
def delete_calendar_airdrop(airdrop_id):
    """Deletar airdrop via calendário"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Buscar o airdrop
        airdrop = Airdrop.query.join(Protocol).filter(
            Airdrop.id == airdrop_id,
            Protocol.user_id == current_user.id
        ).first()
        
        if not airdrop:
            flash('Airdrop não encontrado.', 'error')
            return redirect(url_for('airdrop_calendar'))
        
        # Guardar informações antes de deletar para redirect e flash
        token_name = airdrop.token_name
        protocol_name = airdrop.protocol.name
        redirect_date = airdrop.received_date or airdrop.expected_date
        
        # Deletar o airdrop
        db.session.delete(airdrop)
        db.session.commit()
        
        flash(f'Airdrop {token_name} from protocol {protocol_name} was deleted successfully!', 'success')
        
        # Redirecionar para o mês apropriado
        if redirect_date:
            return redirect(url_for('airdrop_calendar', year=redirect_date.year, month=redirect_date.month))
        else:
            return redirect(url_for('airdrop_calendar'))
        
    except Exception as e:
        logging.error(f"Erro ao deletar airdrop no calendário: {e}")
        flash('Erro ao deletar airdrop. Tente novamente.', 'error')
        db.session.rollback()
        return redirect(url_for('airdrop_calendar'))

def prepare_calendar_data(protocols, year, month):
    """Prepare data for airdrop calendar"""
    import calendar
    from datetime import datetime, date, timedelta
    from collections import defaultdict
    
    # Criar estrutura do calendário
    cal = calendar.monthcalendar(year, month)
    
    # Buscar todos os airdrops do mês
    airdrops_by_date = defaultdict(list)
    
    for protocol in protocols:
        for airdrop in protocol.airdrops:
            # Verificar datas de recebimento
            if airdrop.received_date and airdrop.received_date.year == year and airdrop.received_date.month == month:
                day = airdrop.received_date.day
                airdrops_by_date[day].append({
                    'id': airdrop.id,
                    'protocol': protocol.name,
                    'token': airdrop.token_name,
                    'amount': airdrop.amount_received,
                    'value': airdrop.total_value_usd,
                    'status': airdrop.status.value,
                    'date': airdrop.received_date,
                    'received_date': airdrop.received_date.strftime('%Y-%m-%d') if airdrop.received_date else '',
                    'expected_date': airdrop.expected_date.strftime('%Y-%m-%d') if airdrop.expected_date else '',
                    'airdrop_type': airdrop.airdrop_type.value if airdrop.airdrop_type else 'tge',
                    'tokens_received': airdrop.tokens_received or '',
                    'price_per_token': airdrop.price_per_token or '',
                    'notes': airdrop.notes or '',
                    'network': protocol.network,
                    'type': 'received'
                })
            
            # Verificar datas de expectativa (airdrops futuros)
            if airdrop.expected_date and airdrop.expected_date.year == year and airdrop.expected_date.month == month:
                day = airdrop.expected_date.day
                airdrops_by_date[day].append({
                    'id': airdrop.id,
                    'protocol': protocol.name,
                    'token': airdrop.token_name,
                    'amount': airdrop.amount_received or 0,
                    'value': airdrop.total_value_usd or 0,
                    'status': airdrop.status.value,
                    'date': airdrop.expected_date,
                    'received_date': airdrop.received_date.strftime('%Y-%m-%d') if airdrop.received_date else '',
                    'expected_date': airdrop.expected_date.strftime('%Y-%m-%d') if airdrop.expected_date else '',
                    'airdrop_type': airdrop.airdrop_type.value if airdrop.airdrop_type else 'tge',
                    'tokens_received': airdrop.tokens_received or '',
                    'price_per_token': airdrop.price_per_token or '',
                    'notes': airdrop.notes or '',
                    'network': protocol.network,
                    'type': 'expected'
                })
    
    # Estatísticas do mês
    total_received = sum(
        sum(a['value'] for a in airdrops if a['type'] == 'received')
        for airdrops in airdrops_by_date.values()
    )
    
    total_airdrops = sum(
        len([a for a in airdrops if a['type'] == 'received'])
        for airdrops in airdrops_by_date.values()
    )
    
    expected_airdrops = sum(
        len([a for a in airdrops if a['type'] == 'expected'])
        for airdrops in airdrops_by_date.values()
    )
    
    # Navegação de meses
    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1
    
    month_names = [
        'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho',
        'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'
    ]
    
    return {
        'calendar': cal,
        'airdrops_by_date': dict(airdrops_by_date),
        'stats': {
            'total_received': total_received,
            'total_airdrops': total_airdrops,
            'expected_airdrops': expected_airdrops
        },
        'navigation': {
            'prev_month': prev_month,
            'prev_year': prev_year,
            'next_month': next_month,
            'next_year': next_year,
            'current_month_name': month_names[month - 1]
        }
    }

@app.route('/create_demo_data')
@login_required
def create_demo_data():
    """Criar dados de demonstração para testar o dashboard"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        # Limpar dados existentes do usuário (apenas demo)
        Protocol.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        
        # Criar protocolos de exemplo
        protocols_data = [
            {
                'name': 'LayerZero',
                'network': 'Ethereum',
                'website': 'https://layerzero.network',
                'twitter': 'LayerZero_Labs',
                'start_date': date(2024, 1, 15),
                'daily_missions': True
            },
            {
                'name': 'Starknet',
                'network': 'Starknet',
                'website': 'https://starknet.io',
                'twitter': 'Starknet',
                'start_date': date(2024, 2, 1),
                'daily_missions': False
            },
            {
                'name': 'zkSync',
                'network': 'zkSync Era',
                'website': 'https://zksync.io',
                'twitter': 'zksync',
                'start_date': date(2024, 1, 10),
                'daily_missions': True
            },
            {
                'name': 'Arbitrum Orbit',
                'network': 'Arbitrum',
                'website': 'https://arbitrum.io',
                'twitter': 'arbitrum',
                'start_date': date(2024, 3, 1),
                'daily_missions': False
            },
            {
                'name': 'Optimism Quests',
                'network': 'Optimism',
                'website': 'https://optimism.io',
                'twitter': 'Optimism',
                'start_date': date(2024, 2, 15),
                'daily_missions': True
            }
        ]
        
        created_protocols = []
        for proto_data in protocols_data:
            protocol = Protocol(
                user_id=current_user.id,
                **proto_data
            )
            db.session.add(protocol)
            db.session.flush()  # Para obter o ID
            created_protocols.append(protocol)
        
        # Criar investimentos de exemplo
        investments_data = [
            # LayerZero
            {'protocol_id': created_protocols[0].id, 'amount': 500.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 1, 15), 'description': 'Bridge inicial ETH->AVAX'},
            {'protocol_id': created_protocols[0].id, 'amount': 300.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 2, 10), 'description': 'Mais transações cross-chain'},
            
            # Starknet
            {'protocol_id': created_protocols[1].id, 'amount': 200.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 2, 1), 'description': 'Deploy contracts'},
            {'protocol_id': created_protocols[1].id, 'amount': 150.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 3, 15), 'description': 'DeFi interactions'},
            
            # zkSync
            {'protocol_id': created_protocols[2].id, 'amount': 400.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 1, 10), 'description': 'Bridges e swaps'},
            {'protocol_id': created_protocols[2].id, 'amount': 250.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 2, 20), 'description': 'NFT mints'},
            
            # Arbitrum
            {'protocol_id': created_protocols[3].id, 'amount': 300.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 3, 1), 'description': 'DeFi farming'},
            
            # Optimism
            {'protocol_id': created_protocols[4].id, 'amount': 180.0, 'type': InvestmentType.ENTRY, 'date': date(2024, 2, 15), 'description': 'Quests completion'}
        ]
        
        for inv_data in investments_data:
            investment = Investment(**inv_data)
            db.session.add(investment)
        
        # Criar airdrops de exemplo
        airdrops_data = [
            # LayerZero - Airdrop fictício
            {'protocol_id': created_protocols[0].id, 'token_name': 'ZRO', 'tokens_received': 150.0, 'price_per_token': 3.20, 'status': AirdropStatus.RECEIVED, 'received_date': date(2024, 6, 1), 'notes': 'Airdrop principal LayerZero'},
            
            # Starknet - STRK real
            {'protocol_id': created_protocols[1].id, 'token_name': 'STRK', 'tokens_received': 1800.0, 'price_per_token': 2.15, 'status': AirdropStatus.SOLD, 'received_date': date(2024, 2, 20), 'sold_date': date(2024, 3, 1), 'notes': 'Starknet airdrop vendido'},
            
            # zkSync - ZK real
            {'protocol_id': created_protocols[2].id, 'token_name': 'ZK', 'tokens_received': 680.0, 'price_per_token': 0.27, 'status': AirdropStatus.RECEIVED, 'received_date': date(2024, 6, 17), 'notes': 'zkSync airdrop mantido'},
            
            # Arbitrum - ARB (exemplo adicional)
            {'protocol_id': created_protocols[3].id, 'token_name': 'ARB', 'tokens_received': 900.0, 'price_per_token': 1.45, 'status': AirdropStatus.SOLD, 'received_date': date(2024, 4, 10), 'sold_date': date(2024, 4, 15), 'notes': 'Arbitrum farming airdrop'},
            
            # Optimism - OP
            {'protocol_id': created_protocols[4].id, 'token_name': 'OP', 'tokens_received': 420.0, 'price_per_token': 2.80, 'status': AirdropStatus.RECEIVED, 'received_date': date(2024, 5, 5), 'notes': 'Optimism quests reward'},
            
            # Pendentes
            {'protocol_id': created_protocols[0].id, 'token_name': 'ZRO-2', 'tokens_received': None, 'price_per_token': None, 'status': AirdropStatus.PENDING, 'notes': 'Segunda temporada LayerZero'},
            {'protocol_id': created_protocols[1].id, 'token_name': 'STRK-2', 'tokens_received': None, 'price_per_token': None, 'status': AirdropStatus.PENDING, 'notes': 'Próximo airdrop Starknet'},
        ]
        
        for airdrop_data in airdrops_data:
            airdrop = Airdrop(**airdrop_data)
            db.session.add(airdrop)
        
        # Criar algumas tasks de exemplo
        tasks_data = [
            {'protocol_id': created_protocols[0].id, 'title': 'Bridge ETH para Polygon', 'description': 'Usar LayerZero para bridge cross-chain', 'status': TaskStatus.COMPLETED},
            {'protocol_id': created_protocols[0].id, 'title': 'Interact with dApps', 'description': 'Usar 5 dApps diferentes via LayerZero', 'status': TaskStatus.PENDING},
            
            {'protocol_id': created_protocols[1].id, 'title': 'Deploy smart contract', 'description': 'Deploy contrato na Starknet mainnet', 'status': TaskStatus.COMPLETED},
            {'protocol_id': created_protocols[1].id, 'title': 'Use DEX native', 'description': 'Fazer swaps na AVNU ou outras DEXs', 'status': TaskStatus.COMPLETED},
            
            {'protocol_id': created_protocols[2].id, 'title': 'zkSync Era bridge', 'description': 'Bridge fundos para Era mainnet', 'status': TaskStatus.COMPLETED},
            {'protocol_id': created_protocols[2].id, 'title': 'Mint NFTs', 'description': 'Mint pelo menos 3 NFTs diferentes', 'status': TaskStatus.PENDING},
        ]
        
        for task_data in tasks_data:
            task = Task(**task_data)
            db.session.add(task)
        
        db.session.commit()
        
        flash('✅ Demo data created successfully! Now you can explore the Analytics Dashboard.', 'success')
        return redirect(url_for('analytics_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Erro ao criar dados demo: {e}")
        flash('Erro ao criar dados de demonstração.', 'error')
        return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('base.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('base.html'), 500

@app.route('/set_language/<language>')
def set_language_route(language):
    """Rota para alterar o idioma da aplicação"""
    if set_language(language):
        flash(translate('language_changed'), 'success')
    else:
        flash('Invalid language selected.', 'error')
    
    # Redirecionar para a página anterior ou para home
    return redirect(request.referrer or url_for('index'))

def log_security_event(event_type, user_id, message, extra_data=None):
    """
    🔒 SECURITY LOGGING: Log critical security events for audit trail
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] SECURITY_{event_type.upper()}: User {user_id} - {message}"
    
    if extra_data:
        log_entry += f" | Data: {extra_data}"
    
    # Log to different levels based on event type
    if event_type in ['CRITICAL', 'UNAUTHORIZED_ACCESS', 'DATA_BREACH']:
        logging.error(log_entry)
    elif event_type in ['WARNING', 'SUSPICIOUS']:
        logging.warning(log_entry)
    else:
        logging.info(log_entry)

if __name__ == '__main__':
    print("🚀 Iniciando aplicação Flask com integração MCP Twitter...")
    print("📍 Acesse: http://localhost:8000")
    print("🐦 Dashboard MCP: http://localhost:8000/mcp/twitter/dashboard")
    # Debug desabilitado para evitar reinicializações constantes
    app.run(debug=False, host='0.0.0.0', port=8000)
