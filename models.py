from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime
from enum import Enum
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class InvestmentType(Enum):
    ENTRY = "entry"
    WITHDRAWAL = "withdrawal"

class TaskStatus(Enum):
    PENDING = "pending"
    COMPLETED = "completed"

class ProtocolStatus(Enum):
    ACTIVE = "active"
    ENDED = "ended"

class AirdropStatus(Enum):
    PENDING = "pending"
    RECEIVED = "received"
    SOLD = "sold"

class AirdropType(Enum):
    TGE = "tge"
    CHECKER = "checker"
    CLAIM = "claim"

class PaymentStatus(Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"

class SubscriptionPlan(Enum):
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    BIANNUAL = "biannual"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # Pode ser None para login social
    password_hash = db.Column(db.String(200), nullable=True)  # Pode ser None para login social
    
    # Twitter OAuth fields
    twitter_id = db.Column(db.String(50), unique=True, nullable=True)
    twitter_username = db.Column(db.String(50), nullable=True)
    twitter_display_name = db.Column(db.String(100), nullable=True)
    twitter_avatar_url = db.Column(db.String(200), nullable=True)
    
    # Twitter API tokens (para MCP individual)
    twitter_access_token = db.Column(db.Text, nullable=True)
    twitter_access_token_secret = db.Column(db.Text, nullable=True)
    twitter_consumer_key = db.Column(db.Text, nullable=True)
    twitter_consumer_secret = db.Column(db.Text, nullable=True)
    
    # Account type
    account_type = db.Column(db.String(20), default='email')  # 'email' or 'twitter'
    
    # Premium subscription fields
    is_premium = db.Column(db.Boolean, default=False)
    premium_expires_at = db.Column(db.DateTime, nullable=True)  # Para assinaturas com prazo
    payment_wallet_address = db.Column(db.String(100), nullable=True)  # Endereço da carteira usada no pagamento
    payment_transaction_hash = db.Column(db.String(100), nullable=True)  # Hash da transação de pagamento
    payment_amount_usd = db.Column(db.Float, nullable=True)  # Valor pago em USD
    payment_verified_at = db.Column(db.DateTime, nullable=True)  # Quando o pagamento foi verificado
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    protocols = db.relationship('Protocol', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        """Check password"""
        if not self.password_hash:
            return False
        
        # Verificar se é um hash bcrypt (começa com $2b$)
        if self.password_hash.startswith('$2b$'):
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        else:
            # Hash do Werkzeug (compatibilidade com contas antigas)
            return check_password_hash(self.password_hash, password)
    
    @classmethod
    def create_from_twitter(cls, twitter_data):
        """Create user from Twitter OAuth data"""
        username = twitter_data.get('username')
        # Garantir que o username seja único
        counter = 1
        original_username = username
        while cls.query.filter_by(username=username).first():
            username = f"{original_username}_{counter}"
            counter += 1
        
        user = cls(
            username=username,
            twitter_id=str(twitter_data.get('id')),
            twitter_username=twitter_data.get('username'),
            twitter_display_name=twitter_data.get('name'),
            twitter_avatar_url=twitter_data.get('profile_image_url'),
            account_type='twitter'
        )
        return user
    
    def update_twitter_data(self, twitter_data):
        """Update user with fresh Twitter data"""
        self.twitter_username = twitter_data.get('username')
        self.twitter_display_name = twitter_data.get('name')
        self.twitter_avatar_url = twitter_data.get('profile_image_url')
    
    @property
    def display_name(self):
        """Get display name for user"""
        if self.account_type == 'twitter' and self.twitter_display_name:
            return self.twitter_display_name
        return self.username
    
    @property
    def avatar_url(self):
        """Get avatar URL for user"""
        if self.account_type == 'twitter' and self.twitter_avatar_url:
            return self.twitter_avatar_url
        return None
    
    def get_protocol_limit(self):
        """Get protocol limit based on subscription status"""
        return None if self.is_premium_active() else 3  # None = unlimited, 3 = free limit
    
    def can_add_protocol(self):
        """Check if user can add more protocols"""
        if self.is_premium_active():
            return True
        return len(self.protocols) < 3
    
    def get_protocols_count(self):
        """Get current protocol count"""
        return len(self.protocols)
    
    def is_premium_active(self):
        """Check if premium subscription is currently active"""
        if not self.is_premium:
            return False
        if self.premium_expires_at is None:
            return True  # Vitalício (para compatibilidade com pagamentos antigos)
        return datetime.utcnow() < self.premium_expires_at
    
    def upgrade_to_premium(self, wallet_address, transaction_hash, amount_usd, plan_months=1):
        """Upgrade user to premium after payment verification"""
        from dateutil.relativedelta import relativedelta
        
        self.is_premium = True
        self.payment_wallet_address = wallet_address
        self.payment_transaction_hash = transaction_hash
        self.payment_amount_usd = amount_usd
        self.payment_verified_at = datetime.utcnow()
        
        # Calcular data de expiração baseada no plano
        if self.premium_expires_at and self.premium_expires_at > datetime.utcnow():
            # Se já tem assinatura ativa, estender a partir da data atual de expiração
            self.premium_expires_at = self.premium_expires_at + relativedelta(months=plan_months)
        else:
            # Nova assinatura ou assinatura expirada
            self.premium_expires_at = datetime.utcnow() + relativedelta(months=plan_months)
    
    def get_subscription_status(self):
        """Get human-readable subscription status"""
        if self.is_premium_active():
            if self.premium_expires_at:
                days_left = (self.premium_expires_at - datetime.utcnow()).days
                if days_left <= 7:
                    return f"Premium (expira em {days_left} dias)"
                return f"Premium (expira em {self.premium_expires_at.strftime('%d/%m/%Y')})"
            return "Premium Vitalício"
        elif self.is_premium and self.premium_expires_at:
            return "Premium Expirado"
        return "Gratuito"
    
    def days_until_expiration(self):
        """Get days until premium expires"""
        if not self.premium_expires_at:
            return None
        if not self.is_premium_active():
            return 0
        return (self.premium_expires_at - datetime.utcnow()).days
    
    def __repr__(self):
        return f'<User {self.username}>'

class Protocol(db.Model):
    __tablename__ = 'protocols'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    network = db.Column(db.String(50), nullable=False)
    website = db.Column(db.String(200))
    twitter = db.Column(db.String(100))
    start_date = db.Column(db.Date)
    daily_missions = db.Column(db.Boolean, default=False)
    status = db.Column(db.Enum(ProtocolStatus), default=ProtocolStatus.ACTIVE)
    
    # Visual customization fields
    logo_url = db.Column(db.String(300))  # URL da logo do protocolo
    background_image_url = db.Column(db.String(300))  # URL da imagem de fundo
    primary_color = db.Column(db.String(7))  # Cor primária em hex (#RRGGBB)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint per user
    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='unique_user_protocol'),)
    
    # Relationships
    investments = db.relationship('Investment', backref='protocol', lazy=True, cascade='all, delete-orphan')
    tasks = db.relationship('Task', backref='protocol', lazy=True, cascade='all, delete-orphan')
    airdrops = db.relationship('Airdrop', backref='protocol', lazy=True, cascade='all, delete-orphan')
    tweets = db.relationship('Tweet', backref='protocol', lazy=True, cascade='all, delete-orphan')
    
    def get_total_investment(self):
        """Calculate total current investment (entries - withdrawals)"""
        total = 0
        for investment in self.investments:
            if investment.type == InvestmentType.ENTRY:
                total += investment.amount
            else:  # WITHDRAWAL
                total -= investment.amount
        return max(0, total)  # Don't allow negative values
    
    def get_pending_tasks_count(self):
        """Get count of pending tasks"""
        return len([t for t in self.tasks if t.status == TaskStatus.PENDING])
    
    def get_completed_tasks_count(self):
        """Get count of completed tasks"""
        return len([t for t in self.tasks if t.status == TaskStatus.COMPLETED])
    
    def get_total_airdrop_value(self):
        """Calculate total airdrop value in USD"""
        total = 0
        for airdrop in self.airdrops:
            if airdrop.tokens_received and airdrop.price_per_token:
                total += airdrop.tokens_received * airdrop.price_per_token
        return total
    
    def get_favicon_url(self):
        """Get favicon URL from website with multiple fallback strategies"""
        if self.website:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(self.website)
                domain = f"{parsed.scheme}://{parsed.netloc}"
                
                # Lista de possíveis caminhos para favicon
                favicon_paths = [
                    f"{domain}/favicon.ico",
                    f"{domain}/favicon.png", 
                    f"{domain}/apple-touch-icon.png",
                    f"{domain}/logo.png",
                    f"{domain}/assets/favicon.ico",
                    f"{domain}/images/favicon.ico",
                    f"{domain}/static/favicon.ico",
                    # Serviços externos para obter favicon
                    f"https://www.google.com/s2/favicons?domain={parsed.netloc}&sz=64",
                    f"https://icons.duckduckgo.com/ip3/{parsed.netloc}.ico",
                    f"https://favicone.com/{parsed.netloc}?s=64"
                ]
                
                # Retorna o primeiro caminho (tentaremos todos no frontend)
                return favicon_paths[0]
            except:
                pass
        return None
    
    def get_display_logo(self):
        """Get best available logo URL"""
        if self.logo_url:
            return self.logo_url
        # Fallback para favicon
        favicon = self.get_favicon_url()
        if favicon:
            return favicon
        return None
    
    def get_google_favicon(self):
        """Get favicon from Google service"""
        if self.website:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(self.website)
                return f"https://www.google.com/s2/favicons?domain={parsed.netloc}&sz=64"
            except:
                pass
        return None
    
    def get_letter_avatar(self):
        """Get SVG letter avatar as fallback"""
        letter = self.name[0].upper() if self.name else '?'
        color = self.get_network_color()
        # SVG inline encoded
        svg = f"""data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='4' fill='{color}'/%3E%3Ctext x='12' y='16' font-family='Arial' font-size='12' fill='white' text-anchor='middle'%3E{letter}%3C/text%3E%3C/svg%3E"""
        return svg
    
    def get_network_color(self):
        """Get color based on network"""
        network_colors = {
            'ethereum': '#627eea',
            'polygon': '#8247e5',
            'arbitrum': '#28a0f0',
            'optimism': '#ff0420',
            'avalanche': '#e84142',
            'bsc': '#f3ba2f',
            'fantom': '#1969ff',
            'solana': '#00d18c',
            'cardano': '#0033ad',
            'polkadot': '#e6007a',
            'cosmos': '#2e3148',
            'near': '#00c08b',
            'sui': '#4da2ff',
            'aptos': '#00d4aa',
            'linea': '#121212',
            'base': '#0052ff',
            'zksync': '#8c8dfc',
            'scroll': '#ffeeda',
            'starknet': '#ec796b'
        }
        return network_colors.get(self.network.lower(), '#6c757d')
    
    def get_network_css_class(self):
        """Get CSS class for network badge"""
        network_classes = {
            'ethereum': 'network-ethereum',
            'polygon': 'network-polygon', 
            'arbitrum': 'network-arbitrum',
            'optimism': 'network-optimism',
            'avalanche': 'network-avalanche',
            'bsc': 'network-bsc',
            'fantom': 'network-fantom',
            'solana': 'network-solana',
            'cardano': 'network-cardano',
            'polkadot': 'network-polkadot',
            'cosmos': 'network-cosmos',
            'near': 'network-near',
            'sui': 'network-sui',
            'aptos': 'network-aptos',
            'linea': 'network-linea',
            'base': 'network-base',
            'zksync': 'network-zksync',
            'scroll': 'network-scroll',
            'starknet': 'network-starknet'
        }
        return network_classes.get(self.network.lower(), 'network-other')
    
    def get_network_icon(self):
        """Get icon for network"""
        network_icons = {
            'ethereum': 'fab fa-ethereum',
            'bitcoin': 'fab fa-bitcoin',
            'solana': 'fas fa-sun',
            'polygon': 'fas fa-layer-group',
            'arbitrum': 'fas fa-bolt',
            'optimism': 'fas fa-rocket',
            'avalanche': 'fas fa-mountain',
            'bsc': 'fas fa-link',
            'fantom': 'fas fa-ghost',
            'cardano': 'fas fa-heart',
            'polkadot': 'fas fa-circle-notch',
            'cosmos': 'fas fa-atom',
            'near': 'fas fa-location-arrow',
            'sui': 'fas fa-water',
            'aptos': 'fas fa-leaf',
            'linea': 'fas fa-minus',
            'base': 'fas fa-cube',
            'zksync': 'fas fa-shield-alt',
            'scroll': 'fas fa-scroll',
            'starknet': 'fas fa-star'
        }
        return network_icons.get(self.network.lower(), 'fas fa-network-wired')
    
    def get_card_style(self):
        """Get CSS style for card background"""
        if self.background_image_url:
            return f"background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.8)), url('{self.background_image_url}'); background-size: cover; background-position: center;"
        
        color = self.primary_color or self.get_network_color()
        # Criar gradiente baseado na cor
        return f"background: linear-gradient(135deg, {color}33, {color}11);"

class Investment(db.Model):
    __tablename__ = 'investments'
    
    id = db.Column(db.Integer, primary_key=True)
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocols.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.Enum(InvestmentType), nullable=False)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocols.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.Enum(TaskStatus), default=TaskStatus.PENDING)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def mark_completed(self):
        """Mark task as completed"""
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.utcnow()
    
    def mark_pending(self):
        """Mark task as pending"""
        self.status = TaskStatus.PENDING
        self.completed_at = None

class Airdrop(db.Model):
    __tablename__ = 'airdrops'
    
    id = db.Column(db.Integer, primary_key=True)
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocols.id'), nullable=False)
    token_name = db.Column(db.String(100), nullable=False)
    tokens_received = db.Column(db.Float)
    amount_received = db.Column(db.Float)  # Quantidade total recebida (para compatibilidade)
    price_per_token = db.Column(db.Float)  # Price in USD
    status = db.Column(db.Enum(AirdropStatus), default=AirdropStatus.PENDING)
    received_date = db.Column(db.Date)
    expected_date = db.Column(db.Date)  # Data esperada para o airdrop
    airdrop_type = db.Column(db.Enum(AirdropType), default=AirdropType.TGE)  # Tipo do lançamento
    sold_date = db.Column(db.Date)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def total_value_usd(self):
        """Calculate total airdrop value in USD"""
        if self.tokens_received and self.price_per_token:
            return self.tokens_received * self.price_per_token
        return 0
    
    def mark_received(self, tokens_received, received_date=None):
        """Mark airdrop as received"""
        self.status = AirdropStatus.RECEIVED
        self.tokens_received = tokens_received
        self.amount_received = tokens_received  # Para compatibilidade
        self.received_date = received_date or datetime.utcnow().date()
    
    def mark_sold(self, price_per_token, sold_date=None):
        """Mark airdrop as sold"""
        self.status = AirdropStatus.SOLD
        self.price_per_token = price_per_token
        self.sold_date = sold_date or datetime.utcnow().date()


class Tweet(db.Model):
    __tablename__ = 'tweets'
    
    id = db.Column(db.Integer, primary_key=True)
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocols.id'), nullable=False)
    tweet_id = db.Column(db.String(50), nullable=False)  # ID único do Twitter
    text = db.Column(db.Text, nullable=False)
    author_username = db.Column(db.String(50), nullable=False)
    created_at_twitter = db.Column(db.DateTime, nullable=False)  # Data de criação no Twitter
    tweet_url = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Data de inserção no nosso banco
    
    # Constraint para evitar tweets duplicados
    __table_args__ = (db.UniqueConstraint('protocol_id', 'tweet_id', name='unique_protocol_tweet'),)
    
    @property
    def short_text(self):
        """Return truncated text for display"""
        if len(self.text) > 100:
            return self.text[:100] + "..."
        return self.text


class Payment(db.Model):
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Payment details
    amount_usd = db.Column(db.Float, nullable=False)  # Valor em USD ($4.99)
    wallet_address = db.Column(db.String(100), nullable=False)  # Endereço da carteira do usuário
    payment_address = db.Column(db.String(100), nullable=False)  # Nosso endereço para receber pagamento
    transaction_hash = db.Column(db.String(100), nullable=True)  # Hash da transação (preenchido pelo usuário)
    
    # Crypto details
    token_symbol = db.Column(db.String(10), nullable=False)  # USDC ou USDT
    network = db.Column(db.String(20), default='solana')  # Solana por padrão
    expected_amount = db.Column(db.Float, nullable=False)  # Quantidade esperada em USDC/USDT
    
    # Subscription details
    subscription_plan = db.Column(db.Enum(SubscriptionPlan), nullable=False)  # Plano escolhido
    plan_months = db.Column(db.Integer, nullable=False)  # Duração em meses
    
    # Status and verification
    status = db.Column(db.Enum(PaymentStatus), default=PaymentStatus.PENDING)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified_at = db.Column(db.DateTime, nullable=True)
    verification_notes = db.Column(db.Text, nullable=True)
    
    # Relationship
    user = db.relationship('User', backref='payments')
    
    def mark_verified(self, notes=None):
        """Mark payment as verified and upgrade user"""
        self.status = PaymentStatus.VERIFIED
        self.verified_at = datetime.utcnow()
        if notes:
            self.verification_notes = notes
        
        # Upgrade user to premium with subscription duration
        self.user.upgrade_to_premium(
            wallet_address=self.wallet_address,
            transaction_hash=self.transaction_hash,
            amount_usd=self.amount_usd,
            plan_months=self.plan_months
        )
    
    def mark_failed(self, notes=None):
        """Mark payment as failed"""
        self.status = PaymentStatus.FAILED
        if notes:
            self.verification_notes = notes
    
    @property
    def status_display(self):
        """Get human-readable status"""
        status_map = {
            PaymentStatus.PENDING: "Aguardando Verificação",
            PaymentStatus.VERIFIED: "Verificado",
            PaymentStatus.FAILED: "Falhado"
        }
        return status_map.get(self.status, "Desconhecido")
    
    def __repr__(self):
        return f'<Payment {self.id}: ${self.amount_usd} - {self.status.value}>'

