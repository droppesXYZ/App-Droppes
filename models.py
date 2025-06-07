from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime
from enum import Enum
from werkzeug.security import generate_password_hash, check_password_hash

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class InvestmentType(Enum):
    ENTRY = "entrada"
    WITHDRAWAL = "retirada"

class TaskStatus(Enum):
    PENDING = "pendente"
    COMPLETED = "concluida"

class ProtocolStatus(Enum):
    ACTIVE = "ativo"
    ENDED = "encerrado"

class AirdropStatus(Enum):
    PENDING = "pendente"
    RECEIVED = "recebido"
    SOLD = "vendido"

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
    
    # Account type
    account_type = db.Column(db.String(20), default='email')  # 'email' or 'twitter'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    protocols = db.relationship('Protocol', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password"""
        if not self.password_hash:
            return False
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint per user
    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='unique_user_protocol'),)
    
    # Relationships
    investments = db.relationship('Investment', backref='protocol', lazy=True, cascade='all, delete-orphan')
    tasks = db.relationship('Task', backref='protocol', lazy=True, cascade='all, delete-orphan')
    airdrops = db.relationship('Airdrop', backref='protocol', lazy=True, cascade='all, delete-orphan')
    
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
    price_per_token = db.Column(db.Float)  # Price in USD
    status = db.Column(db.Enum(AirdropStatus), default=AirdropStatus.PENDING)
    received_date = db.Column(db.Date)
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
        self.received_date = received_date or datetime.utcnow().date()
    
    def mark_sold(self, price_per_token, sold_date=None):
        """Mark airdrop as sold"""
        self.status = AirdropStatus.SOLD
        self.price_per_token = price_per_token
        self.sold_date = sold_date or datetime.utcnow().date()

