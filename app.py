import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from datetime import datetime, date
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from authlib.integrations.flask_client import OAuth
from models import db, User, Protocol, Investment, Task, Airdrop, Tweet, InvestmentType, TaskStatus, ProtocolStatus, AirdropStatus
from twitter_service import TwitterService

# Carregar variáveis de ambiente do arquivo .env se existir
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv não está instalado, usar variáveis de ambiente do sistema
    pass

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key_for_development")

# Configure session
from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=7)  # Remember me for 7 days

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
    """Setup database connection with fallback to SQLite"""
    database_url = os.environ.get("DATABASE_URL")
    
    if not database_url:
        # Default to Supabase connection - @ precisa ser codificado como %40
        # Use pooler connection (IPv4 compatible) - session pooler from Supabase dashboard
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
            sock.settimeout(5)
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
                    "connect_timeout": 10,
                    "application_name": "crypto_airdrop_manager"
                }
            }
            
        except Exception as e:
            print(f"❌ Erro de conectividade: {str(e)}")
            print("🔄 Mudando para SQLite local...")
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

# Create tables
with app.app_context():
    try:
        db.create_all()
        if db_url.startswith('postgresql://'):
            print("✅ Conectado ao Supabase com sucesso!")
        else:
            print("✅ Conectado ao SQLite local com sucesso!")
    except Exception as e:
        print(f"❌ Erro criando tabelas: {str(e)}")
        raise

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
    return 'user_id' in session

def get_current_user():
    """Get current logged in user"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

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
    
    # If user is already logged in, redirect to index
    if is_authenticated():
        return redirect(url_for('index'))
    
    return render_template('login.html')

def handle_login():
    """Handle login form submission"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    remember = 'remember' in request.form
    
    if not username or not password:
        flash('Please enter both username and password.', 'error')
        return render_template('login.html')
    
    # Check credentials in database
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = remember
        
        flash(f'Welcome back, {user.username}!', 'success')
        
        # Redirect to next page if specified, otherwise go to index
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('index'))
    else:
        flash('Invalid username or password.', 'error')
        return render_template('login.html')

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
    """Test Twitter OAuth configuration"""
    client_id = os.environ.get("TWITTER_CLIENT_ID")
    client_secret = os.environ.get("TWITTER_CLIENT_SECRET")
    
    if not client_id or not client_secret:
        return jsonify({
            "status": "error",
            "message": "Twitter OAuth credentials not configured",
            "client_id": "Not set",
            "client_secret": "Not set"
        })
    
    return jsonify({
        "status": "success",
        "message": "Twitter OAuth credentials configured",
        "client_id": f"{client_id[:10]}..." if len(client_id) > 10 else client_id,
        "client_secret": f"{client_secret[:10]}..." if len(client_secret) > 10 else "Set",
        "callback_url": url_for('twitter_callback', _external=True)
    })

@app.route('/auth/twitter')
def twitter_login():
    """Initiate Twitter OAuth login"""
    # Verificar se as credenciais estão configuradas
    if not os.environ.get("TWITTER_CLIENT_ID") or not os.environ.get("TWITTER_CLIENT_SECRET"):
        flash('Twitter OAuth não está configurado. Verifique as variáveis de ambiente TWITTER_CLIENT_ID e TWITTER_CLIENT_SECRET.', 'error')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('twitter_callback', _external=True)
    return twitter.authorize_redirect(redirect_uri)

@app.route('/auth/twitter/callback')
def twitter_callback():
    """Handle Twitter OAuth callback"""
    try:
        # Get the authorization token
        token = twitter.authorize_access_token()
        
        # Get user info from Twitter
        resp = twitter.get('https://api.twitter.com/2/users/me?user.fields=id,username,name,profile_image_url', 
                          token=token)
        user_info = resp.json()
        
        logging.info(f"Twitter API response: {user_info}")
        
        if 'data' not in user_info:
            error_msg = user_info.get('errors', [{}])[0].get('message', 'Unknown error')
            flash(f'Falha ao obter informações do usuário do Twitter: {error_msg}', 'error')
            logging.error(f"Twitter API error: {user_info}")
            return redirect(url_for('login'))
        
        twitter_user_data = user_info['data']
        twitter_id = str(twitter_user_data['id'])
        
        # Check if user already exists
        user = User.query.filter_by(twitter_id=twitter_id).first()
        
        if user:
            # Update existing user data
            user.update_twitter_data(twitter_user_data)
            db.session.commit()
            
            # Log in the user
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            flash(f'Welcome back, {user.display_name}!', 'success')
        else:
            # Create new user
            user = User.create_from_twitter(twitter_user_data)
            db.session.add(user)
            db.session.commit()
            
            # Log in the new user
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            flash(f'Account created successfully! Welcome, {user.display_name}!', 'success')
        
        return redirect(url_for('index'))
        
    except Exception as e:
        logging.error(f"Twitter OAuth error: {str(e)}")
        flash('An error occurred during Twitter login. Please try again.', 'error')
        return redirect(url_for('login'))

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
            
            # Create new protocol
            protocol = Protocol(
                user_id=current_user.id,
                name=name,
                network=network,
                website=website,
                twitter=twitter,
                start_date=start_date_obj,
                daily_missions=daily_missions
            )
            
            db.session.add(protocol)
            db.session.commit()
            
            flash(f'Protocol "{name}" added successfully!', 'success')
            return redirect(url_for('index'))
                
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error adding protocol: {str(e)}")
            flash('An error occurred while adding the protocol. Please try again.', 'error')
            return render_template('add_protocol.html')
    
    return render_template('add_protocol.html')

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
            
            # Update protocol
            protocol.name = name
            protocol.network = network
            protocol.website = website
            protocol.twitter = twitter
            protocol.start_date = start_date_obj
            protocol.daily_missions = daily_missions
            
            db.session.commit()
            
            flash(f'Protocol "{name}" updated successfully!', 'success')
            return redirect(url_for('index'))
        
        return render_template('edit_protocol.html', protocol=protocol)
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing protocol: {str(e)}")
        flash('An error occurred while editing the protocol.', 'error')
        return redirect(url_for('index'))

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
            investment.type = InvestmentType.ENTRY if investment_type == 'entrada' else InvestmentType.WITHDRAWAL
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
    """Atualizar tweets de um protocolo específico"""
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
            flash('Este protocolo não tem Twitter configurado.', 'warning')
            return redirect(url_for('protocol_details', protocol_id=protocol_id))
        
        # Atualizar tweets
        twitter_service = TwitterService()
        success = twitter_service.update_protocol_tweets(protocol_id)
        
        if success:
            flash('Tweets atualizados com sucesso!', 'success')
        else:
            flash('Erro ao atualizar tweets. Verifique o Bearer Token ou o username do Twitter.', 'error')
        
    except Exception as e:
        logging.error(f"Error updating tweets: {str(e)}")
        flash('Erro ao atualizar tweets.', 'error')
    
    return redirect(url_for('protocol_details', protocol_id=protocol_id))


@app.route('/admin/update_all_tweets', methods=['POST'])
@login_required
def update_all_tweets():
    """Atualizar tweets de todos os protocolos (admin only)"""
    try:
        current_user = get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        twitter_service = TwitterService()
        result = twitter_service.update_all_protocols_tweets()
        
        flash(f'Atualização concluída: {result["updated"]} sucessos, {result["failed"]} falhas de {result["total"]} protocolos.', 'info')
        
    except Exception as e:
        logging.error(f"Error updating all tweets: {str(e)}")
        flash('Erro ao atualizar todos os tweets.', 'error')
    
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

@app.errorhandler(404)
def not_found_error(error):
    return render_template('base.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('base.html'), 500
