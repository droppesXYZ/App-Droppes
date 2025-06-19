import tweepy
import os
from typing import List, Dict, Optional

class TwitterService:
    def __init__(self):
        self.api = None
        self.client = None
        self.authenticated = False
        self._initialize_twitter()
    
    def _initialize_twitter(self):
        """Inicializa a conexão com o Twitter usando as credenciais do .env"""
        try:
            # Pega as credenciais do ambiente
            api_key = os.getenv('TWITTER_API_KEY')
            api_secret = os.getenv('TWITTER_API_KEY_SECRET')
            access_token = os.getenv('TWITTER_ACCESS_TOKEN')
            access_token_secret = os.getenv('TWITTER_ACCESS_TOKEN_SECRET')
            bearer_token = os.getenv('TWITTER_BEARER_TOKEN')
            
            if not all([api_key, api_secret, access_token, access_token_secret, bearer_token]):
                print("⚠️ Twitter credentials not configured - limited functionality")
                return
            
            # Inicializa o cliente v2 (novo)
            self.client = tweepy.Client(
                bearer_token=bearer_token,
                consumer_key=api_key,
                consumer_secret=api_secret,
                access_token=access_token,
                access_token_secret=access_token_secret,
                wait_on_rate_limit=True
            )
            
            # Inicializa a API v1.1 (legado)
            auth = tweepy.OAuthHandler(api_key, api_secret)
            auth.set_access_token(access_token, access_token_secret)
            self.api = tweepy.API(auth, wait_on_rate_limit=True)
            
            self.authenticated = True
            print("✅ Twitter API inicializada com sucesso!")
            
        except Exception as e:
            print(f"❌ Erro ao inicializar Twitter API: {e}")
            self.authenticated = False
    
    def search_tweets(self, query: str, max_results: int = 10) -> List[Dict]:
        """
        Busca tweets usando a API v2
        """
        if not self.authenticated or not self.client:
            return []
        
        try:
            # Busca tweets usando API v2
            tweets = self.client.search_recent_tweets(
                query=query,
                max_results=min(max_results, 100),  # Máximo permitido é 100
                tweet_fields=['created_at', 'author_id', 'public_metrics', 'context_annotations']
            )
            
            if not tweets.data:
                return []
            
            # Formata os tweets para retorno
            formatted_tweets = []
            for tweet in tweets.data:
                formatted_tweet = {
                    'id': tweet.id,
                    'text': tweet.text,
                    'created_at': tweet.created_at.isoformat() if tweet.created_at else None,
                    'author_id': tweet.author_id,
                    'url': f"https://twitter.com/user/status/{tweet.id}",
                    'metrics': {
                        'retweet_count': tweet.public_metrics.get('retweet_count', 0) if tweet.public_metrics else 0,
                        'like_count': tweet.public_metrics.get('like_count', 0) if tweet.public_metrics else 0,
                        'reply_count': tweet.public_metrics.get('reply_count', 0) if tweet.public_metrics else 0,
                        'quote_count': tweet.public_metrics.get('quote_count', 0) if tweet.public_metrics else 0,
                    }
                }
                formatted_tweets.append(formatted_tweet)
            
            return formatted_tweets
            
        except tweepy.Unauthorized:
            print("❌ Twitter API: Unauthorized - verifique as credenciais")
            return []
        except tweepy.TooManyRequests:
            print("⚠️ Twitter API: Rate limit atingido")
            return []
        except Exception as e:
            print(f"❌ Erro na busca de tweets: {e}")
            return []
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Busca informações de um usuário pelo username
        """
        if not self.authenticated or not self.client:
            return None
        
        try:
            user = self.client.get_user(username=username)
            if user.data:
                return {
                    'id': user.data.id,
                    'username': user.data.username,
                    'name': user.data.name,
                    'description': user.data.description,
                    'followers_count': user.data.public_metrics.get('followers_count', 0) if user.data.public_metrics else 0,
                    'following_count': user.data.public_metrics.get('following_count', 0) if user.data.public_metrics else 0,
                }
            return None
            
        except Exception as e:
            print(f"❌ Erro ao buscar usuário {username}: {e}")
            return None
    
    def is_authenticated(self) -> bool:
        """Verifica se está autenticado"""
        return self.authenticated

# Instância global do serviço
twitter_service = TwitterService() 