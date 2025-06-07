import requests
import os
from datetime import datetime, timezone
from models import db, Protocol, Tweet
import logging

class TwitterService:
    def __init__(self):
        self.bearer_token = os.getenv('TWITTER_BEARER_TOKEN')
        self.base_url = "https://api.twitter.com/2"
        
    def get_user_tweets(self, username, max_results=3):
        """
        Busca os últimos tweets de um usuário
        
        Args:
            username (str): Nome de usuário do Twitter (sem @)
            max_results (int): Número máximo de tweets (padrão: 3)
            
        Returns:
            list: Lista de tweets ou lista vazia se houver erro
        """
        if not self.bearer_token:
            logging.warning("Twitter Bearer Token não configurado")
            return []
            
        try:
            # Primeiro, obter o ID do usuário
            user_id = self._get_user_id(username)
            if not user_id:
                return []
            
            # Buscar tweets do usuário
            url = f"{self.base_url}/users/{user_id}/tweets"
            params = {
                'max_results': max_results,
                'tweet.fields': 'created_at,public_metrics',
                'exclude': 'retweets,replies'  # Excluir retweets e replies
            }
            
            headers = {
                'Authorization': f'Bearer {self.bearer_token}'
            }
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                tweets = []
                
                if 'data' in data:
                    for tweet_data in data['data']:
                        tweet = {
                            'id': tweet_data['id'],
                            'text': tweet_data['text'],
                            'created_at': self._parse_twitter_date(tweet_data['created_at']),
                            'url': f"https://twitter.com/{username}/status/{tweet_data['id']}",
                            'username': username
                        }
                        tweets.append(tweet)
                
                return tweets
            else:
                logging.error(f"Erro ao buscar tweets para {username}: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logging.error(f"Erro ao buscar tweets para {username}: {str(e)}")
            return []
    
    def _get_user_id(self, username):
        """Obtém o ID do usuário pelo username"""
        try:
            url = f"{self.base_url}/users/by/username/{username}"
            headers = {
                'Authorization': f'Bearer {self.bearer_token}'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {}).get('id')
            else:
                logging.error(f"Erro ao buscar ID do usuário {username}: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"Erro ao buscar ID do usuário {username}: {str(e)}")
            return None
    
    def _parse_twitter_date(self, date_string):
        """Converte string de data do Twitter para datetime"""
        try:
            # Twitter retorna datas no formato ISO 8601 com timezone
            return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        except Exception as e:
            logging.error(f"Erro ao converter data {date_string}: {str(e)}")
            return datetime.now(timezone.utc)
    
    def update_protocol_tweets(self, protocol_id):
        """
        Atualiza os tweets de um protocolo específico
        
        Args:
            protocol_id (int): ID do protocolo
            
        Returns:
            bool: True se atualizou com sucesso, False caso contrário
        """
        try:
            protocol = Protocol.query.get(protocol_id)
            if not protocol or not protocol.twitter:
                return False
            
            # Extrair username do campo twitter (pode ter @ ou URL completa)
            username = self._extract_username(protocol.twitter)
            if not username:
                return False
            
            # Buscar tweets
            tweets_data = self.get_user_tweets(username, 3)
            
            if not tweets_data:
                return False
            
            # Limpar tweets antigos do protocolo
            Tweet.query.filter_by(protocol_id=protocol_id).delete()
            
            # Salvar novos tweets
            for tweet_data in tweets_data:
                tweet = Tweet(
                    protocol_id=protocol_id,
                    tweet_id=tweet_data['id'],
                    text=tweet_data['text'],
                    author_username=tweet_data['username'],
                    created_at_twitter=tweet_data['created_at'],
                    tweet_url=tweet_data['url']
                )
                db.session.add(tweet)
            
            db.session.commit()
            logging.info(f"Tweets atualizados para protocolo {protocol.name}: {len(tweets_data)} tweets")
            return True
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Erro ao atualizar tweets do protocolo {protocol_id}: {str(e)}")
            return False
    
    def _extract_username(self, twitter_field):
        """
        Extrai o username do campo twitter
        Suporta formatos: @username, username, https://twitter.com/username, etc.
        """
        if not twitter_field:
            return None
        
        twitter_field = twitter_field.strip()
        
        # Se começa com @, remove
        if twitter_field.startswith('@'):
            return twitter_field[1:]
        
        # Se é uma URL do Twitter
        if 'twitter.com/' in twitter_field:
            try:
                # Extrai username da URL
                parts = twitter_field.split('twitter.com/')
                if len(parts) > 1:
                    username = parts[1].split('/')[0].split('?')[0]
                    return username
            except:
                pass
        
        # Se é só o username
        if twitter_field and not '.' in twitter_field:
            return twitter_field
        
        return None
    
    def update_all_protocols_tweets(self):
        """
        Atualiza tweets de todos os protocolos que têm Twitter configurado
        
        Returns:
            dict: Relatório da atualização
        """
        updated = 0
        failed = 0
        
        try:
            protocols = Protocol.query.filter(Protocol.twitter.isnot(None)).filter(Protocol.twitter != '').all()
            
            for protocol in protocols:
                if self.update_protocol_tweets(protocol.id):
                    updated += 1
                else:
                    failed += 1
            
            logging.info(f"Atualização de tweets concluída: {updated} sucessos, {failed} falhas")
            
        except Exception as e:
            logging.error(f"Erro na atualização geral de tweets: {str(e)}")
        
        return {
            'updated': updated,
            'failed': failed,
            'total': updated + failed
        }


# Função para uso em scripts de atualização
def update_all_tweets():
    """Função standalone para atualizar todos os tweets"""
    service = TwitterService()
    return service.update_all_protocols_tweets() 