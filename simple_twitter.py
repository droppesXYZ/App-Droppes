import tweepy
import os
from datetime import datetime, timedelta
from models import db, Protocol, Tweet
import logging

class SimpleTwitterService:
    def __init__(self):
        # Twitter API configurations (you'll need to set these variables)
        self.api_key = os.getenv('TWITTER_API_KEY', '')
        self.api_secret = os.getenv('TWITTER_API_SECRET', '')
        self.access_token = os.getenv('TWITTER_ACCESS_TOKEN', '')
        self.access_token_secret = os.getenv('TWITTER_ACCESS_TOKEN_SECRET', '')
        self.bearer_token = os.getenv('TWITTER_BEARER_TOKEN', '')
        
        self.client = None
        self.setup_client()
    
    def setup_client(self):
        """Configure Twitter client"""
        try:
            if self.bearer_token:
                self.client = tweepy.Client(bearer_token=self.bearer_token)
                logging.info("✅ Twitter client configured with Bearer Token")
            elif all([self.api_key, self.api_secret, self.access_token, self.access_token_secret]):
                self.client = tweepy.Client(
                    consumer_key=self.api_key,
                    consumer_secret=self.api_secret,
                    access_token=self.access_token,
                    access_token_secret=self.access_token_secret
                )
                logging.info("✅ Twitter client configured with OAuth 1.0a")
            else:
                logging.warning("⚠️ Twitter credentials not configured - limited functionality")
        except Exception as e:
            logging.error(f"❌ Error configuring Twitter client: {e}")
    
    def can_search_today(self, protocol_id):
        """Always allows search - no artificial time limitation"""
        return True
    
    def is_original_tweet(self, tweet):
        """
        Check if a tweet is original (not a retweet, reply, or thread continuation)
        """
        # If it has referenced_tweets, it's probably a reply or retweet
        if hasattr(tweet, 'referenced_tweets') and tweet.referenced_tweets:
            return False
        
        # If it's a reply to another user
        if hasattr(tweet, 'in_reply_to_user_id') and tweet.in_reply_to_user_id:
            return False
        
        # If conversation_id is different from tweet id, it might be part of a thread
        if hasattr(tweet, 'conversation_id') and str(tweet.conversation_id) != str(tweet.id):
            return False
        
        return True
    
    def search_protocol_tweets(self, protocol_id):
        """
        Search for the latest 3 original tweets from a protocol
        - Excludes retweets and replies
        - Excludes secondary threads (only first thread post)
        - Returns only original user posts
        """
        if not self.client:
            return {"error": "Twitter client not configured"}
        
        protocol = Protocol.query.get(protocol_id)
        if not protocol or not protocol.twitter:
            return {"error": "Protocol not found or no Twitter configured"}
        
        # No artificial time limitation - only Twitter API limitations
        
        try:
            # Extract Twitter username (remove @ if exists)
            twitter_username = protocol.twitter.replace('@', '').replace('https://twitter.com/', '').replace('https://x.com/', '')
            
            # First, get the user ID
            user = self.client.get_user(username=twitter_username)
            if not user.data:
                return {"error": f"User @{twitter_username} not found"}
            
            # Search user tweets using ID
            # Exclude retweets, replies to get only original tweets
            tweets = self.client.get_users_tweets(
                id=user.data.id,
                max_results=10,  # Search more to filter later
                tweet_fields=['created_at', 'author_id', 'public_metrics', 'conversation_id', 'in_reply_to_user_id', 'referenced_tweets'],
                exclude=['retweets', 'replies']  # Exclude retweets and replies
            )
            
            if not tweets.data:
                return {"error": "No tweets found"}
            
            # Filter only original tweets (no retweets, no threads, no replies)
            original_tweets = []
            for tweet in tweets.data:
                if self.is_original_tweet(tweet):
                    original_tweets.append(tweet)
                    if len(original_tweets) >= 3:  # Stop when we have 3 original tweets
                        break
            
            if not original_tweets:
                return {"error": "No original tweets found (only retweets or threads)"}
            
            # Save tweets to database (only original tweets)
            saved_tweets = []
            for tweet in original_tweets:
                # Check if tweet already exists
                existing_tweet = Tweet.query.filter_by(
                    protocol_id=protocol_id,
                    tweet_id=str(tweet.id)
                ).first()
                
                if not existing_tweet:
                    new_tweet = Tweet(
                        protocol_id=protocol_id,
                        tweet_id=str(tweet.id),
                        text=tweet.text,
                        author_username=twitter_username,
                        created_at_twitter=tweet.created_at,
                        tweet_url=f"https://twitter.com/{twitter_username}/status/{tweet.id}"
                    )
                    db.session.add(new_tweet)
                    saved_tweets.append(new_tweet)
            
            db.session.commit()
            
            return {
                "success": True,
                "tweets_found": len(original_tweets),
                "tweets_saved": len(saved_tweets),
                "message": f"Found {len(original_tweets)} original tweets (excluding retweets and threads)",
                "tweets": [
                    {
                        "id": tweet.tweet_id,
                        "text": tweet.short_text,
                        "url": tweet.tweet_url,
                        "created_at": tweet.created_at_twitter.strftime("%d/%m/%Y %H:%M")
                    }
                    for tweet in saved_tweets
                ]
            }
            
        except tweepy.TooManyRequests:
            return {"error": "Rate limit reached. Try again later."}
        except tweepy.Unauthorized:
            return {"error": "Unauthorized. Check API credentials."}
        except tweepy.NotFound:
            return {"error": f"User @{twitter_username} not found on Twitter."}
        except Exception as e:
            logging.error(f"Error searching tweets: {e}")
            return {"error": f"Error searching tweets: {str(e)}"}
    
    def get_protocol_tweets(self, protocol_id, limit=3):
        """Return latest saved tweets from a protocol"""
        tweets = Tweet.query.filter_by(protocol_id=protocol_id)\
                           .order_by(Tweet.created_at_twitter.desc())\
                           .limit(limit).all()
        
        return [
            {
                "id": tweet.tweet_id,
                "text": tweet.short_text,
                "url": tweet.tweet_url,
                "created_at": tweet.created_at_twitter.strftime("%d/%m/%Y %H:%M"),
                "author": tweet.author_username
            }
            for tweet in tweets
        ]

# Instância global do serviço
twitter_service = SimpleTwitterService() 