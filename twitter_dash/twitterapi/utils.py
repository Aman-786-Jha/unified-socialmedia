import os
import requests
from urllib.parse import urlencode
from dotenv import load_dotenv
import uuid
from urllib.parse import urlencode

load_dotenv()

TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")
TWITTER_CALLBACK_URL = os.getenv("TWITTER_CALLBACK_URL")

def get_twitter_authorization_url(request):
    state = str(uuid.uuid4())
    request.session['twitter_oauth_state'] = state
    base_url = "https://twitter.com/i/oauth2/authorize"
    params = {
        "response_type": "code",
        "client_id": TWITTER_CLIENT_ID,
        "redirect_uri": TWITTER_CALLBACK_URL,
        "scope": "tweet.read users.read offline.access like.read",  
        "state": state,  
        "code_challenge": "challenge",
        "code_challenge_method": "plain",
        "prompt": "consent",
    }
    return f"{base_url}?{urlencode(params)}"




import base64

def get_twitter_token(code):
    url = "https://api.twitter.com/2/oauth2/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    client_cred = f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}"
    b64_client_cred = base64.b64encode(client_cred.encode()).decode()
    headers["Authorization"] = f"Basic {b64_client_cred}"

    data = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": TWITTER_CALLBACK_URL,
        "code_verifier": "challenge", 
    }

    response = requests.post(url, data=data, headers=headers)
    return response.json()



