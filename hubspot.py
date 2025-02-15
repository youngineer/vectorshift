# slack.py

from fastapi import Request
import os
import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import requests, urllib
from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from urllib.parse import quote
from dotenv import load_dotenv
load_dotenv()

CLIENT_ID = os.getenv('HUBSPOT_CLIENT_ID')
CLIENT_SECRET = os.getenv('HUBSPOT_CLIENT_SECRET')
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"

SCOPES = "oauth cms.domains.write crm.objects.carts.write crm.objects.carts.read crm.objects.subscriptions.read crm.objects.invoices.read crm.objects.services.read crm.objects.users.read crm.objects.services.write crm.objects.contacts.write crm.objects.users.write crm.objects.appointments.read crm.objects.appointments.write crm.objects.invoices.write crm.lists.write crm.objects.companies.read crm.lists.read crm.schemas.carts.write crm.objects.contacts.read crm.schemas.carts.read"
authorization_url = (
    f"https://app-na2.hubspot.com/oauth/authorize"
    f"?client_id={CLIENT_ID}"
    f"&redirect_uri={quote(REDIRECT_URI)}"  # URL encode the redirect URI
    f"&scope={quote(SCOPES)}"  # URL encode the scopes
)

async def authorize_hubspot(user_id, org_id):
    try:
        print("Inside authorize_hubspot")
        state_data = {
            'state': secrets.token_urlsafe(32),
            'user_id': user_id,
            'org_id': org_id
        }
        encoded_state = base64.b64encode(json.dumps(state_data).encode()).decode()
        await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', encoded_state, expire=600)

        return f'{authorization_url}&state={encoded_state}'
    except Exception as e:
        print(f"Error in authorize_hubspot: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error while authorizing HubSpot")


async def oauth2callback_hubspot(request: Request):
    try:
        params = request.query_params
        error = params.get('error')
        if error:
            raise HTTPException(status_code=400, detail=error)
        
        code = params.get('code')
        encoded_state = params.get('state')
        
        if not code:
            raise HTTPException(status_code=400, detail="Authorization code missing")
        if not encoded_state:
            raise HTTPException(status_code=400, detail="State parameter missing")
            
        try:
            state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))
        except Exception as e:
            print(f"Error decoding state: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid state parameter")

        original_state = state_data.get('state')
        user_id = state_data.get('user_id')
        org_id = state_data.get('org_id')

        if not all([original_state, user_id, org_id]):
            raise HTTPException(status_code=400, detail="Missing required state parameters")

        redis_saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
        if not redis_saved_state:
            raise HTTPException(status_code=400, detail="No saved state found")
            
        try:
            saved_state = json.loads(base64.urlsafe_b64decode(redis_saved_state).decode('utf-8')).get('state')
        except Exception as e:
            print(f"Error decoding saved state: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid saved state")

        if not saved_state or original_state != saved_state:
            raise HTTPException(status_code=400, detail='State does not match')
        
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            response, _ = await asyncio.gather(
                client.post(
                    'https://api.hubapi.com/oauth/v1/token',
                    data={
                        'grant_type': 'authorization_code',
                        'code': code,
                        'redirect_uri': REDIRECT_URI,  # Using the corrected REDIRECT_URI
                        'client_id': CLIENT_ID,
                        'client_secret': CLIENT_SECRET
                    },
                    headers={
                        'Content-Type': 'application/x-www-form-urlencoded',
                    }
                ),
                delete_key_redis(f'hubspot_state:{org_id}:{user_id}')
            )
            
            print(f"Token Exchange Response Status: {response.status_code}")
            print(f"Token Exchange Response Body: {response.text}")
            
            if response.status_code != 200:
                error_detail = f"Failed to exchange token with HubSpot: {response.text}"
                print(error_detail)
                raise HTTPException(status_code=response.status_code, detail=error_detail)
            
            token_data = response.json()
            print(f"Token data: {token_data}")

        # Store token in Redis
        await add_key_value_redis(
            f'hubspot_credentials:{org_id}:{user_id}', 
            json.dumps(token_data), 
            expire=token_data.get('expires_in', 600)
        )
    
        close_window_script = """
        <html>
            <script>
                window.close();
            </script>
        </html>
        """
        return HTMLResponse(content=close_window_script)
        
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        print(f"Error in oauth2callback_hubspot: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error during callback handling")

async def get_hubspot_credentials(user_id, org_id):
    pass
    try:
        print("Inside get_hubspot_credentials")
        credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
        if not credentials:
            raise HTTPException(status_code=400, detail='No credentials found.')
        
        credentials = json.loads(credentials)
        if not credentials:
            raise HTTPException(status_code=400, detail='No credentials found.')
        
        await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
        return credentials

    except HTTPException as http_err:
        raise http_err  # Raise the HTTPException if already caught
    except Exception as e:
        print(f"Error in get_hubspot_credentials: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error while retrieving HubSpot credentials")

async def create_integration_item_metadata_object(response_json):
    print("Inside create_integration_item_metadata_object")
    pass

async def get_items_hubspot(credentials):
    print("Inside get_items_hubspot")