##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2021
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre of Gamma House, Enterprise Road,
## Chilworth Science Park, Southampton, SO16 7NS, UK.
##
## This software may not be used, sold, licensed, transferred, copied
## or reproduced in whole or in part in any manner or form or in or
## on any media by any person other than in accordance with the terms
## of the Licence Agreement supplied with the software, or otherwise
## without the prior written consent of the copyright owners.
##
## This software is distributed WITHOUT ANY WARRANTY, without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
## PURPOSE, except where stated in the Licence Agreement supplied with
## the software.
##
##      Created By :            Samuel M Senior
##      Created Date :          2025-11-25
##      Created for Project :   THEMIS
##
##///////////////////////////////////////////////////////////////////////

import json
import requests
from requests import ReadTimeout, ConnectTimeout, HTTPError, Timeout, ConnectionError

from app.core.config import TAI_LA_SERVICE_URL

from fastapi.logger import logger


def login(username, password):

    url = f"{TAI_LA_SERVICE_URL}/realms/myrealm/protocol/openid-connect/token"
    
    payload = f'client_id=myclient&client_secret=myclientsecret&username={username}&password={password}&grant_type=password'
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        
        if response.status_code == 200:
            logger.info("Response status code for login OK")
        elif response.status_code != 200:
            logger.error(f"POST notification to TAI LA returned a {response.status_code}")#, {response.text}")
            raise Exception(f"POST notification to TAI LA returned a non-200 response: {response.status_code}")
            
    except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError,
            Exception) as err:
        logger.error(f"failed to POST event notification {err}")
        raise Exception(f"post_notification failed {err}")
    
    return response.json()['access_token'] , response

def result(access_token, asset_id, case_id, characteristics):
    url = f"{TAI_LA_SERVICE_URL}/assess/results?asset_id={asset_id}&case_id={case_id}&characteristics={characteristics}"
    
    payload = {}
    headers = {
      'Authorization': 'Bearer ' + access_token,
      'Content-Type': 'application/json',
      'accept': 'application/json'
    }
    
    try:
        response = requests.request("GET", url, headers=headers, data=payload, verify=False)

        if response.status_code == 200:
            logger.info("Response status code for getting result OK")
            response_json = response.json()
            
        elif response.status_code != 200:
            logger.error(f"GET notification to TAI LA returned a {response.status_code}")
            raise Exception(f"GET notification to TAI LA returned a non-200 response: {response.status_code}")
            
    except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError,
            Exception) as err:
        logger.error(f"failed to GET event notification {err}")
        raise Exception(f"get_notification failed {err}")
    
    return response_json
