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
##      Created By :            Panos Melas
##      Created Date :          2021-04-29
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

import json
import requests
from requests import ReadTimeout, ConnectTimeout, HTTPError, Timeout, ConnectionError
from datetime import datetime

from app.core.config import UDE_SERVICE_URL, OUTBOUND_REQUEST_TIMEOUT

from fastapi.logger import logger


def post_notification(payload: dict):
    url = UDE_SERVICE_URL
    timeout = OUTBOUND_REQUEST_TIMEOUT

    #remove empty recommendations item
    if not payload['Recommendations']:
        del payload['Recommendations']

    logger.info(f"POSTing an event notification to UDE {url}")
    logger.info(f"PAYLOAD: {json.dumps(payload, indent=4, sort_keys=False)}")

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=timeout)
        logger.debug(f"response status: {res.status_code}")
        if res.status_code != 200:
            logger.error(f"POST notification to UDE returned a {res.status_code}, {res.text}")
            raise Exception(f"POST notification to UDE returned a non-200 response: {res.status_code}")

    except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError,
            Exception) as err:
        logger.error(f"failed to POST event notification {err}")
        raise Exception(f"post_notification failed {err}")

