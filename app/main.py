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


from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from starlette.middleware.cors import CORSMiddleware

#from starlette.exceptions import HTTPException
#from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

from app.api.api_v1.api import router as api_router_v1
from app.api.api_v2.api import router as api_router_v2
from app.core.config import ALLOWED_HOSTS, API_STR, ROOT_PATH, PROJECT_NAME
from app.core.config import SSM_ADAPTOR_MODE
from app.core.config import PROJECT_TITLE, DESCRIPTION, VERSION
from app.core.config import LOGFILE, LOGGING_LEVEL
from app.core.errors import http_422_error_handler, http_error_handler
from app.db.mongodb_utils import close_mongo_connection, connect_to_mongo

from app.ssm.ssm_base_utils import initialise_ssm_client, close_ssm_client

import logging
import time

from fastapi.logger import logger

# setup logger
logger.propagate = 0

if LOGGING_LEVEL == "DEBUG":
    logger.setLevel(level=logging.DEBUG)
else:
    logger.setLevel(level=logging.INFO)

formatter = logging.Formatter("[%(asctime)s] [%(process)d] [%(name)s] [%(levelname)s] %(message)s")
formatter.converter = time.gmtime

#console_handler = logging.StreamHandler()
#logger.addHandler(console_handler)
#console_handler.setFormatter(formatter)

if LOGFILE:
    handler = logging.FileHandler(LOGFILE)
else:
    handler = logging.StreamHandler()
logger.addHandler(handler)
handler.setFormatter(formatter)

logger.info(f"LOGGING level: {LOGGING_LEVEL}")

tags_metadata = [
        {
            "name": "auth",
            "description": "Authentication operations, i.e. login access token",
            },
        {
            "name": "SIEA",
            "description": """Core methods to support Threat Diagnosis and Risk
            Analysis case studies""",
            },
        #{
        #    "name": "SIEM",
        #    "description": """Available methods of API Controller that use
        #    information from SIEM.""",
        #    },
        {
            "name": "SSM Utils",
            "description": """SSM related operations, and SSM-Adaptor utilities""",
            },
        {
            "name": "Cyberkit4SME",
            "description": """Cyberkit4SME operations.""",
            },
        {
            "name": "debug",
            "description": """Adaptor background debug calls and operations.""",
            }
        ]

app = FastAPI(title=PROJECT_TITLE, description=DESCRIPTION, version=VERSION,
        openapi_tags=tags_metadata, root_path=ROOT_PATH,)

@app.get("/")
async def info(request: Request):
    return {"app_name": f"{PROJECT_NAME} v{VERSION}, mode: {SSM_ADAPTOR_MODE}, root_path: {request.scope.get('root_path')}"}

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return FileResponse('app/favicon.ico')

if not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("startup", initialise_ssm_client)
app.add_event_handler("shutdown", close_mongo_connection)
app.add_event_handler("shutdown", close_ssm_client)

#app.add_exception_handler(HTTPException, http_error_handler)
#app.add_exception_handler(HTTP_422_UNPROCESSABLE_ENTITY, http_422_error_handler)

#app.include_router(api_router_v1, prefix=API_STR)
app.include_router(api_router_v2, prefix=API_STR)
