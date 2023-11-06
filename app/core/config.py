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


import os

from dotenv import load_dotenv
from starlette.datastructures import CommaSeparatedStrings, Secret
from databases import DatabaseURL

load_dotenv(".env_adaptor")

# logger info
LOGFILE = os.getenv("LOGFILE", "")
LOGGING_LEVEL = os.getenv("LOGGING_LEVEL", "INFO")

# SSM URL
SSM_URL = os.getenv("SSM_URL",
        'https://protego.it-innovation.soton.ac.uk/system-modeller/')

SSM_ADAPTOR_MODE = os.getenv("SSM_ADAPTOR_MODE", "ALL")

API_STR = os.getenv("API_STR", "/api")

ROOT_PATH = os.getenv("ROOT_PATH", "")

VERSION = "3.5.0"

PROJECT_TITLE = f"SSM Adaptor Microservice ({VERSION})"

DESCRIPTION = f"""This API mediates the communication between the Spyderisk 
        (SSM) v{VERSION} system and Security Information Systems.
        """

PROJECT_NAME = os.getenv("PROJECT_NAME", "FastAPI microservice application")

ALLOWED_HOSTS = CommaSeparatedStrings(os.getenv("ALLOWED_HOSTS", ""))


UDE_SERVICE_URL = os.getenv("UDE_SERVICE_URL",
    "http://localhost:8000/api/v2/fogprotect/adaptationcoordinator/notify")

# KAFKA parameters
KAFKA_SERVICE_URL = os.getenv("KAFKA_SERVICE_URL", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "ssm")
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "False").lower() in ['true', 'on', 'yes', 1]

OUTBOUND_REQUEST_TIMEOUT = int(os.getenv("OUTBOUND_REQUEST_TIMEOUT", 30))

MAX_CONNECTIONS_COUNT = int(os.getenv("MAX_CONNECTIONS_COUNT", 10))
MIN_CONNECTIONS_COUNT = int(os.getenv("MIN_CONNECTIONS_COUNT", 10))
SECRET_KEY = Secret(os.getenv("SECRET_KEY", "secret key for project"))


MONGO_HOST = os.getenv("MONGO_HOST", "mongo")
MONGO_PORT = int(os.getenv("MONGO_PORT", 27017))
MONGO_USER = os.getenv("MONGO_USER", "")
MONGO_PASS = os.getenv("MONGO_PASSWORD", "")
MONGO_DB = os.getenv("MONGO_DB", "ssmadaptor")

MONGODB_URL = DatabaseURL(
        #f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}"
        f"mongodb://{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}"
)

print("MONGO URL:", MONGODB_URL)

database_name = MONGO_DB
pusers_collection = "pusers"
vjobs_collection = "vjobs"
risk_collection = "risks"
rec_collection = "recommendations"
session_collection = "sessions"
twas_change_collection = "twas"
plot_collection = "plots"
state_report_collection = "statereports"

# polling timers
POLLING_DELAY_1 = int(os.getenv("POLLING_DELAY_1", 2))
POLLING_DELAY_2 = int(os.getenv("POLLING_DELAY_2", 2))

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

TEST_USER = "testuser"
TEST_USER_PASSWORD = "changeme"

# Fogprotect parameters
FP_USE_CASE = os.getenv("FP_USE_CASE", "UC1")
GET_ASSET_METADATA_FROM_VULN = os.getenv("GET_ASSET_METADATA_FROM_VULN", "True").lower() in ['true', 'on', 'yes', 1]
# N.B. following value will be updated when FP domain model is available
FP_DISABLEMENT_CONTROL = os.getenv("FP_DISABLEMENT_CONTROL", "Disable")
RISK_CALC_MODE = os.getenv("RISK_CALC_MODE", "FUTURE")
FP_ENABLE_RECOMMENDATIONS = os.getenv("FP_ENABLE_RECOMMENDATIONS", "False").lower() in ['true', 'on', 'yes', 1]

# Generic parameters
MAX_RISKS = int(os.getenv("MAX_RISKS", -1))
ACCEPTABLE_RISK_LEVEL = os.getenv("ACCEPTABLE_RISK_LEVEL", "Medium")
FILTER_LOW_LEVEL_RISKS = os.getenv("FILTER_LOW_LEVEL_RISKS", "True").lower() in ['true', 'on', 'yes', 1]

# MAX number of threats to exploid for recommendations
MAX_THREATS = int(os.getenv("MAX_THREATS", 10))

# Domain model version number
DOMAIN_MODEL_VERSION = int(os.getenv("DOMAIN_MODEL_VERSION", 5))

# Cyberkit4SME parameters
OPENVAS_REPORT_FILE_LOCATION = os.getenv("OPENVAS_REPORT_FILE_LOCATION", "/code/tmp")
NIST_API_KEY = os.getenv("NIST_API_KEY", "")
