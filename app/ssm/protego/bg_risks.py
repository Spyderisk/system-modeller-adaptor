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
##      Created Date :          2021-01-19
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

import os
import asyncio
import aiohttp
import json
import datetime
import time
from bson.objectid import ObjectId

from app.ssm.ssm_client import SSMClient
from ssm_api_client.exceptions import ApiException
from app.models.risk import RiskVector
from app.models.risk import State

from fastapi.encoders import jsonable_encoder
from app.models.protego.recommendations import StoredRecInDB
from app.models.session import SessionLock, SessionLockEnum

from app.crud.store import update_status, get_vjob, store_rec
from app.crud.store import release_session_lock, get_session

from fastapi.logger import logger

#TODO check model exists should be replaced by a wrapper method

# /models/{modelId}/calc_risks
async def bg_get_risk_vector_full(modelId: str, max_risks: int, vjid: str, db_conn, ssm_client: SSMClient):
    # We assume we have a session lock
    logger.info(f"bg job calculate risk/mitigation {modelId}")
    risk_vector = None
    risk_response = None
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed check model found OK")

        # Calculate the risks of the current state
        logger.info('Calculating run-time risks...')
        response = ssm_client.calculate_runtime_risk_vector_full(modelId, 'CURRENT', max_risks)

        risk_response = State(**response)

        json_response = jsonable_encoder(risk_response)
        logger.debug(f"risk_response: {json.dumps(response, indent=4, sort_keys=False)}")

         # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("get risk response has finised")

    except ApiException as ex:
        logger.error("ApiException when calling risk vector: %s\n" % ex)
        await update_status(db_conn, vjid, "FAILED", str(ex))
        body = json.loads(ex.body)
        ex.reason=f"Risk calculation failed with SSM error: {body['message']}"
        raise ex
    except Exception as e:
        logger.error(f"Exception when calling risk response: {e}\n")
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return risk_response


async def bg_get_risk_vector(modelId: str, vjid: str, db_conn, ssm_client: SSMClient):
    # We assume we have a session lock
    logger.info(f"bg job calculate risk/mitigation {modelId}")
    risk_vector = None
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed check model found OK")

        # validate model
        #if not ssm_client.validate_model(modelId):
        #    logger.error("ERROR: model not validated")
        #    # model is not validated.
        #    raise Exception("model failed to validate")

        logger.info("passed check model validation OK")

        # Calculate the risks of the current state
        logger.info('Calculating run-time risks...')
        risk_vector = ssm_client.calculate_runtime_risk_vector(modelId, 'CURRENT')

        json_response = jsonable_encoder(risk_vector)
        logger.debug(f"risk_calculation: {json.dumps(json_response, indent=4, sort_keys=False)}")

         # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("get risk vector has finised")

    except ApiException as ex:
        logger.error("ApiException when calling risk vector: %s\n" % ex)
        await update_status(db_conn, vjid, "FAILED", str(ex))
        body = json.loads(ex.body)
        ex.reason=f"Risk calculation failed with SSM error: {body['message']}"
        raise ex
    except Exception as e:
        logger.error("Exception when calling risk vector: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return risk_vector

async def bg_fetch_risk_vector(modelId: str, vjid: str, db_conn, ssm_client: SSMClient):
    # We assume we have a session lock
    logger.info(f"bg fetch risk vector {modelId}")
    risk_vector = None
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed check model found OK")

        # validate model
        #if not ssm_client.validate_model(modelId):
        #    logger.error("ERROR: model not validated")
        #    # model is not validated.
        #    raise Exception("model failed to validate")

        logger.info("passed check model validation OK")

        # Fetch the risks of the current state
        logger.info('Fetching run-time risks...')
        risk_vector = ssm_client.fetch_runtime_risk_vector(modelId)

        json_response = jsonable_encoder(risk_vector)
        logger.debug(f"risk_fetched: {json.dumps(json_response, indent=4, sort_keys=False)}")

         # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("get risk vector has finised")

    except ApiException as ex:
        logger.error("ApiException when calling risk vector: %s\n" % ex)
        await update_status(db_conn, vjid, "FAILED", str(ex))
        body = json.loads(ex.body)
        ex.reason=f"Risk calculation failed with SSM error: {body['message']}"
        raise ex
    except Exception as e:
        logger.error("Exception when calling fetch risk vector: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return risk_vector
