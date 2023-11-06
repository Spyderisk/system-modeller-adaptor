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

from fastapi.encoders import jsonable_encoder
from app.models.protego.recommendations import StoredRecInDB
from app.models.session import SessionLock, SessionLockEnum

from app.crud.store import update_status, get_vjob, store_rec
from app.crud.store import release_session_lock, get_session

from fastapi.logger import logger


# /models/{modelId}/validate_model
async def bg_validate_model(modelId: str, mode: bool, vjid: str, db_conn, ssm_client: SSMClient):
    # We assume we have a session lock
    logger.info(f"bg job validate {modelId}, mode: {mode}")
    ret_val = True
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed check model found OK")

        # validate model
        if not ssm_client.validate_model(modelId, mode):
            logger.error("ERROR: model not validated")
            # model is not validated.
            raise Exception("model failed to validate model")

        logger.info("passed check model validation OK")

         # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("model validation has finised")

    except ApiException as ex:
        logger.error("ApiException when calling risk vector: %s\n" % ex)
        await update_status(db_conn, vjid, "FAILED", str(ex))
        body = json.loads(ex.body)
        ex.reason=f"Call failed with SSM error: {body['message']}"
        raise ex
    except Exception as e:
        logger.error("Exception when calling model validation: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
        ret_val = False
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return ret_val

