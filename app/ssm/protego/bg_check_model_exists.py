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


from fastapi import HTTPException

from app.models.session import SessionLockEnum

from app.ssm.ssm_client import SSMClient
from ssm_api_client.exceptions import ApiException
from app.crud.store import update_status
from app.crud.store import release_session_lock, get_session

from fastapi.logger import logger


async def bg_check_model_exists(modelId: str, vjid: str, db_conn,
                        ssm_client: SSMClient):

    # We assume we have a session lock
    logger.info(f"bg job check model exists {modelId}")
    exists_flag = False
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to verify lock")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed check model found OK")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("check model exists has finised")

        exists_flag = True

    except ApiException as api_ex:
        logger.error(f"API exception model not found {api_ex}")
        await update_status(db_conn, vjid, "FINISHED")
    except Exception as e:
        logger.error(f"exception when finding model: {e}")
        await update_status(db_conn, vjid, "FAILED", str(e))
        raise HTTPException(status_code=503, detail="find model failed")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return exists_flag
