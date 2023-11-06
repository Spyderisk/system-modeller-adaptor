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

from app.ssm.protego.bg_rollback_utils import restore_twas, list_twas, clear_twas

from app.ssm.ssm_client import SSMClient

from app.crud.store import update_status
from app.crud.store import release_session_lock, get_session

from fastapi.logger import logger


async def bg_rollback_twas(modelId: str, vjid: str, db_conn, ssm_client: SSMClient):

    # We assume we have a session lock
    logger.info(f"bg rollback twa {modelId}")
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

        # reset model TWA changes
        await restore_twas(modelId, ssm_client, db_conn)

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("rollback model vul TWAs has finised")

    except Exception as ex:
        logger.error("Exception when rolling back TWAs: %s\n" % ex)
        await update_status(db_conn, vjid, "FAILED", str(ex))
        raise HTTPException(status_code=503, detail="failed to rollback twas")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return


async def bg_list_twas(modelId: str, vjid: str, db_conn, ssm_client: SSMClient):

    # We assume we have a session lock
    logger.info(f"bg list twas changed {modelId}")
    twas_list = []
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

        # reset model TWA changes
        twas_list = await list_twas(modelId, db_conn)

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("listing changed TWAs has finised")

    except Exception as ex:
        logger.error("Exception when listing changed TWAs: %s\n" % ex)
        await update_status(db_conn, vjid, "FAILED", str(ex))
        raise HTTPException(status_code=503, detail="failed to list changed twas")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return twas_list

async def bg_clear_twas(modelId: str, vjid: str, db_conn, ssm_client: SSMClient):

    # We assume we have a session lock
    logger.info(f"bg clear twas changed {modelId}")
    twas_list = []
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

        # reset model TWA changes
        await clear_twas(modelId, db_conn)

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("cleared cached TWAs has finised")

    except Exception as ex:
        logger.error("Exception when clearing changed TWAs: %s\n" % ex)
        await update_status(db_conn, vjid, "FAILED", str(ex))
        raise HTTPException(status_code=503, detail="failed to clear cached twas")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return twas_list
