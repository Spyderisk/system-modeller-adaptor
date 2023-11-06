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


from typing import Optional

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import Response
from fastapi.responses import PlainTextResponse
from fastapi import status
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

#from app.models.user import User
#from app.api.auth import get_current_user

from app.crud.store import (create_vjob, get_vjob, get_state, get_recommendations)
from app.crud.store import (acquire_session_lock, update_status)
from app.crud.store import release_session_lock

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.risk import State

from app.ssm.cyberkit4sme.bg_calculate_risk import bg_calculate_risk_combined



from app.core.config import RISK_CALC_MODE

from fastapi.logger import logger


router = APIRouter(tags=['Cyberkit4SME'])

@router.post("/models/{model_webkey}/calc-risks",
             #response_model=State,
             responses={
                 404: {"description": "Item not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 },
             status_code=status.HTTP_202_ACCEPTED)
async def calculate_risk(model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm: SSMClient = Depends(get_ssm_base),
                      risk_mode: str = RISK_CALC_MODE
                      ):
    """

    Calculate model risk operation, it takes as a path parameter the model ID.
    This is a blocking call that instantiates the  model risk calculations
    after applying valid state reports. The model is reverted back to it's
    initial state.

    - make a 'copy' model (clear TWAs stack)
    - process state reports
    - calculate risk
    - 'discard' changes (undo TWAs stack)

    :param str model_id: Model ID that can be used to access the model

    :return status: Returns the overall risk as a risk vector, and consequences
                    with a risk level higher than MEDIUM.

    """
    logger.info("Got calculate risk call blocking mode")

    vjob = await create_vjob(db_client, {"modelId": model_webkey})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create calc-risk blocking job")

    vjob_id = str(vjob.id)
    logger.info(f"calc risk blocking job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.info(f"starting foreground job")

    try:
        model_state = await bg_calculate_risk_combined(model_webkey, ssm, vjob_id, db_client, risk_mode)
    except Exception as e:
        logger.error("Exception in calculate risk endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"Calculate risk failed for {model_webkey}")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_client, vjob_id)

    return model_state


