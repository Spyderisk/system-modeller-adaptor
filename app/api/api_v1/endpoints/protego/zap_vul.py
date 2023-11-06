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

from fastapi import (APIRouter, Depends, Path, HTTPException)
from fastapi import status
from fastapi.responses import JSONResponse

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.crud.store import create_vjob
from app.crud.store import (acquire_session_lock, release_session_lock, update_status)

from app.models.protego.zappies import Zappies
from app.models.vjob import VJobStatus

from app.ssm.protego.bg_zap import bg_update_zap_vulnerabilities

from fastapi.logger import logger


router = APIRouter(tags=['SIEM'])


@router.post("/models/{modelId}/asset/zap-vulnerability",
             response_model=VJobStatus,
             responses={
                 404: {"description": "Item not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 },
             status_code=status.HTTP_200_OK)
async def update_zap_vulnerability(zappies: Zappies,
                                   modelId: str = Path(..., title="ModelId webkey"),
                                   authenticated_scan: Optional[bool] = False,
                                   db_client: AsyncIOMotorClient = Depends(get_database),
                                   ssm: SSMClient = Depends(get_ssm_base),
                                   ):
    """
    Add and update new vulnerabilities using a ZAP report.

    SIEM sends a list of vulnerabilities retrieved from a ZAP scan report on
    a given system monitored in order to update the trustworthiness levels of
    the system model in SSM.

    Parse a list of vulnerabilities reported by ZAP system scan for
    a given asset and update its levels of trustworthiness attributes as
    appropriate. To do that, a look-up table is defined to map ZAP alerts
    to sets of trustworthiness attributes and their respective levels.


    Compare and contrast vulnerabilities
    1) Retrieve vulnerabilities from the system model
    2) Find the differences between the two list of vulnerabilities
    3) Update meta data: vulnerabilities on each asset

    The call is BLOCKING.

    :param str model_id: Model ID that can be used to access the model

    :param bool authenticated_scan: Parameter to specify whether ZAP report comes
                                    from an authenticated or unauthenticated ZAP
                                    scan.

    :param Zappies zappies: ZAP vulnerability POST body

    :return:
    """

    logger.info(f"UPDATE ZAP VULNERABILITY request for model {modelId}")

    vjob = await create_vjob(db_client, {"modelId": modelId})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create update zap job")

    vjob_id = str(vjob.id)
    logger.info(f"update zap vulnerability job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.debug(f"starting update zap vulnerability blocking task: {vjob_id}")
    await bg_update_zap_vulnerabilities(modelId, zappies, vjob_id, db_client, ssm, authenticated_scan)
    logger.debug(f"finished update zap vulnerability blocking task: {vjob_id}")

    logger.debug(f"release session lock for zap vulnerability task: {vjob_id}")
    await release_session_lock(db_client, vjob_id)
    logger.debug(f"released session lock for zap vulnerability task: {vjob_id}")

    return JSONResponse(status_code=status.HTTP_200_OK)

