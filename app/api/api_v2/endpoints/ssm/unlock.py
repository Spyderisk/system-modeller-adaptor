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


from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import status
from fastapi.responses import JSONResponse

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.crud.store import release_session_lock, get_session

from fastapi.logger import logger

router = APIRouter(tags=['SSM Utils'])

@router.post("/models/{model_webkey}/force-adaptor-lock-remove",
            responses={
                404: {"description": "lock not found"},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def force_adaptor_lock_remove(model_webkey: str = Path(..., title="ModelId webkey"),
                            db: AsyncIOMotorClient = Depends(get_database)):
    """
    This is an auxilary call to unlock SSM resources. It should only be used
    when a previous call has failed to release SSM resources.

    :param str model_webkey: Model webkey that can be used to access the model

    :return:
    """
    logger.info(f"unlock resources")
    try:
        session = await get_session(db, model_webkey)
        if session:
            logger.debug(f"found session lock {session.json()}")
            await release_session_lock(db, session.task_id)
        else:
            logger.debug("cannot acquire session lock")
    except Exception as ex:
        logger.error(f"exception getting session {ex}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to remove session lock.")

    logger.info(f"force releasing session lock")

    return JSONResponse(content="ok", status_code=status.HTTP_202_ACCEPTED)
