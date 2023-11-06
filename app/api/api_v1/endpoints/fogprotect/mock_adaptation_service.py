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
##      Created By :            Ken Meacham
##      Created Date :          2021-04-29
##      Created for Project :   FogProtect
##
##///////////////////////////////////////////////////////////////////////


import logging
from typing import Optional, Any, List
from fastapi import APIRouter, Body, Depends, Path, Query, HTTPException
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

from app.models.fogprotect.event_notification import Status
from app.models.fogprotect.adaptation_coordinator.notification_models import EventNotification

from fastapi.logger import logger
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

router = APIRouter(tags=['AdaptationCoordinator'])

@router.post("/fogprotect/adaptationcoordinator/notify",
        response_model=Status,
        status_code=status.HTTP_200_OK)
async def notify_event(
        e_notification: EventNotification,
        ):
    logger.debug("mock_adaptation invoked")
    logger.info(f"Adaptation Coord: received notify: {e_notification}")

    return {"status": "OK"}

