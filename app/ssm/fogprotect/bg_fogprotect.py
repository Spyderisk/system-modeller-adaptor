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
##      Created Date :          2021-02-23
##      Created for Project :   FogProtect
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
from app.models.session import SessionLock, SessionLockEnum
from app.crud.store import update_status, get_vjob
from app.crud.store import release_session_lock, get_session

from app.clients.ude_client import post_notification
from app.models.fogprotect.adaptation_coordinator.notification_models import EventNotification

from fastapi.encoders import jsonable_encoder
from fastapi.logger import logger


# dummy background tasks for Fogprotect endpoints
async def bg_fp_task(modelId: str, vjid: str, db_conn,
        ssm_client: SSMClient, verbose=True):

    logger.info("Serving dummy background task")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        # do the long term task
        await asyncio.sleep(10)

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("background task has finised")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.info(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return

dummy_event = {
  "NotificationType": "string",
  "EventName": "string",
  "Risks": [
    {
      "ObjectToIdentify": {
        "Name": "string",
        "Type": "string",
        "AtId": "string"
      },
      "RiskDescription": "string",
      "RiskImpact": "string",
      "RiskName": "string",
      "RiskLikelihood": "string",
      "RiskLevel": "string"
    }
  ],
  "OverallRiskLevel": "string",
  "RiskVector": {
    "High": 0,
    "Low": 0,
    "Medium": 0,
    "VeryHigh": 0,
    "VeryLow": 0
  },
  "AcceptableRiskLevel": "string",
  "AsIsRisk": {
    "AtId": "string",
    "RiskLevel": {
      "OverallRiskLevel": "string",
      "RiskVector": {
        "High": 0,
        "Low": 0,
        "Medium": 0,
        "VeryHigh": 0,
        "VeryLow": 0
      }
    }
  },
  "AdaptationRisks": [
    {
      "AdaptationProposalId": "string",
      "RiskLevel": {
        "OverallRiskLevel": "string",
        "RiskVector": {
          "High": 0,
          "Low": 0,
          "Medium": 0,
          "VeryHigh": 0,
          "VeryLow": 0
        }
      }
    }
  ]
}

# dummy background job with notification call
async def bg_fp_task_notify(modelId: str, vjid: str, db_conn,
        ssm_client: SSMClient, verbose=True):

    logger.info("Serving dummy background task with notification POST")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        # do the long term task
        await asyncio.sleep(10)

        # build EventNotification 
        result = { "notification_type": "EventNotifica"}
 
        logger.info("background task ready to post to UDE")
        payload = jsonable_encoder(EventNotification(**dummy_event))
        post_notification(payload)
        logger.info("background task finished posting to UDE")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("background notification task has finised")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.info(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return
