##///////////////////////////////////////////////////////////////////////
##
## © University of Southampton IT Innovation Centre, 2025
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre, Highfield Campus, SO17 1BJ, UK.
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
##      Created Date :          2025-11-10
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////


from typing import List, Optional
from bson import ObjectId

from slugify import slugify
from datetime import datetime

from app.models.vjob import (VJob, VJobBase, VJobInDB,)
from app.models.session import SessionLock, SessionLockEnum

from app.models.ds2.reporting import ReportingMessage
from app.models.ds2.reporting import ReportingMessageInDB, ReportingInfo

from pymongo import DESCENDING
from app.db.mongodb import AsyncIOMotorClient
from app.core.config import database_name, vjobs_collection

from app.core.config import reporting_collection

from bson.objectid import ObjectId

import dateutil

from fastapi.logger import logger


########## Reporting Message  #################

async def store_reporting(conn: AsyncIOMotorClient, state_doc: ReportingMessage) -> str:

    #state = ReportingMessageInDB(**state_doc.dict())
    #state.created_at = ObjectId(state.id).generation_time
    #state.updated_at = ObjectId(state.id).generation_time
    #row = await conn[database_name][reporting_collection].insert_one(state.dict())

    #return str(row.inserted_id)

    state = ReportingMessageInDB(**state_doc.dict())

    now = datetime.utcnow()
    state.created_at = now
    state.updated_at = now

    data = state.dict()
    # ensure non-serializable objects like Path are converted
    if "output_filename" in data and hasattr(data["output_filename"], "__fspath__"):
        data["output_filename"] = str(data["output_filename"])

    result = await conn[database_name][reporting_collection].insert_one(data)

    oid = result.inserted_id
    created_at_from_oid = oid.generation_time.replace(tzinfo=None)

    state.id = str(oid)
    state.created_at = created_at_from_oid

    return str(oid)

async def get_reporting(conn: AsyncIOMotorClient, state_id: str) -> ReportingMessage:
    object_id = ObjectId(state_id)
    row = await conn[database_name][reporting_collection].find_one({"_id": object_id})
    if row:
        state = ReportingMessage(**row)
        return state
    else:
        raise Exception(f"Could not locate reporting: {state_id}")

async def remove_reportings(conn: AsyncIOMotorClient, model_id) -> int:
    result = await conn[database_name][reporting_collection].delete_many({"model_id": model_id})
    return result.deleted_count

async def remove_reporting(conn: AsyncIOMotorClient, state_id: str) -> int:
    object_id = ObjectId(state_id)
    result = await conn[database_name][reporting_collection].delete_one({"_id": object_id})

    if result.deleted_count != 1:
        raise Exception(f"Failed to delete reporting: {state_id}")

    return result.deleted_count

async def xupdate_reporting_status(conn: AsyncIOMotorClient, rid: str, status: str, msg: str="") -> ReportingMessage:
    oid = ObjectId(rid)
    rjob = await get_reporting(conn, oid)
    if rjob:
        rjob.status = status
    rjob.updated_at = datetime.utcnow()
    updated_at = await conn[database_name][reporting_collection].update_one(
            {"_id": oid}, {'$set': rjob.dict()})
    rjob.updated_at = updated_at
    return vjob

async def update_reporting_status(
    conn: AsyncIOMotorClient,
    rid: str,
    status: str,
    msg: str = ""
) -> Optional["ReportingMessage"]:
    """
    Update the status (and optional message) of a reporting job in the database.

    Parameters
    ----------
    conn : AsyncIOMotorClient
        The MongoDB client connection.
    rid : str
        The reporting job ID (string representation of an ObjectId).
    status : str
        The new status value (e.g., 'running', 'completed', 'failed').
    msg : str, optional
        Optional status message or log detail.

    Returns
    -------
    ReportingMessage or None
        The updated ReportingMessage document, or None if not found.
    """
    oid = ObjectId(rid)
    now = datetime.utcnow()
    update_doc = {
        "$set": {
            "updated_at": now
        }
    }

    if status is not None:
        update_doc["$set"]["status"] = status

    if msg:
        update_doc["$push"] = {"messages": {"timestamp": now, "text": msg}}

    result = await conn[database_name][reporting_collection].update_one(
        {"_id": oid},
        update_doc
    )

    if result.matched_count == 0:
        logger.warning(f"No reporting job found for id: {rid}")
        return None

    # Fetch the updated document
    updated_doc = await conn[database_name][reporting_collection].find_one({"_id": oid})
    if not updated_doc:
        return None

    # Convert to Pydantic model (ReportingMessageInDB)
    return ReportingMessage(**updated_doc)

########## Reporting Message End  #################

