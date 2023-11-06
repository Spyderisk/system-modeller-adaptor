##///////////////////////////////////////////////////////////////////////
##
## © University of Southampton IT Innovation Centre, 2023
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
##      Created Date :          2023-09-13
##      Created for Project :   Cyberkit4SME
##
##///////////////////////////////////////////////////////////////////////

from typing import List, Optional
from bson import ObjectId

from slugify import slugify
from datetime import datetime

from app.models.vjob import (VJob, VJobBase, VJobInDB,)
from app.models.session import SessionLock, SessionLockEnum

from app.models.protego.recommendations import ObjectRecommendation
from app.models.protego.recommendations import StoredRecInDB

from app.models.state_report import StateReportMessage
from app.models.state_report import StateReportMessageInDB, StateReportInfo

from pymongo import DESCENDING
from app.db.mongodb import AsyncIOMotorClient
from app.core.config import database_name, vjobs_collection

from app.core.config import state_report_collection

from bson.objectid import ObjectId

import dateutil

from fastapi.logger import logger


########## State Report Message  #################

async def store_state_report(conn: AsyncIOMotorClient, model_id: str,
        state_doc: StateReportMessage) -> str:

    state = StateReportMessageInDB(**state_doc.dict())
    state.created_at = ObjectId(state.id).generation_time
    state.updated_at = ObjectId(state.id).generation_time
    state.model_id = model_id
    row = await conn[database_name][state_report_collection].insert_one(state.dict())

    return str(row.inserted_id)

async def get_stored_state_report(conn: AsyncIOMotorClient, state_id: str) -> StateReportMessage:
    object_id = ObjectId(state_id)
    row = await conn[database_name][state_report_collection].find_one({"_id": object_id})
    if row:
        state = StateReportMessage(**row)
        return state
    else:
        raise Exception(f"Could not locate state report: {state_id}")

async def remove_state_reports(conn: AsyncIOMotorClient, model_id) -> int:
    result = await conn[database_name][state_report_collection].delete_many({"model_id": model_id})
    return result.deleted_count

async def remove_state_report(conn: AsyncIOMotorClient, state_id: str) -> int:
    object_id = ObjectId(state_id)
    result = await conn[database_name][state_report_collection].delete_one({"_id": object_id})

    if result.deleted_count != 1:
        raise Exception(f"Failed to delete state report: {state_id}")

    return result.deleted_count

async def get_newer_reports(conn: AsyncIOMotorClient, model_id, date: str) -> List[StateReportMessage]:
    date_time = dateutil.parser.parse(date)
    logger.debug(f"CRUD get state reports newer than {date_time}, model_id: {model_id}")
    reports = []
    cursor = conn[database_name][state_report_collection].find({"model_id": model_id, "created_at": { "$gt": date_time}}).sort("created_at", DESCENDING)
    for document in await cursor.to_list(length=100):
        created_at = document["created_at"]
        report = StateReportMessage(**document)
        if not report.expiry:
            reports.append(report)
        elif report.expiry.parse(created_at):
            reports.append(report)
        else:
            logger.debug(f"\tinvalid report ({document['_id']}): {report.expiry}")
            #TODO delete expired reports

    return reports

async def get_valid_reports(conn: AsyncIOMotorClient, model_id) -> List[StateReportMessageInDB]:
    logger.debug(f"CRUD get valid state reports for model_id: {model_id}")
    reports = []
    cursor = conn[database_name][state_report_collection].find({"model_id": model_id}).sort("created_at", DESCENDING)
    for document in await cursor.to_list(length=100):
        created_at = document["created_at"]
        logger.debug(f"CREATED AT: {created_at}")
        report = StateReportMessageInDB(**document)
        report.id = str(document['_id'])
        if not report.expiry:
            reports.append(report)
        elif report.parse_expiry(created_at):
            reports.append(report)
        else:
            logger.debug(f"\tinvalid report ({document['_id']}): {report.expiry}")
            #TODO delete expired reports

    return reports

async def get_all_reports(conn: AsyncIOMotorClient, model_id) -> List[StateReportMessage]:
    reports = []
    cursor = conn[database_name][state_report_collection].find({"model_id": model_id})
    for document in await cursor.to_list(length=100):
        report_info = StateReportInfo(**document)
        report_info.id = str(document["_id"])
        reports.append(report_info)

    return reports

async def get_expired_reports(conn: AsyncIOMotorClient, model_id) -> List[str]:
    logger.debug(f"CRUD remove expired reports for model {model_id}")
    logger.debug(f"CRUD db: {type(conn)}, {conn}")
    report_ids = []
    cursor = conn[database_name][state_report_collection].find({"model_id": model_id})
    for document in await cursor.to_list(length=100):
        created_at = document["created_at"]
        report = StateReportMessage(**document)
        if not report.expiry or report.parse_expiry(created_at):
            pass
        else:
            logger.debug(f"\tinvalid report ({document['_id']}): {report.expiry}")
            report_ids.append(document['_id'])
    return report_ids

########## State Report Message End  #################

