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


from typing import List, Optional
from bson import ObjectId

from slugify import slugify
from datetime import datetime

from app.models.vjob import (VJob, VJobBase, VJobInDB,)
from app.models.protego.recommendations import ObjectRecommendation
from app.models.protego.recommendations import StoredRecInDB
from app.models.graph import SVGPlot, StoredSVGPlotInDB
from app.models.protego.twa import TWA, TWAInDB
from app.models.risk import State, StateInDB
from app.models.session import SessionLock, SessionLockEnum

from pymongo import DESCENDING
from app.db.mongodb import AsyncIOMotorClient
from app.core.config import database_name, vjobs_collection
from app.core.config import risk_collection, rec_collection
from app.core.config import session_collection
from app.core.config import twas_change_collection
from app.core.config import plot_collection

from fastapi.logger import logger

########## Session Lock #################

async def create_session(conn: AsyncIOMotorClient, job_id: str,  model_id: str) -> SessionLock:
    logger.debug(f"creating sessing lock object for {model_id}, {job_id}")
    session = SessionLock(**{"model_id": model_id, "task_id": job_id})
    session.created_at = ObjectId(session.id).generation_time
    session.updated_at = ObjectId(session.id).generation_time
    row = await conn[database_name][session_collection].insert_one(session.dict())
    session = await conn[database_name][session_collection].find_one({"_id": row.inserted_id})
    logger.info(f"created session {session}")
    return session


async def get_session(conn: AsyncIOMotorClient, model_id: str) -> SessionLock:
    logger.debug(f"get_session, {model_id}")
    row = await conn[database_name][session_collection].find_one({"model_id": model_id})
    if row:
        session = SessionLock(**row)
        session.id = str(row["_id"])
        return session

async def release_lock(conn: AsyncIOMotorClient, model_id: str = None) -> SessionLock:
    logger.debug(f"release_session {model_id}")
    session = await get_session(conn, model_id)
    if session:
        session.status = SessionLockEnum.unlocked
        session.updated_at = datetime.now()
        updated_at = await conn[database_name][session_collection].update_one({"_id": session._id}, {'$set': session.dict()})
        return updated_at


async def acquire_session_lock(conn: AsyncIOMotorClient, job_id: str) -> SessionLock:
    logger.debug(f"acquire session lock {job_id}")
    job = await get_vjob(conn, ObjectId(job_id))
    if job:
        logger.debug(f"JOB found: {job}, type: {type(job)}")
        session = await get_session(conn, job.modelId)
        if session:
            if session.model_id == job.modelId and session.status == SessionLockEnum.unlocked:
                session.task_id = job_id
                session.status = SessionLockEnum.locked
                session.updated_at = datetime.now()
                updated_at = await conn[database_name][session_collection].\
                        update_one({"_id": ObjectId(session.id)}, {'$set': session.dict()})
                logger.debug(f"lock acquired for {job_id}")
                return updated_at
            else:
                logger.info(f"session is locked by process {session.task_id}")
        else:
            logger.info("no session found for this model id, creating a new one")
            session = await create_session(conn, job_id, job.modelId)
            return session


async def release_session_lock(conn: AsyncIOMotorClient, job_id: str) -> SessionLock:
    logger.debug(f"release session lock {job_id}")
    job = await get_vjob(conn, ObjectId(job_id))
    if job:
        session = await get_session(conn, job.modelId)
        if session:
            if session.task_id == job_id and session.status == SessionLockEnum.locked:
                session.status = SessionLockEnum.unlocked
                session.task_id = None
                session.updated_at = datetime.now()
                updated_at = await conn[database_name][session_collection].\
                        update_one({"_id": ObjectId(session.id)}, {'$set': session.dict()})
                return updated_at
            else:
                logger.info(f"session is locked by another process {session.task_id}")
        else:
            logger.info("no session found for this model id, creating a new one")


########## Session Lock End #################

async def create_vjob(conn: AsyncIOMotorClient, vul_doc: VJob) -> VJobInDB:
    vul = VJobInDB(**vul_doc)
    vul.created_at = ObjectId(vul.id).generation_time
    vul.updated_at = ObjectId(vul.id).generation_time
    row = await conn[database_name][vjobs_collection].insert_one(vul.dict())
    job = await conn[database_name][vjobs_collection].find_one({"_id": row.inserted_id})
    vul.id = row.inserted_id

    return vul


async def get_vjob(conn: AsyncIOMotorClient, oid: ObjectId) -> VJobInDB:
    row = await conn[database_name][vjobs_collection].find_one({"_id": oid})
    if row:
        job = VJobInDB(**row)
        job.id = str(oid)
        return job

async def update_status(conn: AsyncIOMotorClient, vjid: str, status: str, err_msg: str = "") -> VJobInDB:
    oid = ObjectId(vjid)
    vjob = await get_vjob(conn, oid)
    if vjob:
        vjob.status = status
        if err_msg:
            if vjob.err_msg:
                js = ", ".join([vjob.err_msg, err_msg])
                vjob.err_msg = js
            else:
                vjob.err_msg = err_msg
            #vjob.err_msg = err_msg
        vjob.updated_at = datetime.utcnow()
        updated_at = await conn[database_name][vjobs_collection]\
                .update_one({"_id": oid}, {'$set': vjob.dict()})
        vjob.updated_at = updated_at

        return vjob

async def store_rec(conn: AsyncIOMotorClient, jid: str, rec_doc: ObjectRecommendation) -> StoredRecInDB:
    rec = StoredRecInDB(**rec_doc.dict())
    rec.jobid = jid
    rec.created_at = ObjectId(rec.id).generation_time
    rec.updated_at = ObjectId(rec.id).generation_time
    row = await conn[database_name][rec_collection].insert_one(rec.dict())
    job = await conn[database_name][rec_collection].find_one({"_id": row.inserted_id})
    rec.id = row.inserted_id

    return rec

async def get_recommendations(conn: AsyncIOMotorClient, jid: str) -> ObjectRecommendation:
    row = await conn[database_name][rec_collection].find_one({"jobid": jid})
    if row:
        recommendations = ObjectRecommendation(**row)
        return recommendations

async def store_plot(conn: AsyncIOMotorClient, jid: str, plot: SVGPlot) -> StoredSVGPlotInDB:
    rec = StoredSVGPlotInDB(**plot.dict())
    rec.jobid = jid
    rec.created_at = ObjectId(rec.id).generation_time
    rec.updated_at = ObjectId(rec.id).generation_time
    row = await conn[database_name][plot_collection].insert_one(rec.dict())
    job = await conn[database_name][plot_collection].find_one({"_id": row.inserted_id})
    rec.id = row.inserted_id

    return rec

async def get_plot(conn: AsyncIOMotorClient, jid: str, recid: str) -> SVGPlot:
    row = await conn[database_name][plot_collection].find_one({"jobid": jid, "recid": recid})
    if row:
        svg_plot = SVGPlot(**row)
        return svg_plot


async def store_state(conn: AsyncIOMotorClient, jid: str, risk_doc: State) -> StateInDB:
    risk = StateInDB(**risk_doc.dict())
    risk.jobid = jid
    risk.created_at = ObjectId(risk.id).generation_time
    risk.updated_at = ObjectId(risk.id).generation_time
    row = await conn[database_name][risk_collection].insert_one(risk.dict())
    job = await conn[database_name][risk_collection].find_one({"_id": row.inserted_id})
    risk.id = row.inserted_id

    return risk

async def get_state(conn: AsyncIOMotorClient, jid: str) -> State:
    row = await conn[database_name][risk_collection].find_one({"jobid": jid})
    if row:
        state = State(**row)
        return state

# store twa changes
async def store_twa_change(conn: AsyncIOMotorClient, twa_change: TWA) -> TWAInDB:
    twa = TWAInDB(**twa_change.dict())
    twa.created_at = ObjectId(twa.id).generation_time
    #twa.updated_at = ObjectId(twa.id).generation_time
    row = await conn[database_name][twas_change_collection].insert_one(twa.dict())
    job = await conn[database_name][twas_change_collection].find_one({"_id": row.inserted_id})
    twa.id = row.inserted_id
    return twa

async def get_twa_changes(conn: AsyncIOMotorClient, model_id: str) -> List[TWAInDB]:
    """ note changes are in reverse order """
    twas = []
    #cursor = conn[database_name][twas_change_collection].find({"model_id": model_id})
    #cursor = conn[database_name][twas_change_collection].find({"model_id": model_id}).sort("_id", -1)
    cursor = conn[database_name][twas_change_collection].find({"model_id": model_id}).sort("_id", DESCENDING)
    for doc in await cursor.to_list(length=200):
        logger.debug(f"TWA stored item: {doc['_id']}")
        twa = TWA(**doc)
        twas.append(twa)
    return twas

async def remove_twa_changes(conn: AsyncIOMotorClient, model_id: str) -> int:
    n1 = await conn[database_name][twas_change_collection].count_documents({"model_id": model_id})
    logger.debug(f"{n1} TWAs found for deleting")
    result = conn[database_name][twas_change_collection].delete_many({"model_id": model_id})
    n2 = await conn[database_name][twas_change_collection].count_documents({"model_id": model_id})
    return n2 - n1

