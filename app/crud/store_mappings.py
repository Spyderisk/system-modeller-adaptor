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


from typing import List, Dict, Optional
from bson import ObjectId

from slugify import slugify
from datetime import datetime

from app.models.vjob import (VJob, VJobBase, VJobInDB,)
from app.models.session import SessionLock, SessionLockEnum

from app.models.cve.mapping import ProductMap, ProductMapInDB
from app.models.ssm.twa import CVE2TWAReport, TWASChangeRecord

from pymongo import DESCENDING
from app.db.mongodb import AsyncIOMotorClient
from app.core.config import database_name, vjobs_collection

from app.core.config import mapping_collection

from bson.objectid import ObjectId

import dateutil

from fastapi.logger import logger


########## Reporting Mapping  #################

async def store_mapping(conn: AsyncIOMotorClient, model_webkey: str, mapping_doc: ProductMap) -> str:

    state = ProductMapInDB(**mapping_doc.dict())

    now = datetime.utcnow()
    state.created_at = now
    state.updated_at = now
    state.ssm_model_id = model_webkey

    data = state.dict()

    result = await conn[database_name][mapping_collection].insert_one(data)

    oid = result.inserted_id
    created_at_from_oid = oid.generation_time.replace(tzinfo=None)

    state.id = str(oid)
    state.created_at = created_at_from_oid

    return str(oid)

async def get_mapping(conn: AsyncIOMotorClient, mapping_id: str) -> ProductMap:
    object_id = ObjectId(mapping_id)
    row = await conn[database_name][mapping_collection].find_one({"_id": object_id})
    if row:
        state = ProductMap(**row)
        return state
    else:
        raise Exception(f"Could not locate ProductMap: {mapping_id}")

async def remove_mappings(conn: AsyncIOMotorClient, model_id) -> int:
    result = await conn[database_name][mapping_collection].delete_many({"model_id": model_id})
    return result.deleted_count

async def remove_mapping(conn: AsyncIOMotorClient, mapping_id: str) -> int:
    object_id = ObjectId(mapping_id)
    result = await conn[database_name][mapping_collection].delete_one({"_id": object_id})

    if result.deleted_count != 1:
        raise Exception(f"Failed to delete mapping: {mapping_id}")

    return result.deleted_count


########## Product mapping End  #################

