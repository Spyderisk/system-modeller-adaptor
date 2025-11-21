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

from app.models.cve.sbomcve import CVESBOM, SBOMList, SBOMListInDB
from app.models.ssm.twa import CVE2TWAReport, TWASChangeRecord

from pymongo import DESCENDING
from app.db.mongodb import AsyncIOMotorClient
from app.core.config import database_name, vjobs_collection

from app.core.config import sbomcve_collection

from bson.objectid import ObjectId

import dateutil

import hashlib

from fastapi.logger import logger


########## Reporting Message  #################

async def store_sbomlist(conn: AsyncIOMotorClient, state_doc: SBOMList) -> str:

    state = SBOMListInDB(**state_doc.dict())

    now = datetime.utcnow()
    state.created_at = now
    state.updated_at = now

    data = state.dict()

    result = await conn[database_name][sbomcve_collection].insert_one(data)

    oid = result.inserted_id
    created_at_from_oid = oid.generation_time.replace(tzinfo=None)

    state.id = str(oid)
    state.created_at = created_at_from_oid

    return str(oid)

async def get_sbomlist(conn: AsyncIOMotorClient, state_id: str) -> SBOMList:
    object_id = ObjectId(state_id)
    row = await conn[database_name][sbomcve_collection].find_one({"_id": object_id})
    if row:
        renamed_products = {}
        for k, v in row['products'].items():
            renamed_products[v[0]['asset_name']] = v
        row['products'] = renamed_products
        state = SBOMList(**row)
        return state
    else:
        raise Exception(f"Could not locate SBOMCVE: {state_id}")

async def remove_sbomlist(conn: AsyncIOMotorClient, model_id) -> int:
    result = await conn[database_name][sbomcve_collection].delete_many({"model_id": model_id})
    return result.deleted_count

async def remove_sbomlist(conn: AsyncIOMotorClient, state_id: str) -> int:
    object_id = ObjectId(state_id)
    result = await conn[database_name][sbomcve_collection].delete_one({"_id": object_id})

    if result.deleted_count != 1:
        raise Exception(f"Failed to delete sbomcve: {state_id}")

    return result.deleted_count


async def update_sbomlist_products(conn: AsyncIOMotorClient, sbomid: str,
                                   status: Optional[str] = None,
                                   products: Optional[Dict[str, List[CVE2TWAReport]]] = None
                                   ) -> Optional["SBOMList"]:

    oid = ObjectId(sbomid)
    now = datetime.utcnow()

    update_doc = {
        "$set": {
            "updated_at": now
        }
    }

    if status:
        update_doc["$set"]["status"] = status

    if products:
        # Flatten dict into field updates
        for product_name, reports in products.items():
            report_dicts = [
                r.model_dump() if hasattr(r, "model_dump") else r
                for r in reports
            ]
            hash_name = hashlib.sha256(product_name.encode()).hexdigest()
            update_doc["$set"][f"products.{hash_name}"] = report_dicts

    result = await conn[database_name][sbomcve_collection].update_one(
        {"_id": oid},
        update_doc
    )

    if result.matched_count == 0:
        logger.warning(f"No reporting job found for id: {rid}")
        return None

    # Fetch the updated document
    updated_doc = await conn[database_name][sbomcve_collection].find_one({"_id": oid})
    if not updated_doc:
        return None
    logger.debug(f"RETURN {type(updated_doc)}")
    renamed_products = {}
    for k, v in updated_doc['products'].items():
        renamed_products[v[0]['asset_name']] = v
    updated_doc['products'] = renamed_products
    # Convert to Pydantic model (ReportingMessageInDB)
    return SBOMList(**updated_doc)

########## Reporting Message End  #################

