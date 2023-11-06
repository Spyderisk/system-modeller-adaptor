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
##      Created Date :          2021-01-19
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////


from fastapi import HTTPException

from app.models.session import SessionLockEnum
from app.models.properties import AssetMetadataList

from app.ssm.ssm_client import SSMClient

from app.crud.store import update_status
from app.crud.store import release_session_lock, get_session

from fastapi.logger import logger


async def bg_find_asset(modelId: str, key: str, vjid: str, db_conn,
                        ssm_client: SSMClient):

    # We assume we have a session lock
    logger.info(f"bg job find asset {modelId}")
    asset_metadata_list = None
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to verify lock")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed check model found OK")

        # validate model
        #if not ssm_client.validate_model(modelId):
        #    logger.error("ERROR: model not validated")
        #    # model is not validated.
        #    raise Exception("model failed to validate")

        logger.info("passed check model validation OK")

        assets = ssm_client.get_assets(modelId)
        asset_list = []
        for asset in assets:
            metadata = ssm_client.get_asset_metadata(modelId, asset.id, async_req=False)
            if metadata:
                logger.debug(f"ASSET found {asset.id} with metadata {metadata}")
                properties = {
                        'asset_id': asset.id,
                        'asset_label': asset.label,
                        'additional_properties': []
                        }
                match_flag = False
                for entry in metadata:
                    properties['additional_properties'].append({'key': entry.key, 'value': entry.value})
                    if entry.key == key:
                        match_flag = True
                if match_flag:
                    asset_list.append(properties)

        asset_metadata_list = AssetMetadataList(**{'asset_list': asset_list})

        logger.debug(f"Asset metatata list: {asset_metadata_list}")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("find assets has finised")

    except Exception as e:
        logger.error("Exception when finding asset: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
        raise HTTPException(status_code=503, detail="find asset failed")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return asset_metadata_list
