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
##      Created By :            Samuel Senior
##      Created Date :          2021-06-03
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

from app.models.protego.twa import TWA, TWAChange

from app.crud.store import store_twa_change, get_twa_changes, remove_twa_changes

from fastapi.logger import logger

async def store_twas(ssm_client, db_conn):
    """ Store TWA changes recorded in ssm_client object and clean twa_changes
    list. """

    logger.debug(f"storing twa {len(ssm_client.twa_changes)} changes in db")
    for twa in ssm_client.twa_changes:
        logger.debug(f"storing TWA change: {twa}")
        await store_twa_change(db_conn, TWA(**twa))

    logger.info("flush twa_chanages list")
    ssm_client.twa_changes = []


async def restore_twas(model_id, ssm_client, db_conn):
    """ Restore TWA to their previous values """

    logger.debug("fetch stored twas")
    twas = await get_twa_changes(db_conn, model_id)

    if twas:
        logger.debug(f"{len(twas)} TWAs found for rolling back")
        ssm_client.undo_twas_many(twas)

        # clear twa changes track
        logger.debug("clearing TWA cache")
        num = await remove_twa_changes(db_conn, model_id)
        logger.debug(f"{num} TWAs removed from cache")
    else:
        logger.debug("no TWAs found to restore")


async def list_twas(model_id, db_conn):
    """ List changed TWAs """

    logger.debug("fetch stored twas")
    twas = await get_twa_changes(db_conn, model_id)

    twas_list = []
    for twa in twas:
        twa.twa_key =  twa.twa_key[67:]
        logger.debug(f"{twa.twa_key} changed value from {twa.changed_from[87:]} -> {twa.changed_to[87:]}")
        twas_list.append(TWAChange(**twa.dict()))

    return twas_list

async def clear_twas(model_id, db_conn):
    """ clear stored TWA changes """

    logger.debug("fetch stored twas")
    twas = await get_twa_changes(db_conn, model_id)

    if twas:
        logger.debug(f"{len(twas)} TWAs found for clearing back")

        # clear twa changes track
        logger.debug("clearing TWA cache")
        num = await remove_twa_changes(db_conn, model_id)
        logger.debug(f"{num} TWAs removed from cache")
    else:
        logger.debug("no TWAs found to clear")


