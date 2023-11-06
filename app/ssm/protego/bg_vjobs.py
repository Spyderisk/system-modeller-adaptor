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

import time
from bson.objectid import ObjectId

from fastapi import HTTPException
from fastapi.logger import logger

from app.ssm.ssm_client import SSMClient

from app.models.protego.vulnerability import CVSS
from app.models.protego.twa import TWA
from app.models.session import SessionLockEnum

from app.crud.store import update_status, get_vjob
from app.crud.store import release_session_lock, get_session

from app.ssm.protego.bg_rollback_utils import store_twas

async def get_vjob_status(db_conn, vjob_id: str):
    """ get job status example method """

    logger.debug(f"AWAITING to get job {vjob_id} status")
    status = await get_vjob(db_conn, ObjectId(vjob_id))
    logger.debug(f"AWAITING to get job {vjob_id} status DONE")
    return status

async def get_model_test(model_id, vjid, db_conn, ssm_client):
    """ get model test async method getting model """

    logger.debug("Start background Job to update model")
    await update_status(db_conn, vjid, "RUNNING")
    #await asyncio.sleep(20)
    model = ssm_client.get_full_model(model_id)
    logger.debug(f"model risk {model.risk['label']}")
    logger.degub(f"finished background Job {vjid} to update model")
    await update_status(db_conn, vjid, "FINISHED")


# /models/{modelId}/aset/vulnerability
async def bg_update_vulnerabilities_only(modelId: str, vjid: str, body: CVSS,
                                         db_conn, ssm_client: SSMClient):
    """ background method to update vulnerabilities from an OpenVAS report """

    p_vul_start = time.perf_counter()

    logger.info(f"update_vulnerability for {modelId}")
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {session.task_id} != {vjid}")
            raise Exception("model failed to verify lock")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)

        logger.info(f"A new request has been received for {model.name} with id {model.id}.")

        # validate model
        #if not ssm_client.validate_model(modelId):
        #    logger.error("ERROR: model not validated")
        #    await update_status(db_conn, vjid, "FAILED", "model validation failed")
        #    raise Exception("Precondition operation failed to validate the model")
        #logger.info("passed model validation check")

        # Check the validity of the cvss version. Only CVSS 2.0 is currently supported.
        assert (body.cvss_version == 2.0)

        # Get the set identifiers from the OpenVAS report to uniquely identify
        # and retrieve the corresponding asset in the SSM model

        logger.info(f"asset identifiers ({body.identifiers})")

        identifiers = [{'key': 'ip_address', 'value': body.identifiers.ip_address},
                       {'key': 'port', 'value': body.identifiers.port}]

        logger.debug(f"recomposed identifiers: {identifiers}, {type(identifiers)}")

        asset = ssm_client.find_ssm_asset(identifiers, modelId)

        if not asset:
            logger.error("Failed to identify asset in model")
            raise Exception("Failed to identify asset in model")

        logger.info(f"identified asset {asset.id} {asset.label}")

        # Get asset's metadata
        #asset_meta = ssm_client.get_asset_metadata(modelId, asset.id)
        #logger.info("got asset_meta")

        # Get the list of vulnerabilities for the given asset
        vulnerabilities = body.vulnerabilities

        # Update asset's meta-data to keep information on the vulnerabilities
        # discovered.
        #
        # Use the name of the NVT vulnerability as an identifier (
        # using the 'NVT' prefix) and parse the whole content as a value
        vuln_names = [f"NVT {vuln.name}" for vuln in vulnerabilities]

        logger.info(f'List of vulnerabilities discovered: ')
        for vuln_name in vuln_names:
            logger.info(vuln_name)

        # Remove vulnerabilities from the meta-data of the asset that are not
        # longer detected.
        # TODO check the code below
        # Get a list of all vulnerabilities existing in the given asset
        # current_vulnerabilities = [metapair for metapair in asset_meta
        #                            if not metapair.key.find('NVT') == -1]
        # Get a list of all new vulnerabilities referring to the given asset
        # missing_vulnerabilities = \
        #     set(current_vulnerabilities).difference(vulnerabilities)
        # for mv in missing_vulnerabilities:
        #     api_asset.delete_asset_metadata(modelId, asset['id'], mv)
        #
        # for vulnerability in vulnerabilities:
        #     api_asset.add_asset_metadata(modelId, asset['id'], vulnerability)

        # Update Trustworthiness levels
        # Retrieve current TWAs from the retrieved asset
        current_twas = asset.trustworthiness_attribute_sets
        logger.info(f"Retrieved current TWAs: {len(current_twas)}")

        #for tw_key, tw_val in current_twas.items():
        #    print(tw_key)
        #    cropped_tw_key = tw_key[tw_key.find('TWAS'):]
        #    cropped_tw_key = re.sub(f'-{asset.id}', '', cropped_tw_key)
        #    print(f'Updating {cropped_tw_key} TWAS for {asset.label}')
        #    api_asset.asset_twas_update(modelId, asset.id, tw_val)  # update

        logger.info(f"Number of vulenrabilities to parse {len(vulnerabilities)}")
        for vulnerability in vulnerabilities:
            logger.info(f'Processing vulnerability: \"{vulnerability.name}\"')

            cvss = vulnerability.cvss_base_vector
            logger.info(f'Base CVSS vector: [{cvss}]')

            # convert cvss base vector to python dictionary
            # "AV:N/AC:L/Au:N/C:P/I:P/A:P" -> {"AV": "N", ...}
            cvss_vectors = cvss.split('/')
            cvss_dict = {}
            for vector in cvss_vectors:
                tw_key, tw_value = vector.split(':')
                cvss_dict[tw_key] = tw_value

            # 1. Access Complexity - get trustworthiness level
            if 'AC' in cvss_dict:
                logger.info("1. Access Complexity - get trustworthiness level")
                tw_level_lbl, tw_level_uri = ssm_client.complexity_to_trustworthness(cvss_dict['AC'])
                logger.info(f"TWLevel: {tw_level_lbl},   URI: {tw_level_uri[67:]}")
            else:
                logger.info("CVSS Access Complexity NOT found")

            # 2. Access Vector
            if 'AV' in cvss_dict:
                logger.info("2. Access Vector")
                ssm_client.parse_access_vector(cvss_dict['AV'], tw_level_uri,
                                               current_twas, asset.id, asset.label, modelId)
            else:
                logger.info("CVSS Access Vector NOT found")

            # 3. Authentication
            if 'Au' in cvss_dict:
                logger.info("3. Authentication")
                ssm_client.parse_authentication(cvss_dict['Au'], tw_level_uri,
                                                current_twas, asset.id, asset.label, modelId)
            else:
                logger.info("CVSS Authentication NOT found")

            # 4. CWEs
            logger.info("4. CWEs")
            # extract all cwes from all cves and check if there are weaknesses
            cves = vulnerability.cves
            ssm_client.parse_cwes(cves, cvss_dict, tw_level_uri, current_twas,
                                  asset.id, asset.label, modelId)

        # validate model
        #if not ssm_client.validate_model(modelId):
        #    print("ERROR: model not validated")
        #    raise HTTPException(status_code=412, detail="failed to validate model")

        logger.info("finished updating TWAs")
        await update_status(db_conn, vjid, "FINISHED")

        if ssm_client.twa_changes:
            logger.debug(f"Recorded TWA changes len: {len(ssm_client.twa_changes)}, {ssm_client.twa_changes}")
            await store_twas(ssm_client, db_conn)
        else:
            logger.debug("no TWA changes recorded")

        p_vul_finish = time.perf_counter()
        logger.debug(f"Time stats: vulnerability completed in {p_vul_finish - p_vul_start} sec")

    except Exception as ex:
        logger.error(f"Exception when calling update_vulnerabilities_only: {ex}")
        await update_status(db_conn, vjid, "FAILED", str(ex))
        raise HTTPException(status_code=503, detail="validation operation failed")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return
