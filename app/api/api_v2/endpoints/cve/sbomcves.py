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
##      Created Date :          2025-08-28
##      Created for Project :   TELEMETRY
##
##///////////////////////////////////////////////////////////////////////

from typing import List
from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import Response
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi import status, Query
from fastapi import Body

from fastapi import UploadFile, File

from app.db.mongodb import AsyncIOMotorClient, get_database
from fastapi import BackgroundTasks
import json

from app.models.cve.sbomcve import CVESBOM, SBOMList
from app.models.cve.mapping import ProductMap, ProductMapDict

from app.crud.store_sbomlist import store_sbomlist, get_sbomlist
from app.crud.store_mappings import store_mapping, get_mapping

from app.ssm.indicators.bg_workflow_i import bg_workflow_i, bg_workflow_multi

from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base
from ssmclientlib.exceptions import ApiException
from fastapi.logger import logger

router = APIRouter(tags=['TELEMETRY'])

@router.get(
    "/sbom/{model_webkey}/productmap",
    summary="Retrieve a product map by ID",
    status_code=status.HTTP_200_OK,
)
async def get_productmap(
        mapping_id: str = Query(..., description="Mapping identifier"),
        model_webkey: str = Path(..., title="Model webkey"),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
    ):

    logger.info(f"Get mapping {mapping_id} for model: {model_webkey}")
    try:
        mapping_data = await get_mapping(db_client, mapping_id)

        if not mapping_data:
            raise HTTPException(status_code=404, detail=f"Mapping '{mapping_id}' not found")

        return JSONResponse(content=jsonable_encoder(mapping_data.data))

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving mapping: {e}")


@router.post(
    "/sbom/{model_webkey}/productmap",
    responses={
        404: {"description": "Model not found"},
        423: {"description": "Resource locked, by another process try again later."},
        500: {"description": "Internal server error."},
    },
    summary="Upload ProductMap mapping",
    status_code=status.HTTP_200_OK,
)
async def upload_product_map(
        model_webkey: str = Path(..., title="Model webkey"),
        file: UploadFile = File(..., description="JSON file containing product map"),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):
    """
    Upload a product mapping from a JSON file.
    """
    logger.info(f"Parsing product mapping for model: {model_webkey}")

    try:
        # Read uploaded file
        contents = await file.read()

        # Parse JSON
        json_data = json.loads(contents)

        # Validate as ProductMap
        product_map = ProductMapDict(json_data)
        p1 = ProductMap(data=json_data)

        logger.debug(f"Product mapping has {len(product_map.root)} entries")
        for product, vals in product_map.root.items():
            logger.debug(f"  {product}: {vals}")

        # Store or process as needed here
        mapping_id = await store_mapping(db_client, model_webkey, p1)
        logger.debug(f"Mapping stored with id: {mapping_id}")

        return JSONResponse({"status": "ok", "mapping_id": mapping_id})

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail="Model not found")
    except Exception as e:
        logger.error("Exception in product map endpoint: %s\n" % e)
        raise HTTPException(status_code=500, detail=f"Failed to process product map: {e}")


#@router.post("/sbom/{model_webkey}/productmap1",
#            responses={
#                404: {"description": "Model not found"},
#                423: {"description": "Resource locked, by another process try again later."},
#                500: {"description": "Internal server error."},
#                },
#            summary="Upload ProductMapI mapping",
#            status_code=status.HTTP_200_OK)
#async def sbomlist(
#        product_map: ProductMap,
#        model_webkey: str = Path(..., title="Model webkey"),
#        db_client: AsyncIOMotorClient = Depends(get_database),
#        ssm_client: SSMClient = Depends(get_ssm_base),
#        ):
#    """Upload an prduct mapping """
#
#    logger.info(f"Parsing product mapping for model: {model_webkey}")
#
#    try:
#        #TODO
#        # Check whether the system model exists (via basic model info)
#        ##model = ssm_client.get_model_info(model_webkey)
#        ##assert (model is not None)
#
#        # Check CVEs
#        logger.debug(f"product mapping has: {product_map}")
#        for product, val in product_map.root.items():
#            logger.debug(f"\tReceived product: {product}: {val}")
#
#        #state_id = await store_sbomlist(db_client, sbomlist_obj)
#        #logger.debug(f"STATUS: {state_id}")
#
#        return JSONResponse({"status": "ok", "productmap": "23"})
#
#    except ApiException as api_ex:
#        logger.info(f"API exception: model not found {api_ex}")
#        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
#    except Exception as e:
#        logger.error("Exception in product map endpoint: %s\n" % e)
#        raise HTTPException(status_code=404, detail=f"No CVEs found for {model_webkey}")


@router.post("/sbom/{model_webkey}/sbomlist",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            summary="Upload SBOM CVE list",
            status_code=status.HTTP_200_OK)
async def sbomlist(
        sbomcve_list: List[CVESBOM] = Body(...),
        model_webkey: str = Path(..., title="Model webkey"),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):
    """Upload an SBOM CVE list """

    logger.info(f"Parsing SBOM CVE list for model: {model_webkey}")

    try:
        #TODO
        # Check whether the system model exists (via basic model info)
        ##model = ssm_client.get_model_info(model_webkey)
        ##assert (model is not None)

        # Check CVEs
        logger.debug(f"SBOMCVE has {len(sbomcve_list)}")
        for sbomcve in sbomcve_list:
            logger.debug(f"\tReceived CVE: {sbomcve}")

        sbomlist_obj = SBOMList(cves=sbomcve_list)

        state_id = await store_sbomlist(db_client, sbomlist_obj)
        logger.debug(f"STATUS: {state_id}")

        return JSONResponse({"status": "ok", "sbomlist": state_id})

    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in SBOM CVE endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No CVEs found for {model_webkey}")


@router.post("/sbom/{model_webkey}/analyse",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def analyse_sbom(
        sbomlist_id: str,
        background_tasks: BackgroundTasks,
        model_webkey: str = Path(..., title="Model webkey"),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):
    """
    Apply basic Workflow analysis on SBOMList with sboblist_id
    """

    try:
        #TODO
        # Check whether the system model exists (via basic model info)
        ##model = ssm_client.get_model_info(model_webkey)
        ##assert (model is not None)

        logger.debug(f"SBOMCVE ID {sbomlist_id}")

        #status = await bg_workflow_i(model_webkey, sbomlist_id, ssm_client, db_client)
        background_tasks.add_task(bg_workflow_i, model_webkey, sbomlist_id, ssm_client, db_client)
        logger.debug("return from bg job")

        return JSONResponse({"status": "ok", "sbomlist": "in progress..."})

    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in SBOM CVE endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No CVEs found for {model_webkey}")


@router.get("/sbom/{model_webkey}/{sbomlist_id}",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def get_sbom_report(
        sbomlist_id: str,
        model_webkey: str = Path(..., title="Model webkey"),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    logger.info(f"Get SBOM CVE list analysis for model: {model_webkey}")

    try:
        #TODO
        # Check whether the system model exists (via basic model info)
        ##model = ssm_client.get_model_info(model_webkey)
        ##assert (model is not None)

        sbomlist_obj = await get_sbomlist(db_client, sbomlist_id)

        return JSONResponse({"status": "ok", "reports": jsonable_encoder(sbomlist_obj.products or {})})
        #if sbomlist_obj.products:
        #        return JSONResponse({"status": "ok", "reports": jsonable_encoder(sbomlist_obj.products)})
        #    else:
        #        return JSONResponse({"status": "not complete", "reports": None})

    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in get SBOMList endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No CVEs found for {model_webkey}")


@router.post("/sbom/{model_webkey}/workflow_multi",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def workflow_multi(
        sbomlist_id: str,
        mapping_id: str,
        background_tasks: BackgroundTasks,
        model_webkey: str = Path(..., title="Model webkey"),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):
    """
    Apply basic Workflow multi SBOMList with sboblist_id
    """

    try:
        #TODO
        # Check whether the system model exists (via basic model info)
        ##model = ssm_client.get_model_info(model_webkey)
        ##assert (model is not None)

        logger.debug(f"SBOMCVE ID {sbomlist_id}")

        #status = await bg_workflow_i(model_webkey, sbomlist_id, ssm_client, db_client)
        background_tasks.add_task(bg_workflow_multi, model_webkey, sbomlist_id, mapping_id, ssm_client, db_client)
        logger.debug("return from bg job")

        return JSONResponse({"status": "ok", "sbomlist": "in progress..."})

    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in SBOM CVE endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No CVEs found for {model_webkey}")


