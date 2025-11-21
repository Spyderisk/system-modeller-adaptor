import json

from fastapi.logger import logger

from app.models.cve.sbomcve import CVESBOM, SBOMList
from app.models.cve.mapping import ProductMap, ProductMapDict

from app.crud.store_sbomlist import get_sbomlist, update_sbomlist_products
from app.crud.store_mappings import get_mapping

from app.ssm.indicators.workflow import ExperimentWorkflow

from app.ssm.ssm_client import TWALevel

async def bg_workflow_i(model_id: str, sbomlist_id: str, ssm, db_conn) -> int:
    """
    Workflow I implementation
    """
    logger.info("bg process workflow I")

    sbomlist = await get_sbomlist(db_conn, sbomlist_id)

    logger.debug(f"SBOM list contains {len(sbomlist.cves)}")
    for sbomcve in sbomlist.cves:
        logger.debug(f"\tCVE item: {sbomcve}")

    logger.debug("START THE WORKFLOW")
    experiment = ExperimentWorkflow(ssm)

    logger.debug("generating product cves")
    product_cves = experiment.product_to_cves(sbomlist)

    logger.debug("next stage")
    products = experiment.workflow_security_cves(product_cves)
    logger.debug(f"PRODUCTS: {len(products)}, sbomlist: {len(sbomlist.cves)}")
    logger.debug(f"PRODUCTS to CVES: {len(product_cves)}")
    for p, c in product_cves.items():
        logger.debug(f" product: {p}, {len(c)}")
    for k, v in products.items():
        logger.debug(f"  key: {k}, value: {type(v[0])}, {len(v)}")
    u_sbomlist = await update_sbomlist_products(db_conn, sbomlist_id, "wf1", products)
    logger.debug(f"SBOMLIST: {u_sbomlist}")

async def bg_workflow_multi(model_id: str, sbomlist_id: str, mapping_id: str, ssm, db_conn) -> int:
    """
    Workflow multi implementation
    """
    logger.info("bg process workflow multi")
    exp = ExperimentWorkflow(ssm)

    sbomlist = await get_sbomlist(db_conn, sbomlist_id)
    product_cves = exp.product_to_cves(sbomlist)

    mapping = await get_mapping(db_conn, mapping_id)

    #TODO call workflow multi but needs to be adapted for input ...
    runs = exp.workflow_multi_in_mem(model_id, product_cves, mapping.data)
    # mapping:  6914611fad6e43acaa8b4a33
    # sbomlist: 69146266ad6e43acaa8b4a34
    # model_id: '2a10b5m2brdhsj51tk62hjnce2l5h0sj7on8gtfveeilli0iq716mui9ab9h13oc1mh5jd3vhpjp6596bs7nm2fl85bp0r0isrtgttg'

    logger.debug(f"TEXT: {runs}")


