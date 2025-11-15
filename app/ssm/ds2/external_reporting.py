##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2025
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
##      Created Date :          2025-11-10
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

import sys
import subprocess

from app.ssm.ssm_client import SSMClient
import tempfile
import shutil
from pathlib import Path

from fastapi import File
from fastapi.logger import logger

from app.models.ds2.reporting import ReportingMessage

from app.crud.store_reporting import store_reporting, get_reporting, update_reporting_status

async def invoke_reporting_job(db_client, rjob_id, reporting_msg):
    logger.info("Invoking external reporting tool")
    logger.debug(f"Processing URL: {reporting_msg}")

    await update_reporting_status(db_client, rjob_id, "running")

    try:
        cmd = [
            "python3", "/code/reporting/risk-report.py",
            "-i", reporting_msg.nq_filename,
            "-o", str(reporting_msg.output_filename),
            "-d", "/code/reporting/domain-network-132-e5cfa54/csv"
        ]

        result = subprocess.run(
            cmd,
            cwd=reporting_msg.tempdir,
            capture_output=True,
            text=True
        )

        reporting_msg.returncode = result.returncode

        logger.debug(f"STDOUT:\n{result.stdout.strip()}")
        logger.debug(f"STDERR:\n{result.stderr.strip()}")
        logger.debug(f"Return code: {result.returncode}")

        if result.returncode != 0:
            await update_reporting_status(db_client, rjob_id, "failed", str(result.returncode))
            logger.warning(f"External tool exited with code {result.returncode}")

        if reporting_msg.output_filename.exists():
            csv_content = reporting_msg.output_filename.read_text()
            logger.debug(f"Output CSV content:\n{csv_content}")
            await update_reporting_status(db_client, rjob_id, "finished")
        else:
            csv_content = None
            logger.warning("Expected output file not found!")
            await update_reporting_status(db_client, rjob_id, "failed")

        if reporting_msg.jtype == "SYNC":
            return {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "tempdir": reporting_msg.tempdir,
                "uploaded_file": reporting_msg.nq_filename,
                "output_csv": csv_content
            }

    except Exception as e:
        logger.exception(f"Error while invoking reporting tool: {e}")
        raise

    finally:
        # clean up temp directory
        try:
            shutil.rmtree(reporting_msg.tempdir)
            logger.debug(f"Cleaned up temp directory: {reporting_msg.tempdir}")
        except Exception as cleanup_err:
            logger.warning(f"Failed to remove tempdir {reporting_msg.tempdir}: {cleanup_err}")

