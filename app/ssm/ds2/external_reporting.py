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


def invoke_reporting(nq_file: File):
    logger.info("Invoking external reporting tool")
    logger.debug(f"Processing file: {nq_file.filename}")

    tmpdir = tempfile.mkdtemp(prefix="reporting_")
    tmp_path = Path(tmpdir) / nq_file.filename
    output_file = Path(tmpdir) / "test.csv"

    logger.debug(f"Temporary directory: {tmpdir}")
    logger.debug(f"Temporary file path: {tmp_path}")

    try:
        # Save uploaded file to temp folder
        with open(tmp_path, "wb") as buffer:
            shutil.copyfileobj(nq_file.file, buffer)

        cmd = [
            "python3", "/code/reporting/risk-report.py",
            "-i", tmp_path.name,
            "-o", output_file.name,
            "-d", "/code/reporting/domain-network-132-e5cfa54/csv"
        ]

        result = subprocess.run(
            cmd,
            cwd=tmpdir,
            capture_output=True,
            text=True
        )

        logger.debug(f"STDOUT:\n{result.stdout.strip()}")
        logger.debug(f"STDERR:\n{result.stderr.strip()}")
        logger.debug(f"Return code: {result.returncode}")

        if result.returncode != 0:
            logger.warning(f"External tool exited with code {result.returncode}")

        if output_file.exists():
            csv_content = output_file.read_text()
            logger.debug(f"Output CSV content:\n{csv_content}")
        else:
            csv_content = None
            logger.warning("Expected output file not found!")

        return {
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "tempdir": tmpdir,
            "uploaded_file": tmp_path.name,
            "output_csv": csv_content
        }

    except Exception as e:
        logger.exception(f"Error while invoking reporting tool: {e}")
        raise

    finally:
        # clean up temp directory
        try:
            shutil.rmtree(tmpdir)
            logger.debug(f"Cleaned up temp directory: {tmpdir}")
        except Exception as cleanup_err:
            logger.warning(f"Failed to remove tempdir {tmpdir}: {cleanup_err}")

