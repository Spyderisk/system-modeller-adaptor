##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2025
##
##      Created By :            Panos Melas
##      Created Date :          2025-11-10
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

import os
import shutil
import subprocess
from pathlib import Path

from fastapi.logger import logger

from app.crud.store_reporting import update_reporting_status
from app.ssm.ds2.report_pdf import render_report_pdf

REPORTING_DOMAIN_CSV = "/code/reporting/domain-current/csv"
REPORTING_SCRIPTS = {
    "security": "/code/reporting/security/risk-report.py",
    "compliance": "/code/reporting/compliance/risk-report.py",
}


def _run_reporting_script(reporting_msg, report_type, output_filename):
    cmd = [
        "python3", REPORTING_SCRIPTS[report_type],
        "-i", reporting_msg.nq_filename,
        "-o", str(output_filename),
        "-iso", reporting_msg.iso,
        "-d", REPORTING_DOMAIN_CSV,
    ]
    reporting_env = os.environ.copy()
    reporting_env["PYTHONPATH"] = os.pathsep.join(filter(None, [
        "/code/reporting",
        reporting_env.get("PYTHONPATH"),
    ]))
    logger.info(f"Reporting type: {report_type}")
    return subprocess.run(
        cmd,
        cwd=reporting_msg.tempdir,
        capture_output=True,
        text=True,
        env=reporting_env,
    )


async def invoke_reporting_job(db_client, rjob_id, reporting_msg):
    logger.info("Invoking external reporting tool")
    logger.debug(f"Processing URL: {reporting_msg}")
    await update_reporting_status(db_client, rjob_id, "running")

    try:
        if reporting_msg.report_type == "combined" and reporting_msg.output_format != "pdf":
            raise ValueError("Combined reports are only available as PDF")

        report_types = (
            ["security", "compliance"]
            if reporting_msg.report_type == "combined"
            else [reporting_msg.report_type]
        )
        csv_outputs = []
        process_results = []
        for report_type in report_types:
            csv_output = Path(reporting_msg.tempdir) / f"{report_type}.csv"
            result = _run_reporting_script(reporting_msg, report_type, csv_output)
            process_results.append(result)
            reporting_msg.returncode = result.returncode
            logger.debug(f"STDOUT ({report_type}):\n{result.stdout.strip()}")
            logger.debug(f"STDERR ({report_type}):\n{result.stderr.strip()}")
            if result.returncode != 0 or not csv_output.exists():
                await update_reporting_status(db_client, rjob_id, "failed", str(result.returncode))
                raise RuntimeError(f"{report_type} reporting failed with code {result.returncode}")
            csv_outputs.append((report_type.title(), csv_output))

        if reporting_msg.output_format == "pdf":
            render_report_pdf(csv_outputs, reporting_msg.output_filename, reporting_msg.iso)
        else:
            shutil.copyfile(csv_outputs[0][1], reporting_msg.output_filename)

        if not reporting_msg.output_filename.exists():
            await update_reporting_status(db_client, rjob_id, "failed")
            raise RuntimeError("Expected output file not found")

        output_content = reporting_msg.output_filename.read_bytes()
        await update_reporting_status(db_client, rjob_id, "finished")

        if reporting_msg.jtype == "SYNC":
            return {
                "return_code": reporting_msg.returncode,
                "stdout": "\n".join(result.stdout for result in process_results),
                "stderr": "\n".join(result.stderr for result in process_results),
                "tempdir": reporting_msg.tempdir,
                "uploaded_file": reporting_msg.nq_filename,
                "output_content": output_content,
                "media_type": (
                    "application/pdf"
                    if reporting_msg.output_format == "pdf"
                    else "text/csv"
                ),
                "filename": f"report.{reporting_msg.output_format}",
            }

    except Exception as error:
        await update_reporting_status(db_client, rjob_id, "failed", str(error))
        logger.exception(f"Error while invoking reporting tool: {error}")
        raise

    finally:
        if reporting_msg.jtype == "SYNC":
            try:
                shutil.rmtree(reporting_msg.tempdir)
                logger.debug(f"Cleaned up temp directory: {reporting_msg.tempdir}")
            except Exception as cleanup_error:
                logger.warning(
                    f"Failed to remove tempdir {reporting_msg.tempdir}: {cleanup_error}"
                )
