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
import sys
import time
from pathlib import Path

from fastapi.logger import logger

from app.crud.store_reporting import update_reporting_status

REPORTING_ROOT = Path(os.getenv("REPORTING_ROOT", "/code/reporting"))
if str(REPORTING_ROOT) not in sys.path:
    sys.path.insert(0, str(REPORTING_ROOT))

from report_pdf import render_report_pdf

REPORTING_DOMAIN_CSV = str(REPORTING_ROOT / "domain-current" / "csv")
REPORTING_SCRIPTS = {
    "security": str(REPORTING_ROOT / "security" / "risk-report.py"),
    "compliance": str(REPORTING_ROOT / "compliance" / "risk-report.py"),
}
REPORTING_TIMEOUT_SECONDS = int(os.getenv("REPORTING_TIMEOUT_SECONDS", "900"))


class ReportingTimeoutError(RuntimeError):
    pass


def _run_reporting_script(reporting_msg, report_type, output_filename, timeout):
    cmd = [
        "python3", REPORTING_SCRIPTS[report_type],
        "-i", reporting_msg.nq_filename,
        "-o", str(output_filename),
        "-iso", reporting_msg.iso,
        "-d", REPORTING_DOMAIN_CSV,
    ]
    reporting_env = os.environ.copy()
    reporting_env["PYTHONPATH"] = os.pathsep.join(filter(None, [
        str(REPORTING_ROOT),
        reporting_env.get("PYTHONPATH"),
    ]))
    logger.info(f"Reporting type: {report_type}")
    return subprocess.run(
        cmd,
        cwd=reporting_msg.tempdir,
        capture_output=True,
        text=True,
        env=reporting_env,
        timeout=timeout,
    )


async def invoke_reporting_job(db_client, rjob_id, reporting_msg):
    logger.info("Invoking external reporting tool")
    logger.debug(f"Processing URL: {reporting_msg}")
    await update_reporting_status(db_client, rjob_id, "running")
    deadline = time.monotonic() + REPORTING_TIMEOUT_SECONDS
    job_failed = False

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
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise ReportingTimeoutError(
                    f"Report generation exceeded the {REPORTING_TIMEOUT_SECONDS}-second limit"
                )
            csv_output = Path(reporting_msg.tempdir) / f"{report_type}.csv"
            try:
                result = _run_reporting_script(
                    reporting_msg,
                    report_type,
                    csv_output,
                    remaining_seconds,
                )
            except subprocess.TimeoutExpired as error:
                raise ReportingTimeoutError(
                    f"Report generation exceeded the {REPORTING_TIMEOUT_SECONDS}-second limit"
                ) from error
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
        job_failed = True
        await update_reporting_status(db_client, rjob_id, "failed", str(error))
        logger.exception(f"Error while invoking reporting tool: {error}")
        raise

    finally:
        if reporting_msg.jtype == "SYNC" or job_failed:
            try:
                shutil.rmtree(reporting_msg.tempdir)
                logger.debug(f"Cleaned up temp directory: {reporting_msg.tempdir}")
            except Exception as cleanup_error:
                logger.warning(
                    f"Failed to remove tempdir {reporting_msg.tempdir}: {cleanup_error}"
                )
