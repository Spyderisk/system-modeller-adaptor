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
##      Created Date :          2021-04-29
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

import json
from kafka import KafkaProducer

from app.core.config import KAFKA_SERVICE_URL, KAFKA_TOPIC

from fastapi.logger import logger

def connect_n_publish(key, value):
    logger.info("connect and publish to KAFKA")
    key_bytes = bytes(key, encoding='utf-8')
    value_bytes = bytes(value, encoding='utf-8')

    kafka_producer = KafkaProducer(bootstrap_servers=[KAFKA_SERVICE_URL])

    if not kafka_producer.bootstrap_connected():
        logger.debug("failed to get kafka producer connected")
        raise Exception(f"connect_kafka_producer error {ex}")

    logger.info(f"publish {key} message to KAFKA")
    kafka_producer.send(KAFKA_TOPIC, key_bytes, value_bytes)

    logger.info("published")
    kafka_producer.flush()
    logger.info("flushed")

    kafka_producer.close()

def xconnect_n_publish(key, value):
    logger.info("connect and publish to KAFKA")
    logger.info(f"1aconnect and publish to KAFKA {key}, {KAFKA_TOPIC}")
    key_bytes = bytes(key, encoding='utf-8')
    logger.info(f"1bconnect and publish to KAFKA {key_bytes}, {KAFKA_TOPIC}")
    value_bytes = bytes(value, encoding='utf-8')
    logger.info(f"1cconnect and publish to KAFKA {key}, {KAFKA_TOPIC}")

    try:
        logger.info(f"1connect and publish to KAFKA {key}, {KAFKA_TOPIC}")
        kafka_producer = KafkaProducer(bootstrap_servers=[KAFKA_SERVICE_URL])
        logger.info("2connect and publish to KAFKA")

        if not kafka_producer.bootstrap_connected():
            logger.debug("failed to get kafka producer connected")
            raise Exception(f"connect_kafka_producer error {ex}")

        logger.info(f"publish {key} message to KAFKA")
        kafka_producer.send(KAFKA_TOPIC, key_bytes, value_bytes)

        logger.info("published")
        kafka_producer.flush()
        logger.info("flushed")

        kafka_producer.close()
    except Exception as ex:
        logger.error(f"Exception while connecting to kafka {ex}")

