##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2016
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

#
# docker container for the SSM adaptor microservice
#

FROM ubuntu:22.04

LABEL org.opencontainers.image.title="Spyderisk System Modeller Adapter build image"
LABEL org.opencontainers.image.revision=${CI_COMMIT_SHA}
LABEL org.opencontainers.image.created=${CI_COMMIT_TIMESTAMP}

LABEL org.opencontainers.image.vendor="IT Innovation Centre"
LABEL org.opencontainers.image.title="Spyderisk System Modeller Adapter"
LABEL org.opencontainers.image.revision=${CI_COMMIT_SHA}
LABEL org.opencontainers.image.created=${CI_COMMIT_TIMESTAMP}

ENV PYTHONUNBUFFERED 1

ENV DEBIAN_FRONTEND=noninteractive

ENV LANG C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils locales curl \
               python3-pip python3-dev python3-setuptools \
               build-essential libffi-dev \
               graphviz \
    && rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8

RUN mkdir /code

WORKDIR /code

COPY . /code/

RUN pip3 install -r requirements.txt

## Set up the needed ENV variable
ENV PYTHONPATH=$PYTHONPATH:/code/app

# cleanup
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
