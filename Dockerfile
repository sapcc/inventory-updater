FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/ubuntu:latest

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y python3 \
    && apt-get install -y python3-pip \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

ARG FOLDERNAME=inventory-updater

RUN mkdir /${FOLDERNAME}
RUN mkdir /${FOLDERNAME}/logs

WORKDIR /${FOLDERNAME}

RUN pip3 install --break-system-packages --upgrade pip
COPY requirements.txt /${FOLDERNAME}
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY *.py /${FOLDERNAME}/

LABEL source_repository="https://github.com/sapcc/inventory-updater"
LABEL maintainer="Bernd Kuespert <bernd.kuespert@sap.com>"
