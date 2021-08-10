FROM cccs/assemblyline-v4-service-base:stable

ENV SERVICE_PATH python_exe_unpack.PythonExeUnpack

USER root

RUN apt update
RUN apt install -y gcc
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

USER assemblyline

WORKDIR /opt/al_service
COPY . .

ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
