FROM python:buster

RUN apt update && apt install -y rustc && apt clean

RUN pip install platformio future
RUN adduser --disabled-password --ingroup dialout platformio
USER platformio
WORKDIR /home/platformio