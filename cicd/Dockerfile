FROM python:latest
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV PIP_NO_CACHE_DIR=1

RUN pip install platformio
RUN adduser --disabled-password --gecos "" --ingroup dialout platformio
USER platformio
RUN pip install --user cffi cryptography future pycparser pyparsing==2.2.0
WORKDIR /home/platformio
ADD platformio.ini ./
RUN echo "Triggering a void pio run to force Platformio to install everything that it needs." \
 && (pio run -t upload 2>/dev/null || true)
RUN pio system prune --cache -f \
 && pio platform list \
 && pio platform update \
 && rm -rf .pio platformio.ini
