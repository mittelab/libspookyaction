FROM python:3.9-alpine3.13 AS builder
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
RUN apk add py3-wheel python3-dev libressl-dev musl-dev libffi-dev libffi-dev musl-dev make gcc
# TODO Package cryptography was pinned to 3.4.8 due to https://github.com/espressif/esp-idf/issues/7631
RUN mkdir /wheels && pip wheel --wheel-dir=/wheels/ cffi cryptography==3.4.8 future pycparser pyparsing==2.2.0

FROM python:3.9-alpine3.13 AS platformio-base
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV PIP_NO_CACHE_DIR=1

RUN adduser --disabled-password --gecos "" --ingroup dialout platformio \
    && pip install platformio \
    && apk add --update --no-cache libc6-compat gcompat libstdc++ libressl3.1-libssl \
# TODO When bumping to alpine 3.14, remember that this becomes    libressl3.3-libssl

USER platformio
WORKDIR /home/platformio

FROM platformio-base AS plaformio-installed
COPY --from=builder /wheels /wheels
ADD platformio.ini /
# Triggering a void pio run to force Platformio to install everything that it needs.
RUN pip install --user --no-index --find-links=/wheels/ cffi cryptography future pycparser pyparsing \
    && mkdir dummy_pio_run \
    && cp /platformio.ini dummy_pio_run/ \
    && cd dummy_pio_run \
    && (pio run -t upload 2>/dev/null || true) \
    && cd .. \
    && rm -rf dummy_pio_run \
    && pio platform update \
    && pio system prune -f --cache \
    && pio platform list

FROM platformio-base
# Carry over all user-installed packages and the platformio data without cache, wheels and default platformio.ini
COPY --from=plaformio-installed /home/platformio /home/platformio
