FROM python:alpine as builder
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
RUN apk add py3-wheel python3-dev libressl-dev musl-dev libffi-dev libffi-dev musl-dev make gcc
RUN mkdir /wheels && pip wheel --wheel-dir=/wheels/ cffi cryptography future pycparser pyparsing==2.2.0

FROM python:alpine
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV PIP_NO_CACHE_DIR=1

RUN adduser --disabled-password --gecos "" --ingroup dialout platformio \
    && pip install platformio \
    && apk add --update --no-cache libc6-compat gcompat libstdc++ libressl3.1-libssl

USER platformio
COPY --from=builder /wheels /wheels
WORKDIR /home/platformio
ADD platformio.ini ./

#Triggering a void pio run to force Platformio to install everything that it needs.
RUN pip install --user --no-index --find-links=/wheels/ cffi cryptography future pycparser pyparsing==2.2.0 \
    && (pio run -t upload 2>/dev/null || true) \
    && pio platform list \
    && pio platform update \
    && pio system prune -f --cache \
    && rm -rf .pio platformio.ini
