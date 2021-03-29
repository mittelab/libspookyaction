FROM python:alpine as dep_builder
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
RUN mkdir /wheels
RUN apk add gcc musl-dev python3-dev libffi-dev openssl-dev cargo py3-wheel
RUN pip wheel --wheel-dir=/wheels platformio future cryptography

FROM python:latest
COPY --from=dep_builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels platformio future cryptography
RUN adduser --disabled-password --ingroup dialout platformio
USER platformio
WORKDIR /home/platformio