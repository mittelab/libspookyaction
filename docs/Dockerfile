FROM python:3.11.5-alpine3.18 AS builder
RUN apk add --update --no-cache g++ make flex bison cmake \
    && wget https://github.com/doxygen/doxygen/releases/download/Release_1_9_8/doxygen-1.9.8.src.tar.gz \
    && tar -xzf doxygen-1.9.8.src.tar.gz \
    && rm doxygen-1.9.8.src.tar.gz \
    && mkdir build \
    && cd build \
    && cmake -G "Unix Makefiles" ../doxygen-1.9.8 \
    && make -j $(nproc) \
    && make install

FROM python:3.11.5-alpine3.18
COPY requirements.txt /requirements.txt
RUN apk add --update --no-cache libstdc++ git make graphviz \
    && pip install -r /requirements.txt
COPY --from=builder /usr/local/bin/doxygen /usr/local/bin/doxygen
