FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV INSTALL_DIR=/opt/mmt/networkfuzzer

# Install system dependencies required for NetworkFuzzer
RUN apt-get update && apt-get install --yes \
        gnupg ca-certificates curl wget git gcc g++ make python3 python3-pip tcpdump \
        libxml2-dev libpcap-dev libconfuse-dev libsctp-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Clone and build MMT-DPI (dicom branch)
RUN git clone --depth 1 --branch dicom https://github.com/Montimage/mmt-dpi.git && \
    cd mmt-dpi/sdk && \
    make -j2 && make install && ldconfig && \
    cd /tmp && rm -rf mmt-dpi

# Copy requirements.txt and install Python dependencies
COPY utils/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy application source code
COPY . ${INSTALL_DIR}
WORKDIR ${INSTALL_DIR}

# Build NetworkFuzzer and compile sample rules
RUN make -j2 && make sample-rules

CMD ["./networkfuzzer", "-h"]
