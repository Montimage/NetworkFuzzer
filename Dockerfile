FROM ubuntu:22.04

LABEL maintainer="Montimage <contact@montimage.eu>"

ENV DEBIAN_FRONTEND=noninteractive
ENV INSTALL_DIR=/opt/mmt/networkfuzzer

# Install all system dependencies in one layer early
RUN echo 'Acquire::AllowInsecureRepositories "true";' > /etc/apt/apt.conf.d/99insecure && \
    apt-get update --allow-insecure-repositories && \
    apt-get install -y --no-install-recommends \
        gnupg ca-certificates curl wget git gcc g++ make python3 python3-pip tcpdump \
        libxml2-dev libpcap-dev libconfuse-dev libsctp-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Clone and build DPI once in its own layer
RUN git clone --depth 1 --branch dicom https://github.com/Montimage/mmt-dpi.git && \
    cd mmt-dpi/sdk && \
    make -j2 && make install && ldconfig && \
    cd /tmp && rm -rf mmt-dpi

# Copy only requirements.txt and install Python dependencies
COPY utils/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Now copy your entire application source code
COPY . ${INSTALL_DIR}
WORKDIR ${INSTALL_DIR}

# Build sample rules (depends on your source code)
RUN make sample-rules

CMD ["./networkfuzzer", "-h"]
