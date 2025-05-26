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

# Build and install MMT-SECURITY
WORKDIR /tmp
RUN git clone https://github.com/Montimage/mmt-security.git && \
    cd mmt-security && \
    make clean-all && \
    make -j1 && \
    make install && ldconfig && \
    make deb

# Build and install MMT-PROBE
WORKDIR /tmp
RUN git clone https://github.com/Montimage/mmt-probe.git && \
    cd mmt-probe && \
    make && \
    make install && make deb

# Copy only requirements.txt and install Python dependencies
COPY utils/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Now copy your entire application source code
COPY . ${INSTALL_DIR}
WORKDIR ${INSTALL_DIR}

# Build sample rules (depends on your source code)
RUN make sample-rules

# Compile utility binaries in /opt/mmt/examples
RUN gcc -g -o /opt/mmt/examples/extract_all /opt/mmt/examples/extract_all.c \
        -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap && \
    gcc -o /opt/mmt/examples/proto_attributes_iterator /opt/mmt/examples/proto_attributes_iterator.c \
        -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap

CMD ["./networkfuzzer", "-h"]
