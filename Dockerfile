FROM ubuntu:22.04

LABEL maintainer="Montimage <contact@montimage.eu>"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Set default installation directory (can be overridden)
ENV INSTALL_DIR /opt/mmt/networkfuzzer

# ONLY if you encounter issues with unsigned APT repositories (e.g., GPG errors)
RUN echo 'Acquire::AllowInsecureRepositories "true";' > /etc/apt/apt.conf.d/99insecure \
 && apt-get update --allow-insecure-repositories \
 && apt-get install -y --no-install-recommends \
    gnupg ca-certificates curl wget git gcc make libxml2-dev libpcap-dev libconfuse-dev libsctp-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Update & install essential tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gnupg \
    ca-certificates \
    curl \
    wget \
    git \
    gcc \
    g++ \
    make \
    libxml2-dev \
    libpcap-dev \
    libconfuse-dev \
    libsctp-dev \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create install directory
ADD .   ${INSTALL_DIR}
WORKDIR ${INSTALL_DIR}

# Install DPI from source (use 'dicom' branch)
RUN rm -rf mmt-dpi
RUN git clone --depth 1 --branch dicom https://github.com/Montimage/mmt-dpi.git \
         && cd mmt-dpi/sdk                                       \
         && make -j2                                             \
         && make install && ldconfig                             \
         && cd ../../ && rm -rf mmt-dpi

RUN  make sample-rules

ENTRYPOINT ["./networkfuzzer"]
# default parameter
CMD ["-h"]
