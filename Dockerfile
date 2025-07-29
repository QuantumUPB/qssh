# syntax=docker/dockerfile:1.4
FROM debian:bookworm-slim

# Disable interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    zlib1g-dev \
    libssl-dev \
    libpam0g-dev \
    libselinux1-dev \
    libedit-dev \
    libwrap0-dev \
    libaudit-dev \
    libcurl4-openssl-dev \
    libjson-c-dev \
    uuid-dev \
    pkg-config \
    autoconf \
    automake \
    bison \
    flex \
    curl \
    wget \
    nano \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Default SSH port can be overridden at runtime
ENV SSH_PORT=2222

# Create a user for SSH login
RUN useradd -ms /bin/bash sshuser
RUN echo 'sshuser:password' | chpasswd

# Copy your custom OpenSSH source code into the container
COPY openssh-portable /openssh-portable
COPY sshd_config /etc/ssh/sshd_config
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh
COPY ssh_config /root/.ssh/config
RUN chmod 600 /root/.ssh/config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set the working directory
WORKDIR /openssh-portable

# Build and install OpenSSH
RUN autoreconf && \
    ./configure --with-pam --with-sandbox=no --prefix=/usr --sysconfdir=/etc/ssh && \
    make clean

# Adjust linker flags so that the custom QKD key exchange code links
# against libcurl, json-c, OpenSSL and uuid. Without these libraries
# the build fails during the final link step.
RUN sed -i '/^LDFLAGS[[:space:]]*=/ s/$/ -lcurl -ljson-c -lssl -lcrypto -luuid/' Makefile && \
    sed -i '/^LIBS[[:space:]]*=/ s/$/ -lcurl -ljson-c -lssl -lcrypto -luuid/' Makefile

RUN make && \
    make install

# # Configure SSH server
RUN mkdir /var/run/sshd

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN echo "KexAlgorithms=qkd128-etsi-014" >> /etc/ssh/ssh_config
RUN echo "StrictHostKeyChecking=no" >> /etc/ssh/ssh_config

RUN echo "KexAlgorithms qkd128-etsi-014" >> /etc/ssh/sshd_config
RUN echo "LogLevel DEBUG3" >> /etc/ssh/sshd_config

RUN useradd -u 35 -g 33 -c sshd -d / sshd

RUN mkdir /certs
# Copy provided certificates (if any) into the image. The source
# directory exists in the repository but may be empty, so this step
# succeeds even when no certificate files are present.
COPY certs/ /certs/


# Expose default SSH port
EXPOSE 2222

# Start sshd via custom entrypoint to allow dynamic port configuration
CMD ["/entrypoint.sh"]
