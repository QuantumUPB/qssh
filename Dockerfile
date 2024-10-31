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

# Create a user for SSH login
RUN useradd -ms /bin/bash sshuser
RUN echo 'sshuser:password' | chpasswd

# Copy your custom OpenSSH source code into the container
COPY openssh-portable /openssh-portable

# Set the working directory
WORKDIR /openssh-portable

RUN mkdir /certs

COPY gssapi_mech/qkd.crt /certs/qkd.crt 
COPY gssapi_mech/qkd-ca.crt /certs/qkd-ca.crt  
COPY gssapi_mech/qkd-new.key /certs/qkd.key

# Build and install OpenSSH
RUN autoreconf && \
    ./configure --with-pam --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/certs && \
    make clean

# Allow password authentication and root login (for testing purposes)
# RUN sed -i '/^LDFLAGS[[:space:]]*=/ s/$/-lcurl -ljson-c -lssl -lcrypto -luuid/' Makefile

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

# # Expose SSH port
EXPOSE 22

# Set the default command to run when starting the container
CMD ["/usr/sbin/sshd", "-D", "-e"]
