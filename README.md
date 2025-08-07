# QKD-Based Session Key Integration

## Overview


The session key forming mechanism involves a protocol where three 256-bit keys are retrieved from the QKD devices. Specific parts of these keys are used for mutual authentication and to form the session key for the SSH session.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Docker Deployment](#docker-deployment)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [Session Key Forming Mechanism](#session-key-forming-mechanism)
  - [Key Retrieval](#key-retrieval)
  - [First Message (Client to Server)](#first-message-client-to-server)
  - [Second Message (Server to Client)](#second-message-server-to-client)
  - [Session Key Formation](#session-key-formation)
- [Particularities](#particularities)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Quantum-Safe Key Exchange**: Utilizes keys from QKD devices to establish SSH sessions.
- **Mutual Authentication**: Verifies that both client and server have synchronized keys.
- **Secure Session Key Formation**: Derives the session key from verified key material.

## Prerequisites

- **Operating System**: Linux (e.g., Ubuntu, CentOS)
- **C Compiler**: GCC or Clang
- **libcurl**: For HTTP communication with QKD devices
- **Access to QKD Devices**: With an HTTP API for key retrieval

## Build Instructions

### 1. Clone the Repository

```bash
git clone git@github.com:QuantumUPB/qssh.git
cd qssh
```

### 2. Install Dependencies

For **Debian/Ubuntu**:

```bash
sudo apt-get update
sudo apt-get install libcurl4-openssl-dev libjson-c-dev libssl-dev uuid-dev
```

For **CentOS/RHEL**:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install libcurl-devel
```

### 3. Provide QKD Certificates (Optional)

If you have QKD certificate files, place them in the `certs` directory:

```
qssh-master/certs/qkd.crt
qssh-master/certs/qkd-ca.crt
qssh-master/certs/qkd.key
```

These files are not tracked in version control. If the directory is empty or missing, the Docker image will still build, but no certificates will be included.


## Docker Deployment

You can build and run the project inside Docker containers using the provided
`docker-compose.yml` file and the top-level `Makefile`.

### Configure environment variables

Copy the sample files and adjust the values before starting the containers:

```bash
cp server.env.sample server.env
cp client.env.sample client.env
```

Edit `server.env` and `client.env` to match your environment. Each file defines
settings such as `SSH_PORT`, `QKD_ENC_IPPORT`, `QKD_DEC_IPPORT`,
`QKD_ENC_SAE_ID`, `QKD_DEC_SAE_ID`, `QKD_ENC_KME`, `QKD_DEC_KME`,
`SELF_REPORTING`, `REPORT_ENDPOINT`, `REPORTING_NAME`,
`REPORT_TRUST_SELF_SIGNED`, and `REPORT_TOKEN`.

### Build the Docker image

```bash
make build
```

### Run in production mode

```bash
make prod
```

This starts a single container that makes the SSH service available on
port `2222` of the host.
You can override the exposed port by providing a `PORT` variable:

```bash
make prod PORT=2200
```

The SSH daemon inside the container will also listen on the chosen port.

### Run in testing mode

```bash
make testing
```

This launches both a server container and a client container. The server binds
to port `2222` and the client binds to port `2223`. Ensure no other services are
occupying these ports.
Custom ports can be provided using the `PORT` and `CLIENT_PORT` variables:

```bash
make testing PORT=2200 CLIENT_PORT=2201
```

### Connect to running containers

Use the `connect.sh` helper script to start a shell inside one of the containers:

```bash
./connect.sh server   # or ./connect.sh client
```

### Environment Variables

The containers load configuration from `server.env` and `client.env` (generated
from the `*.env.sample` files). The following variables are recognised:

- `QKD_ENC_IPPORT` – address of the encryption key service. Defaults to `localhost:6600` if not set.
- `QKD_DEC_IPPORT` – address of the decryption key service. Defaults to `localhost:6600` if not set.
- `QKD_ENC_SAE_ID` – SAE identifier used when requesting encryption keys. Defaults to `UPB-BC-UPBR` if not set.
- `QKD_DEC_SAE_ID` – SAE identifier used when requesting decryption keys. Defaults to `UPB-BC-UPBP` if not set.
- `QKD_ENC_KME` – KME path for encryption key requests. Defaults to `kme` if not set.
- `QKD_DEC_KME` – KME path for decryption key requests. Defaults to `kme` if not set.
- `SSH_PORT` – port on which the SSH daemon runs inside the container. Adjust
  this value in `server.env` and `client.env` before launching.

## Usage

After starting the containers you can initiate an SSH connection using the
default credentials `sshuser:password`.

### From the host machine

```bash
ssh -p 2222 sshuser@localhost
```

### From the client container

```bash
./connect.sh client
ssh -vvv sshuser@ssh_server
```

The `-vvv` flag enables verbose output for debugging purposes.

## Session Key Forming Mechanism

### Overview

The session key forming mechanism ensures that both the client and server use synchronized keys from their respective QKD devices. The protocol involves exchanging encrypted messages that confirm key synchronization and ultimately derive a session key for the SSH session.

### Key Retrieval

- **Client and Server** each independently retrieve **three 256-bit keys** from their QKD devices:
  - **Key1**: 256 bits
  - **Key2**: 256 bits
  - **Key3**: 256 bits

### First Message (Client to Server)

1. **Client** takes the **first 128 bits of Key1** (`Key1[1-128]`).
2. **Client** encrypts `Key1[1-128]` using a One-Time Pad (OTP) with the **first 128 bits of Key2** (`Key2[1-128]`):
   - **Encryption**: `EM1 = Key1[1-128] ⊕ Key2[1-128]`
3. **Client** sends `EM1` along with the **Key IDs** for Key1, Key2, and Key3 to the **Server**.

### Second Message (Server to Client)

1. **Server** receives `EM1` and the Key IDs.
2. **Server** retrieves **Key1**, **Key2**, and **Key3** from its QKD device using the provided Key IDs.
3. **Server** decrypts `EM1` using `Key2[1-128]` to obtain `Key1[1-128]`:
   - **Decryption**: `Key1[1-128] = EM1 ⊕ Key2[1-128]`
4. **Server** verifies that `Key1[1-128]` matches its own `Key1[1-128]`.
5. **Server** encrypts the **next 128 bits of Key2** (`Key2[129-256]`) using an OTP with the **first 128 bits of Key3** (`Key3[1-128]`):
   - **Encryption**: `EM2 = Key2[129-256] ⊕ Key3[1-128]`
6. **Server** sends `EM2` back to the **Client**.

### Session Key Formation

1. **Client** receives `EM2`.
2. **Client** decrypts `EM2` using `Key3[1-128]` to obtain `Key2[129-256]`:
   - **Decryption**: `Key2[129-256] = EM2 ⊕ Key3[1-128]`
3. **Client** verifies that `Key2[129-256]` matches its own `Key2[129-256]`.
4. **Both Client and Server** form the **session key** by concatenating:
   - `SessionKey = Key1[129-256] || Key3[129-256]`
5. **SessionKey** is a 256-bit key used to secure the SSH session.

### Diagram

```
Client                                            Server
------                                            ------

Retrieve Key1, Key2, Key3                         Retrieve Key1, Key2, Key3

Compute EM1 = Key1[1-128] ⊕ Key2[1-128]
Send EM1, Key IDs to Server  ------------------>  

                                               Decrypt EM1:
                                               Key1[1-128] = EM1 ⊕ Key2[1-128]
                                               Verify Key1[1-128]

                                               Compute EM2 = Key2[129-256] ⊕ Key3[1-128]
                               <------------------  Send EM2 to Client

Decrypt EM2:
Key2[129-256] = EM2 ⊕ Key3[1-128]
Verify Key2[129-256]

Form SessionKey = Key1[129-256] || Key3[129-256]
                                               Form SessionKey = Key1[129-256] || Key3[129-256]
```

## Particularities

- **One-Time Pad (OTP)**: Encryption and decryption are performed using bitwise XOR operations, adhering to OTP principles.
- **Key Segments**: Keys are split into segments to ensure that each bit of key material is used only once.
- **Key IDs**: Key IDs are exchanged to retrieve the correct keys from the QKD devices.
- **Synchronization Verification**: The protocol verifies synchronization of all key segments used in the session key.
- **No Key Reuse**: Each key segment is used for a single purpose to maintain OTP security.

## Security Considerations

- **Key Material Protection**: Keys are securely handled in memory, and sensitive data is zeroized before being freed.
- **Desynchronization Detection**: The protocol detects any desynchronization of keys, preventing insecure connections.
- **Error Handling**: Meaningful error messages are provided without exposing sensitive information.

## Troubleshooting

- **Verbose Logging**: Use `ssh -vvv` to enable verbose logging and observe the authentication process.
- **Common Issues**:
  - **Key Synchronization Failed**: Indicates that the keys are desynchronized or incorrect keys were retrieved.
  - **Defective Token**: Suggests an issue with token serialization or deserialization.
- **Logs and Debugging**:
  - Check system logs and OpenSSH logs for additional information.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).

