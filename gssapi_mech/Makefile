# Compiler and flags
CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g -I/usr/include/gssapi -Wno-unused-parameter -Wno-override-init
LDFLAGS = -shared -lcurl -ljson-c -lssl -lcrypto -luuid

# Source and target files
SRC = qkd_gssapi.c qkd.c
LIB = libgss_qkd.so
TEST_SRC = test_qkd.c qkd.c
TEST_BIN = test_qkd

DESTDIR?=/

# Default target
all: $(LIB)

# Build the shared library
$(LIB): $(SRC)
	$(CC) $(CFLAGS) -o $(LIB) $(SRC) $(LDFLAGS)

# Build the test program
$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC) -lcurl -ljson-c -lssl -lcrypto -luuid

# Install the shared library
install: $(LIB)
# Create the directory if it doesn't exist
	mkdir -p $(DESTDIR)/usr/lib/gssapi
# Copy the library to the GSSAPI mechanism directory
	cp $(LIB) $(DESTDIR)/usr/lib/gssapi/$(LIB)
# Set proper permissions
	chmod 755 $(DESTDIR)/usr/lib/gssapi/$(LIB)
# Create the mechanism configuration directory
	mkdir -p $(DESTDIR)/etc/gss/mech.d
# Copy the mechanism configuration file
	cp qkd_mech.conf $(DESTDIR)/etc/gss/mech.d/
# Set proper permissions
	chmod 644 $(DESTDIR)/etc/gss/mech.d/qkd_mech.conf

# Clean up build artifacts
clean:
	rm -f $(LIB) test_qkd
