IMAGE_NAME=qkd_ssh_image
COMPOSE=docker compose
COMPOSE_FILE=docker-compose.yml
PORT?=2222
CLIENT_PORT?=2223

.PHONY: build testing prod stop clean

build:
	$(COMPOSE) -f $(COMPOSE_FILE) build

testing: build
	SERVER_PORT=$(PORT) CLIENT_PORT=$(CLIENT_PORT) $(COMPOSE) -f $(COMPOSE_FILE) up -d server client

prod: build
	SERVER_PORT=$(PORT) $(COMPOSE) -f $(COMPOSE_FILE) up -d server

stop:
	$(COMPOSE) -f $(COMPOSE_FILE) down

clean: stop
	$(COMPOSE) -f $(COMPOSE_FILE) rm -f server client

zip:
	zip -r qssh.zip ./*
