# mail-controller image — build & test entrypoints.
# Run from the repo root: `make <target>`.
IMAGE        ?= mail-controller:test
IMAGE_DIR    := $(CURDIR)
TESTS_DIR    := $(IMAGE_DIR)/tests
COMPOSE_FILE := $(TESTS_DIR)/compose.test.yml
VENV         := $(TESTS_DIR)/.venv
PYTEST       ?= $(VENV)/bin/python -m pytest
PYTEST_FLAGS ?= -q

.PHONY: build venv test itest lint clean

## build: build the image as $(IMAGE)
build:
	docker build -t $(IMAGE) $(IMAGE_DIR)

$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -r $(TESTS_DIR)/requirements.txt

## venv: create the test virtualenv
venv: $(VENV)

## test: all unit tests (no docker, no compose)
test: venv
	cd $(TESTS_DIR) && $(PYTEST) $(PYTEST_FLAGS) -m "not integration"

## itest: integration tests via the compose stack (builds image, postgres:16)
itest: venv build
	cd $(TESTS_DIR) && $(PYTEST) -v -m integration test_integration.py
	@docker compose -f $(COMPOSE_FILE) down -v >/dev/null 2>&1 || true

## lint: validate compose + python syntax of CLI/app
lint: venv
	@echo "==> docker compose config"; \
	docker compose -f $(COMPOSE_FILE) config >/dev/null && echo "  OK"
	@echo "==> py_compile"; \
	$(VENV)/bin/python -m py_compile mailctl.py wsgi.py gunicorn.conf.py $$(find mail_controller -name '*.py')
	@echo "  OK"

## clean: tear down stack + scratch
clean:
	-docker compose -f $(COMPOSE_FILE) down -v 2>/dev/null
	rm -rf $(VENV) $(TESTS_DIR)/.pytest_cache
