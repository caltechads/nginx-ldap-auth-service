VERSION = 2.1.2

PACKAGE = nginx-ldap-auth-service

DOCKER_REGISTRY = caltechads
#======================================================================

image_name:
	@echo ${PACKAGE}

version:
	@echo ${VERSION}

docs:
	@echo "Generating docs..."
	@cd doc && rm -rf build && make json
	@cd doc/build && tar zcf docs.tar.gz json
	@mv doc/build/docs.tar.gz .
	@echo "New doc package is in docs.tar.gz"

clean:
	rm -rf *.tar.gz dist *.egg-info *.rpm
	find . -name "*.pyc" -exec rm '{}' ';'

dist: clean
	@uv build --sdist --wheel

build:
	docker build --platform linux/amd64,linux/arm64 --sbom=true --provenance=true -t ${PACKAGE}:${VERSION} .
	docker tag ${PACKAGE}:${VERSION} ${PACKAGE}:latest
	docker image prune -f

force-build:
	docker build --platform linux/amd64,linux/arm64 --sbom=true --provenance=true --no-cache -t ${PACKAGE}:${VERSION} .
	docker tag ${PACKAGE}:${VERSION} ${PACKAGE}:latest

tag:
	docker tag ${PACKAGE}:${VERSION} ${DOCKER_REGISTRY}/${PACKAGE}:${VERSION}
	docker tag ${PACKAGE}:latest ${DOCKER_REGISTRY}/${PACKAGE}:latest

push: tag
	docker push ${DOCKER_REGISTRY}/${PACKAGE}:latest
	docker push ${DOCKER_REGISTRY}/${PACKAGE}:${VERSION}

pull:
	docker pull ${DOCKER_REGISTRY}/${PACKAGE}:${VERSION}

dev:
	docker compose up

dev-detached:
	docker compose up -d

devdown:
	docker compose down

restart:
	docker compose restart nginx-ldap-auth-service

exec:
	docker exec -it nginx-ldap-auth-service /bin/sh

scout:
	docker scout cves --only-severity=critical,high ${PACKAGE}:${VERSION}

release: dist
	@bin/release.sh
	@twine upload dist/*

log:
	docker compose logs -f nginx-ldap-auth-service

logall:
	docker compose logs -f

compile: uv.lock
	@uv pip compile --extra=docs pyproject.toml -o requirements.txt

docker-clean:
	docker stop $(shell docker ps -a -q)
	docker rm $(shell docker ps -a -q)

.PHONY: list build force-build
list:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs
