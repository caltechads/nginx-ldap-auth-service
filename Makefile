VERSION = 2.0.2

PACKAGE = nginx-ldap-auth-service

DOCKER_REGISTRY = 131067624433.dkr.ecr.us-west-2.amazonaws.com/caltech-imss-ads
#======================================================================


clean:
	rm -rf *.tar.gz dist *.egg-info *.rpm
	find . -name "*.pyc" -exec rm '{}' ';'

dist: clean
	@python setup.py sdist
	@python setup.py bdist_wheel --universal

build:
	docker build -t ${PACKAGE}:${VERSION} .
	docker tag ${PACKAGE}:${VERSION} ${PACKAGE}:latest
	docker image prune -f

force-build:
	docker build --no-cache -t ${PACKAGE}:${VERSION} .
	docker tag ${PACKAGE}:${VERSION} ${PACKAGE}:latest

tag:
	docker tag ${PACKAGE}:${VERSION} ${DOCKER_REGISTRY}/${PACKAGE}:${VERSION}
	docker tag ${PACKAGE}:latest ${DOCKER_REGISTRY}/${PACKAGE}:latest

push: tag
	docker push ${DOCKER_REGISTRY}/${PACKAGE}

pull:
	docker pull ${DOCKER_REGISTRY}/${PACKAGE}:${VERSION}

dev:
	docker-compose up

dev-detached:
	docker-compose up -d

devdown:
	docker-compose down

restart:
	docker-compose restart nginx_ldap_auth

exec:
	docker exec -it nginx_ldap_auth /bin/bash

release: dist
	@twine upload dist/*

log:
	docker-compose logs -f nginx_ldap_auth

logall:
	docker-compose logs -f

docker-clean:
	docker stop $(shell docker ps -a -q)
	docker rm $(shell docker ps -a -q)

docker-destroy: docker-clean
	docker rmi -f $(shell docker images -q | uniq)
	docker image prune -f; docker volume prune -f; docker container prune -f

.PHONY: list build force-build
list:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs
