VERSION = 2.0.5

PACKAGE = nginx-ldap-auth-service

DOCKER_REGISTRY = caltechads
#======================================================================

image_name:
	@echo ${PACKAGE}

version:
	@echo ${VERSION}

docs:
	@echo "Installing docs dependencies ..."
	@pip install -r doc/requirements.txt
	@echo "Generating docs..."
	@cd doc && rm -rf build && make json
	@cd doc/build && tar zcf docs.tar.gz json
	@mv doc/build/docs.tar.gz .
	@echo "New doc package is in docs.tar.gz"

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
	docker push ${DOCKER_REGISTRY}/${PACKAGE}:latest
	docker push ${DOCKER_REGISTRY}/${PACKAGE}:${VERSION}

pull:
	docker pull ${DOCKER_REGISTRY}/${PACKAGE}:${VERSION}

dev:
	docker-compose up

dev-detached:
	docker-compose up -d

devdown:
	docker-compose down

restart:
	docker-compose restart nginx-ldap-auth-service

exec:
	docker exec -it nginx-ldap-auth-service /bin/sh

release: dist
	@bin/release.sh
	@twine upload dist/*

log:
	docker-compose logs -f nginx-ldap-auth-service

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
