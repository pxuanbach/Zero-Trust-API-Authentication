infras:
	docker compose -f ./src/docker-compose.yml -f ./src/dbs.yml -f ./src/services.yml up -d
