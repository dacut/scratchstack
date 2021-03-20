start-local-postgres:	## Start the local PostgreSQL database for testing on the local machine.
	PGPORT=10811 pg_ctl --pgdata=$$PWD/local-testing/pgsql/data --log=$$PWD/local-testing/pgsql/postgresql.log start

stop-local-postgres:	## Stop the local PostgreSQL database.
	PGPORT=10811 pg_ctl --pgdata=$$PWD/local-testing/pgsql/data --log=$$PWD/local-testing/pgsql/postgresql.log stop

bootstrap-local-postgres:	## Bootstrap the local PostgreSQL database.
	mkdir -p $$PWD/local-testing/pgsql/data
	@chmod 750 $$PWD/local-testing/pgsql/data
	PGPORT=10811 initdb -D $$PWD/local-testing/pgsql/data
	cp $$PWD/local-testing/pgsql/etc/postgresql.conf $$PWD/local-testing/pgsql/data/postgresql.conf
	$$PWD/local-testing/pgsql/etc/generate_hbaconf.sh $$PWD/local-testing/pgsql/data/pg_hba.conf
	cargo install diesel_cli --no-default-features --features postgres
	PGPORT=10811 pg_ctl --pgdata=$$PWD/local-testing/pgsql/data --log=$$PWD/local-testing/pgsql/postgresql.log start
	DATABASE_URL=postgres://$$LOGNAME@localhost:10811/scratchstack diesel setup
	if [[ ! -f $$PWD/local-testing/pgsql/etc/postgres-limitstore-password.txt ]]; then dd if=/dev/urandom bs=24 count=1 | base64 > $$PWD/local-testing/pgsql/etc/postgres-limitstore-password.txt; fi;
	if [[ ! -f $$PWD/local-testing/pgsql/etc/postgres-iam-password.txt ]]; then dd if=/dev/urandom bs=24 count=1 | base64 > $$PWD/local-testing/pgsql/etc/postgres-iam-password.txt; fi;
	@psql --port=10811 --dbname=postgres --command "CREATE USER limitstore PASSWORD '$$(cat $$PWD/local-testing/pgsql/etc/postgres-limitstore-password.txt)'; CREATE USER iam PASSWORD '$$(cat $$PWD/local-testing/pgsql/etc/postgres-iam-password.txt)'"
	psql --port=10811 --dbname=scratchstack --command "GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA limitstore TO limitstore; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA iam TO iam; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA limitstore TO iam"

# ----------------------------------------------------------------------------
# Self-Documented Makefile
# ref: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
# ----------------------------------------------------------------------------
help:  ## Display help comments for each make command
	@COLS=$$(expr $$(tput cols) - 2 || echo 78); printf '\033[97;1;48;5;28m  %-*s\033[0m\n' $$COLS "Makefile targets"
	@grep -E '^[0-9a-zA-Z_-]+:.*? .*$$' $(MAKEFILE_LIST)  \
		| awk 'BEGIN { FS=":.*?## " }; {printf "\033[38;5;15;48;5;19m  %-28s\033[0m  %s\n", $$1, $$2}'  \
		| sort

.PHONY: bootstrap-local-postgres start-local-postgres stop-local-postgres help