all: test

clean:
	rm -rf fixer-fix/src/tag.rs fixer-fix/src/enums.rs fixer-fix/src/field.rs fixer-fix/src/lib.rs
	rm -rf fixer-fix/src/fix40 fixer-fix/src/fix41 fixer-fix/src/fix42 fixer-fix/src/fix43 fixer-fix/src/fix44
	rm -rf fixer-fix/src/fix50 fixer-fix/src/fix50sp1 fixer-fix/src/fix50sp2 fixer-fix/src/fixt11

generate: clean
	cargo run -p fixer-gen -- spec/FIX40.xml spec/FIX41.xml spec/FIX42.xml spec/FIX43.xml spec/FIX44.xml spec/FIX50.xml spec/FIX50SP1.xml spec/FIX50SP2.xml -o fixer-fix/src

generate-float: clean
	cargo run -p fixer-gen -- --use-float spec/FIX40.xml spec/FIX41.xml spec/FIX42.xml spec/FIX43.xml spec/FIX44.xml spec/FIX50.xml spec/FIX50SP1.xml spec/FIX50SP2.xml -o fixer-fix/src

# Regenerate the bundled FIXML abbreviation tables from a FIX repository
# checkout. The repository is not redistributable, so spec/fixml is checked in
# and this only needs re-running for a new repository edition. There is no
# default path — point FIX_REPOSITORY at your own copy:
#   make fixml-abbr FIX_REPOSITORY=/path/to/fix_repository_2010_edition_20200402
fixml-abbr:
	@test -n "$(FIX_REPOSITORY)" || { \
	  echo "FIX_REPOSITORY is not set."; \
	  echo "usage: make fixml-abbr FIX_REPOSITORY=/path/to/fix_repository"; \
	  exit 1; \
	}
	cargo run -p fixer-gen --bin fixml-abbr -- $(FIX_REPOSITORY) -o spec/fixml

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace -- -D warnings

test:
	cargo test --workspace

build-test:
	cargo build -p fixer-test

fix40: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix40.cfg 5010 _test/definitions/server/fix40/*.def

fix41: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix41.cfg 5002 _test/definitions/server/fix41/*.def

fix42: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix42.cfg 5003 _test/definitions/server/fix42/*.def

fix43: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix43.cfg 5004 _test/definitions/server/fix43/*.def

fix44: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix44.cfg 5005 _test/definitions/server/fix44/*.def

fix50: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix50.cfg 5006 _test/definitions/server/fix50/*.def

fix50sp1: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix50sp1.cfg 5007 _test/definitions/server/fix50sp1/*.def

fix50sp2: build-test
	cargo run -p fixer-test -- _test/cfg/server/fix50sp2.cfg 5008 _test/definitions/server/fix50sp2/*.def

ACCEPT_SUITE = fix40 fix41 fix42 fix43 fix44 fix50 fix50sp1 fix50sp2
accept: $(ACCEPT_SUITE)

.PHONY: all clean generate generate-float fmt clippy test build-test $(ACCEPT_SUITE) accept
