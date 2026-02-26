all: test

clean:
	rm -rf fixer-fix/src/tag.rs fixer-fix/src/enums.rs fixer-fix/src/field.rs fixer-fix/src/lib.rs
	rm -rf fixer-fix/src/fix40 fixer-fix/src/fix41 fixer-fix/src/fix42 fixer-fix/src/fix43 fixer-fix/src/fix44
	rm -rf fixer-fix/src/fix50 fixer-fix/src/fix50sp1 fixer-fix/src/fix50sp2 fixer-fix/src/fixt11

generate: clean
	cargo run -p fixer-gen -- spec/FIX40.xml spec/FIX41.xml spec/FIX42.xml spec/FIX43.xml spec/FIX44.xml spec/FIX50.xml spec/FIX50SP1.xml spec/FIX50SP2.xml -o fixer-fix/src

generate-float: clean
	cargo run -p fixer-gen -- --use-float spec/FIX40.xml spec/FIX41.xml spec/FIX42.xml spec/FIX43.xml spec/FIX44.xml spec/FIX50.xml spec/FIX50SP1.xml spec/FIX50SP2.xml -o fixer-fix/src

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace -- -D warnings

test:
	cargo test --workspace

.PHONY: all clean generate generate-float fmt clippy test
