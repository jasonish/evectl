all:
	cross build --release --target aarch64-unknown-linux-musl
	cross build --release --target x86_64-unknown-linux-musl

clean:
	find . -name \*~ -delete
	cargo clean

.PHONY: test-housekeeper
test-housekeeper:
	cargo build
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s src/housekeeper -p 'test_*.py' -v
