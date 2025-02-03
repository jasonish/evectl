all:
	cross build --release --target aarch64-unknown-linux-musl
	cross build --release --target x86_64-unknown-linux-musl

format:
	cargo fmt

fix:
	cargo clippy --fix --all-features --allow-dirty

update:
	cargo update

update-breaking:
	cargo +nightly -Z unstable-options update --breaking

dev-clean:
	rm -rf ~/.config/evectl
	rm -rf ~/.local/share/evectl

clean:
	find . -name \*~ -delete
	cargo clean
