set -euxo pipefail

main() {
    cargo check --target $TARGET

    cargo test --target $TARGET
    cargo test --target $TARGET --release
}

main
