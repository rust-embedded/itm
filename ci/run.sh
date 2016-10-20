set -ex

test_mode() {
    cargo build --target $TARGET
    cargo build --target $TARGET --release
    cargo test --target $TARGET
    cargo test --target $TARGET --release
}

deploy_mode() {
    cargo rustc --target $TARGET --release --bin itmdump -- -C lto
}

run() {
    if [ -z $TRAVIS_TAG ]; then
        test_mode
    elif [ $TRAVIS_RUST_VERSION = $DEPLOY_VERSION ]; then
        deploy_mode
    fi
}

run
