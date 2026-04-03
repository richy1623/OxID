# OxID

A Rust based Authentication Mangement System

[![codecov](https://codecov.io/gh/richy1623/OxID/graph/badge.svg?token=7J9YMIGJM2)](https://codecov.io/gh/richy1623/OxID)

## Code Generation

### Changing the API

> Note: requires openapi-generator-cli

```shell
openapi-generator-cli generate -i resources/OpenAPISpec.yaml -g rust -o oxid_service_interface --additional-properties=packageName=oxid_service_interface
```

## How to run tests with coverage

This repo uses `tarpaulin` to generate code coverage reports for Rust code. The `.tarpaulin.toml` file contains the configuration.

### Local

```shell
cargo tarpaulin
```

### CI

To run the tests with coverage include `[ci]` in the commit message to trigger a GitHub Action to run the tests + coverage

## Certificate Management

To run the `todo` a certificate is required. It should be generated and then mounted in the container
or kept in the local file system.

### Certificate Management - Local

```shell
# Generate a P-256 EC private key
openssl ecparam -name prime256v1 -genkey -noout -out certs/key.pem

# Create a self-signed cert valid for 365 days
openssl req -new -x509 -key certs/key.pem -out certs/cert.pem -days 365 -subj "/CN=localhost"
```

Note: You can trust the cert with the following command:

```shell
mkcert -key-file key.pem -cert-file cert.pem 127.0.0.1 localhost
```

### Certificate Management - Prod

```shell
# P-256 (prime256v1)
sudo certbot certonly --standalone --key-type ecdsa --elliptic-curve secp256r1 -d example.com
```

## Diesel

Diesel is the ORM used to interact DB

### Get Started

[Diesel](https://diesel.rs/guides/getting-started.html)

### Common Commands

- Migrate DB

  ```bash
  diesel migration run
  ```

- Create New Migration

  ```bash
  diesel migration generate <migration_name>
  ```

## Troubleshooting

### Windows Build Issues

If you encounter linker errors (such as LNK1318) or CMake generator mismatches while building OxID on Windows, try force the Ninja Generator.
Rust's build scripts for C-libraries (like aws-lc-sys or openssl-sys) often struggle to find the correct Visual Studio instance. Using Ninja provides a more reliable and faster build experience.
Setting an environment variable `CMAKE_GENERATOR=Ninja` to use Ninja.
