# OxID
A Rust based Authentication Mangement System

## Code Generation

### Changing the API

> Note: requires openapi-generator-cli

```shell
openapi-generator-cli generate -i resources\OpenAPISpec.yaml -g rust -o oxid_service_interface
```
