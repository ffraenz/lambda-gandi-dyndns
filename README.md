
# lambda-gandi-dyndns

Amazon AWS Lambda function forwarding IP address updates from routers (e.g. FRITZ!Box) to the [Gandi.net LiveDNS API](https://doc.livedns.gandi.net/) to provide a custom dynamic DNS service.

## Build

Build Lambda function ZIP archive:

```bash
pip3 install --target ./package requests
cd package
zip -r9 ../function.zip .
cd ..
zip -g function.zip main.py
```

## Setup

- Create a Lambda function with the content of this repository and connect it to the API Gateway service.

- Use `main.handle_update` as the function handler.

- Configure the Lambda function with the environment variables listed below.

- Configure the endpoints listed below in the API Gateway service and deploy the API.

- Use the following `Update-URL` structure to configure the Amazon AWS Lambda endpoint as a custom dynamic DNS service on FRITZ!Box routers:

  ```
  https://example.execute-api.region.amazonaws.com/stage/name/update?domain=<domain>&ip=<ipaddr>&ip6=<ip6addr>
  ```

- Use a username, password and domain that matches the environment config.

## Endpoints

### GET /update

Updates the IP address for the given dynamic DNS domain name.

Parameters:

- `ip` – New IPv4 address
- `ip6` – New IPv6 address
- `domain` – Single or multiple comma-separated (`,`) Dynamic DNS domain names; Needs to be whitelisted in the environment variables

## Environment variables

| Key                    | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| `AUTH_USERNAME`        | Basic authentication username required to fulfil requests   |
| `AUTH_PASSWORD`        | Basic authentication password required to fulfil requests   |
| `GANDI_API_KEY`        | [Gandi.net API key](https://doc.livedns.gandi.net/)          |
| `RECORD_TTL`           | Record time to live (TTL)                                    |
| `DOMAIN_WHITELIST`     | Comma-separated (`,`) whitelist of domain names that may receive updates |

