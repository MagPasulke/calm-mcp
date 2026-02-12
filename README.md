# SAP Cloud ALM MCP Server

MCP Server for SAP Cloud ALM APIs, deployed on SAP BTP Cloud Foundry.

## Project Structure

```
src/
├── index.ts                        # Express HTTP server, OAuth flow, session management
├── mcp-server.ts                   # MCP server wrapper, wires services and tools
├── services/
│   ├── auth-service.ts             # XSUAA authentication and token validation
│   ├── destination-service.ts      # BTP Destination Service connectivity
│   └── sap-client.ts              # CALM API calls (landscape, properties, events)
├── tools/
│   └── tool-registry.ts           # MCP tool definitions
├── types/
│   ├── mcp-types.ts               # MCP type definitions
│   ├── sap-types.ts               # CALM API query parameter types and enums
│   ├── sap-xsenv.d.ts            # @sap/xsenv type declarations
│   └── sap-xssec.d.ts            # @sap/xssec type declarations
└── utils/
    ├── config.ts                   # Configuration from env vars and VCAP_SERVICES
    ├── error-handler.ts            # Centralized error handling
    └── logger.ts                   # Winston-based logger
mta.yaml                           # MTA deployment descriptor
xs-security.json                   # XSUAA security configuration
```

## Supported CALM APIs

| Tool | API Endpoint | Description |
|------|-------------|-------------|
| `get-landscape-info` | `/calm-landscape/v1/landscapeObjects` | Query landscape objects with optional filters (name, objectType, role, serviceType, etc.) |
| `get-landscape-property-info` | `/calm-landscape/v1/properties` | Get properties for a single landscape object by ID |
| `get-status-events` | `/bsm-service/v1/events` | Query status events with optional filters (type, eventType, serviceName, period, etc.) |

All tools require the `read` scope via the `CALMViewer` role collection.

## Destination Configuration

Create a destination in your BTP subaccount pointing to the SAP Cloud ALM API:

| Property | Value |
|----------|-------|
| Name | Value of `CALM_DESTINATION_NAME` env var 
| Type | HTTP |
| URL | `https://<your-calm-tenant>.<your-region>.alm.cloud.sap/api` |
| Proxy Type | Internet |
| Authentication | OAuth2ClientCredentials |
| Token Service URL | `https://<your-calm-tenant>.authentication.<region>.hana.ondemand.com/oauth/token` |

The destination name used by the application is configured via the `CALM_DESTINATION_NAME` environment variable. 

## Deployment on BTP

### Build and Deploy

```bash
npm run build:btp
npm run deploy:btp
```

This builds the MTA archive and deploys it to your current CF target. The `mta.yaml` creates the required service instances (XSUAA, Connectivity) and binds them to the application. The Destination service instance must already exist.

### Post-Deployment

Assign the `CALMViewer` role to users that need access.

## Development and Testing in Local Hybrid Mode

Hybrid mode runs the server locally while binding to real BTP service instances via `cds bind`.

### Prerequisites

- [Cloud Foundry CLI](https://docs.cloudfoundry.org/cf-cli/)
- `cf login` to your BTP subaccount/space
- The application already deployed once (so service bindings exist)

### Bind Services

Bind each required BTP service instance to the local project:

```bash
cds bind -2 "xsuaa service name as per mta.yml"
cds bind -2 "destination service name as per mta.yml"
cds bind -2 "connectivity service name as per mta.yml"
```

Replace `<space>` with your CF space name. This creates a `.cdsrc-private.json` with the service keys.

### Run

```bash
npm run start:hybrid
```

This executes `cds bind --exec -- npm run start:http`, which:
1. Fetches service keys for bound XSUAA, Destination, and Connectivity instances
2. Sets `VCAP_SERVICES` in the local environment
3. Builds and starts the HTTP server on `http://localhost:3000`
