import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import 'dotenv/config';

import { MCPServer, createMCPServer } from './mcp-server.js';
import { Logger } from './utils/logger.js';
import { Config } from './utils/config.js';
import { AuthService, AuthRequest } from './services/auth-service.js';

// Global type extensions
declare global {
    var mcpProxyStates: Map<string, {
        mcpRedirectUri: string;
        state: string;
        mcpCodeChallenge?: string;
        mcpCodeChallengeMethod?: string;
        timestamp: number;
    }>;
}

// Helper function to get the correct base URL from request
function getBaseUrl(req: express.Request): string {
    const protocol = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('host');
    return `${protocol}://${host}`;
}

/**
 * BTP MCP Server CALM - HTTP Server
 * 
 * This server provides HTTP transport for the MCP server with:
 * - OAuth 2.0 authentication via SAP XSUAA
 * - Session management
 * - Streamable HTTP transport for MCP communication
 */

const logger = new Logger('btp-mcp-server-calm'); 
const config = new Config();
const authService = new AuthService(logger, config);

// Session storage for HTTP transport with user context
const sessions: Map<string, {
    server: MCPServer;
    transport: StreamableHTTPServerTransport;
    createdAt: Date;
    userToken?: string;
    userId?: string;
}> = new Map();

/**
 * Clean up expired sessions
 */
function cleanupExpiredSessions(): void {
    const now = new Date();
    const maxAge = config.get<number>('session.timeoutMs', 3600000); // Default 1 hour

    for (const [sessionId, session] of sessions.entries()) {
        if (now.getTime() - session.createdAt.getTime() > maxAge) {
            logger.info(`🧹 Cleaning up expired session: ${sessionId}`);
            session.transport.close();
            sessions.delete(sessionId);
        }
    }
}

/**
 * Get or create a session for the given session ID with optional user context
 */
async function getOrCreateSession(sessionId?: string, userToken?: string): Promise<{
    sessionId: string;
    server: MCPServer;
    transport: StreamableHTTPServerTransport;
}> {
    // Check for existing session
    if (sessionId && sessions.has(sessionId)) {
        const session = sessions.get(sessionId)!;
        logger.debug(`♻️  Reusing existing session: ${sessionId}`);
        return {
            sessionId,
            server: session.server,
            transport: session.transport
        };
    }

    // Create new session
    const newSessionId = sessionId || randomUUID();
    logger.info(`🆕 Creating new MCP session: ${newSessionId}`);

    try {
        // Create and initialize MCP server with user token if available
        const mcpServer = await createMCPServer(userToken);

        // Create HTTP transport - same pattern as original
        const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => newSessionId,
            onsessioninitialized: (id) => {
                logger.debug(`✅ Session initialized: ${id}`);
            },
            enableDnsRebindingProtection: true,
            allowedHosts: config.getAllowedHosts()
        });

        // Connect server to transport
        await mcpServer.getServer().connect(transport);

        // Store session with user context if provided
        sessions.set(newSessionId, {
            server: mcpServer,
            transport,
            createdAt: new Date(),
            userToken: userToken
        });

        // Clean up session when transport closes
        transport.onclose = () => {
            logger.info(`🔌 Transport closed for session: ${newSessionId}`);
            sessions.delete(newSessionId);
        };

        logger.info(`🎉 Session created successfully: ${newSessionId}`);
        return {
            sessionId: newSessionId,
            server: mcpServer,
            transport
        };

    } catch (error) {
        logger.error(`❌ Failed to create session: ${error}`);
        throw error;
    }
}

/**
 * Create Express application
 */
export function createApp(): express.Application {
    const app = express();

    // Security and parsing middleware
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", "data:", "https:"]
            }
        }
    }));

    const allowedOrigins = config.get<string[]>('cors.allowedOrigins');
    const isProduction = config.get('node.env') === 'production';

    app.use(cors({
        origin: isProduction ? allowedOrigins : true,
        credentials: true,
        exposedHeaders: ['Mcp-Session-Id'],
        allowedHeaders: ['Content-Type', 'mcp-session-id', 'MCP-Protocol-Version', 'Authorization']
    }));

    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request logging middleware
    app.use((req, res, next) => {
        logger.debug(`📨 ${req.method} ${req.path}`, {
            sessionId: req.headers['mcp-session-id'],
            userAgent: req.headers['user-agent']
        });
        next();
    });

    // Health check endpoint
    app.get('/health', (req, res) => {
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            activeSessions: sessions.size,
            version: '1.0.0'
        });
    });

    // Main MCP endpoint - handles all MCP communication
    app.post('/mcp', authService.authenticateJWT() as express.RequestHandler, async (req, res) => {
        const authReq = req as AuthRequest;
        try {
            // Get session ID from header
            const sessionId = authReq.headers['mcp-session-id'] as string | undefined;
            let session;

            if (sessionId && sessions.has(sessionId)) {
                // Reuse existing session
                session = await getOrCreateSession(sessionId, authReq.jwtToken);
            } else if (!sessionId && isInitializeRequest(authReq.body)) {
                // New initialization request with user token if available
                session = await getOrCreateSession(undefined, authReq.jwtToken);
            } else {
                // Invalid request
                logger.warn(`❌ Invalid MCP request - no session ID and not initialize request`);
                return res.status(400).json({
                    jsonrpc: '2.0',
                    error: {
                        code: -32000,
                        message: 'Bad Request: No valid session ID provided or not an initialize request'
                    },
                    id: authReq.body?.id || null
                });
            }

            // Handle the request
            await session.transport.handleRequest(authReq, res, authReq.body);

        } catch (error) {
            logger.error('❌ Error handling MCP request:', error);

            if (!res.headersSent) {
                res.status(500).json({
                    jsonrpc: '2.0',
                    error: {
                        code: -32603,
                        message: `Internal server error: ${error instanceof Error ? error.message : 'Unknown error'}`
                    },
                    id: authReq.body?.id || null
                });
            }
        }
    });

    // Handle session termination
    app.delete('/mcp', async (req, res) => {
        try {
            const sessionId = req.headers['mcp-session-id'] as string | undefined;

            if (!sessionId || !sessions.has(sessionId)) {
                logger.warn(`❌ Cannot terminate - invalid session ID: ${sessionId}`);
                return res.status(400).json({
                    error: 'Invalid or missing session ID'
                });
            }

            const session = sessions.get(sessionId)!;

            // Handle the termination request
            await session.transport.handleRequest(req, res);

            // Clean up session
            sessions.delete(sessionId);
            logger.info(`🗑️  Session terminated: ${sessionId}`);

        } catch (error) {
            logger.error('❌ Error terminating session:', error);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Internal server error' });
            }
        }
    });

    // Handle HEAD requests to /mcp (for health checks)
    app.head('/mcp', (req, res) => {
        res.status(200).end();
    });

    // =========================================================================
    // OAuth Discovery Endpoints
    // =========================================================================

    // OAuth 2.0 Authorization Server Metadata (RFC 8414)
    app.get(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp'], (req, res) => {
        try {
            if (!authService.isConfigured()) {
                return res.status(501).json({
                    error: 'OAuth not configured',
                    message: 'XSUAA service is not configured for this deployment',
                    setup_required: 'Bind XSUAA service to this application'
                });
            }

            const xsuaaMetadata = authService.getXSUAADiscoveryMetadata()!;
            const appScopes = authService.getApplicationScopes();
            const baseUrl = getBaseUrl(req);
            const discoveryMetadata = {
                // Core OAuth 2.0 Authorization Server Metadata
                issuer: xsuaaMetadata.issuer,
                authorization_endpoint: `${baseUrl}/oauth/authorize`,
                token_endpoint: `${baseUrl}/oauth/token`,
                userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
                revocation_endpoint: `${baseUrl}/oauth/revoke`,
                introspection_endpoint: `${baseUrl}/oauth/introspect`,

                // Client Registration Endpoint (RFC 7591) - Static client support
                registration_endpoint: `${baseUrl}/oauth/client-registration`,

                // Supported response types
                response_types_supported: [
                    'code'
                ],

                // Supported grant types
                grant_types_supported: [
                    'authorization_code',
                    'refresh_token'
                ],

                // Client Registration Support (RFC 7591)
                registration_endpoint_auth_methods_supported: [
                    'none'
                ],
                client_registration_types_supported: [
                    'static'
                ],

                // Supported scopes - only advertise openid and app-specific scopes
                // Note: Do not advertise profile, email, uaa.user, uaa.resource
                // as Custom IAS IdPs may not support them, causing XSUAA to
                // reject the entire scope request and fall back to openid only.
                scopes_supported: [
                    'openid',
                    ...appScopes
                ],

                // PKCE support
                code_challenge_methods_supported: ['S256'],

                // Service documentation
                service_documentation: `${baseUrl}/docs`,

                // Additional XSUAA specific metadata
                'x-xsuaa-metadata': {
                    client_id: xsuaaMetadata.clientId,
                    identityZone: xsuaaMetadata.identityZone,
                    tenantMode: xsuaaMetadata.tenantMode
                },

                // MCP-specific extensions
                'x-mcp-server': {
                    name: 'btp-mcp-server-calm',
                    version: '1.0.0',
                    mcp_endpoint: `${baseUrl}/mcp`,
                    authentication_required: true,
                    capabilities: [
                        'caps of your service'
                    ]
                },

                // MCP Static Client Support
                'x-mcp-static-client': {
                    supported: true,
                    registration_endpoint: `${baseUrl}/oauth/client-registration`,
                    client_id: xsuaaMetadata.clientId,
                    client_authentication_method: 'client_secret_basic'
                }
            };

            res.setHeader('Access-Control-Allow-Origin', '*'); //TODO: restrict allowed origins if needed, e.g. when using browser-based MCP Clients
            res.setHeader('Cache-Control', 'public, max-age=3600');
            res.json(discoveryMetadata);
        } catch (error) {
            logger.error('Failed to generate OAuth discovery metadata:', error);
            res.status(500).json({
                error: 'Failed to generate discovery metadata',
                message: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });

    // Static Client Registration Endpoint (RFC 7591 alternative for XSUAA)
    app.post('/oauth/client-registration', (req, res) => {
        try {
            if (!authService.isConfigured()) {
                return res.status(501).json({
                    error: 'OAuth not configured',
                    message: 'XSUAA service is not configured for this deployment'
                });
            }

            if (!authService.getServiceInfo()) {
                return res.status(501).json({
                    error: 'OAuth not configured',
                    message: 'XSUAA service credentials not available'
                });
            }

            // Get client credentials including secret (sensitive operation)
            const clientCredentials = authService.getClientCredentials();
            if (!clientCredentials) {
                return res.status(501).json({
                    error: 'OAuth credentials not available',
                    message: 'XSUAA client credentials not configured'
                });
            }

            const baseUrl = getBaseUrl(req);

            // Return static client registration response per RFC 7591
            const clientRegistrationResponse = {
                client_id: clientCredentials.client_id,
                client_secret: clientCredentials.client_secret,
                client_id_issued_at: Math.floor(Date.now() / 1000),
                client_secret_expires_at: 0, // Never expires for static clients

                // OAuth 2.0 Client Metadata
                redirect_uris: [
                    `${baseUrl}/oauth/callback`
                ],
                grant_types: [
                    'authorization_code',
                    'refresh_token'
                ],
                response_types: [
                    'code'
                ],
                client_name: 'BTP MCP Server Dedicated',
                client_uri: baseUrl,

                // Token endpoint authentication method
                token_endpoint_auth_method: 'client_secret_basic',

                // XSUAA specific metadata
                'x-xsuaa-metadata': {
                    url: clientCredentials.url,
                    identityzone: clientCredentials.identityZone,
                    tenantmode: clientCredentials.tenantMode,
                    uaadomain: clientCredentials.url.replace(/^https?:\/\//, '').replace(/\/$/, '')
                },

                // MCP-specific metadata
                'x-mcp-integration': {
                    server_name: 'btp-mcp-server-calm',
                    mcp_endpoint: `${baseUrl}/mcp`,
                    authentication_flow: 'authorization_code',
                    supports_refresh: true
                },

                // Static client indicator
                registration_client_uri: `${baseUrl}/oauth/client-registration`,
                client_registration_type: 'static'
            };

            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.json(clientRegistrationResponse);

        } catch (error) {
            logger.error('Failed to handle client registration:', error);
            res.status(500).json({
                error: 'registration_failed',
                error_description: `Client registration failed: ${error instanceof Error ? error.message : 'Unknown error'}`
            });
        }
    });

    // GET version of client registration for static client discovery
    app.get('/oauth/client-registration', (req, res) => {
        try {
            if (!authService.isConfigured()) {
                return res.status(501).json({
                    error: 'OAuth not configured',
                    message: 'XSUAA service is not configured for this deployment'
                });
            }

            const baseUrl = getBaseUrl(req);

            const clientInfo = {
                registration_endpoint: `${baseUrl}/oauth/client-registration`,
                client_registration_types_supported: ['static'],
                registration_endpoint_auth_methods_supported: ['none'],
                static_client_available: true,
                'x-mcp-integration': {
                    server_name: 'btp-mcp-server-calm',
                    mcp_endpoint: `${baseUrl}/mcp`,
                    authentication_required: true,
                    static_client_supported: true
                }
            };

            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Cache-Control', 'public, max-age=3600');
            res.json(clientInfo);

        } catch (error) {
            logger.error('Failed to handle client registration info:', error);
            res.status(500).json({
                error: 'server_error',
                error_description: `Failed to get client registration info: ${error instanceof Error ? error.message : 'Unknown error'}`
            });
        }
    });

    // OAuth authorize endpoint
    app.get('/oauth/authorize', (req, res) => {
        logger.info('Start OAuth authorization flow');
        try {
            if (!authService.isConfigured()) {
                return res.status(501).json({
                    error: 'OAuth not configured',
                    message: 'XSUAA service is not configured for this deployment'
                });
            }

            const state = req.query.state as string || randomUUID();
            const baseUrl = getBaseUrl(req);
            const mcpRedirectUri = req.query.redirect_uri as string;
            const mcpScope = req.query.scope as string;
            const authUrl = authService.getAuthorizationUrl(state, baseUrl, mcpScope);
            const mcpCodeChallenge = req.query.code_challenge as string;
            const mcpCodeChallengeMethod = req.query.code_challenge_method as string;

            if (!mcpRedirectUri) {
                return res.status(400).json({
                    error: 'Missing redirect_uri parameter',
                    message: 'MCP redirect URI is required'
                });
            }

            // Store mapping for callback
            if (!globalThis.mcpProxyStates) {
                globalThis.mcpProxyStates = new Map();
            }
            globalThis.mcpProxyStates.set(state, {
                mcpRedirectUri,
                state,
                mcpCodeChallenge,
                mcpCodeChallengeMethod,
                timestamp: Date.now()
            });

            // Clean up old states (older than 10 minutes)
            for (const [key, value] of globalThis.mcpProxyStates.entries()) {
                if (Date.now() - value.timestamp > 600000) {
                    globalThis.mcpProxyStates.delete(key);
                }
            }

            logger.info(`MCP OAuth proxy initiated for redirect: ${mcpRedirectUri}`);
            logger.info(`Redirecting to XSUAA authUrl: ${authUrl}`);
            res.redirect(authUrl);
        } catch (error) {
            logger.error('Failed to initiate OAuth flow:', error);
            res.status(500).json({ error: 'Failed to initiate OAuth flow' });
        }
    });

    // OAuth token endpoint
    const tokenHandler = async (req: Request, res: Response) => {
        logger.info(`Start OAuth token exchange flow - grant_type: ${req.body?.grant_type}`);
        const baseUrl = getBaseUrl(req);
        try {
            if (!authService.isConfigured()) {
                return res.status(501).json({
                    error: 'oauth_not_configured',
                    error_description: 'XSUAA service is not configured for this deployment'
                });
            }

            const grantType = req.body?.grant_type;
            let tokenData;

            if (grantType === 'authorization_code' || req.body?.code) {
                const code = req.body.code;
                if (!code) {
                    return res.status(400).json({
                        error: 'invalid_request',
                        error_description: 'Missing required parameter: code'
                    });
                }
                logger.info('Processing authorization_code grant');
                tokenData = await authService.exchangeCodeForToken(code, authService.getRedirectUri(baseUrl));
            } else if (grantType === 'refresh_token' || req.body?.refresh_token) {
                const refreshToken = req.body.refresh_token;
                if (!refreshToken) {
                    return res.status(400).json({
                        error: 'invalid_request',
                        error_description: 'Missing required parameter: refresh_token'
                    });
                }
                logger.info('Processing refresh_token grant');
                tokenData = await authService.refreshAccessToken(refreshToken);
            } else {
                return res.status(400).json({
                    error: 'unsupported_grant_type',
                    error_description: 'Supported grant types: authorization_code, refresh_token'
                });
            }

            logger.info(`OAuth token exchange successful - grant_type: ${grantType}`);
            res.json(tokenData);
        } catch (error) {
            logger.error('OAuth token exchange failed:', error);
            res.status(400).json({
                error: 'invalid_grant',
                error_description: error instanceof Error ? error.message : 'Token exchange failed'
            });
        }
    };
    app.get('/oauth/token', tokenHandler);
    app.post('/oauth/token', tokenHandler);

    // OAuth callback endpoint
    app.get('/oauth/callback', async (req, res) => {
        logger.info('Start OAuth callback handling');
        try {
            const code = req.query.code as string;
            // Normalize state parameter - URL decoding converts + to space, so we need to reverse it
            let state = req.query.state as string;
            if (state) {
                state = state.replaceAll(' ', '+');
            }
            const error = req.query.error as string;

            if (error) {
                const errorMsg = req.query.error_description as string || error;
                return res.status(400).send(`
                    <html><body style="font-family: sans-serif; text-align: center; padding: 2rem;">
                        <h1>❌ Authentication Failed</h1>
                        <p>${errorMsg}</p>
                        <a href="/oauth/authorize" style="display: inline-block; padding: 0.5rem 1rem; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">Try Again</a>
                    </body></html>
                `);
            }

            if (!code) {
                return res.status(400).send(`
                    <html><body style="font-family: sans-serif; text-align: center; padding: 2rem;">
                        <h1>❌ Authentication Failed</h1>
                        <p>Authorization code not provided.</p>
                        <a href="/oauth/authorize" style="display: inline-block; padding: 0.5rem 1rem; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">Try Again</a>
                    </body></html>
                `);
            }

            // Check if this is a MCP proxy callback
            const mcpProxyStates = globalThis.mcpProxyStates;
            const mcpInfo = state && mcpProxyStates?.get(state);

            if (!mcpInfo) {
                logger.warn(`MCP state not found for state: ${state}`);
                return res.status(400).send(`
                    <html><body style="font-family: sans-serif; text-align: center; padding: 2rem;">
                        <h1>❌ Authentication Failed</h1>
                        <p>MCP state not found.</p>
                        <a href="/oauth/authorize" style="display: inline-block; padding: 0.5rem 1rem; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">Try Again</a>
                    </body></html>
                `);
            }

            const callbackUrl = new URL(mcpInfo.mcpRedirectUri);
            const params = new URLSearchParams({ code, state }).toString();

            logger.info(`MCP OAuth proxy successful, redirecting to: ${mcpInfo.mcpRedirectUri}`);
            return res.redirect(`${callbackUrl.toString()}?${params}`);

        } catch (error) {
            logger.error('OAuth callback failed:', error);
            res.status(500).send(`
                <html><body style="font-family: sans-serif; text-align: center; padding: 2rem;">
                    <h1>❌ Authentication Failed</h1>
                    <p>Error: ${error instanceof Error ? error.message : 'Unknown error'}</p>
                    <a href="/oauth/authorize" style="display: inline-block; padding: 0.5rem 1rem; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">Try Again</a>
                </body></html>
            `);
        }
    });

    // Token refresh endpoint
    app.post('/oauth/refresh', async (req, res) => {
        try {
            const refreshToken = req.body?.refreshToken || req.body?.refresh_token;
            if (!refreshToken) {
                return res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'Refresh token not provided. Include refreshToken or refresh_token in request body.'
                });
            }

            logger.info('Processing token refresh via /oauth/refresh endpoint');
            const tokenData = await authService.refreshAccessToken(refreshToken);
            logger.info('Token refresh successful');
            res.json(tokenData);
        } catch (error) {
            logger.error('Token refresh failed:', error);
            res.status(401).json({
                error: 'invalid_grant',
                error_description: error instanceof Error ? error.message : 'Token refresh failed'
            });
        }
    });

    // API documentation endpoint
    app.get('/docs', (req, res) => {
        res.json({
            title: 'BTP MCP Server Dedicated API',
            description: 'Model Context Protocol server for dedicated SAP OData service integration',
            version: '1.0.0',
            endpoints: {
                'GET /health': 'Health check endpoint',
                'POST /mcp': 'Main MCP communication endpoint',
                'DELETE /mcp': 'Session termination endpoint',
                'GET /docs': 'This API documentation',
                'GET /.well-known/oauth-authorization-server': 'OAuth 2.0 Authorization Server Metadata (RFC 8414)',
                'GET /oauth/authorize': 'Initiate OAuth authorization flow',
                'GET /oauth/callback': 'OAuth authorization callback',
                'POST /oauth/token': 'Token exchange endpoint',
                'POST /oauth/refresh': 'Refresh access tokens'
            },
            usage: {
                authentication: 'OAuth 2.0 with SAP XSUAA - JWT tokens required for MCP operations',
                sessionManagement: 'Automatic session creation with user token context',
                workflowSteps: [
                    '1. Get OAuth token via /oauth/authorize flow',
                    '2. Include token in Authorization header for /mcp requests',
                    '3. Use registered MCP tools to interact with SAP services'
                ]
            }
        });
    });

    // Handle 404s
    app.use((req, res) => {
        logger.warn(`❌ 404 - Not found: ${req.method} ${req.path}`);
        res.status(404).json({
            error: 'Not Found',
            message: `The requested endpoint ${req.method} ${req.path} was not found`,
            availableEndpoints: ['/health', '/mcp', '/docs']
        });
    });

    // Global error handler
    app.use((error: Error, req: express.Request, res: express.Response) => {
        logger.error('❌ Unhandled error:', error);

        if (!res.headersSent) {
            res.status(500).json({
                error: 'Internal Server Error',
                message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
            });
        }
    });

    // Clean up expired sessions periodically
    setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // Every hour

    return app;
}

/**
 * Start the server
 */
export async function startServer(port?: number): Promise<void> {
    const serverPort = port || config.get<number>('server.port', 3000);
    const app = createApp();

    return new Promise((resolve, reject) => {
        try {

            const baseUrl = config.getServerUrl(serverPort);
            const server = app.listen(serverPort, async () => {
                logger.info(
                    `🚀 BTP MCP Server Dedicated running\n` +
                    `   Base URL: ${baseUrl}\n` +
                    `   📊 Health check: ${baseUrl}/health\n` +
                    `   📚 API docs: ${baseUrl}/docs\n` +
                    `   🔧 MCP endpoint: ${baseUrl}/mcp`
                );
                resolve();
            });

            server.on('error', (error) => {
                logger.error(`❌ Server error:`, error);
                reject(error);
            });

            // Graceful shutdown
            process.on('SIGTERM', () => {
                logger.info('🛑 SIGTERM received, shutting down gracefully...');

                // Close all sessions
                for (const [sessionId, session] of sessions.entries()) {
                    logger.info(`🔌 Closing session: ${sessionId}`);
                    session.transport.close();
                }
                sessions.clear();

                server.close(() => {
                    logger.info('✅ Server shut down successfully');
                    process.exit(0);
                });
            });

        } catch (error) {
            logger.error(`❌ Failed to start server:`, error);
            reject(error);
        }
    });
}

// Start server if this file is run directly
const port = Number.parseInt(process.env.PORT || '3000');

try {
    await startServer(port);
} catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
}
