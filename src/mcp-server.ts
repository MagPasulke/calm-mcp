import { ToolRegistry } from './tools/tool-registry.js';
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import 'dotenv/config';
import { DestinationService } from './services/destination-service.js';
import { SAPClient } from './services/sap-client.js';
import { Logger } from './utils/logger.js';
import { Config } from './utils/config.js';
import { ErrorHandler } from './utils/error-handler.js';
import { AuthService } from './services/auth-service.js';

/**
 * MCP Server for SAP BTP Dedicated
 * 
 * This class wraps the Model Context Protocol server and manages
 * tool registration, user authentication, and HTTP transport.
 */
export class MCPServer {
    private readonly logger: Logger;
    private readonly config: Config;
    private readonly destinationService: DestinationService;
    private readonly sapClient: SAPClient;
    private readonly mcpServer: McpServer;
    private readonly toolRegistry: ToolRegistry;
    private userToken?: string;
    private readonly authService: AuthService;

    constructor() {
        this.logger = new Logger('mcp-server-calm');
        this.config = new Config();
        this.destinationService = new DestinationService(this.logger, this.config);
        this.authService = new AuthService(this.logger, this.config);
        this.sapClient = new SAPClient(this.destinationService, this.logger, this.authService);
        
        this.mcpServer = new McpServer({
            name: "btp-mcp-server-calm",
            version: "1.0.0"
        });
        
        this.mcpServer.server.onerror = (error) => {
            this.logger.error('MCP Server Error:', error);
            ErrorHandler.handle(error);
        };

        this.toolRegistry = new ToolRegistry(this.mcpServer, this.sapClient, this.logger);
    }

    /**
     * Set the user's JWT token for authenticated operations
     */
    setUserToken(token?: string): void {
        this.userToken = token;
        this.toolRegistry.setUserToken(token);
        this.logger.debug(`User token ${token ? 'set' : 'cleared'} for MCP server`);
    }

    /**
     * Initialize the MCP server
     * - Initializes the destination service
     * - Registers all tools
     */
    async initialize(): Promise<void> {
        try {
            // Initialize destination service
            await this.destinationService.initialize();
            
            // Register tools
            await this.toolRegistry.registerTools();
            
            this.logger.info('🔧 MCP Server initialized successfully');
        } catch (error) {
            this.logger.error('❌ Failed to initialize MCP server:', error);
            throw error;
        }
    }

    /**
     * Get the underlying McpServer instance
     */
    getServer(): McpServer {
        return this.mcpServer;
    }

    /**
     * Get the configuration instance
     */
    getConfig(): Config {
        return this.config;
    }
}

/**
 * Factory function to create and initialize an MCP server
 */
export async function createMCPServer(userToken?: string): Promise<MCPServer> {
    const server = new MCPServer();
    if (userToken) {
        server.setUserToken(userToken);
    }
    await server.initialize();
    return server;
}
