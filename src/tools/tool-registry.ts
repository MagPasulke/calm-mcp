import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SAPClient } from "../services/sap-client.js";
import { Logger } from "../utils/logger.js";
import { TypeEnum, EventTypeEnum } from "../types/sap-types.js";
import { z } from "zod";

/**
 * Tool Registry for BTP MCP Server Dedicated
 * 
 * This registry manages the MCP tools that are exposed to AI assistants.
 * It provides a structured way to register tools that interact with SAP services.
 * 
 * Developers should add their own tool registration methods to expose
 * SAP OData operations as MCP tools.
 */
export class ToolRegistry {
    private userToken?: string;

    constructor(
        private readonly mcpServer: McpServer,
        private readonly sapClient: SAPClient,
        private readonly logger: Logger
    ) {}

    /**
     * Set the user's JWT token for authenticated operations
     */
    setUserToken(token?: string): void {
        this.userToken = token;
        this.sapClient.setUserToken(token);
        this.logger.debug(`User token ${token ? 'set' : 'cleared'} for tool registry`);
    }

    /**
     * Register all MCP tools
     * Call this during server initialization
     */
    async registerTools(): Promise<void> {
        this.logger.info('🔧 Registering MCP tools...');

        // Register the landscape tool
        this.registerLandscapeTool();

        // Register the landscape property tool
        this.registerLandscapePropertyTool();

        // Register the status events tool
        this.registerStatusEventsTool();

        this.logger.info('✅ MCP tools registered successfully');
    }
    
    /**
     * Landscape Tool - Retrieves landscape objects from SAP Cloud ALM
     *
     * Registers a tool that queries the landscapeObjects API with optional
     * filter parameters. All parameters are optional and only included
     * in the request when provided.
     */
    private registerLandscapeTool(): void {
        this.mcpServer.registerTool(
            "get-landscape-info",
            {
                title: "Get Landscape Info",
                description: "Retrieves landscape objects from SAP Cloud ALM. All filter parameters are optional. Returns a list of landscape objects matching the given criteria.",
                inputSchema: {
                    name: z.string().optional().describe("Filter by landscape object name, equals SID"),
                    systemNumber: z.string().optional().describe("Filter by system number"),
                    objectType: z.string().optional().describe("Filter by object type (e.g. CloudService)"),
                    source: z.string().optional().describe("Filter by source (e.g. IMPORTED)"),
                    lmsId: z.string().optional().describe("Filter by LMS ID"),
                    serviceType: z.string().optional().describe("Filter by service type (e.g. SCP_HCAAS_DATALAKE)"),
                    role: z.string().optional().describe("Filter by role (e.g. PROD)"),
                    externalId: z.string().optional().describe("Filter by external ID"),
                    limit: z.number().optional().describe("Maximum number of results to return"),
                    offset: z.number().optional().describe("Offset for pagination"),
                    deploymentModel: z.string().optional().describe("Filter by deployment model (e.g. BTP System)")
                }
            },
            async (args: Record<string, unknown>) => {
                try {
                    const result = await this.sapClient.getLandscapeInfo({
                        name: args.name as string | undefined,
                        systemNumber: args.systemNumber as string | undefined,
                        objectType: args.objectType as string | undefined,
                        source: args.source as string | undefined,
                        lmsId: args.lmsId as string | undefined,
                        serviceType: args.serviceType as string | undefined,
                        role: args.role as string | undefined,
                        externalId: args.externalId as string | undefined,
                        limit: args.limit as number | undefined,
                        offset: args.offset as number | undefined,
                        deploymentModel: args.deploymentModel as string | undefined
                    });

                    return {
                        content: [{
                            type: "text" as const,
                            text: JSON.stringify(result, null, 2)
                        }]
                    };
                } catch (error) {
                    this.logger.error('Get Landscape Info tool error:', error);
                    return {
                        content: [{
                            type: "text" as const,
                            text: JSON.stringify({
                                error: 'Failed to execute get-landscape-info',
                                message: error instanceof Error ? error.message : 'Unknown error'
                            }, null, 2)
                        }],
                        isError: true
                    };
                }
            }
        );

        this.logger.debug('Registered tool: get-landscape-info');
    }

        /**
     * Landscape Property Tool - Retrieves Landscape Properties from SAP Cloud ALM for a single Ladndscape ID
     *
     * Registers a tool that queries the Properties API with mandatory
     * landscape ID parameter. 
     */
    private registerLandscapePropertyTool(): void {
        this.mcpServer.registerTool(
            "get-landscape-property-info",
            {
                title: "Get Landscape Property Info",
                description: "Retrieves landscape properties from SAP Cloud ALM for a single landscape ID.",
                inputSchema: {
                    lmsId: z.string().describe("Landscape ID"),
                }
            },
            async (args: Record<string, unknown>) => {
                try {
                    const result = await this.sapClient.getLandscapeProperties(args.lmsId as string);

                    return {
                        content: [{
                            type: "text" as const,
                            text: JSON.stringify(result, null, 2)
                        }]
                    };
                } catch (error) {
                    this.logger.error('Get Landscape Property tool error:', error);
                    return {
                        content: [{
                            type: "text" as const,
                            text: JSON.stringify({
                                error: 'Failed to execute get-landscape-property-info',
                                message: error instanceof Error ? error.message : 'Unknown error'
                            }, null, 2)
                        }],
                        isError: true
                    };
                }
            }
        );

        this.logger.debug('Registered tool: get-landscape-property-info');
    }

    /**
     * Status Events Tool - Retrieves status events from SAP Cloud ALM
     *
     * Registers a tool that queries the Status Events API with optional
     * filter parameters. All parameters are optional and only included
     * in the request when provided.
     */
    private registerStatusEventsTool(): void {
        this.mcpServer.registerTool(
            "get-status-events",
            {
                title: "Get Status Events",
                description: "Retrieves status events from SAP Cloud ALM. All filter parameters are optional. Returns a list of status events matching the given criteria.",
                inputSchema: {
                    type: z.enum(["BusinessService", "CloudService", "TechnicalSystem"]).optional().describe("Filter by type"),
                    serviceName: z.string().optional().describe("Filter by service name"),
                    eventType: z.enum(["Maintenance", "Degradation", "Disruption", "Communication", "Planned Availability"]).optional().describe("Filter by event type"),
                    serviceType: z.string().optional().describe("Filter by service type"),
                    period: z.string().optional().describe("Filter by period"),
                    startTime: z.string().optional().describe("Filter by start time"),
                    endTime: z.string().optional().describe("Filter by end time"),
                    limit: z.number().optional().describe("Maximum number of results to return"),
                    offset: z.number().optional().describe("Offset for pagination")
                }
            },
            async (args: Record<string, unknown>) => {
                try {
                    const result = await this.sapClient.getStatusEvents({
                        type: args.type as TypeEnum | undefined,
                        serviceName: args.serviceName as string | undefined,
                        eventType: args.eventType as EventTypeEnum | undefined,
                        serviceType: args.serviceType as string | undefined,
                        period: args.period as string | undefined,
                        startTime: args.startTime as string | undefined,
                        endTime: args.endTime as string | undefined,
                        limit: args.limit as number | undefined,
                        offset: args.offset as number | undefined
                    });

                    return {
                        content: [{
                            type: "text" as const,
                            text: JSON.stringify(result, null, 2)
                        }]
                    };
                } catch (error) {
                    this.logger.error('Get Status Events tool error:', error);
                    return {
                        content: [{
                            type: "text" as const,
                            text: JSON.stringify({
                                error: 'Failed to execute get-status-events',
                                message: error instanceof Error ? error.message : 'Unknown error'
                            }, null, 2)
                        }],
                        isError: true
                    };
                }
            }
        );

        this.logger.debug('Registered tool: get-status-events');
    }

}
