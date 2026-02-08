import { DestinationService } from './destination-service.js';
import { Logger } from '../utils/logger.js';
import { executeHttpRequest } from '@sap-cloud-sdk/http-client'
import { LandscapeQueryParams } from '../types/sap-types.js';

import { AuthService } from './auth-service.js';

/**
 * SAP Client for BTP MCP Server Dedicated
 * 
 * This client provides methods for interacting with SAP OData services.
 * It handles user token management and provides access to the destination service.
 * 
 * Developers should extend this class with their own OData service methods
 * based on their specific integration requirements.
 */
export class SAPClient {
    private currentUserToken?: string;

    constructor(
        private readonly destinationService: DestinationService,
        private readonly logger: Logger,
        private readonly authService: AuthService
    ) { }

    /**
     * Set the user's JWT token for authenticated operations
     * This token will be used for OAuth2SAMLBearer authentication
     * when making requests to SAP systems.
     */
    setUserToken(token?: string): void {
        this.currentUserToken = token;
        this.logger.debug(`User token ${token ? 'set' : 'cleared'} for SAP client`);
    }

    /**
     * Get the current user token
     */
    getUserToken(): string | undefined {
        return this.currentUserToken;
    }

    /**
     * Get the destination service instance
     * Useful for developers who need direct access to destination resolution
     */
    getDestinationService(): DestinationService {
        return this.destinationService;
    }

    /**
     * Hello World method - demonstrates the pattern for implementing SAP service methods
     * 
     * This is a sample method that shows how to structure your OData service calls.
     * Replace this with your actual SAP OData service methods.
     * 
     * @param name The name to greet
     * @returns A greeting message
     */
    async helloWorld(name: string): Promise<{ message: string; timestamp: string }> {
        this.logger.info(`Hello World called with name: ${name}`);

        // In a real implementation, you would:
        // 1. Get the destination
        // const destination = await this.destinationService.getDestination(this.currentUserToken);
        // 
        // 2. Use @sap-cloud-sdk/http-client to make OData calls
        // const response = await executeHttpRequest(destination, {
        //     method: 'GET',
        //     url: '/sap/opu/odata/sap/YOUR_SERVICE/EntitySet',
        //     headers: { 'Accept': 'application/json' }
        // });
        //
        // 3. Return typed response
        // return response.data;

        return {
            message: `Hello, ${name}! This is your BTP MCP Server.`,
            timestamp: new Date().toISOString()
        };
    }

    async getLandscapeInfo(params?: LandscapeQueryParams): Promise<string> {

        // Get SecurityContext from token
        if (!this.currentUserToken) {
            throw new Error('No user token set');
        }
        const securityContext = await this.authService.validateToken(this.currentUserToken);

        const requiredScope = 'mcp-server-calm.read';
        if (!this.authService.hasScope(securityContext, requiredScope)) {
            this.logger.warn(`User token missing required scope: ${requiredScope}`);
            throw new Error('Forbidden: missing required scope');
        }

        let destination;
        try {
            destination = await this.destinationService.getDestination(this.currentUserToken);
        }
        catch (error) {
            this.logger.error('Error fetching destination for landscape info:', error);
            throw new Error('Failed to get destination for landscape info');
        }

        this.logger.info(`Fetching landscape details`);

        const queryParams = this.buildQueryString(params);

        const response = await executeHttpRequest(
            destination,
            {
                method: 'get',
                url: `/landscapeObjects${queryParams}`
            }
        );

        return response.data;
    }

    /**
     * Builds a URL-encoded query string from the provided parameters.
     * Only includes parameters that are defined (not undefined/null).
     *
     * @param params - Optional key-value pairs to include as query parameters
     * @returns A query string prefixed with '?' or an empty string if no params are set
     */
    private buildQueryString(params?: LandscapeQueryParams): string {
        if (!params) {
            return '';
        }

        const entries = Object.entries(params)
            .filter(([, value]) => value !== undefined && value !== null)
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);

        return entries.length > 0 ? `?${entries.join('&')}` : '';
    }
}
