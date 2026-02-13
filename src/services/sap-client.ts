import { DestinationService } from './destination-service.js';
import { Logger } from '../utils/logger.js';
import { executeHttpRequest } from '@sap-cloud-sdk/http-client'
import { LandscapeQueryParams, StatusEventsQueryParams } from '../types/sap-types.js';

import { AuthService } from './auth-service.js';

/**
 * SAP Client for BTP CALM MCP Server
 * 
 * This client provides methods for interacting with CALM APIs.
 * It handles user token management and provides access to the destination service.
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
     */
    getDestinationService(): DestinationService {
        return this.destinationService;
    }

    async getLandscapeInfo(params?: LandscapeQueryParams): Promise<string> {
        await this.ensureAuthorized('read');

        let destination;
        try {
            destination = await this.destinationService.getDestination(this.currentUserToken);
        }
        catch (error) {
            this.logger.debug('Error fetching destination for landscape info:', error);
            throw new Error('Failed to get destination for landscape info');
        }

        this.logger.debug(`Fetching landscape details`);
        const queryParams = this.buildQueryString(params);

        const response = await executeHttpRequest(
            destination,
            {
                method: 'get',
                url: `/calm-landscape/v1/landscapeObjects${queryParams}`
            }
        );

        return response.data;
    }

    async getLandscapeProperties(lmsId: string): Promise<string> {
        if (!lmsId || lmsId.trim() === '') {
            throw new Error('No Landscape ID provided');
        }

        await this.ensureAuthorized('read');

        const destination = await this.destinationService.getDestination(this.currentUserToken);

        const response = await executeHttpRequest(
            destination,
            {
                method: 'get',
                url: `/calm-landscape/v1/properties?lmsId=${encodeURIComponent(lmsId)}`
            }
        );

        return response.data;
    }

    async getStatusEvents(params?: StatusEventsQueryParams): Promise<string> {
        await this.ensureAuthorized('read');

        let destination;
        try {
            destination = await this.destinationService.getDestination(this.currentUserToken);
        }
        catch (error) {
            this.logger.debug('Error fetching destination for landscape info:', error);
            throw new Error('Failed to get destination for landscape info');
        }

        this.logger.debug(`Fetching landscape details`);
        const queryParams = this.buildQueryString(params);

        const response = await executeHttpRequest(
            destination,
            {
                method: 'get',
                url: `/bsm-service/v1/events${queryParams}`
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
    private buildQueryString(params?: LandscapeQueryParams | StatusEventsQueryParams): string {
        if (!params) {
            return '';
        }

        const entries = Object.entries(params)
            .filter(([, value]) => value !== undefined && value !== null)
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);

        return entries.length > 0 ? `?${entries.join('&')}` : '';
    }

        /**
     * Validates the current user token and checks the required local scope.
     * Throws if no token is set or the required scope is missing.
     */
    private async ensureAuthorized(scope: string): Promise<void> {
        if (!this.currentUserToken) {
            throw new Error('No user token set');
        }

        const securityContext = await this.authService.validateToken(this.currentUserToken);

        // Debug: log token claims
        try {
            const payload = JSON.parse(Buffer.from(this.currentUserToken.split('.')[1], 'base64').toString());
            this.logger.debug(`Token scopes: ${JSON.stringify(payload.scope)}`);
            this.logger.debug(`Token role collections: ${JSON.stringify(payload['xs.rolecollections'])}`);
            this.logger.debug(`Token origin: ${payload.origin}`);
            this.logger.debug(`Token grant_type: ${payload.grant_type}`);
        } catch (e) {
            this.logger.debug('Could not decode token');
            this.logger.debug(`e.message: ${e instanceof Error ? e.message : String(e)}`);
        }

        const hasLocalScope = securityContext.checkLocalScope(scope);
        this.logger.debug(`checkLocalScope('${scope}') = ${hasLocalScope}`);

        if (!hasLocalScope) {
            throw new Error(`Forbidden: missing required scope '${scope}'`);
        }
    }
}
