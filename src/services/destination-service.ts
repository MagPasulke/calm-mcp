import { getDestination, HttpDestination } from '@sap-cloud-sdk/connectivity';
import xsenv from '@sap/xsenv';
import { Logger } from '../utils/logger.js';
import { Config } from '../utils/config.js';

/**
 * Destination Service for SAP BTP
 * 
 * Handles connectivity to SAP systems via the BTP Destination service.
 * Supports both local development (via environment variables) and
 * cloud deployment (via VCAP_SERVICES).
 */
export class DestinationService {
    private readonly config: Config;
    private vcapServices!: Record<string, unknown>;

    constructor(
        private readonly logger: Logger,
        config?: Config
    ) {
        this.config = config || new Config();
    }

    /**
     * Initialize the destination service
     * Loads VCAP_SERVICES for local development and cloud deployment
     */
    async initialize(): Promise<void> {
        try {
            // Load VCAP services
            xsenv.loadEnv();
            this.vcapServices = xsenv.getServices({
                destination: { label: 'destination' },
                connectivity: { label: 'connectivity' },
                xsuaa: { label: 'xsuaa' }
            });

            this.logger.info('Destination service initialized successfully');

        } catch (error) {
            this.logger.error('Failed to initialize destination service:', error);
            throw error;
        }
    }

    /**
     * Get the configured SAP destination
     * 
     * Uses CALM_DESTINATION_NAME from environment configuration.
     * Supports optional JWT token for OAuth2SAMLBearer authentication.
     * 
     * @param jwtToken Optional JWT for user-specific authentication
     * @returns The resolved HttpDestination
     */
    async getDestination(jwtToken?: string): Promise<HttpDestination> {
        const destinationName = this.config.get('calm.destinationName', 'CALM');

        this.logger.debug(`Fetching destination: ${destinationName} ${jwtToken ? 'with JWT' : 'without JWT'}`);

        try {
            // First try environment variables (for local development)
            const envDestinations = process.env.destinations;
            if (envDestinations) {
                const destinations = JSON.parse(envDestinations);
                const envDest = destinations.find((d: Record<string, unknown>) => d.name === destinationName);
                if (envDest) {
                    this.logger.info(`Successfully retrieved destination '${destinationName}' from environment variable.`);
                    return {
                        url: envDest.url,
                        username: envDest.username,
                        password: envDest.password,
                        authentication: 'BasicAuthentication'
                    } as HttpDestination;
                }
            }
        } catch (envError) {
            this.logger.debug('Failed to load from environment destinations:', envError);
        }

        try {
            // Use SAP Cloud SDK getDestination with optional JWT
            const destination = await getDestination({
                destinationName,
                jwt: jwtToken || this.getJWT()
            });
            if (!destination) {
                throw new Error(`Destination '${destinationName}' not found in environment variables or BTP destination service`);
            }
            this.logger.info(`Successfully retrieved destination: ${destinationName}`);
            return destination as HttpDestination;
        } catch (error) {
            this.logger.error('Failed to get SAP destination:', error);
            throw error;
        }
    }

    private getJWT(): string | undefined {
        // In a real application, this would extract JWT from the current request
        // For technical user scenario, this might not be needed
        return process.env.USER_JWT || undefined;
    }

    /**
     * Get destination service credentials from VCAP_SERVICES
     */
    getDestinationCredentials() {
        return (this.vcapServices?.destination as { credentials?: unknown })?.credentials;
    }

    /**
     * Get connectivity service credentials from VCAP_SERVICES
     */
    getConnectivityCredentials() {
        return (this.vcapServices?.connectivity as { credentials?: unknown })?.credentials;
    }
}
