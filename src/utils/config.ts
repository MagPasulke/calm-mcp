import xsenv from '@sap/xsenv';

/**
 * Configuration management for BTP MCP Server Dedicated
 * 
 * Handles loading and accessing configuration from environment variables
 * and VCAP services for SAP BTP deployment.
 */
export class Config {
    private readonly config: Map<string, unknown> = new Map();
    private readonly cfAppUris: string[];

    constructor() {
        this.cfAppUris = this.parseCloudFoundryAppUris();
        this.loadConfiguration();
    }

    getServerUrl(port: number): string {
        if (this.cfAppUris.length > 0) {
            return `https://${this.cfAppUris[0]}`;
        }
        return `http://localhost:${port}`;
    }

    private loadConfiguration(): void {
        // SAP Destination Configuration
        this.config.set('calm.destinationName', process.env.CALM_DESTINATION_NAME || 'SAP_SYSTEM');

        // Server Configuration
        this.config.set('server.port', Number.parseInt(process.env.PORT || '3000'));
        this.config.set('request.timeout', Number.parseInt(process.env.REQUEST_TIMEOUT || '30000'));

        // Logging Configuration
        this.config.set('log.level', process.env.LOG_LEVEL || 'info');
        this.config.set('node.env', process.env.NODE_ENV || 'development');

        // Session Configuration
        this.config.set('session.timeoutMs', Number.parseInt(process.env.SESSION_TIMEOUT_MS || '3600000')); // 1 hour default

        // CORS Configuration - merge manual config with auto-detected CF URLs
        const manualOrigins = process.env.ALLOWED_ORIGINS || '';
        const allowedOrigins = manualOrigins ? manualOrigins.split(',').map(o => o.trim()) : [];
        
        const cfAppUrls = this.cfAppUris.map(uri => `https://${uri}`);
        const mergedOrigins = [...new Set([...allowedOrigins, ...cfAppUrls, 'http://localhost:3000'])];
        this.config.set('cors.allowedOrigins', mergedOrigins);

        // Load from VCAP services if available
        try {
            xsenv.loadEnv();
            const vcapServices = process.env.VCAP_SERVICES ? JSON.parse(process.env.VCAP_SERVICES) : {};
            this.config.set('vcap.services', vcapServices);
        } catch (error) {
            console.warn('Failed to load VCAP services:', error);
        }
    }

    /**
     * Get a configuration value
     * @param key The configuration key (e.g., 'calm.destinationName')
     * @param defaultValue Optional default value if key not found
     */
    get<T = string>(key: string, defaultValue?: T): T {
        const value = this.config.get(key);
        if (value === undefined) {
            return defaultValue as T;
        }
        return value as T;
    }

    /**
     * Set a configuration value
     * @param key The configuration key
     * @param value The value to set
     */
    set(key: string, value: unknown): void {
        this.config.set(key, value);
    }

    /**
     * Check if a configuration key exists
     * @param key The configuration key
     */
    has(key: string): boolean {
        return this.config.has(key);
    }

    /**
     * Get all configuration as a plain object
     */
    getAll(): Record<string, unknown> {
        return Object.fromEntries(this.config);
    }

    /**
     * Get allowed hosts for DNS rebinding protection.
     * Includes auto-detected CF hostnames.
     */
    getAllowedHosts(): string[] {
        return [...new Set(this.cfAppUris)];
    }

    /**
     * Parse application URIs from Cloud Foundry's VCAP_APPLICATION once.
     * These are bare hostnames like 'my-app.cfapps.eu10.hana.ondemand.com'.
     */
    private parseCloudFoundryAppUris(): string[] {
        try {
            const vcapApp = process.env.VCAP_APPLICATION;
            if (!vcapApp) {
                return [];
            }

            const parsed = JSON.parse(vcapApp) as { application_uris?: string[]; uris?: string[] };
            return parsed.application_uris || parsed.uris || [];
        } catch (error) {
            console.warn('Failed to parse VCAP_APPLICATION:', error);
            return [];
        }
    }
}
