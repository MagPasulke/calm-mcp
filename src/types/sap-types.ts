/**
 * Types 
 * 
 * This file contains minimal type definitions for CALM connectivity.
 */

/**
 * Configuration for SAP destination
 */
export interface DestinationConfig {
    name: string;
    url?: string;
    authentication?: string;
}

/**
 * Generic SAP API response wrapper
 * Extend this for your specific OData responses
 */
export interface SAPResponse<T = unknown> {
    data: T;
    status: number;
    headers?: Record<string, string>;
}

/**
 * Generic SAP API error structure
 */
export interface SAPError {
    code: string;
    message: string;
    details?: Array<{
        code: string;
        message: string;
        target?: string;
    }>;
}

/**
 * Query parameters for the landscapeObjects API endpoint.
 * All parameters are optional.
 */
export interface LandscapeQueryParams {
    name?: string;
    systemNumber?: string;
    objectType?: string;
    source?: string;
    lmsId?: string;
    serviceType?: string;
    role?: string;
    externalId?: string;
    limit?: number;
    offset?: number;
    deploymentModel?: string;
}

/**
 * Enum for the 'type' property in StatusEventsQueryParams
 */
export enum TypeEnum {
    BusinessService = "BusinessService",
    CloudService = "CloudService",
    TechnicalSystem = "TechnicalSystem"
}

/**
 * Enum for the 'eventType' property in StatusEventsQueryParams
 */
export enum EventTypeEnum {
    Maintenance = "Maintenance",
    Degradation = "Degradation",
    Disruption = "Disruption",
    Communication = "Communication",
    PlannedAvailability = "Planned Availability"
}
    
/**
 * Query parameters for the Status Events API endpoint.
 * All parameters are optional.
 */
export interface StatusEventsQueryParams {

    type?: TypeEnum;
    serviceName?: string;
    eventType?: EventTypeEnum;
    serviceType?: string;
    period?: string;
    startTime?: string;
    endTime?: string;
    limit?: number;
    offset?: number;
}

