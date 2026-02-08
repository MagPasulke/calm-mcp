/**
 * SAP Types for BTP MCP Server Dedicated
 * 
 * This file contains minimal type definitions for SAP connectivity.
 * Developers should extend this file with their own OData entity types
 * based on the specific SAP services they integrate with.
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

// =============================================================================
// Add your OData entity types below
// =============================================================================
// 
// Define interfaces for the SAP OData entities you will be working with.
// These types will be used by your SAP client methods and tool implementations.
//
// Example:
//
// export interface Customer {
//     CustomerID: string;
//     CustomerName: string;
//     City: string;
//     Country: string;
// }
//
// export interface SalesOrder {
//     OrderID: string;
//     CustomerID: string;
//     OrderDate: string;
//     TotalAmount: number;
//     Currency: string;
//     Status: string;
// }
//
// export interface Product {
//     ProductID: string;
//     ProductName: string;
//     Category: string;
//     Price: number;
//     Currency: string;
//     StockQuantity: number;
// }
