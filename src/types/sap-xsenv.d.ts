declare module '@sap/xsenv' {
    export function loadEnv(): void;
    
    export function getServices(options: Record<string, { label?: string; name?: string; tag?: string }>): Record<string, unknown>;
    
    export function readServices(options?: { vcap?: string }): Record<string, unknown[]>;
    
    export function filterServices(filter: { label?: string; name?: string; tag?: string }): unknown[];
    
    export function serviceCredentials(filter: { label?: string; name?: string; tag?: string }): unknown;
    
    export default {
        loadEnv,
        getServices,
        readServices,
        filterServices,
        serviceCredentials
    };
}
