declare module '@sap/xssec' {
    export interface SecurityContext {
        getUserName(): string;
        getEmail(): string;
        getGivenName(): string;
        getFamilyName(): string;
        getSubdomain(): string;
        getClientId(): string;
        getExpirationDate(): Date;
        checkScope(scope: string): boolean;
        checkLocalScope(scope: string): boolean;
        getToken(): string;
        getHdbToken(): string;
        getAppToken(): string;
        getIdentityZone(): string;
        getSubaccountId(): string;
        isInForeignMode(): boolean;
    }

    export interface XsuaaCredentials {
        url: string;
        clientid: string;
        clientsecret: string;
        identityzone?: string;
        identityzoneid?: string;
        tenantid?: string;
        tenantmode?: string;
        verificationkey?: string;
        xsappname?: string;
    }

    export interface ServiceConfig {
        validation?: {
            audiences?: string[];
        };
        cache?: {
            enabled?: boolean;
        };
    }

    export interface SecurityContextConfig {
        jwt?: string;
        token?: unknown;
        req?: unknown;
        skipValidation?: boolean;
        correlationId?: string;
        clientCertificatePem?: string;
    }

    export class XsuaaService {
        constructor(credentials: XsuaaCredentials | Record<string, unknown>, serviceConfig?: ServiceConfig);
        createSecurityContext(token: unknown, contextConfig?: SecurityContextConfig): Promise<SecurityContext>;
    }

    export function createSecurityContext(
        services: XsuaaService | XsuaaService[],
        contextConfig: SecurityContextConfig
    ): Promise<SecurityContext>;
}
