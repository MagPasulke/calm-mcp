export interface MCPTool {
    name: string;
    title: string;
    description: string;
    inputSchema: unknown;
}

export interface MCPRequest {
    method: string;
    params: {
        name: string;
        arguments: Record<string, unknown>;
    };
}

export interface MCPResponse {
    content: Array<{
        type: 'text' | 'image' | 'resource';
        text?: string;
        data?: unknown;
        mimeType?: string;
    }>;
    isError?: boolean;
}
