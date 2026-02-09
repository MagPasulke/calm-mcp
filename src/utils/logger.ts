import winston from 'winston';

export class Logger {
    private readonly winston: winston.Logger;

    constructor(private readonly component: string) {
        this.winston = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            defaultMeta: {
                component: this.component,
                service: 'btp-mcp-server-calm'
            },
            transports: [
                new winston.transports.Console()
            ]
        });
    }

    debug(message: string, meta?: unknown): void {
        this.winston.debug(message, meta);
    }

    info(message: string, meta?: unknown): void {
        this.winston.info(message, meta);
    }

    warn(message: string, meta?: unknown): void {
        this.winston.warn(message, meta);
    }

    error(message: string, meta?: unknown): void {
        this.winston.error(message, meta);
    }
}
