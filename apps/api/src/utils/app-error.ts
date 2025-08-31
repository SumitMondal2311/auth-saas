export class AppError extends Error {
    statusCode: number;
    details: string;
    metadata?: Record<string, any>;

    constructor(
        statusCode: number,
        {
            metadata,
            message,
            details,
        }: {
            metadata?: Record<string, any>;
            message: string;
            details: string;
        }
    ) {
        super(message);

        this.name = "Clove Error";
        this.statusCode = statusCode;
        this.details = details;
        this.metadata = metadata;
    }

    toJSON() {
        return {
            name: this.name,
            statusCode: this.statusCode,
            message: this.message,
            metadata: this.metadata,
        };
    }
}
