export class AppError extends Error {
    statusCode: number;

    constructor(
        statusCode: number,
        {
            message,
        }: {
            message: string;
        }
    ) {
        super(message);

        this.name = "AuthSaaS-Error";
        this.statusCode = statusCode;
    }

    toJSON() {
        return {
            name: this.name,
            statusCode: this.statusCode,
            message: this.message,
        };
    }
}
