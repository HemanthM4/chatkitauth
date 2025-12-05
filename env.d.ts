export interface CloudflareBindings {
    LOGINBINDS: D1Database;
}

declare global {
    namespace NodeJS {
        interface ProcessEnv extends CloudflareBindings {
            // Additional environment variables can be added here
        }
    }
}
