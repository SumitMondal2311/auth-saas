export const redisKey = {
    authEmailRateLimit: (email: string) => `auth-email-rate-limit:${email}`,
    authEmailResends: (email: string) => `auth-email-resends:${email}`,
};
