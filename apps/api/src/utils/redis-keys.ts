export const redisKey = {
    authEmailResends: (email: string) => `auth-email-resends:${email}`,
    authEmailRateLimit: (email: string) => `auth-email-rate-limit:${email}`,
    blacklistJti: (jti: string) => `blacklist-jti:${jti}`,
};
