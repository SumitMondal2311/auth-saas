export const redisKey = {
    signupEmailRateLimit: (email: string) => `signup-email-rate-limit:${email}`,
    signupEmailResends: (email: string) => `signup-email-resends:${email}`,
};
