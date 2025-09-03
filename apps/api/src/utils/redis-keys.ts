export const redisKey = {
    loginEmailRateLimit: (email: string) => `login-email-rate-limit:${email}`,
    loginEmailResends: (email: string) => `login-email-resends:${email}`,
    signupEmailRateLimit: (email: string) => `signup-email-rate-limit:${email}`,
    signupEmailResends: (email: string) => `signup-email-resends:${email}`,
};
