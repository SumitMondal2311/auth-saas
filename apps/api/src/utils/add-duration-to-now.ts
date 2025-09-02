export const addDurationToNow = (durationMs: number): Date => {
    return new Date(Date.now() + durationMs);
};
