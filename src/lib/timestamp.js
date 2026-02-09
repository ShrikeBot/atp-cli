const TWO_HOURS = 2 * 60 * 60; // 7200 seconds

/**
 * Validate a timestamp is within 2 hours of current time.
 * @param {number} c - Unix timestamp in seconds
 * @param {string} context - Description for error messages
 * @throws {Error} if timestamp is more than 2 hours from now
 */
export function validateTimestamp(c, context = 'Document') {
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(c - now);
  if (diff > TWO_HOURS) {
    const direction = c > now ? 'in the future' : 'in the past';
    const hours = (diff / 3600).toFixed(1);
    throw new Error(`${context} timestamp is ${hours}h ${direction} (exceeds 2h tolerance)`);
  }
}
