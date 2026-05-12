/**
 * Shared session-activity tracker.
 *
 * Keeps a single `lastActivityMs` timestamp that is bumped by:
 *   - DOM interaction events (mousedown, keydown, scroll, touchstart)
 *   - Successful API responses (via the response interceptor in main.tsx)
 *
 * The `useSessionTimeout` hook reads this value to decide whether the user
 * has been idle long enough to warrant a session-expiry warning.
 */

let lastActivityMs = Date.now()

/** Record that user/app activity just occurred. */
export function recordActivity(): void {
  lastActivityMs = Date.now()
}

/** Return the epoch-ms of the most recent recorded activity. */
export function getLastActivityMs(): number {
  return lastActivityMs
}
