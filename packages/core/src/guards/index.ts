/**
 * @amtarc/auth-utils - Guards & Route Protection
 * Export all guard utilities
 */

// Core guard types and functions
export type {
  GuardContext,
  GuardResult,
  GuardFunction,
  RequireAuthOptions,
} from './require-auth';

export { requireAuth } from './require-auth';

// Guest guard
export type { RequireGuestOptions } from './require-guest';
export { requireGuest } from './require-guest';

// Composable guards
export {
  requireAny,
  requireAll,
  chainGuards,
  allowAll,
  denyAll,
  conditionalGuard,
} from './composable';

// Redirect management
export type {
  RedirectStorage,
  RedirectValidationOptions,
  SaveRedirectOptions,
  RestoreRedirectOptions,
} from './redirect';

export {
  isValidRedirect,
  saveAuthRedirect,
  restoreAuthRedirect,
  peekAuthRedirect,
  clearAuthRedirect,
} from './redirect';
