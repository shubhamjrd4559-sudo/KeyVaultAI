/**
 * In-memory access token store.
 *
 * SECURITY DESIGN (Hybrid model):
 * - Access token: kept in module-level memory (JS variable) only.
 *   • Survives React re-renders but NOT page refreshes.
 *   • Never written to localStorage / sessionStorage / cookies.
 *   • Not accessible to third-party scripts via DOM storage APIs.
 * - Refresh token: set by the backend as an HttpOnly; Secure; SameSite=Strict
 *   cookie. JS cannot read or modify it.
 *   • Automatically sent by the browser to /api/v1/auth/ endpoints.
 *   • Rotated on every use by the backend.
 *   • Cleared by the backend on logout.
 *
 * Page refresh flow:
 *   On a hard reload the access token is lost (memory cleared). The app
 *   calls /api/v1/auth/token/refresh/ on mount; the browser automatically
 *   sends the HttpOnly cookie. If valid, a new access token is returned and
 *   the user stays logged in transparently. If the cookie is absent or
 *   expired, the user is shown the login screen.
 */

import type { AuthTokens } from "@/types";

let _accessToken: string | null = null;

export const tokenStore = {
  /** Current in-memory access token. Null after a page refresh until restored. */
  get access(): string | null {
    return _accessToken;
  },

  /**
   * Persist a new access token in memory.
   * The refresh token is handled as an HttpOnly cookie by the backend —
   * the frontend never receives or stores it.
   */
  save(tokens: Pick<AuthTokens, "access_token">): void {
    _accessToken = tokens.access_token;
  },

  /** Clear the in-memory access token (e.g. on logout or auth error). */
  clear(): void {
    _accessToken = null;
  },
};
