import { tokenStore } from "@/lib/auth";
import type { ApiError, AuthTokens, Credential, CredentialSecurity, DeletedCredential, MLPrediction, SecuritySummary } from "@/types";

const BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1").replace(/\/$/, "");

function error(message: string, s?: number): ApiError {
  const result = new Error(message) as ApiError;
  result.status = s;
  return result;
}

async function request<T>(path: string, init: RequestInit = {}, accessToken?: string): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...init,
    // Include cookies so the browser sends the HttpOnly refresh token cookie
    // to /api/v1/auth/ endpoints cross-origin (requires CORS_ALLOW_CREDENTIALS).
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...init.headers,
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw error(body.detail || friendlyStatus(response.status), response.status);
  return body as T;
}

export function friendlyStatus(s: number) {
  return ({
    401: "Your session has expired. Please sign in again.",
    403: "You do not have permission for that action.",
    404: "That item could not be found.",
    409: "This conflicts with existing data.",
    422: "Please check the details and try again.",
    429: "Too many attempts. Please wait and try again.",
    500: "The vault is temporarily unavailable.",
  } as Record<number, string>)[s] || "Something went wrong. Please try again.";
}

export const api = {
  register: (data: { full_name: string; email: string; password: string }) =>
    request<{ user: unknown }>("/auth/register/", { method: "POST", body: JSON.stringify(data) }),

  verifyEmail: (token: string) =>
    request<{ detail: string }>("/auth/verify-email/", { method: "POST", body: JSON.stringify({ token }) }),

  resendVerification: (email: string) =>
    request<{ detail: string }>("/auth/resend-verification/", { method: "POST", body: JSON.stringify({ email }) }),

  forgotPassword: (email: string) =>
    request<{ detail: string }>("/auth/forgot-password/", { method: "POST", body: JSON.stringify({ email }) }),

  resetPassword: (token: string, password: string) =>
    request<{ detail: string }>("/auth/reset-password/", { method: "POST", body: JSON.stringify({ token, password }) }),

  login: (data: { email: string; password: string }) =>
    // Returns { access_token, token_type }. Backend sets refresh token as HttpOnly cookie.
    request<Pick<AuthTokens, "access_token" | "token_type">>("/auth/login/", { method: "POST", body: JSON.stringify(data) }),

  /**
   * Silently refresh the access token using the HttpOnly refresh cookie.
   * No body needed — the browser sends the cookie automatically.
   * Returns { access_token, token_type }. Backend rotates the cookie.
   */
  refresh: () =>
    request<Pick<AuthTokens, "access_token" | "token_type">>("/auth/token/refresh/", { method: "POST", body: JSON.stringify({}) }),

  /** Logout — backend revokes the refresh token and clears the cookie. */
  logout: (access: string) =>
    request<{ detail: string }>("/auth/logout/", { method: "POST", body: JSON.stringify({}) }, access),

  credentials: (access: string, query = "") =>
    request<{ credentials: Credential[] }>(`/vault/credentials/${query}`, {}, access),

  createCredential: (access: string, data: Record<string, unknown>) =>
    request<{ credential: Credential }>("/vault/credentials/", { method: "POST", body: JSON.stringify(data) }, access),

  updateCredential: (access: string, id: string, data: Record<string, unknown>) =>
    request<{ credential: Credential }>(`/vault/credentials/${id}/`, { method: "PATCH", body: JSON.stringify(data) }, access),

  deleteCredential: (access: string, id: string) =>
    request<{ detail: string }>(`/vault/credentials/${id}/`, { method: "DELETE" }, access),

  softDeleteCredential: (access: string, id: string) =>
    request<{ detail: string }>(`/vault/credentials/${id}/soft-delete/`, { method: "POST" }, access),

  recentlyDeleted: (access: string) =>
    request<{ credentials: DeletedCredential[]; count: number }>("/vault/recently-deleted/", {}, access),

  restoreCredential: (access: string, id: string) =>
    request<{ credential: Credential }>(`/vault/credentials/${id}/restore/`, { method: "POST" }, access),

  permanentDeleteCredential: (access: string, id: string) =>
    request<{ detail: string }>(`/vault/credentials/${id}/permanent-delete/`, { method: "DELETE" }, access),

  reveal: (access: string, id: string) =>
    request<{ password: string }>(`/vault/credentials/${id}/reveal/`, { method: "POST" }, access),

  copy: (access: string, id: string) =>
    request<{ password: string }>(`/vault/credentials/${id}/copy/`, { method: "POST" }, access),

  // M5 Security Engine
  securitySummary: (access: string) =>
    request<{ summary: SecuritySummary }>("/security/summary/", {}, access),

  securityCredentials: (access: string) =>
    request<{ credentials: CredentialSecurity[]; count: number }>("/security/credentials/", {}, access),

  // M6 ML Engine
  mlPredict: (access: string, data: { security_score: number; security_level: string; is_reused?: boolean }) =>
    request<MLPrediction>("/ml/predict/", { method: "POST", body: JSON.stringify(data) }, access),
};

export async function withRefresh<T>(operation: (access: string) => Promise<T>): Promise<T> {
  let access = tokenStore.access;
  if (!access) throw error("Please sign in to open your vault.", 401);
  try {
    return await operation(access);
  } catch (caught) {
    const apiError = caught as ApiError;
    if (apiError.status !== 401) throw apiError;
    // Access token expired — use the HttpOnly cookie to get a new one silently.
    const tokens = await api.refresh();
    tokenStore.save(tokens);
    access = tokens.access_token;
    return operation(access);
  }
}
