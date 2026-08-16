import { tokenStore } from "@/lib/auth";
import type { ApiError, AuthTokens, Credential } from "@/types";

const BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1").replace(/\/$/, "");

function error(message: string, status?: number): ApiError {
  const result = new Error(message) as ApiError;
  result.status = status;
  return result;
}

async function request<T>(path: string, init: RequestInit = {}, accessToken?: string): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}), ...init.headers }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw error(body.detail || friendlyStatus(response.status), response.status);
  return body as T;
}

export function friendlyStatus(status: number) {
  return ({ 401: "Your session has expired. Please sign in again.", 403: "You do not have permission for that action.", 404: "That item could not be found.", 409: "This conflicts with existing data.", 422: "Please check the details and try again.", 429: "Too many attempts. Please wait and try again.", 500: "The vault is temporarily unavailable." } as Record<number, string>)[status] || "Something went wrong. Please try again.";
}

export const api = {
  register: (data: { full_name: string; email: string; password: string }) => request<{ user: unknown }>("/auth/register/", { method: "POST", body: JSON.stringify(data) }),
  login: (data: { email: string; password: string }) => request<AuthTokens>("/auth/login/", { method: "POST", body: JSON.stringify(data) }),
  refresh: (refresh_token: string) => request<AuthTokens>("/auth/token/refresh/", { method: "POST", body: JSON.stringify({ refresh_token }) }),
  logout: (refresh_token: string, access: string) => request<{ detail: string }>("/auth/logout/", { method: "POST", body: JSON.stringify({ refresh_token }) }, access),
  credentials: (access: string, query = "") => request<{ credentials: Credential[] }>(`/vault/credentials/${query}`, {}, access),
  createCredential: (access: string, data: Record<string, unknown>) => request<{ credential: Credential }>("/vault/credentials/", { method: "POST", body: JSON.stringify(data) }, access),
  updateCredential: (access: string, id: string, data: Record<string, unknown>) => request<{ credential: Credential }>(`/vault/credentials/${id}/`, { method: "PATCH", body: JSON.stringify(data) }, access),
  deleteCredential: (access: string, id: string) => request<{ detail: string }>(`/vault/credentials/${id}/`, { method: "DELETE" }, access),
  reveal: (access: string, id: string) => request<{ password: string }>(`/vault/credentials/${id}/reveal/`, { method: "POST" }, access),
  copy: (access: string, id: string) => request<{ password: string }>(`/vault/credentials/${id}/copy/`, { method: "POST" }, access)
};

export async function withRefresh<T>(operation: (access: string) => Promise<T>): Promise<T> {
  let access = tokenStore.access;
  if (!access) throw error("Please sign in to open your vault.", 401);
  try { return await operation(access); }
  catch (caught) {
    const apiError = caught as ApiError;
    if (apiError.status !== 401 || !tokenStore.refresh) throw apiError;
    const tokens = await api.refresh(tokenStore.refresh);
    tokenStore.save(tokens);
    access = tokens.access_token;
    return operation(access);
  }
}
