import type { AuthTokens } from "@/types";

const ACCESS = "keyvaultai_access";
const REFRESH = "keyvaultai_refresh";

export const tokenStore = {
  get access() { return typeof window === "undefined" ? null : sessionStorage.getItem(ACCESS); },
  get refresh() { return typeof window === "undefined" ? null : sessionStorage.getItem(REFRESH); },
  save(tokens: AuthTokens) {
    sessionStorage.setItem(ACCESS, tokens.access_token);
    sessionStorage.setItem(REFRESH, tokens.refresh_token);
  },
  clear() { sessionStorage.removeItem(ACCESS); sessionStorage.removeItem(REFRESH); }
};
