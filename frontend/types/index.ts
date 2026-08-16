export type Credential = {
  credential_id: string;
  website_name: string;
  website_url: string;
  username: string;
  email: string;
  category: string;
  notes?: string;
  favorite: boolean;
  security_score: number;
  security_level: "weak" | "fair" | "strong" | "very_strong";
  created_at: string;
  updated_at: string;
  last_used_at?: string | null;
};

export type AuthTokens = { access_token: string; refresh_token: string; token_type: string };
export type ApiError = Error & { status?: number };
