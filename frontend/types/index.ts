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

// M5 Security Engine types
export type SecurityLevel = "weak" | "fair" | "strong" | "very_strong";

export type SecuritySummary = {
  total: number;
  very_strong_count: number;
  strong_count: number;
  fair_count: number;
  weak_count: number;
  reused_count: number;
  average_score: number;
  overall_score: number;
  overall_level: SecurityLevel;
};

export type CredentialSecurity = {
  credential_id: string;
  website_name: string;
  category: string;
  security_score: number;
  security_level: SecurityLevel;
  is_reused: boolean;
  alerts: string[];
};
