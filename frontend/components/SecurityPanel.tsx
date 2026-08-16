"use client";

/**
 * SecurityPanel — M5 Security Engine UI component.
 *
 * Displays vault-wide security posture:
 *   - Overall score arc / badge
 *   - Level counts (very_strong / strong / fair / weak)
 *   - Reused credentials count
 *   - Per-credential alerts
 *
 * Security: never displays passwords or encrypted values.
 * All data comes from /api/v1/security/* endpoints.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, LoaderCircle, RefreshCw, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { api, withRefresh } from "@/lib/api";
import type { CredentialSecurity, SecuritySummary } from "@/types";

// ── Helpers ─────────────────────────────────────────────────────────────────

const LEVEL_COLORS: Record<string, string> = {
  very_strong: "#22c55e",
  strong:      "#84cc16",
  fair:        "#facc15",
  weak:        "#f43f5e",
};

const LEVEL_LABELS: Record<string, string> = {
  very_strong: "Very Strong",
  strong:      "Strong",
  fair:        "Fair",
  weak:        "Weak",
};

const ALERT_LABELS: Record<string, string> = {
  weak_password:    "Weak password",
  reused_password:  "Password reused",
  low_security_score: "Low score",
};

function ScoreArc({ score }: { score: number }) {
  const r = 52;
  const circumference = 2 * Math.PI * r;
  const fill = (score / 100) * circumference;
  const gap  = circumference - fill;

  const color =
    score >= 80 ? "#22c55e"
    : score >= 60 ? "#84cc16"
    : score >= 40 ? "#facc15"
    : "#f43f5e";

  return (
    <svg width="130" height="130" viewBox="0 0 130 130" aria-hidden="true">
      <circle cx="65" cy="65" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" />
      <circle
        cx="65" cy="65" r={r}
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={`${fill} ${gap}`}
        strokeDashoffset={circumference * 0.25}
        style={{ transition: "stroke-dasharray 0.8s ease" }}
      />
      <text x="65" y="60" textAnchor="middle" fill="white" fontSize="26" fontWeight="800">{score}</text>
      <text x="65" y="78" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="10">/100</text>
    </svg>
  );
}

// ── Component ────────────────────────────────────────────────────────────────

export function SecurityPanel() {
  const [summary, setSummary]               = useState<SecuritySummary | null>(null);
  const [credentials, setCredentials]       = useState<CredentialSecurity[]>([]);
  const [loading, setLoading]               = useState(true);
  const [error, setError]                   = useState("");
  const [showAlerts, setShowAlerts]         = useState(false);

  async function loadSecurity() {
    setLoading(true);
    setError("");
    try {
      const [sumData, credData] = await Promise.all([
        withRefresh(access => api.securitySummary(access)),
        withRefresh(access => api.securityCredentials(access)),
      ]);
      setSummary(sumData.summary);
      setCredentials(credData.credentials);
    } catch (caught) {
      setError((caught as Error).message || "Security analysis unavailable.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void loadSecurity(); }, []);

  if (loading) {
    return (
      <div className="security-panel glass-card p-6 animate-pulse">
        <div className="flex items-center gap-3 mb-4">
          <ShieldCheck className="text-indigo-300" size={22} />
          <h2 className="text-base font-bold text-slate-200">Security Analysis</h2>
        </div>
        <div className="grid place-items-center py-8 text-slate-400">
          <LoaderCircle className="animate-spin mb-2" size={28} />
          <span className="text-sm">Analysing your vault…</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-3 text-rose-300">
          <ShieldX size={22} />
          <h2 className="text-base font-bold">Security Analysis</h2>
        </div>
        <p className="text-sm text-slate-400">{error}</p>
        <button
          onClick={() => void loadSecurity()}
          className="mt-3 flex items-center gap-2 text-xs text-indigo-300 hover:text-white transition-colors"
        >
          <RefreshCw size={14} /> Retry
        </button>
      </div>
    );
  }

  if (!summary) return null;

  const alertCredentials = credentials.filter(c => c.alerts.length > 0);
  const levelColor = LEVEL_COLORS[summary.overall_level] || "#f43f5e";

  return (
    <section className="glass-card p-6 space-y-5" aria-label="Security Analysis">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck size={22} style={{ color: levelColor }} />
          <div>
            <h2 className="text-base font-bold text-slate-100">Security Analysis</h2>
            <p className="text-xs text-slate-400">Deterministic · Rule-based · Local</p>
          </div>
        </div>
        <button
          onClick={() => void loadSecurity()}
          title="Refresh analysis"
          className="rounded-lg p-2 text-slate-400 hover:bg-white/10 hover:text-white transition-colors"
          aria-label="Refresh security analysis"
        >
          <RefreshCw size={15} />
        </button>
      </div>

      {/* Score arc + level */}
      <div className="flex flex-col items-center gap-1">
        <ScoreArc score={summary.overall_score} />
        <span
          className="rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wider"
          style={{ background: `${levelColor}22`, color: levelColor }}
        >
          {LEVEL_LABELS[summary.overall_level]}
        </span>
        <p className="text-xs text-slate-400 mt-1">{summary.total} credential{summary.total !== 1 ? "s" : ""} analysed</p>
      </div>

      {/* Counts row */}
      <div className="grid grid-cols-2 gap-3 text-center text-sm">
        {[
          { label: "Very Strong", count: summary.very_strong_count, color: LEVEL_COLORS.very_strong },
          { label: "Strong",      count: summary.strong_count,      color: LEVEL_COLORS.strong },
          { label: "Fair",        count: summary.fair_count,        color: LEVEL_COLORS.fair },
          { label: "Weak",        count: summary.weak_count,        color: LEVEL_COLORS.weak },
        ].map(({ label, count, color }) => (
          <div key={label} className="rounded-xl bg-white/5 p-3">
            <p className="text-xl font-black" style={{ color }}>{count}</p>
            <p className="text-xs text-slate-400">{label}</p>
          </div>
        ))}
      </div>

      {/* Stats row */}
      <div className="space-y-2 text-sm">
        <div className="flex items-center justify-between rounded-lg bg-white/5 px-3 py-2">
          <span className="text-slate-400">Avg score</span>
          <span className="font-bold text-slate-100">{summary.average_score.toFixed(1)}</span>
        </div>
        <div className="flex items-center justify-between rounded-lg bg-white/5 px-3 py-2">
          <span className="text-slate-400 flex items-center gap-2">
            {summary.reused_count > 0
              ? <AlertTriangle size={14} className="text-amber-400" />
              : <CheckCircle2 size={14} className="text-green-400" />}
            Reused passwords
          </span>
          <span
            className="font-bold"
            style={{ color: summary.reused_count > 0 ? "#fb923c" : "#4ade80" }}
          >
            {summary.reused_count}
          </span>
        </div>
      </div>

      {/* Alerts section */}
      {alertCredentials.length > 0 && (
        <div>
          <button
            onClick={() => setShowAlerts(prev => !prev)}
            className="flex w-full items-center justify-between rounded-xl border border-amber-400/20 bg-amber-400/8 px-3 py-2 text-sm text-amber-300 hover:bg-amber-400/15 transition-colors"
            aria-expanded={showAlerts}
          >
            <span className="flex items-center gap-2">
              <ShieldAlert size={15} />
              {alertCredentials.length} credential{alertCredentials.length !== 1 ? "s need" : " needs"} attention
            </span>
            <span className="text-xs">{showAlerts ? "▲ hide" : "▼ show"}</span>
          </button>

          {showAlerts && (
            <ul className="mt-3 space-y-2" role="list" aria-label="Security alerts">
              {alertCredentials.map(cred => (
                <li
                  key={cred.credential_id}
                  className="rounded-lg bg-white/5 p-3 text-xs"
                >
                  <p className="font-bold text-slate-100 truncate">{cred.website_name}</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {cred.alerts.map(alert => (
                      <span
                        key={alert}
                        className="rounded-full bg-rose-400/15 px-2 py-0.5 text-rose-300"
                      >
                        {ALERT_LABELS[alert] ?? alert}
                      </span>
                    ))}
                    {cred.is_reused && (
                      <span className="rounded-full bg-amber-400/15 px-2 py-0.5 text-amber-300">
                        Reused
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {alertCredentials.length === 0 && summary.total > 0 && (
        <div className="flex items-center gap-2 rounded-xl bg-green-400/10 px-3 py-2 text-sm text-green-300">
          <CheckCircle2 size={16} />
          All credentials look healthy!
        </div>
      )}
    </section>
  );
}
