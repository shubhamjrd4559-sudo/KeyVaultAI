"use client";

/**
 * SecurityPanel — M5 Security Engine + M6 ML Risk Prediction UI component.
 *
 * Displays vault-wide security posture:
 *   - Overall score arc / badge
 *   - Level counts (very_strong / strong / fair / weak)
 *   - Reused credentials count
 *   - Per-credential alerts
 *   - M6 ML risk level + confidence + explanation
 *
 * Security: never displays passwords or encrypted values.
 * All data comes from /api/v1/security/* and /api/v1/ml/predict/ endpoints.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, BrainCircuit, CheckCircle2, LoaderCircle, RefreshCw, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { api, withRefresh } from "@/lib/api";
import type { CredentialSecurity, MLPrediction, SecuritySummary } from "@/types";

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

// ── M6 ML Risk helpers ───────────────────────────────────────────────────────

const ML_RISK_COLORS: Record<string, string> = {
  LOW:    "#22c55e",
  MEDIUM: "#facc15",
  HIGH:   "#f43f5e",
};

const ML_RISK_LABELS: Record<string, string> = {
  LOW:    "Low Risk",
  MEDIUM: "Medium Risk",
  HIGH:   "High Risk",
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
      <circle cx="65" cy="65" r={r} fill="none" stroke="rgba(0,0,0,0.06)" strokeWidth="10" />
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
      <text x="65" y="60" textAnchor="middle" fill="#0f172a" fontSize="26" fontWeight="800">{score}</text>
      <text x="65" y="78" textAnchor="middle" fill="#64748b" fontSize="10">/100</text>
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
  const [mlPrediction, setMlPrediction]     = useState<MLPrediction | null>(null);
  const [mlLoading, setMlLoading]           = useState(false);

  async function loadSecurity() {
    setLoading(true);
    setError("");
    setMlPrediction(null);
    try {
      const [sumData, credData] = await Promise.all([
        withRefresh(access => api.securitySummary(access)),
        withRefresh(access => api.securityCredentials(access)),
      ]);
      setSummary(sumData.summary);
      setCredentials(credData.credentials);
      // M6: load ML risk prediction from the vault's overall score
      void loadMlPrediction(sumData.summary);
    } catch (caught) {
      setError((caught as Error).message || "Security analysis unavailable.");
    } finally {
      setLoading(false);
    }
  }

  async function loadMlPrediction(sum: SecuritySummary) {
    if (sum.total === 0) return;
    setMlLoading(true);
    try {
      const result = await withRefresh(access => api.mlPredict(access, {
        security_score: sum.overall_score,
        security_level: sum.overall_level,
        is_reused: sum.reused_count > 0,
      }));
      setMlPrediction(result);
    } catch {
      // ML prediction is best-effort — do not block M5 UI on ML failure
      setMlPrediction(null);
    } finally {
      setMlLoading(false);
    }
  }

  useEffect(() => { void loadSecurity(); }, []);

  if (loading) {
    return (
      <div className="security-panel glass-card p-6 animate-pulse">
        <div className="flex items-center gap-3 mb-4">
          <ShieldCheck className="text-indigo-600" size={22} />
          <h2 className="text-base font-bold text-slate-900">Security Analysis</h2>
        </div>
        <div className="grid place-items-center py-8 text-slate-500">
          <LoaderCircle className="animate-spin mb-2" size={28} />
          <span className="text-sm">Analysing your vault…</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-3 text-rose-600">
          <ShieldX size={22} />
          <h2 className="text-base font-bold text-slate-900">Security Analysis</h2>
        </div>
        <p className="text-sm text-slate-600">{error}</p>
        <button
          onClick={() => void loadSecurity()}
          className="mt-3 flex items-center gap-2 text-xs text-indigo-600 hover:text-indigo-800 transition-colors"
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
            <h2 className="text-base font-bold text-slate-900">Security Analysis</h2>
            <p className="text-xs text-slate-500">Deterministic · Rule-based · Local</p>
          </div>
        </div>
        <button
          onClick={() => void loadSecurity()}
          title="Refresh analysis"
          className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition-colors"
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
        <p className="text-xs text-slate-500 mt-1">{summary.total} credential{summary.total !== 1 ? "s" : ""} analysed</p>
      </div>

      {/* Counts row */}
      <div className="grid grid-cols-2 gap-3 text-center text-sm">
        {[
          { label: "Very Strong", count: summary.very_strong_count, color: LEVEL_COLORS.very_strong },
          { label: "Strong",      count: summary.strong_count,      color: LEVEL_COLORS.strong },
          { label: "Fair",        count: summary.fair_count,        color: LEVEL_COLORS.fair },
          { label: "Weak",        count: summary.weak_count,        color: LEVEL_COLORS.weak },
        ].map(({ label, count, color }) => (
          <div key={label} className="rounded-xl border border-amber-200/50 bg-amber-50/40 p-3">
            <p className="text-xl font-black" style={{ color }}>{count}</p>
            <p className="text-xs text-slate-600 font-medium">{label}</p>
          </div>
        ))}
      </div>

      {/* M6 ML Risk Prediction */}
      {(mlLoading || mlPrediction) && (
        <div
          className="rounded-xl px-4 py-3 text-sm"
          style={{
            background: mlPrediction ? `${ML_RISK_COLORS[mlPrediction.risk_level]}12` : "rgba(0,0,0,0.03)",
            border: `1px solid ${mlPrediction ? ML_RISK_COLORS[mlPrediction.risk_level] + "40" : "rgba(0,0,0,0.08)"}`,
          }}
          aria-label="ML Risk Prediction"
        >
          <div className="flex items-center gap-2 mb-2">
            <BrainCircuit size={15} className="text-indigo-600 shrink-0" />
            <span className="font-semibold text-slate-800 text-xs uppercase tracking-wide">ML Risk Prediction</span>
            {mlLoading && <LoaderCircle size={12} className="animate-spin text-slate-400 ml-auto" />}
          </div>
          {mlPrediction && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span
                  className="font-black text-sm"
                  style={{ color: ML_RISK_COLORS[mlPrediction.risk_level] }}
                >
                  {ML_RISK_LABELS[mlPrediction.risk_level]}
                </span>
                <span className="text-xs text-slate-500">
                  {(mlPrediction.confidence * 100).toFixed(0)}% confidence
                </span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">{mlPrediction.explanation}</p>
            </div>
          )}
        </div>
      )}

      {/* Stats row */}
      <div className="space-y-2 text-sm">
        <div className="flex items-center justify-between rounded-lg border border-amber-200/40 bg-amber-50/40 px-3 py-2">
          <span className="text-slate-600">Avg score</span>
          <span className="font-bold text-slate-900">{summary.average_score.toFixed(1)}</span>
        </div>
        <div className="flex items-center justify-between rounded-lg border border-amber-200/40 bg-amber-50/40 px-3 py-2">
          <span className="text-slate-600 flex items-center gap-2">
            {summary.reused_count > 0
              ? <AlertTriangle size={14} className="text-amber-500" />
              : <CheckCircle2 size={14} className="text-emerald-500" />}
            Reused passwords
          </span>
          <span
            className="font-bold"
            style={{ color: summary.reused_count > 0 ? "#ea580c" : "#16a34a" }}
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
            className="flex w-full items-center justify-between rounded-xl border border-amber-300 bg-amber-50/90 px-3 py-2 text-sm text-amber-900 hover:bg-amber-100 transition-colors"
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
                  className="rounded-lg border border-amber-200/50 bg-amber-50/50 p-3 text-xs"
                >
                  <p className="font-bold text-slate-900 truncate">{cred.website_name}</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {cred.alerts.map(alert => (
                      <span
                        key={alert}
                        className="rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-rose-700 font-medium"
                      >
                        {ALERT_LABELS[alert] ?? alert}
                      </span>
                    ))}
                    {cred.is_reused && (
                      <span className="rounded-full border border-amber-300 bg-amber-100 px-2 py-0.5 text-amber-800 font-medium">
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
        <div className="flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
          <CheckCircle2 size={16} />
          All credentials look healthy!
        </div>
      )}
    </section>
  );
}
