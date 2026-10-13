"use client";

import { FormEvent, useState } from "react";
import { LoaderCircle, X } from "lucide-react";
import { api } from "@/lib/api";
import type { AuthTokens } from "@/types";

export function AuthDialog({ mode, onClose, onAuthenticated }: { mode: "login" | "register"; onClose: () => void; onAuthenticated: (tokens: Pick<AuthTokens, "access_token" | "token_type">) => void }) {
  const [currentMode, setCurrentMode] = useState<"login" | "register" | "forgot">(mode); const [error, setError] = useState(""); const [notice, setNotice] = useState(""); const [loading, setLoading] = useState(false); const [sentTo, setSentTo] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); setLoading(true); setError(""); setNotice(""); const data = new FormData(event.currentTarget); const email = String(data.get("email")).trim(); try { if (currentMode === "register") { await api.register({ full_name: String(data.get("name")), email, password: String(data.get("password")) }); setSentTo(email); setNotice("Check your inbox for a verification link before signing in."); return; } if (currentMode === "forgot") { await api.forgotPassword(email); setNotice("If an account matches that address, password reset instructions have been sent."); return; } const tokens = await api.login({ email, password: String(data.get("password")) }); onAuthenticated(tokens); } catch (caught) { const apiError = caught as Error & { status?: number }; setError(apiError.message); if (apiError.status === 403) setSentTo(email); } finally { setLoading(false); } }
  async function resend() { setLoading(true); setError(""); try { await api.resendVerification(sentTo); setNotice("If the account needs verification, a new link has been sent."); } catch (caught) { setError((caught as Error).message); } finally { setLoading(false); } }
  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-slate-900/40 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`${currentMode} to KeyVault AI`}
    >
      <form
        onSubmit={submit}
        className="glass-card w-full max-w-md p-7 text-slate-800 shadow-2xl"
      >
        <div className="mb-6 flex items-start justify-between">
          <div>
            <p className="gradient-title text-2xl font-black">KeyVault-AI</p>
            <h2 className="mt-1 text-xl font-bold text-slate-900">
              {currentMode === "login" ? "Unlock your vault" : currentMode === "register" ? "Create your vault" : "Reset your password"}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition"
          >
            <X size={20} />
          </button>
        </div>

        {currentMode === "register" && (
          <label>
            Full name
            <input name="name" required className="field" />
          </label>
        )}

        <label>
          Email
          <input name="email" type="email" required autoComplete="email" className="field" />
        </label>

        {currentMode !== "forgot" && <label>
          Password
          <input
            name="password"
            type="password"
            required
            minLength={10}
            autoComplete={currentMode === "login" ? "current-password" : "new-password"}
            className="field"
          />
        </label>}

        {notice && <p role="status" className="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">{notice}</p>}
        {sentTo && <button type="button" disabled={loading} onClick={() => void resend()} className="mt-3 w-full text-sm font-semibold text-indigo-700 hover:underline">Resend verification email</button>}

        {error && (
          <p role="alert" className="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
            {error}
          </p>
        )}

        <button
          disabled={loading}
          className="mt-6 flex w-full justify-center rounded-xl bg-gradient-to-r from-fuchsia-500 to-indigo-500 px-5 py-3 font-bold text-white shadow-md shadow-fuchsia-500/20 transition hover:opacity-95 disabled:opacity-60"
        >
          {loading ? (
            <LoaderCircle className="animate-spin" size={20} />
          ) : currentMode === "login" ? (
            "Unlock Vault"
          ) : currentMode === "register" ? (
            "Register Now"
          ) : (
            "Send reset link"
          )}
        </button>

        <p className="mt-4 text-center text-sm text-slate-600">
          {currentMode === "login" ? "New here?" : currentMode === "register" ? "Already have an account?" : "Remembered it?"}{" "}
          <button
            type="button"
            onClick={() => {
              setCurrentMode(currentMode === "login" ? "register" : "login"); setError(""); setNotice(""); setSentTo("");
            }}
            className="font-bold text-pink-600 hover:underline"
          >
            {currentMode === "login" ? "Create account" : "Login"}
          </button>
        </p>
        {currentMode === "login" && <button type="button" onClick={() => { setCurrentMode("forgot"); setError(""); setNotice(""); }} className="mt-3 block w-full text-center text-sm font-semibold text-indigo-700 hover:underline">Forgot password?</button>}
      </form>
    </div>
  );
}
