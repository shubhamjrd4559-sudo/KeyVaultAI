"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

export default function ResetPasswordPage() {
  const [token, setToken] = useState(""); const [password, setPassword] = useState(""); const [status, setStatus] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { const url = new URL(window.location.href); setToken(new URLSearchParams(url.hash.slice(1)).get("token") || ""); window.history.replaceState({}, "", url.pathname); }, []);
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); setBusy(true); setStatus(""); try { const result = await api.resetPassword(token, password); setStatus(result.detail || "Your password has been reset. You can sign in now."); } catch (error) { setStatus((error as Error).message); } finally { setBusy(false); } }
  return <main className="grid min-h-screen place-items-center bg-[#faf8f4] p-6"><section className="glass-card w-full max-w-lg p-8"><h1 className="text-2xl font-black">Choose a new password</h1>{token ? <form onSubmit={submit} className="mt-5 space-y-4"><label className="block">New password<input required minLength={10} autoComplete="new-password" type="password" value={password} onChange={event => setPassword(event.target.value)} className="field" /></label><button disabled={busy} className="w-full rounded-xl bg-indigo-600 p-3 font-bold text-white disabled:opacity-60">{busy ? "Saving…" : "Reset password"}</button></form> : <p className="mt-4">This reset link is incomplete or has expired.</p>}{status && <p role="status" className="mt-4 text-slate-700">{status}</p>}<Link className="mt-6 inline-block font-bold text-indigo-700" href="/">Return to KeyVault-AI</Link></section></main>;
}
