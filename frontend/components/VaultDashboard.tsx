"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { Check, Copy, Eye, EyeOff, KeyRound, LoaderCircle, LogOut, Plus, Search, ShieldCheck, Star, Trash2, X, RotateCcw } from "lucide-react";
import { api, withRefresh } from "@/lib/api";
import { tokenStore } from "@/lib/auth";
import type { Credential, DeletedCredential } from "@/types";
import { SecurityPanel } from "./SecurityPanel";

type Props = { onLogout: () => void };
const initialForm = { website_name: "", website_url: "", username: "", email: "", password: "", category: "general", notes: "", favorite: false };

const STICKY_THEMES = [
  {
    // Pastel Yellow
    bg: "#fef9c3",
    border: "#fef08a",
    pin: "#ef4444",
    tagBg: "rgba(234, 179, 8, 0.22)",
    tagText: "#713f12",
    codeBg: "rgba(0, 0, 0, 0.04)",
    codeBorder: "rgba(161, 98, 7, 0.2)",
    glow: "rgba(254, 240, 138, 0.38)",
    glowSoft: "rgba(253, 224, 71, 0.2)",
  },
  {
    // Pastel Pink
    bg: "#fce7f3",
    border: "#fbcfe8",
    pin: "#ec4899",
    tagBg: "rgba(236, 72, 153, 0.2)",
    tagText: "#831843",
    codeBg: "rgba(0, 0, 0, 0.04)",
    codeBorder: "rgba(190, 24, 93, 0.2)",
    glow: "rgba(251, 207, 232, 0.38)",
    glowSoft: "rgba(244, 114, 182, 0.2)",
  },
  {
    // Pastel Sky Blue
    bg: "#e0f2fe",
    border: "#bae6fd",
    pin: "#0284c7",
    tagBg: "rgba(14, 165, 233, 0.2)",
    tagText: "#0c4a6e",
    codeBg: "rgba(0, 0, 0, 0.04)",
    codeBorder: "rgba(3, 105, 161, 0.2)",
    glow: "rgba(186, 230, 253, 0.38)",
    glowSoft: "rgba(125, 211, 252, 0.2)",
  },
  {
    // Pastel Green
    bg: "#dcfce7",
    border: "#bbf7d0",
    pin: "#16a34a",
    tagBg: "rgba(34, 197, 94, 0.2)",
    tagText: "#14532d",
    codeBg: "rgba(0, 0, 0, 0.04)",
    codeBorder: "rgba(21, 128, 61, 0.2)",
    glow: "rgba(187, 247, 208, 0.38)",
    glowSoft: "rgba(134, 239, 172, 0.2)",
  },
  {
    // Light Lavender
    bg: "#ede9fe",
    border: "#ddd6fe",
    pin: "#8b5cf6",
    tagBg: "rgba(139, 92, 246, 0.2)",
    tagText: "#4c1d95",
    codeBg: "rgba(0, 0, 0, 0.04)",
    codeBorder: "rgba(109, 40, 217, 0.2)",
    glow: "rgba(221, 214, 254, 0.38)",
    glowSoft: "rgba(196, 181, 253, 0.2)",
  },
];

const ROTATIONS = ["-1.4deg", "1.2deg", "-0.8deg", "1.5deg", "-1.2deg", "0.9deg"];
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

export function VaultDashboard({ onLogout }: Props) {
  const [items, setItems] = useState<Credential[]>([]); const [deletedItems, setDeletedItems] = useState<DeletedCredential[]>([]); const [view, setView] = useState<"vault" | "deleted">("vault"); const [query, setQuery] = useState(""); const [category, setCategory] = useState(""); const [loading, setLoading] = useState(true); const [error, setError] = useState(""); const [emailError, setEmailError] = useState(""); const [message, setMessage] = useState(""); const [form, setForm] = useState(initialForm); const [editing, setEditing] = useState<Credential | null>(null); const [reveal, setReveal] = useState<Record<string, string>>({});
  const filtered = useMemo(() => items.filter(item => (!query || `${item.website_name} ${item.username} ${item.email}`.toLowerCase().includes(query.toLowerCase())) && (!category || item.category === category)), [items, query, category]);
  async function load() { setLoading(true); setError(""); try { const data = await withRefresh(access => api.credentials(access)); setItems(data.credentials); } catch (caught) { setError((caught as Error).message); } finally { setLoading(false); } }
  async function loadDeleted() { setLoading(true); setError(""); try { const data = await withRefresh(access => api.recentlyDeleted(access)); setDeletedItems(data.credentials); } catch (caught) { setError((caught as Error).message); } finally { setLoading(false); } }
  useEffect(() => { void load(); }, []);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setEmailError("");
    const trimmedEmail = form.email.trim();
    if (trimmedEmail && !EMAIL_REGEX.test(trimmedEmail)) {
      setEmailError("Please enter a valid email address. Example: example@gmail.com");
      return;
    }
    try {
      const result = await withRefresh(access => editing ? api.updateCredential(access, editing.credential_id, form) : api.createCredential(access, form));
      setItems(current => editing ? current.map(item => item.credential_id === editing.credential_id ? result.credential : item) : [result.credential, ...current]);
      setMessage(editing ? "Credential updated." : "Credential secured in your vault.");
      setEditing(null);
      setForm(initialForm);
    } catch (caught) {
      setError((caught as Error).message);
    }
  }
  async function revealPassword(id: string, copy = false) { try { const data = await withRefresh(access => copy ? api.copy(access, id) : api.reveal(access, id)); if (copy) { await navigator.clipboard.writeText(data.password); setMessage("Password copied to clipboard."); } else setReveal(current => ({ ...current, [id]: data.password })); } catch (caught) { setError((caught as Error).message); } }
  async function remove(id: string) { if (!window.confirm("Move this credential to Recently Deleted? It can be restored for 72 hours.")) return; try { await withRefresh(access => api.softDeleteCredential(access, id)); setItems(current => current.filter(item => item.credential_id !== id)); setMessage("Credential moved to Recently Deleted for 72 hours."); } catch (caught) { setError((caught as Error).message); } }
  async function restore(item: DeletedCredential) { try { const result = await withRefresh(access => api.restoreCredential(access, item.credential_id)); setDeletedItems(current => current.filter(x => x.credential_id !== item.credential_id)); setItems(current => [result.credential, ...current]); setMessage("Credential restored."); } catch (caught) { setError((caught as Error).message); } }
  async function permanentlyDelete(item: DeletedCredential) { if (!window.confirm("Permanently delete this credential now? This cannot be undone.")) return; try { await withRefresh(access => api.permanentDeleteCredential(access, item.credential_id)); setDeletedItems(current => current.filter(x => x.credential_id !== item.credential_id)); setMessage("Credential permanently deleted."); } catch (caught) { setError((caught as Error).message); } }
  async function signOut() { const access = tokenStore.access; try { if (access) await api.logout(access); } catch { /* Backend will still clear the cookie on next request; local clear protects this session. */ } tokenStore.clear(); onLogout(); }
  function beginEdit(item: Credential) { setEditing(item); setEmailError(""); setForm({ website_name: item.website_name, website_url: item.website_url, username: item.username, email: item.email, password: "", category: item.category, notes: item.notes || "", favorite: item.favorite }); window.scrollTo({ top: 0, behavior: "smooth" }); }
  return (
    <main className="min-h-screen bg-[#faf8f4] text-slate-800">
      <header className="sticky top-0 z-20 flex items-center justify-between border-b border-amber-900/10 bg-[#fffdf9]/90 px-5 py-4 backdrop-blur-xl md:px-10">
        <div className="flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-fuchsia-500 to-indigo-500 text-white shadow-md shadow-fuchsia-500/20">
            <ShieldCheck size={22} />
          </span>
          <div>
            <p className="gradient-title text-xl font-black">KeyVault-AI</p>
            <p className="text-xs text-slate-500">Your encrypted password vault</p>
          </div>
        </div>
        <button
          onClick={signOut}
          className="flex items-center gap-2 rounded-xl border border-slate-300 bg-white/80 px-3 py-2 text-sm text-slate-700 shadow-sm transition hover:bg-white hover:text-slate-900"
        >
          <LogOut size={16} /> Sign out
        </button>
      </header>

      <section className="mx-auto grid max-w-7xl gap-7 p-5 lg:grid-cols-[380px_1fr] lg:p-10">
        <aside className="flex flex-col gap-6">
          <div className="glass-card h-fit p-6">
            <div className="mb-6 flex items-center gap-3">
              <KeyRound className="text-pink-500" size={24} />
              <div>
                <h1 className="text-xl font-black text-slate-900">
                  {editing ? "Edit credential" : "Add a credential"}
                </h1>
                <p className="text-sm text-slate-500">
                  Passwords are encrypted before storage.
                </p>
              </div>
            </div>

            <form onSubmit={save} className="space-y-3">
              <input
                required
                placeholder="Website or app name"
                value={form.website_name}
                onChange={e => setForm({ ...form, website_name: e.target.value })}
                className="field"
              />
              <input
                placeholder="Website URL"
                type="url"
                value={form.website_url}
                onChange={e => setForm({ ...form, website_url: e.target.value })}
                className="field"
              />
              <input
                placeholder="Username"
                value={form.username}
                onChange={e => setForm({ ...form, username: e.target.value })}
                className="field"
              />
              <div>
                <input
                  placeholder="Email"
                  type="email"
                  value={form.email}
                  onChange={e => {
                    setForm({ ...form, email: e.target.value });
                    if (emailError) setEmailError("");
                  }}
                  className={`field ${emailError ? "!border-rose-400 !outline-rose-400" : ""}`}
                />
                {emailError && (
                  <p className="mt-1 text-xs font-medium text-rose-600">
                    {emailError}
                  </p>
                )}
              </div>
              <input
                placeholder={editing ? "New password (leave blank to keep)" : "Password"}
                required={!editing}
                type="password"
                value={form.password}
                onChange={e => setForm({ ...form, password: e.target.value })}
                className="field"
              />
              <select
                value={form.category}
                onChange={e => setForm({ ...form, category: e.target.value })}
                className="field"
              >
                <option value="general">General</option>
                <option value="social">Social</option>
                <option value="finance">Finance</option>
                <option value="work">Work</option>
                <option value="shopping">Shopping</option>
                <option value="entertainment">Entertainment</option>
                <option value="education">Education</option>
                <option value="other">Other</option>
              </select>
              <textarea
                placeholder="Private notes"
                value={form.notes}
                onChange={e => setForm({ ...form, notes: e.target.value })}
                className="field min-h-20"
              />
              <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={form.favorite}
                  onChange={e => setForm({ ...form, favorite: e.target.checked })}
                />
                Mark as favorite
              </label>
              <button className="flex w-full justify-center rounded-xl bg-gradient-to-r from-fuchsia-500 to-indigo-500 py-3 font-bold text-white shadow-md shadow-fuchsia-500/20 transition hover:opacity-95">
                {editing ? "Save changes" : <><Plus size={18} className="mr-2" /> Secure credential</>}
              </button>
              {editing && (
                <button
                  type="button"
                  onClick={() => { setEditing(null); setForm(initialForm); setEmailError(""); }}
                  className="w-full text-sm text-slate-500 hover:text-slate-700"
                >
                  Cancel edit
                </button>
              )}
            </form>
          </div>
          <SecurityPanel />
        </aside>

        <section>
          <div className="mb-4 flex gap-2"><button onClick={() => { setView("vault"); void load(); }} className={`rounded-xl px-4 py-2 text-sm font-bold ${view === "vault" ? "bg-indigo-600 text-white" : "bg-white text-slate-700"}`}>Vault</button><button onClick={() => { setView("deleted"); void loadDeleted(); }} className={`rounded-xl px-4 py-2 text-sm font-bold ${view === "deleted" ? "bg-indigo-600 text-white" : "bg-white text-slate-700"}`}>Recently Deleted</button></div>
          {view === "deleted" ? <><div className="glass-card mb-5 p-4"><h2 className="text-lg font-bold">Recently Deleted</h2><p className="text-sm text-slate-600">Credentials are permanently removed 72 hours after deletion.</p></div>{loading ? <div className="grid min-h-60 place-items-center text-slate-500"><LoaderCircle className="animate-spin" size={28} /></div> : deletedItems.length === 0 ? <div className="glass-card p-8 text-center text-slate-600">No recently deleted credentials.</div> : <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{deletedItems.map(item => <article key={item.credential_id} className="glass-card p-5"><h3 className="font-bold">{item.website_name}</h3><p className="mt-1 text-sm text-slate-600">{item.username || item.email || "No username"}</p><p className="mt-3 text-xs text-slate-500">Deleted {new Date(item.deleted_at).toLocaleString()}</p><div className="mt-4 flex gap-2"><button onClick={() => void restore(item)} className="flex items-center gap-1 rounded-lg bg-emerald-100 px-3 py-2 text-sm font-semibold text-emerald-800"><RotateCcw size={15} /> Restore</button><button onClick={() => void permanentlyDelete(item)} className="rounded-lg bg-rose-100 px-3 py-2 text-sm font-semibold text-rose-800">Delete forever</button></div></article>)}</div>}</> : <>
          <div className="glass-card mb-5 flex flex-col gap-3 p-4 sm:flex-row">
            <label className="flex flex-1 items-center gap-2 rounded-xl border border-[#e5dfd3] bg-[#fffefb] px-3 shadow-inner">
              <Search size={18} className="text-slate-400" />
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search your vault"
                className="w-full bg-transparent py-3 outline-none text-slate-800 placeholder:text-slate-400"
              />
            </label>
            <select
              value={category}
              onChange={e => setCategory(e.target.value)}
              className="rounded-xl border border-[#e5dfd3] bg-[#fffefb] px-3 py-2 text-sm text-slate-800 outline-none"
            >
              <option value="">All categories</option>
              <option value="work">Work</option>
              <option value="social">Social</option>
              <option value="finance">Finance</option>
              <option value="general">General</option>
            </select>
          </div>

          {error && (
            <p role="alert" className="mb-4 rounded-xl border border-rose-200 bg-rose-50 p-4 text-rose-800">
              {error}
              <button onClick={() => setError("")} className="float-right"><X size={18} /></button>
            </p>
          )}

          {message && (
            <p className="mb-4 rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-emerald-800">
              <Check className="mr-2 inline" size={17} />{message}
            </p>
          )}

          {loading ? (
            <div className="grid min-h-60 place-items-center text-slate-500">
              <LoaderCircle className="animate-spin" size={28} />
            </div>
          ) : filtered.length === 0 ? (
            <div className="glass-card grid min-h-64 place-items-center p-8 text-center">
              <KeyRound size={40} className="mb-4 text-pink-500" />
              <div>
                <h2 className="text-xl font-bold text-slate-900">
                  {items.length ? "No matching credentials" : "Your vault is ready"}
                </h2>
                <p className="mt-2 text-slate-500">
                  {items.length ? "Try another search or filter." : "Add your first encrypted credential using the form."}
                </p>
              </div>
            </div>
          ) : (
            <div className="grid gap-6 sm:grid-cols-2 xl:grid-cols-3 pt-3">
              {filtered.map((item, index) => {
                const theme = STICKY_THEMES[index % STICKY_THEMES.length];
                const rotation = ROTATIONS[index % ROTATIONS.length];

                return (
                  <article
                    key={item.credential_id}
                    className="credential-card"
                    style={{
                      backgroundColor: theme.bg,
                      border: `1px solid ${theme.border}`,
                      rotate: rotation,
                      ...({
                        "--card-border-glow": theme.border,
                        "--card-glow": theme.glow,
                        "--card-glow-soft": theme.glowSoft,
                      } as React.CSSProperties),
                    }}
                  >
                    {/* Decorative Push-Pin Tack */}
                    <div
                      className="absolute -top-3 left-1/2 -translate-x-1/2 z-10 pointer-events-none drop-shadow-sm"
                      aria-hidden="true"
                    >
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                        <ellipse cx="12" cy="22" rx="4" ry="1.5" fill="rgba(0,0,0,0.18)" />
                        <path d="M12 13V21" stroke="#64748b" strokeWidth="2.2" strokeLinecap="round" />
                        <circle cx="12" cy="7.5" r="5.5" fill={theme.pin} />
                        <circle cx="10" cy="5.5" r="1.8" fill="white" opacity="0.65" />
                        <path d="M7.5 11.5C7.5 10.5 8.5 10 12 10C15.5 10 16.5 10.5 16.5 11.5L15.5 13H8.5L7.5 11.5Z" fill={theme.pin} />
                      </svg>
                    </div>

                    <div className="flex items-start justify-between pt-1">
                      <div>
                        <p className="text-lg font-black text-slate-900 tracking-tight">{item.website_name}</p>
                        <p className="mt-0.5 text-sm font-medium text-slate-600">{item.username || item.email || "No username"}</p>
                      </div>
                      <button
                        onClick={() => void withRefresh(access => api.updateCredential(access, item.credential_id, { favorite: !item.favorite })).then(({ credential }) => setItems(current => current.map(x => x.credential_id === credential.credential_id ? credential : x))).catch(caught => setError((caught as Error).message))}
                        aria-label="Toggle favorite"
                        className="rounded-full p-1 hover:bg-black/5 transition-colors"
                      >
                        <Star size={18} className={item.favorite ? "fill-amber-500 text-amber-500" : "text-slate-400 hover:text-slate-600"} />
                      </button>
                    </div>

                    <div className="mt-4 flex items-center gap-2">
                      <span
                        className="rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize"
                        style={{ backgroundColor: theme.tagBg, color: theme.tagText }}
                      >
                        {item.category}
                      </span>
                      <span
                        className="rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize"
                        style={{ backgroundColor: "rgba(0,0,0,0.06)", color: "#1e293b" }}
                      >
                        {item.security_level.replace("_", " ")}
                      </span>
                    </div>

                    <div
                      className="mt-4 rounded-md p-2.5 font-mono text-sm text-slate-900 font-semibold"
                      style={{ backgroundColor: theme.codeBg, border: `1px solid ${theme.codeBorder}` }}
                    >
                      {reveal[item.credential_id] ? reveal[item.credential_id] : "••••••••••••"}
                    </div>

                    <div className="mt-4 flex flex-wrap items-center gap-2">
                      <button
                        onClick={() => reveal[item.credential_id] ? setReveal(current => { const next = { ...current }; delete next[item.credential_id]; return next; }) : void revealPassword(item.credential_id)}
                        className="icon-button"
                        aria-label="Reveal password"
                      >
                        {reveal[item.credential_id] ? <EyeOff size={17} /> : <Eye size={17} />}
                      </button>
                      <button
                        onClick={() => void revealPassword(item.credential_id, true)}
                        className="icon-button"
                        aria-label="Copy password"
                      >
                        <Copy size={17} />
                      </button>
                      <button
                        onClick={() => beginEdit(item)}
                        className="rounded-md px-2.5 py-1 text-xs font-semibold text-slate-700 hover:bg-black/5 transition-colors"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => void remove(item.credential_id)}
                        className="ml-auto icon-button text-rose-600 hover:bg-rose-100/70 hover:text-rose-700"
                        aria-label="Delete credential"
                      >
                        <Trash2 size={17} />
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
          </>}
        </section>
      </section>
    </main>
  );

}
