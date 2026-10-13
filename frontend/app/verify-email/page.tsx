"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

export default function VerifyEmailPage() {
  const [status, setStatus] = useState("Verifying your email…");
  useEffect(() => {
    const url = new URL(window.location.href);
    const token = new URLSearchParams(url.hash.slice(1)).get("token");
    window.history.replaceState({}, "", url.pathname);
    if (!token) { setStatus("This verification link is incomplete or has expired."); return; }
    void api.verifyEmail(token).then(result => setStatus(result.detail || "Your email is verified. You can sign in now."))
      .catch(error => setStatus((error as Error).message));
  }, []);
  return <main className="grid min-h-screen place-items-center bg-[#faf8f4] p-6"><section className="glass-card max-w-lg p-8 text-center"><h1 className="text-2xl font-black">Email verification</h1><p role="status" className="mt-4 text-slate-700">{status}</p><Link className="mt-6 inline-block font-bold text-indigo-700" href="/">Return to KeyVault-AI</Link></section></main>;
}
