"use client";

import { useState } from "react";
import { AuthDialog } from "@/components/AuthDialog";
import { LandingHero } from "@/components/LandingHero";
import { VaultDashboard } from "@/components/VaultDashboard";
import { tokenStore } from "@/lib/auth";
import type { AuthTokens } from "@/types";

export default function Home() {
  const [screen, setScreen] = useState<"landing" | "vault">("landing");
  const [dialog, setDialog] = useState<"login" | "register" | null>(null);
  function openVault() { if (tokenStore.access) setScreen("vault"); else setDialog("login"); }
  function authenticated(tokens: AuthTokens) { tokenStore.save(tokens); setDialog(null); setScreen("vault"); }
  return screen === "vault" ? <VaultDashboard onLogout={() => setScreen("landing")}/> : <><LandingHero onAuth={setDialog} onVault={openVault}/>{dialog && <AuthDialog mode={dialog} onClose={() => setDialog(null)} onAuthenticated={authenticated}/>}</>;
}
