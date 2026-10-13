"use client";

import { useEffect, useState } from "react";
import { AuthDialog } from "@/components/AuthDialog";
import { LandingHero } from "@/components/LandingHero";
import { VaultDashboard } from "@/components/VaultDashboard";
import { tokenStore } from "@/lib/auth";
import { api } from "@/lib/api";
import type { AuthTokens } from "@/types";

export default function Home() {
  const [screen, setScreen] = useState<"landing" | "vault" | "restoring">("restoring");
  const [dialog, setDialog] = useState<"login" | "register" | null>(null);

  // On mount: try to restore the session from the HttpOnly refresh cookie.
  // If the cookie is valid the backend returns a new access token silently.
  useEffect(() => {
    api.refresh()
      .then((tokens) => {
        tokenStore.save(tokens);
        setScreen("vault");
      })
      .catch(() => {
        // No valid cookie (not logged in or cookie expired) — show landing.
        setScreen("landing");
      });
  }, []);

  function openVault() {
    if (tokenStore.access) setScreen("vault");
    else setDialog("login");
  }

  function authenticated(tokens: Pick<AuthTokens, "access_token" | "token_type">) {
    tokenStore.save(tokens);
    setDialog(null);
    setScreen("vault");
  }

  // While attempting silent session restore, render nothing (avoids flash).
  if (screen === "restoring") return null;

  return screen === "vault"
    ? <VaultDashboard onLogout={() => { tokenStore.clear(); setScreen("landing"); }} />
    : (
      <>
        <LandingHero onAuth={setDialog} onVault={openVault} />
        {dialog && (
          <AuthDialog
            mode={dialog}
            onClose={() => setDialog(null)}
            onAuthenticated={authenticated}
          />
        )}
      </>
    );
}
