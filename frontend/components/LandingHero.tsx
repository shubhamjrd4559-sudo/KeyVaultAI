"use client";

import { motion } from "framer-motion";
import { ArrowRight, LockKeyhole, ShieldCheck, Sparkles } from "lucide-react";

// ── Inline brand SVG icons ────────────────────────────────────────────────────
// Lightweight local SVGs — no external dependency or image URL.

function IconInstagram() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="20" rx="5" ry="5" />
      <circle cx="12" cy="12" r="4" />
      <circle cx="17.5" cy="6.5" r="0.8" fill="currentColor" stroke="none" />
    </svg>
  );
}

function IconTelegram() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm4.93 6.71-1.73 8.15c-.13.59-.47.73-.95.45l-2.62-1.93-1.27 1.22c-.14.14-.26.26-.53.26l.19-2.67 4.87-4.4c.21-.19-.05-.29-.33-.1L8.3 14.59l-2.55-.8c-.55-.17-.56-.55.12-.82l9.96-3.84c.46-.17.86.11.7.82z" />
    </svg>
  );
}

function IconAmazon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M13.23 10.56v-.28c-.94.01-1.92.2-1.92 1.29 0 .55.28.93.77.93.36 0 .67-.22.87-.59.24-.43.28-.84.28-1.35zm2.19 3.01a.48.48 0 01-.33.11c-.49 0-.57-.28-.57-.77V9.98c0-1.01-.71-1.66-2.18-1.66-1.3 0-2.14.64-2.24 1.67h1.21c.1-.51.43-.71.95-.71.38 0 .88.14.88.73v.13c-.14.02-1.01.11-2.17.38-.94.23-1.56.73-1.56 1.7 0 .97.64 1.57 1.71 1.57.71 0 1.4-.3 1.85-.96.03.35.11.65.26.87h1.26a5.4 5.4 0 01-.07-.9v-2.1c0-.34.2-.56.49-.56.28 0 .46.21.46.56v3.87zm3.88 2.37c-1.34.95-3.3 1.46-4.97 1.46-2.35 0-4.47-.87-6.07-2.31-.13-.12-.01-.27.14-.18 1.73 1.01 3.87 1.61 6.08 1.61 1.49 0 3.13-.31 4.64-.96.23-.1.42.14.18.38zm.52-.6c-.17-.22-1.14-.11-1.58-.05-.13.02-.15-.1-.03-.19.77-.54 2.04-.38 2.19-.2.14.18-.04 1.43-.76 2.03-.11.09-.22.04-.17-.08.16-.41.52-1.3.35-1.51z" />
    </svg>
  );
}

function IconLinkedIn() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M16 8a6 6 0 016 6v7h-4v-7a2 2 0 00-2-2 2 2 0 00-2 2v7h-4v-7a6 6 0 016-6zM2 9h4v12H2z" />
      <circle cx="4" cy="4" r="2" />
    </svg>
  );
}

function IconNetflix() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M5 3h3.5L12 13V3h3.5v17.5L12 20.5 8.5 11v9H5z" />
    </svg>
  );
}

function IconGmail() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M20 4H4C2.9 4 2 4.9 2 6v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" />
    </svg>
  );
}

function IconSpotify() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm4.59 14.41a.625.625 0 01-.86.21c-2.36-1.44-5.33-1.77-8.83-.97a.625.625 0 11-.28-1.22c3.83-.87 7.11-.5 9.76 1.12.3.18.4.57.21.86zm1.22-2.72a.78.78 0 01-1.07.26C14.2 12.27 10.66 11.8 7.87 12.6a.782.782 0 01-.95-.52.78.78 0 01.52-.95c3.19-.91 7.14-.37 9.79 1.53.37.24.48.73.26 1.03h.02zm.11-2.83c-3.14-1.86-8.33-2.03-11.33-1.12a.937.937 0 11-.54-1.8c3.44-1.04 9.16-.84 12.78 1.3a.938.938 0 01-1.02 1.58l.11.04z" />
    </svg>
  );
}

function IconDropbox() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M6 2L1 5.5 6 9l5-3.5L6 2zm12 0l-5 3.5L18 9l5-3.5L18 2zM1 12.5L6 16l5-3.5-5-3.5-5 3.5zm17-3.5l-5 3.5 5 3.5 5-3.5-5-3.5zM6 17.5L11 21l5-3.5-5-3.5-5 3.5z" />
    </svg>
  );
}

function IconFacebook() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M18 2h-3a5 5 0 00-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 011-1h3z" />
    </svg>
  );
}

function IconCodeChef() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M12 2a10 10 0 100 20A10 10 0 0012 2zm-1 14.5V13H9l3-5.5 3 5.5h-2v3.5h-2z" />
    </svg>
  );
}

function IconReddit() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <circle cx="12" cy="12" r="10" />
      <path fill="white" d="M20 12a1.7 1.7 0 00-1.7-1.7c-.46 0-.87.18-1.18.47A8.4 8.4 0 0013 9.5l.5-2.33 1.62.34a1.2 1.2 0 102.38-.12 1.2 1.2 0 00-1.15.88l-1.8-.38L13.87 10a8.44 8.44 0 00-4.08 1.27 1.7 1.7 0 10-1.67 2.89 3.4 3.4 0 000 .34c0 1.73 2.02 3.13 4.5 3.13s4.5-1.4 4.5-3.13v-.34A1.7 1.7 0 0020 12zm-8.5 2.5a1 1 0 110-2 1 1 0 010 2zm3 2c-.62.62-2.38.62-3 0a.3.3 0 01.42-.42c.45.45 1.7.45 2.16 0a.3.3 0 01.42.42zm-.5-1a1 1 0 110-2 1 1 0 010 2z" />
    </svg>
  );
}

function IconLeetCode() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
      <path d="M13.48 3.37L8.37 8.48a1.5 1.5 0 000 2.12l1.06 1.06a1.5 1.5 0 002.12 0l1.06-1.06 3.18 3.18-5.3 5.3a1.5 1.5 0 000 2.12l1.06 1.06a1.5 1.5 0 002.12 0l7.07-7.07a1.5 1.5 0 000-2.12l-5.3-5.3 1.06-1.06a1.5 1.5 0 000-2.12l-1.06-1.06a1.5 1.5 0 00-2.12 0l-.84.84zM3.37 10.52a1.5 1.5 0 000 2.12l7.07 7.07a1.5 1.5 0 002.12-2.12L5.49 10.52a1.5 1.5 0 00-2.12 0z" />
    </svg>
  );
}

// ── Note data ──────────────────────────────────────────────────────────────────

type NoteData = {
  name: string;
  color: string;
  textColor: string;
  rotation: string;
  icon: React.ReactNode;
  slug: string;
};

const notes: NoteData[] = [
  { name: "Instagram",  color: "#f7de42", textColor: "#111", rotation: "-4deg",  icon: <IconInstagram />,  slug: "instagram" },
  { name: "Telegram",   color: "#f29bc9", textColor: "#111", rotation: "3deg",   icon: <IconTelegram />,   slug: "telegram"  },
  { name: "Amazon",     color: "#79c7ee", textColor: "#111", rotation: "-2deg",  icon: <IconAmazon />,     slug: "amazon"    },
  { name: "LinkedIn",   color: "#a4c9eb", textColor: "#0a2540", rotation: "2deg",icon: <IconLinkedIn />,   slug: "linkedin"  },
  { name: "Netflix",    color: "#f5d540", textColor: "#111", rotation: "-2deg",  icon: <IconNetflix />,    slug: "netflix"   },
  { name: "Google Mail",color: "#5bbbe5", textColor: "#111", rotation: "1deg",   icon: <IconGmail />,      slug: "gmail"     },
  { name: "Spotify",    color: "#69db94", textColor: "#111", rotation: "-3deg",  icon: <IconSpotify />,    slug: "spotify"   },
  { name: "Dropbox",    color: "#88c4ef", textColor: "#111", rotation: "4deg",   icon: <IconDropbox />,    slug: "dropbox"   },
  { name: "Facebook",   color: "#e9e9ff", textColor: "#1c2c4c", rotation: "-2deg",icon: <IconFacebook />, slug: "facebook"  },
  { name: "CodeChef",   color: "#f7db40", textColor: "#111", rotation: "2deg",   icon: <IconCodeChef />,   slug: "codechef"  },
  { name: "Reddit",     color: "#e9cd66", textColor: "#111", rotation: "-3deg",  icon: <IconReddit />,     slug: "reddit"    },
  { name: "LeetCode",   color: "#f6de3e", textColor: "#111", rotation: "2deg",   icon: <IconLeetCode />,   slug: "leetcode"  },
];

// ── Component ──────────────────────────────────────────────────────────────────

type Props = {
  onAuth: (mode: "login" | "register") => void;
  onVault: () => void;
};

export function LandingHero({ onAuth, onVault }: Props) {
  return (
    <main className="hero-grid min-h-screen overflow-hidden text-white" style={{ color: "white" }}>

      {/* ── Top Navigation ────────────────────────────────────── */}
      <header className="relative z-30 flex items-center justify-between border-b border-white/10 bg-[#071821]/85 px-5 py-4 backdrop-blur-xl md:px-10">
        {/* Logo */}
        <button
          className="flex items-center gap-3 text-left"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          aria-label="KeyVault-AI home"
        >
          <span className="grid h-10 w-10 place-items-center rounded-xl border border-fuchsia-300/60 bg-gradient-to-br from-indigo-500 via-fuchsia-400 to-emerald-300 shadow-[0_0_24px_#d96cff80]">
            <ShieldCheck size={22} />
          </span>
          <span className="text-xl font-black tracking-tight md:text-2xl">
            <span className="gradient-title">KeyVault</span>
            <span className="text-white">-AI</span>
          </span>
        </button>

        {/* Desktop nav */}
        <nav className="hidden items-center gap-5 text-sm font-semibold text-slate-200 md:flex">
          <button
            onClick={() => onAuth("register")}
            className="transition hover:text-pink-300"
          >
            Create Account
          </button>
          <button
            className="rounded-xl border border-white/25 px-5 py-2 transition hover:bg-white/10"
            onClick={() => onAuth("login")}
          >
            Login
          </button>
          <button
            className="rounded-xl bg-gradient-to-r from-indigo-500 to-blue-500 px-5 py-2 font-bold shadow-lg shadow-indigo-500/30 transition hover:from-indigo-400 hover:to-blue-400"
            onClick={onVault}
          >
            Unlock Vault
          </button>
        </nav>

        {/* Mobile — just Login */}
        <button
          className="rounded-lg border border-white/20 px-3 py-2 text-sm md:hidden"
          onClick={() => onAuth("login")}
        >
          Login
        </button>
      </header>

      {/* ── Hero Section ─────────────────────────────────────── */}
      <section className="relative mx-auto grid min-h-[calc(100vh-73px)] max-w-[1600px] place-items-center px-4 py-8 md:px-8">

        {/* Pink + blue radial glow */}
        <div
          className="pointer-events-none absolute inset-0 z-[1]"
          style={{
            background: [
              "radial-gradient(circle at 50% 43%, rgba(235,68,182,.20), transparent 22%)",
              "radial-gradient(circle at 75% 20%, rgba(65,170,255,.15), transparent 27%)",
              "radial-gradient(circle at 25% 70%, rgba(99,102,241,.12), transparent 28%)",
            ].join(","),
          }}
        />

        {/* ── Sticky notes wall ───────────────────────────────── */}
        <div className="notes-wall absolute inset-5 grid grid-cols-3 gap-4 opacity-80 md:grid-cols-4 md:gap-8 z-[2]">
          {notes.map((note, index) => (
            <motion.article
              key={note.slug}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.045, duration: 0.5 }}
              className={`note note-${index} hidden sm:block`}
              style={{
                backgroundColor: note.color,
                rotate: note.rotation,
                color: note.textColor,
              }}
            >
              {/* Header row: icon + name */}
              <div className="flex items-center gap-2">
                <span
                  className="note-dot"
                  style={{ color: note.textColor }}
                  aria-hidden="true"
                >
                  {note.icon}
                </span>
                <span className="text-base font-black leading-tight md:text-lg">
                  {note.name}
                </span>
              </div>

              {/* "Password:" label */}
              <p className="mt-2 text-sm font-bold opacity-80 md:text-base">
                Password :–
              </p>

              {/* Dots strip representing hidden password */}
              <div className="note-pwd mt-1">
                {Array.from({ length: 9 }).map((_, i) => (
                  <span key={i} />
                ))}
              </div>
            </motion.article>
          ))}
        </div>

        {/* ── Central pink glassmorphism card ──────────────────── */}
        <motion.div
          initial={{ opacity: 0, scale: 0.88 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          className="relative z-10 mt-4 w-full max-w-[360px] rounded-[26px] border border-pink-200/70 bg-pink-300/70 p-[3px] shadow-[0_0_80px_rgba(236,72,153,.55)] backdrop-blur-xl"
        >
          <div className="rounded-[23px] border border-white/40 bg-[#ff88c9]/65 px-6 py-8 text-center text-[#160914] shadow-inner md:px-10">
            <Sparkles className="mx-auto mb-3 text-[#5b1643]/70" size={26} />
            <p className="text-xl font-black tracking-tight md:text-2xl">
              AI PASSWORD VAULT
            </p>
            <p className="text-base font-bold opacity-80">(by SK)</p>
            <div className="mx-auto my-4 h-px w-3/4 bg-[#5b1643]/30" />
            <p className="text-2xl font-black leading-snug">
              NEW INSTAGRAM
              <br />
              LOGIN
            </p>
            <p className="mt-4 text-3xl font-black leading-none">
              STRONG
              <br />
              PASSWORDS
            </p>
          </div>
        </motion.div>

        {/* ── Bottom floating action bar ────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35, duration: 0.55 }}
          className="relative z-20 mt-[-1.5rem] flex w-full max-w-2xl flex-col items-center gap-3 rounded-[28px] border border-white/15 bg-[#081a22]/85 p-4 shadow-2xl backdrop-blur-2xl sm:flex-row sm:justify-center"
        >
          {/* Left copy */}
          <p className="hidden max-w-[180px] text-xs leading-relaxed text-slate-300 lg:block">
            To unlock your full vault,
            <br />
            use your AI/ML backend.
          </p>

          <button
            id="hero-get-started"
            className="w-full rounded-xl bg-white/10 px-7 py-4 font-black tracking-wide transition hover:bg-white/20 sm:w-auto"
            onClick={onVault}
          >
            GET STARTED <ArrowRight className="ml-2 inline" size={17} />
          </button>

          <button
            id="hero-register-now"
            className="w-full rounded-xl border border-indigo-300/80 bg-indigo-500/10 px-7 py-4 font-black tracking-wide text-indigo-100 transition hover:bg-indigo-500/30 sm:w-auto"
            onClick={() => onAuth("register")}
          >
            REGISTER NOW
          </button>

          {/* Right copy */}
          <p className="hidden max-w-[180px] text-xs leading-relaxed text-slate-300 lg:block">
            To unlock your vault with
            <br />
            AI/ML backend features
          </p>
        </motion.div>

        {/* Decorative lock icon */}
        <LockKeyhole
          className="absolute bottom-10 right-8 text-white/35 z-[2]"
          size={26}
        />
      </section>
    </main>
  );
}
