import { useState } from "react";
import { LockKeyhole, Mail, ShieldCheck, KeyRound } from "lucide-react";
import { loginAdmin, requestPasswordReset, resetPassword } from "../api";

const DEFAULT_EMAIL = "security@vantagecircle.com";

export default function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState(DEFAULT_EMAIL);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function handleLogin(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setMessage("");
    try {
      const auth = await loginAdmin(email.trim(), password);
      onAuthenticated(auth.user);
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleForgotPassword(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setMessage("");
    try {
      const response = await requestPasswordReset(email.trim());
      setMessage(response.message);
      setMode("reset");
    } catch (err) {
      setError(err.message || "Could not send reset code");
    } finally {
      setLoading(false);
    }
  }

  async function handleResetPassword(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setMessage("");
    try {
      const response = await resetPassword(email.trim(), code.trim(), newPassword);
      setMessage(response.message);
      setPassword("");
      setCode("");
      setNewPassword("");
      setMode("login");
    } catch (err) {
      setError(err.message || "Password reset failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen px-6 py-10 auth-shell">
      <div className="scanline-overlay" />
      <div className="mx-auto max-w-5xl grid gap-8 lg:grid-cols-[1.2fr_0.8fr] items-stretch relative z-10">
        <section className="glass-card min-w-0 p-8 lg:p-10">
          <div className="flex items-center gap-3 mb-8">
            <ShieldCheck size={24} className="text-[var(--violet)]" />
            <div className="min-w-0">
              <div className="text-xs tracking-[0.25em] uppercase text-[var(--text-dim)]">Restricted Access</div>
              <h1 className="text-3xl font-semibold text-[var(--text)]">Automation Bug Hunting Admin</h1>
            </div>
          </div>
          <p className="max-w-xl text-sm text-slate-400 leading-6 break-words">
            Access to runs, bug signals, and route telemetry is locked behind the admin account. Password reset verification is sent to <span className="text-[var(--text)]">{DEFAULT_EMAIL}</span>.
          </p>

          <div className="mt-8 flex flex-wrap gap-2">
            {["login", "forgot", "reset"].map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => { setMode(item); setError(""); setMessage(""); }}
                className={`px-3.5 py-2 rounded-lg text-[11px] font-semibold tracking-[0.12em] uppercase border whitespace-nowrap ${
                  mode === item ? "border-[var(--violet)] bg-[rgba(63,114,175,0.12)] text-[var(--violet)]" : "border-[rgba(63,114,175,0.18)] text-[var(--text-dim)]"
                }`}
              >
                {item === "forgot" ? "Forgot Password" : item}
              </button>
            ))}
          </div>
        </section>

        <section className="glass-card min-w-0 p-6 lg:p-8">
          {mode === "login" && (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-dim)] mb-1.5">Admin Email</div>
                <label className="auth-field">
                  <span className="auth-field-icon">
                    <Mail size={14} />
                  </span>
                  <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" className="auth-input" required />
                </label>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-dim)] mb-1.5">Password</div>
                <label className="auth-field">
                  <span className="auth-field-icon">
                    <LockKeyhole size={14} />
                  </span>
                  <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" className="auth-input" required />
                </label>
              </div>
              <button type="submit" disabled={loading} className="auth-button">
                {loading ? "Signing In..." : "Open Console"}
              </button>
            </form>
          )}

          {mode === "forgot" && (
            <form onSubmit={handleForgotPassword} className="space-y-4">
              <div>
                <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-dim)] mb-1.5">Verification Email</div>
                <label className="auth-field">
                  <span className="auth-field-icon">
                    <Mail size={14} />
                  </span>
                  <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" className="auth-input" required />
                </label>
              </div>
              <button type="submit" disabled={loading} className="auth-button">
                {loading ? "Sending Code..." : "Send Verification Code"}
              </button>
            </form>
          )}

          {mode === "reset" && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              <div>
                <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-dim)] mb-1.5">Admin Email</div>
                <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" className="auth-input" required />
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-dim)] mb-1.5">Verification Code</div>
                <label className="auth-field">
                  <span className="auth-field-icon">
                    <KeyRound size={14} />
                  </span>
                  <input value={code} onChange={(e) => setCode(e.target.value)} type="text" className="auth-input" required />
                </label>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-dim)] mb-1.5">New Password</div>
                <input value={newPassword} onChange={(e) => setNewPassword(e.target.value)} type="password" className="auth-input" minLength={12} required />
              </div>
              <button type="submit" disabled={loading} className="auth-button">
                {loading ? "Updating Password..." : "Reset Password"}
              </button>
            </form>
          )}

          {message && <p className="mt-4 text-sm text-emerald-400">{message}</p>}
          {error && <p className="mt-4 text-sm text-red-400">{error}</p>}
        </section>
      </div>
    </div>
  );
}
