import { useEffect, useMemo, useState } from "react";
import "./App.css";

const statusOptions = [
  "Alle Tickets",
  "Offen",
  "In Bearbeitung",
  "Wartet auf Rückmeldung",
  "Gelöst",
];

const opaStatus = {
  "Alle Tickets": "Alle Probleme",
  "Offen": "Noch kaputt",
  "In Bearbeitung": "Wird repariert",
  "Wartet auf Rückmeldung": "Wartet auf dich",
  "Gelöst": "Wieder heile"
};

async function api(path, options = {}) {
  const query = options.query || '';
  const fullPath = query ? `${path}?${query}` : path;
  const response = await fetch(fullPath, {
    ...options,
    credentials: "include",
    headers: options.body instanceof FormData ? options.headers || {} : { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const data = await response.json().catch((err) => {
      console.error('Fehler beim Parsen der Antwort:', err);
      return {};
    });
  if (response.status === 401) {
    if (data.mfaRequired) {
      window.dispatchEvent(new CustomEvent("mfa_required"));
    } else if (path !== "/api/auth/me" && path !== "/api/auth/login") {
      window.dispatchEvent(new CustomEvent("session_expired"));
    }
  }
  if (!response.ok) {
    const error = new Error(data.error || "Die Anfrage konnte nicht verarbeitet werden.");
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

async function csrfToken() {
  await api("/api/csrf");
  return (
    document.cookie
      .split("; ")
      .find((cookie) => cookie.startsWith("csrf_token="))
      ?.split("=")[1] || ""
  );
}

function formatDate() {
  const now = new Date();
  const days = ["SONNTAG", "MONTAG", "DIENSTAG", "MITTWOCH", "DONNERSTAG", "FREITAG", "SAMSTAG"];
  const months = ["JANUAR", "FEBRUAR", "MÄRZ", "APRIL", "MAI", "JUNI", "JULI", "AUGUST", "SEPTEMBER", "OKTOBER", "NOVEMBER", "DEZEMBER"];
  return `${days[now.getDay()]}, ${now.getDate()}. ${months[now.getMonth()]} ${now.getFullYear()}`;
}

function getGreeting() {
  const hour = new Date().getHours();
  if (hour < 12) return "Guten Morgen";
  if (hour < 18) return "Guten Tag";
  return "Guten Abend";
}

function ChangePasswordModal({ onPasswordChanged }) {
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  async function submit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const currentPassword = String(form.get("currentPassword") || "");
    const newPassword = String(form.get("newPassword") || "");
    const confirmPassword = String(form.get("confirmPassword") || "");

    if (newPassword !== confirmPassword) {
      setError("Die Passwörter stimmen nicht überein.");
      return;
    }
    if (newPassword.length < 8) {
      setError("Das neue Passwort muss mindestens 8 Zeichen haben.");
      return;
    }

    try {
      const token = await csrfToken();
      const result = await api("/api/auth/change-password", {
        method: "POST",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setSuccess(true);
      setTimeout(() => onPasswordChanged(result.user), 1500);
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  return (
    <div className="modal-backdrop">
      <form className="modal" onSubmit={submit}>
        <div className="modal-header">
          <div>
            <span className="eyebrow">SICHERHEIT</span>
            <h2>Passwort ändern</h2>
            <p style={{ marginTop: "0.5rem", color: "var(--muted)" }}>
              Aus Sicherheitsgründen musst du dein Passwort bei der ersten Anmeldung ändern.
            </p>
          </div>
        </div>
        <label>
          Aktuelles Passwort
          <input name="currentPassword" type="password" required placeholder="Dein aktuelles Passwort" />
        </label>
        <label>
          Neues Passwort
          <input name="newPassword" type="password" required minLength="8" placeholder="Mindestens 8 Zeichen" />
        </label>
        <label>
          Neues Passwort bestätigen
          <input name="confirmPassword" type="password" required minLength="8" placeholder="Passwort wiederholen" />
        </label>
        {error && <p className="form-error">{error}</p>}
        {success && <p className="form-success">Passwort erfolgreich geändert! Weiterleitung...</p>}
        <label>
          Neues Passwort
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Leer lassen, um es nicht zu ändern" />
        </label>
        <button className="new-ticket auth-submit" type="submit" disabled={success}>
          Passwort ändern <span>→</span>
        </button>
      </form>
    </div>
  );
}

function ProfileModal({ onClose, onProfileChanged }) {
  const [name, setName] = useState("");
  const [avatar, setAvatar] = useState("");
  const [password, setPassword] = useState("");

  async function submit(event) {
    event.preventDefault();
    try {
      const token = await csrfToken();
      const result = await api("/api/profile", {
        method: "PATCH",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ name, avatar, ...(password ? { password } : {}) }),
      });
      onProfileChanged(result.user);
      onClose();
    } catch (err) {
    }
  }

  function handleFile(e) {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => setAvatar(ev.target.result);
      reader.readAsDataURL(file);
    }
  }

  return (
    <div className="modal-backdrop">
      <form className="modal" onSubmit={submit}>
        <div className="modal-header">
          <div>
            <span className="eyebrow">PROFIL</span>
            <h2>Profil bearbeiten</h2>
          </div>
          <button type="button" className="close-button" onClick={onClose}>×</button>
        </div>
        <label>
          Anzeigename
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Neuer Name" required />
        </label>
        <label>
          Profilbild
          <input type="file" accept="image/*" onChange={handleFile} />
        </label>
        <button className="new-ticket auth-submit" type="submit">
          Speichern <span>→</span>
        </button>
      </form>
    </div>
  );
}

function CreateUserModal({ onClose, onUserCreated }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("Kunde");
  const [successData, setSuccessData] = useState(null);

  async function submit(event) {
    event.preventDefault();
    try {
      const token = await csrfToken();
      const result = await api("/api/users", {
        method: "POST",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ name, email, password, role }),
      });
      setSuccessData(result.user);
      if (onUserCreated) onUserCreated(result.user);
    } catch (err) {
    }
  }

  if (successData) {
    return (
      <div className="modal-backdrop">
        <div className="modal">
          <div className="modal-header">
            <div>
              <span className="eyebrow">ERFOLG</span>
              <h2>Benutzer erstellt</h2>
            </div>
            <button type="button" className="close-button" onClick={onClose}>×</button>
          </div>
          <p>Bitte kopiere diese Zugangsdaten:</p>
          <pre style={{ background: "var(--surface)", padding: "1rem", borderRadius: "8px", marginTop: "1rem" }}>
            E-Mail: {email}{"\n"}Passwort: {password}
          </pre>
        </div>
      </div>
    );
  }

  return (
    <div className="modal-backdrop">
      <form className="modal" onSubmit={submit}>
        <div className="modal-header">
          <div>
            <span className="eyebrow">VERWALTUNG</span>
            <h2>Benutzer anlegen</h2>
          </div>
          <button type="button" className="close-button" onClick={onClose}>×</button>
        </div>
        <label>Name <input value={name} onChange={e => setName(e.target.value)} required /></label>
        <label>E-Mail <input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label>
        <label>Passwort <input type="text" value={password} onChange={e => setPassword(e.target.value)} required /></label>
        <label>Rolle
          <select value={role} onChange={e => setRole(e.target.value)}>
            <option>Kunde</option>
            <option>Mitarbeiter</option>
          </select>
        </label>
        <button className="new-ticket auth-submit" type="submit">Erstellen <span>→</span></button>
      </form>
    </div>
  );
}

function MfaLoginModal({ onVerified, onCancel }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const token = await csrfToken();
      const result = await api("/api/auth/totp/validate", {
        method: "POST",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ code }),
      });
      onVerified(result.user);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <form className="modal mfa-modal" onSubmit={submit}>
        <div className="modal-header">
          <div>
            <span className="eyebrow">SICHERHEIT</span>
            <h2>Zwei-Faktor-Anmeldung</h2>
          </div>
          {onCancel && (
            <button type="button" className="close-button" onClick={onCancel}>
              ×
            </button>
          )}
      <nav style={{ marginTop: "12px" }}>
        <button
          className={currentView === "settings" ? "nav-item active" : "nav-item"}
          onClick={() => setCurrentView("settings")}
        >
          <span>⚙</span> Einstellungen
        </button>
      </nav>
        </div>
        <p className="mfa-description">Bitte gib den 6-stelligen Code aus deiner Authenticator-App ein.</p>
        <label>
          Bestätigungscode
          <input
            autoFocus
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength="6"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="123456"
            required
            className="mfa-input"
          />
        </label>
        {error && <p className="form-error">{error}</p>}
        <button className="new-ticket auth-submit" type="submit" disabled={loading || code.length !== 6}>
          Bestätigen <span>→</span>
        </button>
      </form>
    </div>
  );
}

function MfaSetupModal({ onClose, onComplete }) {
  const [step, setStep] = useState("setup");
  const [secret, setSecret] = useState("");
  const [uri, setUri] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadSetup() {
      try {
        const token = await csrfToken();
        const result = await api("/api/auth/totp/setup", {
          method: "POST",
          headers: { "X-CSRF-Token": token },
        });
        setSecret(result.secret);
        setUri(result.uri);
      } catch (err) {
        setError(err.message);
      }
    }
    loadSetup();
  }, []);

  async function verify(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const token = await csrfToken();
      const result = await api("/api/auth/totp/verify", {
        method: "POST",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ code }),
      });
      setStep("success");
      setTimeout(() => onComplete(result.user), 1500);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal">
        <div className="modal-header">
          <div>
            <span className="eyebrow">SICHERHEIT</span>
            <h2>MFA einrichten</h2>
            <p style={{ marginTop: "0.5rem", color: "var(--muted)" }}>
              Schütze dein Konto mit einem zweiten Faktor.
            </p>
          </div>
          {!loading && step !== "success" && (
            <button type="button" className="close-button" onClick={onClose}>
              ×
            </button>
          )}
        </div>
        
        {step === "setup" && (
          <form onSubmit={verify}>
            <p style={{ marginBottom: "1rem" }}>
              Lade eine Authenticator-App (z. B. Google Authenticator) herunter und richte den Zugang mit diesem Schlüssel ein:
            </p>
            
            <label>
              Dein geheimer Schlüssel
              <input type="text" readOnly value={secret || "Lade..."} />
            </label>

            <a href={uri} style={{ display: "inline-block", marginBottom: "1rem", color: "var(--brand-coral)", textDecoration: "none", fontWeight: "600" }}>
              Oder direkt in der App öffnen ↗
            </a>

            <label>
              Bestätigungscode
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength="6"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
                required
              />
            </label>
            
            {error && <p className="form-error">{error}</p>}
            <button className="new-ticket auth-submit" type="submit" disabled={loading || code.length !== 6 || !secret}>
              MFA Aktivieren <span>✓</span>
            </button>
          </form>
        )}

        {step === "success" && (
          <div style={{ textAlign: "center", padding: "2rem 0" }}>
            <div style={{ fontSize: "3rem", color: "var(--brand-teal)", marginBottom: "1rem" }}>✓</div>
            <h3>Erfolgreich aktiviert!</h3>
            <p style={{ color: "var(--muted)" }}>Dein Konto ist nun besser geschützt.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function AuditLogView() {
  const [entries, setEntries] = useState([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    api(`/api/audit-log?page=${page}&limit=20`)
      .then(res => {
        if (!active) return;
        setEntries(res.entries);
        setTotalPages(res.totalPages);
        setLoading(false);
      })
      .catch(err => {
        if (!active) return;
        setError(err.message);
        setLoading(false);
      });
    return () => { active = false; };
  }, [page]);

  if (loading && entries.length === 0) return <div className="loading-state">Lade Protokoll...</div>;
  if (error) return <div className="error-state">{error}</div>;

  return (
    <section className="audit-log-panel">
      <div className="audit-log-header">
        <p>Protokoll aller sicherheitsrelevanten Systemereignisse. Diese Aufzeichnung ist revisionssicher.</p>
      </div>
      <div className="table-responsive">
        <table className="audit-table">
          <thead>
            <tr>
              <th>Zeitpunkt</th>
              <th>Benutzer</th>
              <th>Aktion</th>
              <th>Ziel</th>
              <th>Details</th>
              <th>IP Adresse</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan="6" className="empty-cell">Keine Einträge gefunden.</td>
              </tr>
            )}
            {entries.map(entry => (
              <tr key={entry.id}>
                <td className="time-cell">{new Date(entry.timestamp + "Z").toLocaleString("de-DE")}</td>
                <td>{entry.user_email || "System"}</td>
                <td><code className="action-code">{entry.action}</code></td>
                <td>{entry.target_type ? `${entry.target_type}:${entry.target_id}` : "-"}</td>
                <td className="details-cell">{entry.details || "-"}</td>
                <td className="ip-cell">{entry.ip_address || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pagination">
        <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Zurück</button>
        <span>Seite {page} von {totalPages || 1}</span>
        <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Weiter</button>
      </div>
    </section>
  );
}

function Login({ onLogin }) {
  const [error, setError] = useState(
    () => new URLSearchParams(window.location.search).get("auth_error") || "",
  );

  async function submit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const token = await csrfToken();
      const body = {
        email: String(form.get("email") || "").trim(),
        password: String(form.get("password") || ""),
      };
      const result = await api(`/api/auth/login`, {
        method: "POST",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify(body),
      });
      onLogin(result.user);
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-visual">
          <div className="auth-brand">
            {/* [TEMPLATE CUSTOMIZATION] Change "Ticket" and "System" to your own app name */}
            <span className="brand-logo"><span className="brand-ticket">Ticket</span><span className="brand-system">System</span></span>
          </div>
        <div className="auth-quote">
          <span>„</span>
          <h1>
            Einfacher und<br /><em>schneller</em> IT-Support.
          </h1>
          <p>Erstelle Tickets, verfolge den Status und finde Antworten in unserer Wissensdatenbank.</p>
        </div>
        <div className="auth-orbit orbit-one"></div>
        <div className="auth-orbit orbit-two"></div>
      </div>
      <main className="auth-card">
          <div className="mobile-brand">
            <span className="brand-logo"><span className="brand-ticket">Ticket</span><span className="brand-system">System</span></span>
          </div>
        <div className="auth-card-head">
          <span className="eyebrow">SUPPORT-PORTAL</span>
          <h2>Willkommen beim Support</h2>
          <p>Melde dich an, um auf deine Tickets zuzugreifen.</p>
        </div>
        <form onSubmit={submit} className="auth-form">
          <label>
            E-Mail Adresse
            <input
              name="email"
              type="email"
              required
              placeholder="z.B. user@example.com"
            />
          </label>
          <label>
            Dein Geheimwort (Passwort)
            <input
              name="password"
              type="password"
              required
              placeholder="Dein geheimes Wort"
            />
          </label>
          {error && <p className="form-error">{error}</p>}
          <button className="new-ticket auth-submit" type="submit">
            Lass mich rein <span>→</span>
          </button>
        </form>
      </main>
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);
  const [mfaPending, setMfaPending] = useState(false);
  const [isSetupMfaOpen, setIsSetupMfaOpen] = useState(false);
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [, setError] = useState("");
  const [activeStatus, setActiveStatus] = useState("Alle Tickets");
  const [activeCategory, setActiveCategory] = useState("Alle");
  const [activePriority, setActivePriority] = useState("Alle");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [comments, setComments] = useState([]);
  const [commentText, setCommentText] = useState("");
  const [replyMode, setReplyMode] = useState("public");
  const [commentsLoading, setCommentsLoading] = useState(false);  const [currentView, setCurrentView] = useState("dashboard");  const [darkMode, setDarkMode] = useState(
    () => localStorage.getItem("werkraum-theme") === "dark",
  );
  const [stats, setStats] = useState(null);
  const [teamMembers, setTeamMembers] = useState([]);
  const [articles, setArticles] = useState([]);
  const [isArticleModalOpen, setIsArticleModalOpen] = useState(false);
  const [editingArticle, setEditingArticle] = useState(null);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isCreateUserOpen, setIsCreateUserOpen] = useState(false);

  const isAdmin = user?.role === "Administrator";
  const isStaff = user?.role === "Administrator" || user?.role === "Mitarbeiter";

  useEffect(() => {
    const handleMfaRequired = () => setMfaPending(true);
    const handleSessionExpired = () => {
      setUser(null);
      setTickets([]);      setTeamMembers([]);
      setMfaPending(false);
    };

    window.addEventListener("mfa_required", handleMfaRequired);
    window.addEventListener("session_expired", handleSessionExpired);
    
    if (new URLSearchParams(window.location.search).get("mfa_required")) {
      setMfaPending(true);
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    api("/api/auth/me")
      .then((result) => {
        setUser(result.user);
        const filters = `status=${activeStatus}&category=${activeCategory}&priority=${activePriority}&search=${encodeURIComponent(search)}`;
        return api("/api/tickets", { query: filters });
      })
      .then((result) => {
        setTickets(result.tickets);
        if (result.tickets.length > 0) setSelectedId(result.tickets[0].id);
      })
.catch((err) => {
        console.error('Fehler beim Laden der Daten:', err);
        setError('Daten konnten nicht geladen werden.');
      })
      .finally(() => setLoading(false));
      
    return () => {
      window.removeEventListener("mfa_required", handleMfaRequired);
      window.removeEventListener("session_expired", handleSessionExpired);
    };
  }, []);

  useEffect(() => {
    if (isAdmin) {
      api("/api/stats").then(setStats).catch((err) => {
        console.error('Fehler beim Laden der Statistik:', err);
      });
      api("/api/users").then((r) => setTeamMembers(r.users)).catch((err) => {
        console.error('Fehler beim Laden der Team-Mitglieder:', err);
      });
    }
  }, [isAdmin]);

  async function login(nextUser) {
    if (!nextUser) return;
    setUser(nextUser);
    setMfaPending(false);
    const result = await api("/api/tickets");
    setTickets(result.tickets);
    if (result.tickets.length > 0) setSelectedId(result.tickets[0].id);
    if (nextUser.role === "Administrator") {
      api("/api/stats").then(setStats).catch((err) => {
        console.error('Fehler beim Laden der Statistik:', err);
      });
      api("/api/users").then((r) => setTeamMembers(r.users)).catch((err) => {
        console.error('Fehler beim Laden der Team-Mitglieder:', err);
      });
    }
  }
  async function logout() {
    try {
      const token = await csrfToken();
      await api("/api/auth/logout", {
        method: "POST",
        headers: { "X-CSRF-Token": token },
      });
    } finally {
      setUser(null);
      setTickets([]);
      setComments([]);
      setIsDetailOpen(false);
      setStats(null);
      setTeamMembers([]);
    }
  }
  async function openTicket(ticketId) {
    setSelectedId(ticketId);
    setIsDetailOpen(true);
    setCommentsLoading(true);
    try {
      const result = await api(`/api/tickets/${ticketId}/comments`);
      setComments(result.comments);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCommentsLoading(false);
    }
  }
  async function addComment(event) {
    event.preventDefault();
    if (!commentText.trim() || !selectedTicket) return;
    try {
      const token = await csrfToken();
      const result = await api(`/api/tickets/${selectedTicket.id}/comments`, {
        method: "POST",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ body: commentText, internal: replyMode === "internal" }),
      });
      setComments((current) => [...current, result.comment]);
      setCommentText("");
      setTickets((current) =>
        current.map((ticket) =>
          ticket.id === selectedTicket.id
            ? {
                ...ticket,
                status:
                  ticket.status === "Offen" ? "In Bearbeitung" : ticket.status,
                updated: "gerade eben",
              }
            : ticket,
        ),
      );
    } catch (requestError) {
      setError(requestError.message);
    }
  }
  async function updatePriority(newPriority) {
    if (!selectedTicket || !isStaff) return;
    try {
      const token = await csrfToken();
      await api(`/api/tickets/${selectedTicket.id}/priority`, {
        method: "PATCH",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ priority: newPriority }),
      });
      setTickets((current) =>
        current.map((ticket) =>
          ticket.id === selectedTicket.id ? { ...ticket, priority: newPriority } : ticket
        )
      );
    } catch (requestError) {
      setError(requestError.message);
    }
  }
  
  async function setCustomerReplyPermission(allowed) {
    if (!selectedTicket || !isAdmin) return;
    try {
      const token = await csrfToken();
      await api(`/api/tickets/${selectedTicket.id}/reply-permission`, {
        method: "PATCH",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ customerCanReply: allowed }),
      });
      setTickets((current) =>
        current.map((ticket) =>
          ticket.id === selectedTicket.id
            ? { ...ticket, customerCanReply: allowed }
            : ticket,
        ),
      );
    } catch (requestError) {
      setError(requestError.message);
    }
  }
  const visibleTickets = useMemo(
    () =>
      tickets.filter((ticket) => {
        const matchesStatus =
          activeStatus === "Alle Tickets" || ticket.status === activeStatus;
        const matchesCategory =
          activeCategory === "Alle" || ticket.category === activeCategory;
        const matchesPriority =
          activePriority === "Alle" || ticket.priority === activePriority;
        const query = search.toLowerCase();
        return (
          matchesStatus &&
          matchesCategory &&
          matchesPriority &&
          (!query ||
            `${ticket.title} ${ticket.id} ${ticket.requester}`
              .toLowerCase()
              .includes(query))
        );
      }),
    [tickets, activeStatus, activeCategory, activePriority, search],
  );
  const selectedTicket =
    tickets.find((ticket) => ticket.id === selectedId) || tickets[0];
  const openCount = tickets.filter(
    (ticket) => ticket.status === "Offen",
  ).length;
  const inProgressCount = tickets.filter(
    (ticket) => ticket.status === "In Bearbeitung",
  ).length;
  function toggleDarkMode() {
    setDarkMode((current) => {
      const next = !current;
      localStorage.setItem("werkraum-theme", next ? "dark" : "light");
      return next;
    });
  }

  async function updateStatus(status) {
    try {
      const token = await csrfToken();
      await api(`/api/tickets/${selectedTicket.id}/status`, {
        method: "PATCH",
        headers: { "X-CSRF-Token": token },
        body: JSON.stringify({ status }),
      });
      setTickets((current) =>
        current.map((ticket) =>
          ticket.id === selectedTicket.id
            ? { ...ticket, status, updated: "gerade eben" }
            : ticket,
        ),
      );
    } catch (requestError) {
      setError(requestError.message);
    }
  }
  async function createTicket(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const token = await csrfToken();
      const result = await api("/api/tickets", {
        method: "POST",
        headers: { "X-CSRF-Token": token },
        body: form,
      });
      setTickets((current) => [result.ticket, ...current]);
      setActiveStatus("Alle Tickets");
      setActiveCategory("Alle");
      setActivePriority("Alle");
      setIsCreateOpen(false);
      await openTicket(result.ticket.id);
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  if (loading)
    return (
      <div className="loading-screen">Ticket Support wird geladen ...</div>
    );
  
  if (mfaPending) return <MfaLoginModal onVerified={login} onCancel={() => setMfaPending(false)} />;
  if (!user) return <Login onLogin={login} />;

  if (user.mustChangePassword) {
    return (
      <ChangePasswordModal
        onPasswordChanged={(updatedUser) => setUser(updatedUser)}
      />
    );
  }

  async function disableSelfMfa() {
    try {
      const token = await csrfToken();
      const result = await api("/api/auth/totp", { method: "DELETE", headers: { "X-CSRF-Token": token } });
      setUser(result.user);
    } catch (requestError) {
      alert("Fehler beim Deaktivieren der 2FA: " + requestError.message);
    }
  }

  if (["knowledge", "team", "settings", "audit"].includes(currentView))
    return (
      <>
        <SimpleWorkspace
          view={currentView}
          user={user}
          isAdmin={isAdmin}
          isStaff={isStaff}
          tickets={tickets}
          teamMembers={teamMembers}
          articles={articles}
          darkMode={darkMode}
          onToggleDarkMode={toggleDarkMode}
          onNavigate={setCurrentView}
          onLogout={logout}
          onOpenMfaSetup={() => setIsSetupMfaOpen(true)}
          onDisableMfa={disableSelfMfa}
          onOpenProfile={() => setIsProfileOpen(true)}
          onOpenCreateUser={() => setIsCreateUserOpen(true)}
          onOpenCreateArticle={() => { setEditingArticle(null); setIsArticleModalOpen(true); }}
          onEditArticle={(a) => { setEditingArticle(a); setIsArticleModalOpen(true); }}
          onDeleteArticle={async (id) => {
            if (!confirm('Artikel wirklich löschen?')) return;
            try {
              const token = await csrfToken();
              await api(`/api/articles/${id}`, { method: 'DELETE', headers: { 'X-CSRF-Token': token } });
              setArticles(prev => prev.filter(a => a.id !== id));
            } catch (err) {
              alert(err.message);
            }
          }}
        />
        {isSetupMfaOpen && (
          <MfaSetupModal 
            onClose={() => setIsSetupMfaOpen(false)} 
            onComplete={(updatedUser) => { setUser(updatedUser); setIsSetupMfaOpen(false); }} 
          />
        )}
        {isProfileOpen && (
          <ProfileModal
            onClose={() => setIsProfileOpen(false)}
            onProfileChanged={(u) => setUser(u)}
          />
        )}
        {isCreateUserOpen && (
          <CreateUserModal
            onClose={() => setIsCreateUserOpen(false)}
            onUserCreated={(u) => setTeamMembers(prev => [...prev, u])}
          />
        )}
        {isArticleModalOpen && (
          <ArticleModal
            article={editingArticle}
            onClose={() => setIsArticleModalOpen(false)}
            onSave={(savedArticle) => {
              if (editingArticle) {
                setArticles(prev => prev.map(a => a.id === savedArticle.id ? savedArticle : a));
              } else {
                setArticles(prev => [...prev, savedArticle]);
              }
              setIsArticleModalOpen(false);
            }}
          />
        )}

      </>
    );

  return (
    <div className={`app-shell ${darkMode ? "dark-mode" : ""}`}>
      <Sidebar
        user={user}
        isAdmin={isAdmin}
        isStaff={isStaff}
        currentView={currentView}
        setCurrentView={setCurrentView}
        tickets={tickets}
        logout={logout}
        onHelp={() => setIsCreateOpen(true)}
      />
      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">{formatDate()}</p>
            <h1>
              {getGreeting()}, {user.name.split(" ")[0]} <span>✦</span>
            </h1>
            <p className="subtitle">
              {isAdmin
                ? "Aktuelle Übersicht über alle laufenden Tickets und Aufgaben."
                : "Übersicht über alle deine Tickets und deren Status."}
            </p>
          </div>
          <div className="top-actions">
            <button
              className="new-ticket"
              onClick={() => setIsCreateOpen(true)}
            >
              <span>🆘</span> HILFE RUFEN!
            </button>
          </div>
        </header>

        {isAdmin && (
          <section className="stats-grid">
            <article className="stat-card">
              <div className="stat-icon coral">🚨</div>
              <div>
                <span>🚨 Offene Tickets</span>
                <strong>{stats?.openCount ?? openCount}</strong>
                <StatsComparison current={stats?.openThisMonth} previous={stats?.openLastMonth} />
              </div>
              <div className="spark coral-spark"></div>
            </article>
            <article className="stat-card">
              <div className="stat-icon blue">🛠️</div>
              <div>
                <span>🛠️ In Bearbeitung</span>
                <strong>{stats?.inProgressCount ?? inProgressCount}</strong>
                <small className="trend neutral">
                  {stats?.totalTickets ?? tickets.length} <em>Tickets gesamt</em>
                </small>
              </div>
              <div className="spark blue-spark"></div>
            </article>
            
            <article className="stat-card">
              <div className="stat-icon violet">⏱️</div>
              <div>
                <span>⏱️ Ø Lösungszeit</span>
                <strong>
                  {stats?.avgResolutionHours ?? 0}{" "}
                  <small>Std.</small>
                </strong>
                <StatsComparison current={stats?.solvedThisMonth} previous={stats?.solvedLastMonth} label="gelöst" />
              </div>
              <div className="spark violet-spark"></div>
            </article>
          </section>
        )}

        {!isAdmin && (
          <section className="stats-grid">
            <article className="stat-card">
              <div className="stat-icon coral">🚨</div>
              <div>
                <span>🚨 Offene Anfragen</span>
                <strong>{openCount}</strong>
              </div>
            </article>
            <article className="stat-card">
              <div className="stat-icon blue">🛠️</div>
              <div>
                <span>🛠️ In Bearbeitung</span>
                <strong>{inProgressCount}</strong>
              </div>
            </article>
            <article className="stat-card">
              <div className="stat-icon violet">📝</div>
              <div>
                <span>📝 Gesamt</span>
                <strong>{tickets.length}</strong>
              </div>
            </article>
          </section>
        )}

        <section className="ticket-section">
          <div className="section-heading">
            <div>
              <h2>{isStaff ? "Aktuelle Tickets" : "Meine Problemchen"}</h2>
              <p>
                {isStaff
                  ? "Alle Anfragen aus deinem Service Desk"
                  : "Hier siehst du, was noch repariert werden muss. Ich drück dir die Daumen!"}
              </p>
            </div>
            <button
              className="outline-button"
              onClick={() => {
                setActiveStatus("Alle Tickets");
                setActiveCategory("Alle");
                setActivePriority("Alle");
                setSearch("");
              }}
            >
              Alle anzeigen <span>→</span>
            </button>
          </div>
          <div className="ticket-toolbar">
            <div className="tabs">
              {statusOptions.map((status) => (
                <button
                  key={status}
                  className={activeStatus === status ? "tab active" : "tab"}
                  onClick={() => setActiveStatus(status)}
                >
                  {opaStatus[status]}
                  {status === "Offen" && <b>{openCount}</b>}
                </button>
              ))}
            </div>
            <div className="tools">
              <label className="search">
                <span>⌕</span>
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Wonach suchst du?..."
                />
              </label>
              <select
                value={activeCategory}
                onChange={(event) => setActiveCategory(event.target.value)}
                aria-label="Kategorie filtern"
              >
                <option>Alle</option>
                <option>Hardware</option>
                <option>Software</option>
                <option>Sonstiges</option>
              </select>
              <select
                value={activePriority}
                onChange={(event) => setActivePriority(event.target.value)}
                aria-label="Priorität filtern"
              >
                <option>Alle</option>
                <option>Hoch</option>
                <option>Mittel</option>
                <option>Niedrig</option>
              </select>
              <button
                className="filter-button"
                onClick={() => {
                  setActiveStatus("Alle Tickets");
                  setActiveCategory("Alle");
                  setActivePriority("Alle");
                  setSearch("");
                }}
              >
                Filter zurücksetzen
              </button>
            </div>
          </div>
          <div className="ticket-layout">
            <div className="ticket-list">
              {visibleTickets.map((ticket) => (
                <button
                  key={ticket.id}
                  className={
                    selectedTicket?.id === ticket.id
                      ? "ticket-row selected"
                      : "ticket-row"
                  }
                  onClick={() => {
                    openTicket(ticket.id);
                  }}
                >
                  <span className={`avatar ${ticket.tone}`}>
                    {ticket.initials}
                  </span>
                  <span className="ticket-summary">
                    <b>{ticket.title}</b>
                    <small>
                      {ticket.id}{isStaff ? ` · ${ticket.requester}` : ""}
                    </small>
                  </span>
                  <span className="ticket-meta">
                    <strong
                      className={`priority ${ticket.priority.toLowerCase()}`}
                    >
                      {ticket.priority === "Hoch" ? "SEHR WICHTIG" : ticket.priority === "Mittel" ? "Geht so" : "Unwichtig"}
                    </strong>
                    <span
                      className={`status-dot ${ticket.status.toLowerCase().replaceAll(" ", "-")}`}
                    >
                      {opaStatus[ticket.status] || ticket.status}
                    </span>
                  </span>
                  <span className="row-time">{ticket.updated}</span>
                  <span className="row-arrow">›</span>
                </button>
              ))}
              {visibleTickets.length === 0 && (
                <div className="empty-state">
                  Keine Tickets für diese Auswahl.
                </div>
              )}
            </div>
            <TicketDetail
              ticket={selectedTicket}
              canManageStatus={isStaff}
              updateStatus={updateStatus}
              onOpen={() => selectedTicket && openTicket(selectedTicket.id)}
              isAdmin={isStaff}
            />
          </div>
        </section>
        <footer>
          <span>Ticket Support · Service Desk</span>
          <span>
            Systemstatus <b className="online-dot"></b> Alle Systeme
            funktionsfähig
          </span>
        </footer>
      </main>
      {isCreateOpen && (
        <div
          className="modal-backdrop"
          onMouseDown={(event) =>
            event.target === event.currentTarget && setIsCreateOpen(false)
          }
        >
          <form className="modal" onSubmit={createTicket}>
            <div className="modal-header">
              <div>
                <span className="eyebrow">NEUE ANFRAGE</span>
                <h2>Ticket erstellen</h2>
              </div>
              <button
                type="button"
                className="close-button"
                onClick={() => setIsCreateOpen(false)}
              >
                ×
              </button>
            </div>
            <label>
              Betreff
              <input name="title" required placeholder="Worum geht es?" />
            </label>
            <label>
              Beschreibung <span className="required-label">Pflichtfeld</span>
              <textarea
                name="description"
                required
                minLength="15"
                rows="4"
                placeholder="Beschreibe das Problem so genau wie möglich (mind. 15 Zeichen)..."
              ></textarea>
            </label>
            <div className="form-grid">
              <label>
                Kategorie
                <select name="category" id="ticket-category-select" onChange={(e) => { const el = document.getElementById("cat-hint"); el.textContent = { Hardware: "🖥️ PC, Drucker oder sonstige Technik funktioniert nicht.", Software: "💻 Du brauchst Hilfe bei einem Programm, einer App oder einem Zugang.", Sonstiges: "📋 Alles andere, was nicht in die anderen Bereiche passt." }[e.target.value] || ""; }}>
                  <option value="Hardware">Hardware (PC, Technik)</option>
                  <option value="Software">Software (Programme, Zugänge)</option>
                  <option value="Sonstiges">Sonstiges</option>
                </select>
                <small id="cat-hint" style={{ display: "block", color: "var(--muted)", marginTop: "5px", fontSize: "11px" }}>🖥️ PC, Drucker oder sonstige Technik funktioniert nicht.</small>
              </label>
              <input type="hidden" name="priority" value="Mittel" />
            </div>

            <div className="form-grid" style={{ marginTop: '1rem' }}>
              <label>
                Bilder / Screenshots (max. 5)
                <input type="file" name="attachments" multiple accept="image/*" style={{ marginTop: '5px' }} />
              </label>
            </div>
            <button className="new-ticket" type="submit">
              Ticket erstellen <span>→</span>
            </button>
          </form>
        </div>
      )}
      {isDetailOpen && selectedTicket && (
        <div
          className="modal-backdrop"
          onMouseDown={(event) =>
            event.target === event.currentTarget && setIsDetailOpen(false)
          }
        >
          <div className="detail-modal">
            <div className="detail-modal-head">
              <div>
                <span className="detail-label">TICKET {selectedTicket.id}</span>
                <h2>{selectedTicket.title}</h2>
              </div>
              <button
                className="close-button"
                onClick={() => setIsDetailOpen(false)}
              >
                ×
              </button>
            </div>
            <div className="detail-modal-grid">
              <div>
                {isStaff && (
                  <div className="detail-person">
                    <span className={`avatar ${selectedTicket.tone}`}>
                      {selectedTicket.initials}
                    </span>
                    <div>
                      <b>{selectedTicket.requester}</b>
                      <small>{selectedTicket.team}</small>
                    </div>
                  </div>
                )}
                <p className="full-description">{selectedTicket.description}</p>
                {selectedTicket.attachments && selectedTicket.attachments.length > 0 && (
                  <div className="ticket-attachments" style={{ marginTop: '1rem', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                    {selectedTicket.attachments.map((att, i) => (
                      <a key={i} href={"/uploads/" + att.filename} target="_blank" rel="noopener noreferrer">
                        <img src={"/uploads/" + att.filename} alt={att.original_name} style={{ width: '100px', height: '100px', objectFit: 'cover', borderRadius: '4px', border: '1px solid var(--border)' }} />
                      </a>
                    ))}
                  </div>
                )}
              </div>
              <div className="detail-modal-meta">
                <div>
                  <span>KATEGORIE</span>
                  <b>{selectedTicket.category}</b>
                </div>
                <div>
                  <span>PRIORITÄT</span>
                  {isStaff ? (
                    <select
                      value={selectedTicket.priority}
                      onChange={(event) => updatePriority(event.target.value)}
                      className="priority-select"
                    >
                      <option value="Niedrig">🟢 Niedrig</option>
                      <option value="Mittel">🟡 Mittel</option>
                      <option value="Hoch">🔴 Hoch</option>
                    </select>
                  ) : (
                    <b className={`priority ${selectedTicket.priority?.toLowerCase()}`}>{selectedTicket.priority}</b>
                  )}
                </div>
                <div>
                  <span>STATUS</span>
                  {isStaff ? (
                    <select
                      value={selectedTicket.status}
                      onChange={(event) => updateStatus(event.target.value)}
                    >
                      {statusOptions.slice(1).map((status) => (
                        <option key={status}>{status}</option>
                      ))}
                    </select>
                  ) : (
                    <b>{selectedTicket.status}</b>
                  )}
                </div>
              </div>
            </div>
            <section
              className="conversation"
              aria-labelledby="conversation-title"
            >
              <div className="conversation-heading">
                <div>
                  <span className="detail-label">VERLAUF</span>
                  <h3 id="conversation-title">Kommunikation</h3>
                </div>
                <span className="conversation-count">
                  {comments.length}{" "}
                  {comments.length === 1 ? "Antwort" : "Antworten"}
                </span>
              </div>
              {commentsLoading ? (
                <p className="conversation-empty">Verlauf wird geladen ...</p>
              ) : comments.length === 0 ? (
                <p className="conversation-empty">
                  {isStaff
                    ? "Noch keine Antworten. Starte die Kommunikation mit dem Kunden."
                    : "Noch keine Antworten vom Support."}
                </p>
              ) : (
                <div className="comment-list">
                  {comments.map((comment) => (
                    <article
                      className={`comment ${comment.role === "Mitarbeiter" ? "staff" : ""} ${comment.isInternal ? "internal-note" : ""}`}
                      key={comment.id}
                    >
                      <span
                        className={`avatar ${comment.role === "Mitarbeiter" ? "teal" : "coral"}`}
                      >
                        {comment.isInternal ? "🔒" : comment.initials}
                      </span>
                      <div>
                        <div className="comment-meta">
                          <b>{isStaff ? comment.author : (comment.role === "Mitarbeiter" ? "IT-Support" : "Du")}</b>
                          <span>
                            {comment.isInternal ? "Interne Notiz" : (comment.role === "Mitarbeiter" ? "IT-Support" : "Kunde")} · {comment.createdAt}
                          </span>
                        </div>
                        <p>{comment.body}</p>
                      </div>
                    </article>
                  ))}
                </div>
              )}
              {isStaff && (
                <>
                  <label className="reply-permission">
                    <input
                      type="checkbox"
                      checked={selectedTicket.customerCanReply}
                      onChange={(event) =>
                        setCustomerReplyPermission(event.target.checked)
                      }
                    />
                    <span>
                      <b>Kunde darf antworten</b>
                      <small>
                        Der Kunde erhält ein Antwortfeld in diesem Ticket.
                      </small>
                    </span>
                  </label>
                  <div className="reply-tabs">
                    <button type="button" className={replyMode === "public" ? "reply-tab active" : "reply-tab"} onClick={() => setReplyMode("public")}>💬 Kundenantwort</button>
                    <button type="button" className={replyMode === "internal" ? "reply-tab active" : "reply-tab"} onClick={() => setReplyMode("internal")}>🔒 Interne Notiz</button>
                  </div>
                  <form className={replyMode === "internal" ? "reply-form internal-note" : "reply-form"} onSubmit={addComment}>
                    <input type="hidden" name="internal" value={replyMode === "internal" ? "1" : "0"} />
                    <textarea
                      value={commentText}
                      onChange={(event) => setCommentText(event.target.value)}
                      minLength="2"
                      maxLength="5000"
                      required
                      rows="3"
                      placeholder={replyMode === "internal" ? "Interne Notiz (für Kunden nicht sichtbar) ..." : "Antwort für den Kunden schreiben ..."}
                    ></textarea>
                    <div className="reply-actions">
                      <small>{replyMode === "internal" ? "🔒 Nur für das Team sichtbar" : "✉️ Wird dem Kunden angezeigt"}</small>
                      <button
                        className="new-ticket"
                        type="submit"
                        disabled={!commentText.trim()}
                      >
                        {replyMode === "internal" ? "Notiz speichern" : "Antwort senden"} <span>→</span>
                      </button>
                    </div>
                  </form>
                </>
              )}
              {!isStaff &&
                selectedTicket.customerCanReply && (
                  <form className="reply-form" onSubmit={addComment}>
                    <textarea
                      value={commentText}
                      onChange={(event) => setCommentText(event.target.value)}
                      minLength="2"
                      maxLength="5000"
                      required
                      rows="3"
                      placeholder="Antwort an den IT-Support schreiben ..."
                    ></textarea>
                    <div className="reply-actions">
                      <small>Antwort an den IT-Support</small>
                      <button
                        className="new-ticket"
                        type="submit"
                        disabled={!commentText.trim()}
                      >
                        Antwort senden <span>→</span>
                      </button>
                    </div>
                  </form>
                )}
              {!isStaff &&
                !selectedTicket.customerCanReply && (
                  <p className="reply-locked">
                    Antworten sind für dieses Ticket noch nicht freigegeben.
                  </p>
                )}
            </section>
            {selectedTicket.status !== 'Gelöst' && (
              <button
                className="detail-action"
                onClick={() => updateStatus("Gelöst")}
              >
                Ticket als gelöst markieren <span>✓</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StatsComparison({ current, previous, label }) {
  if (current == null || previous == null) return null;
  if (previous === 0 && current === 0) return <small className="trend neutral">— <em>keine Daten</em></small>;
  const diff = previous === 0 ? 100 : Math.round(((current - previous) / previous) * 100);
  const direction = diff > 0 ? "up" : diff < 0 ? "down" : "neutral";
  const arrow = diff > 0 ? "↗" : diff < 0 ? "↘" : "→";
  return (
    <small className={`trend ${direction}`}>
      {arrow} {Math.abs(diff)}% <em>vs. letzter Monat{label ? ` (${label})` : ""}</em>
    </small>
  );
}

function Sidebar({ user, isAdmin, isStaff, currentView, setCurrentView, tickets, logout, onHelp }) {
  return (
    <aside className="sidebar">
        <div className="brand"><span className="brand-logo"><span className="brand-ticket">Ticket</span><span className="brand-system">System</span></span></div>
      <div className="workspace-label">ARBEITSBEREICH</div>
      <nav>
        <button
          className={
            currentView === "dashboard" ? "nav-item active" : "nav-item"
          }
          onClick={() => setCurrentView("dashboard")}
        >
          <span>▦</span> {isStaff ? "Übersicht" : "Meine Tickets"} <strong>{tickets.length}</strong>
        </button>
        
        <button
          className="nav-item"
          onClick={() => setCurrentView("knowledge")}
        >
          <span>⌁</span> Wissensdatenbank
        </button>
      </nav>
      {isAdmin && (
        <>
          <div className="workspace-label section-label">VERWALTUNG</div>
          <nav>
            <button className="nav-item" onClick={() => setCurrentView("team")}>
              <span>♙</span> Mitarbeitende
            </button>
            <button
              className={currentView === "audit" ? "nav-item active" : "nav-item"}
              onClick={() => setCurrentView("audit")}
            >
              <span>≡</span> Protokoll
            </button>
          </nav>
        </>
      )}
      <nav style={{ marginTop: "12px" }}>
        <button
          className={currentView === "settings" ? "nav-item active" : "nav-item"}
          onClick={() => setCurrentView("settings")}
        >
          <span>⚙</span> Einstellungen
        </button>
      </nav>
      <div className="sidebar-bottom">
        <div className="help-card" onClick={onHelp}>
    <span className="help-icon">?</span>
    <div>
      <b>Brauchst du Hilfe?</b>
      <small>Erstelle ein neues Ticket.</small>
    </div>
  </div>
        <div className="user-mini">
          {user.avatar ? (
            <img src={user.avatar} alt="" className="avatar-img" />
          ) : (
            <span className={`avatar ${user.tone || "teal"}`}>{user.initials}</span>
          )}
          <div>
            <b>{user.name}</b>
            <small>{user.role}</small>
          </div>
          <button
            className="logout-button"
            onClick={logout}
            aria-label="Abmelden"
            title="Abmelden"
          >
            ↪ <span>Abmelden</span>
          </button>
        </div>
      </div>
    </aside>
  );
}

function TicketDetail({ ticket, canManageStatus, updateStatus, onOpen, isAdmin }) {
  if (!ticket)
    return (
      <aside className="ticket-detail empty-detail">
        <h3>Noch keine Tickets</h3>
        <p className="detail-description">
          Erstelle deine erste Anfrage, damit sie hier angezeigt wird.
        </p>
      </aside>
    );
  return (
    <aside className="ticket-detail">
      <div className="detail-top">
        <span className="detail-label">TICKET {ticket.id}</span>
        <button className="more" onClick={onOpen}>
          Öffnen ↗
        </button>
      </div>
      <h3>{ticket.title}</h3>
      <p className="detail-description">{ticket.description}</p>
      {isAdmin && (
        <div className="detail-person">
          <span className={`avatar ${ticket.tone}`}>{ticket.initials}</span>
          <div>
            <b>{ticket.requester}</b>
            <small>{ticket.team}</small>
          </div>
        </div>
      )}
      <div className="detail-divider"></div>
      <div className="detail-fields">
        <div>
          <span>KATEGORIE</span>
          <b>{ticket.category}</b>
        </div>
        <div>
          <span>PRIORITÄT</span>
          <b className={`priority ${ticket.priority.toLowerCase()}`}>
            {ticket.priority}
          </b>
        </div>
      </div>
      <div className="status-control">
        <span>STATUS</span>
        {canManageStatus ? (
          <select
            value={ticket.status}
            onChange={(event) => updateStatus(event.target.value)}
          >
            {statusOptions.slice(1).map((status) => (
              <option key={status}>{status}</option>
            ))}
          </select>
        ) : (
          <span className="customer-status">{ticket.status}</span>
        )}
      </div>
      {ticket.status !== 'Gelöst' && (
        <button
          className="detail-action"
          onClick={() => updateStatus("Gelöst")}
        >
          Ticket als gelöst markieren <span>✓</span>
        </button>
      )}
    </aside>
  );
}

function SimpleWorkspace({ view, user, isAdmin, isStaff, tickets, teamMembers, articles, darkMode, onToggleDarkMode, onNavigate, onLogout, onOpenMfaSetup, onDisableMfa, onOpenProfile, onOpenCreateUser, onOpenCreateArticle, onEditArticle, onDeleteArticle }) {
  const [query, setQuery] = useState("");
  
  const titles = {
    knowledge: [
      "📚 Wissensdatenbank",
      "Schnelle Antworten für wiederkehrende IT-Fragen.",
    ],
    team: [
      "👥 Mitarbeitende",
      "Teams, Rollen und aktueller Erreichbarkeitsstatus.",
    ],
    audit: [
      "🛡️ Protokoll",
      "Sicherheitsrelevante Ereignisse nachvollziehen.",
    ],
    settings: [
      "⚙️ Einstellungen",
      "Dein Arbeitsbereich und persönliche Präferenzen.",
    ],
  };
  return (
    <div className={`app-shell ${darkMode ? "dark-mode" : ""}`}>
      <aside className="sidebar">
        <div className="brand"><span className="brand-logo"><span className="brand-ticket">Ticket</span><span className="brand-system">System</span></span></div>
        <div className="workspace-label">ARBEITSBEREICH</div>
        <nav>
          <button className="nav-item" onClick={() => onNavigate("dashboard")}>
            <span>▦</span> {isStaff ? "Übersicht" : "Meine Tickets"} <strong>{tickets.length}</strong>
          </button>
          <button
            className={view === "knowledge" ? "nav-item active" : "nav-item"}
            onClick={() => onNavigate("knowledge")}
          >
            <span>⌁</span> Wissensdatenbank
          </button>
        </nav>
        {isAdmin && (
          <>
            <div className="workspace-label section-label">VERWALTUNG</div>
            <nav>
              <button
                className={view === "team" ? "nav-item active" : "nav-item"}
                onClick={() => onNavigate("team")}
              >
                <span>♙</span> Mitarbeitende
              </button>
              <button
                className={view === "audit" ? "nav-item active" : "nav-item"}
                onClick={() => onNavigate("audit")}
              >
                <span>≡</span> Protokoll
              </button>
              <button
                className={view === "settings" ? "nav-item active" : "nav-item"}
                onClick={() => onNavigate("settings")}
              >
                <span>⚙</span> Einstellungen
              </button>
            </nav>
          </>
        )}
        <div className="sidebar-bottom">
          <div className="user-mini">
            {user.avatar ? (
              <img src={user.avatar} alt="" className="avatar-img" />
            ) : (
              <span className={`avatar ${user.tone || "teal"}`}>{user.initials}</span>
            )}
            <div>
              <b>{user.name}</b>
              <small>{user.role}</small>
            </div>
            <button
              className="logout-button"
              onClick={onLogout}
              aria-label="Abmelden"
            >
              ↪ <span>Abmelden</span>
            </button>
          </div>
        </div>
      </aside>
      <main className="main-content simple-page">
        <header className="topbar">
          <div>
            <p className="eyebrow">{new Date().toLocaleDateString('de-DE', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</p>
            <h1>{titles[view][0]}</h1>
            <p className="subtitle">{titles[view][1]}</p>
          </div>
          {view === "knowledge" && (
          <section className="people-list">
            {(isAdmin || isStaff) && (
              <div className="team-actions" style={{ marginBottom: "1rem" }}>
                <button className="new-ticket" onClick={onOpenCreateArticle}>+ Artikel erstellen</button>
              </div>
            )}
          </section>
        )}
        {view === "knowledge" && (
            <label className="search simple-search">
              <span>⌕</span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Artikel durchsuchen..."
              />
            </label>
          )}
        </header>
        {view === "knowledge" && (
          <section className="simple-grid">
            {articles
              .filter((article) =>
                `${article.title} ${article.category} ${article.content}`
                  .toLowerCase()
                  .includes(query.toLowerCase()),
              )
              .map((article) => (
                <article className="info-card" key={article.id}>
                  <span className="article-icon">✦</span>
                  <span className="card-kicker">{article.category}</span>
                  <h2>{article.title}</h2>
                  <p>{article.content}</p>
                  <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                    {(isAdmin || isStaff) && (
                      <>
                        <button className="outline-button" style={{ padding: '4px 8px', fontSize: '11px' }} onClick={() => onEditArticle(article)}>Bearbeiten</button>
                        <button className="outline-button" style={{ padding: '4px 8px', fontSize: '11px', color: 'var(--brand-coral)', borderColor: 'var(--brand-coral)' }} onClick={() => onDeleteArticle(article.id)}>Löschen</button>
                      </>
                    )}
                  </div>
                </article>
              ))}
          </section>
        )}
        {view === "team" && isAdmin && (
          <section className="people-list">
            <div className="team-actions" style={{ marginBottom: "1rem" }}>
              <button className="new-ticket" onClick={onOpenCreateUser}>+ Benutzer anlegen</button>
            </div>
            {teamMembers.length === 0 && (
              <div className="empty-state">Keine Mitarbeitenden gefunden.</div>
            )}
            {teamMembers.map((person) => (
              <article className="person-row" key={person.id}>
                <span className={`avatar ${person.tone}`}>
                  {person.initials}
                </span>
                <div>
                  <b>{person.name}</b>
                  <small>
                    {person.role} · {person.email}
                  </small>
                </div>
                <small>Seit {new Date(person.createdAt).toLocaleDateString("de-DE")}</small>
              </article>
            ))}
          </section>
        )}
        {view === "team" && !isAdmin && (
          <section className="people-list">
            <div className="empty-state">Keine Berechtigung für diese Ansicht.</div>
          </section>
        )}
        {view === "audit" && isAdmin && (
          <AuditLogView />
        )}
        {view === "audit" && !isAdmin && (
          <section className="people-list">
            <div className="empty-state">Keine Berechtigung für diese Ansicht.</div>
          </section>
        )}
        {view === "settings" && (
          <section className="settings-panel">
            <div className="setting-row">
              <div>
                <b>Profil bearbeiten</b>
                <small>Ändere deinen Namen oder Profilbild.</small>
              </div>
              <button className="outline-button" onClick={onOpenProfile}>
                Bearbeiten
              </button>
            </div>
            <div className="setting-row">
              <div>
                <b>Darstellung</b>
                <small>Wähle, wie das Ticket System im Browser erscheint.</small>
              </div>
              <button
                className={`theme-toggle ${darkMode ? "enabled" : ""}`}
                onClick={onToggleDarkMode}
              >
                <span></span>
                {darkMode ? "Dunkel" : "Hell"}
              </button>
            </div>
            
            <div className="setting-row">
              <div>
                <b>Zwei-Faktor-Authentifizierung (MFA)</b>
                <small>Schütze dein Konto mit einem zweiten Faktor.</small>
              </div>
              {user.totpEnabled || user.totp_enabled ? (
                <button className="outline-button" onClick={onDisableMfa}>
                  Deaktivieren
                </button>
              ) : (
                <button className="outline-button" onClick={onOpenMfaSetup}>
                  Aktivieren
                </button>
              )}
            </div>

            <div className="setting-row">
              <div>
                <b>Persönliche Sitzung</b>
                <small>Dein Konto ist geschützt angemeldet.</small>
              </div>
              <button className="outline-button" onClick={onLogout}>
                Abmelden
              </button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;


function ArticleModal({ onClose, onSave, article = null }) {
  const [title, setTitle] = useState(article?.title || "");
  const [category, setCategory] = useState(article?.category || "");
  const [content, setContent] = useState(article?.content || "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const token = await csrfToken();
      const method = article ? "PUT" : "POST";
      const url = article ? `/api/articles/${article.id}` : "/api/articles";
      const res = await api(url, {
        method,
        headers: { "X-CSRF-Token": token, "Content-Type": "application/json" },
        body: JSON.stringify({ title, category, content }),
      });
      onSave(res.article);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <header className="modal-header">
          <h2>{article ? "Artikel bearbeiten" : "Neuen Artikel erstellen"}</h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </header>
        <div className="modal-body">
          {error && <div className="error-banner">{error}</div>}
          <form className="auth-form" onSubmit={handleSubmit}>
            <label>
              Titel
              <input value={title} onChange={(e) => setTitle(e.target.value)} required minLength="3" maxLength="100" placeholder="z.B. VPN Zugang einrichten" />
            </label>
            <label>
              Kategorie / Schlagwort
              <input value={category} onChange={(e) => setCategory(e.target.value)} required minLength="2" maxLength="50" placeholder="z.B. Netzwerk, Hardware, Allgemein" />
            </label>
            <label>
              Inhalt
              <textarea value={content} onChange={(e) => setContent(e.target.value)} required minLength="10" maxLength="5000" rows="6" placeholder="Der Inhalt des Artikels..."></textarea>
            </label>
            <button className="new-ticket" type="submit" disabled={loading} style={{ width: "100%", marginTop: "1rem" }}>
              {loading ? "Wird gespeichert..." : "Artikel speichern"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
