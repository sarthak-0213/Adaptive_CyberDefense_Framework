import { useEffect, useState } from "react";
import {
  ShieldCheck,
  Play,
  RefreshCw,
  Server,
  Globe,
  Lock,
  KeyRound,
  Users,
  Network,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  ArrowDown,
  ArrowRight,
  Terminal,
  Check,
  FileCheck,
} from "lucide-react";

import { toast } from "sonner";
import { AnimatedCard } from "../components/AnimatedCard";
import {
  runSecurityAssessment,
  getLatestAssessment,
  type SecurityAssessmentFullResponse,
} from "../api/securityAssessment";

type ActiveTab =
  | "network"
  | "portal"
  | "http_https"
  | "session"
  | "access_control"
  | "segmentation"
  | "hardening"
  | "summary";

export default function SecurityAssessment() {
  const [assessment, setAssessment] = useState<SecurityAssessmentFullResponse | null>(null);
  const [target, setTarget] = useState<string>("localhost:8000");
  const [loading, setLoading] = useState<boolean>(true);
  const [running, setRunning] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<ActiveTab>("summary");

  const loadData = async () => {
    try {
      setLoading(true);
      const data = await getLatestAssessment();
      setAssessment(data);
      if (data?.target) {
        setTarget(data.target);
      }
    } catch (err: any) {
      console.error("Failed to load security assessment:", err);
      toast.error("Could not fetch latest security assessment telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunAssessment = async () => {
    if (!target.trim()) {
      toast.error("Please enter a valid authorized target host or URL.");
      return;
    }
    try {
      setRunning(true);
      toast.info(`Executing authorized security assessment against ${target}...`);
      const res = await runSecurityAssessment({
        target: target.trim(),
        authorized: true,
      });
      setAssessment(res);
      toast.success("Security assessment completed successfully.");
    } catch (err: any) {
      console.error("Assessment execution failed:", err);
      toast.error(err?.response?.data?.detail || "Failed to execute security assessment.");
    } finally {
      setRunning(false);
    }
  };

  const renderStatusBadge = (status: string) => {
    const s = (status || "").toUpperCase();
    if (s === "PASS" || s === "SECURE" || s === "COMPLETED" || s === "RESOLVED" || s === "OBSERVED") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <CheckCircle2 className="w-3.5 h-3.5" />
          {status}
        </span>
      );
    }
    if (s === "WARNING" || s === "FILTERED") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
          <AlertTriangle className="w-3.5 h-3.5" />
          {status}
        </span>
      );
    }
    if (s === "FAIL" || s === "CRITICAL" || s === "CLOSED" || s === "FAILED") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
          <XCircle className="w-3.5 h-3.5" />
          {status}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-200">
        <HelpCircle className="w-3.5 h-3.5" />
        {status || "NOT ASSESSED"}
      </span>
    );
  };

  const tabs: { id: ActiveTab; label: string; icon: any }[] = [
    { id: "summary", label: "Final Assessment", icon: FileCheck },
    { id: "network", label: "Network Recon", icon: Server },
    { id: "portal", label: "Portal Analysis", icon: Globe },
    { id: "http_https", label: "HTTP / HTTPS", icon: Lock },
    { id: "session", label: "Session Security", icon: KeyRound },
    { id: "access_control", label: "Access Control", icon: Users },
    { id: "segmentation", label: "Segmentation", icon: Network },
    { id: "hardening", label: "Defensive Hardening", icon: ShieldCheck },
  ];

  if (loading && !assessment) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-3">
        <RefreshCw className="w-8 h-8 animate-spin text-[var(--accent-blue)]" />
        <p className="text-sm font-medium text-[var(--text-secondary)]">
          Loading Security Assessment Engine...
        </p>
      </div>
    );
  }

  const summary = assessment?.summary;

  return (
    <div className="w-full space-y-6">
      {/* ── Page Header & Target Configuration ────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[var(--border)] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-[var(--text-primary)]">
              Security Assessment
            </h1>
            <span className="rounded-full bg-blue-50 border border-blue-200 px-2.5 py-0.5 text-xs font-semibold text-blue-700">
              Authorized Defense Scope
            </span>
          </div>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Safe, non-intrusive security posture evaluation across network, transport, session, and access boundaries.
          </p>
        </div>

        {/* Target Input & Run Action */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Authorized Target (e.g. localhost:8000)"
              className="w-64 rounded-lg border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--text-primary)] shadow-sm focus:border-[var(--accent-blue)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-blue)]"
            />
          </div>
          <button
            onClick={handleRunAssessment}
            disabled={running}
            className="flex items-center gap-2 rounded-lg bg-[var(--accent-blue)] px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-[var(--accent-blue-hover)] transition-colors disabled:opacity-50"
          >
            {running ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-current" />
            )}
            <span>{running ? "Assessing Target..." : "Run Assessment"}</span>
          </button>
        </div>
      </div>

      {/* ── Metric Highlights Ribbon ─────────────────────────────────── */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="rounded-xl border border-[var(--border)] bg-white p-3.5 shadow-sm">
            <div className="text-xs font-medium text-[var(--text-secondary)]">Total Checks</div>
            <div className="text-xl font-bold text-[var(--text-primary)] mt-1">
              {summary.total_checks}
            </div>
          </div>
          <div className="rounded-xl border border-emerald-100 bg-emerald-50/50 p-3.5 shadow-sm">
            <div className="text-xs font-medium text-emerald-700">Passed Checks</div>
            <div className="text-xl font-bold text-emerald-700 mt-1">
              {summary.passed_checks}
            </div>
          </div>
          <div className="rounded-xl border border-amber-100 bg-amber-50/50 p-3.5 shadow-sm">
            <div className="text-xs font-medium text-amber-700">Warnings</div>
            <div className="text-xl font-bold text-amber-700 mt-1">
              {summary.warning_checks}
            </div>
          </div>
          <div className="rounded-xl border border-rose-100 bg-rose-50/50 p-3.5 shadow-sm">
            <div className="text-xs font-medium text-rose-700">Failed Checks</div>
            <div className="text-xl font-bold text-rose-700 mt-1">
              {summary.failed_checks}
            </div>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-slate-50 p-3.5 shadow-sm">
            <div className="text-xs font-medium text-[var(--text-secondary)]">Not Assessed</div>
            <div className="text-xl font-bold text-slate-700 mt-1">
              {summary.not_assessed_checks}
            </div>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-white p-3.5 shadow-sm">
            <div className="text-xs font-medium text-[var(--text-secondary)]">Findings</div>
            <div className="text-xl font-bold text-[var(--text-primary)] mt-1">
              {summary.findings_count}
            </div>
          </div>
        </div>
      )}

      {/* ── Section Navigation Tabs ──────────────────────────────────── */}
      <div className="flex border-b border-[var(--border)] overflow-x-auto gap-2 pb-px">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                active
                  ? "border-[var(--accent-blue)] text-[var(--accent-blue)] bg-blue-50/40"
                  : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-gray-300"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* ── SECTION 1: NETWORK RECONNAISSANCE ────────────────────────── */}
      {activeTab === "network" && assessment?.network && (
        <AnimatedCard delay={0.05}>
          <div className="space-y-6">
            <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
                <div>
                  <h3 className="text-base font-semibold text-[var(--text-primary)]">
                    Network Reconnaissance & Host Observation
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    Safe visibility checks against authorized target: {assessment.network.target}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  {renderStatusBadge(assessment.network.status)}
                </div>
              </div>

              {/* Host Telemetry Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
                <div className="rounded-lg border border-[var(--border)] bg-slate-50 p-4">
                  <span className="text-xs font-medium text-[var(--text-secondary)]">Host Reachability</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`w-2.5 h-2.5 rounded-full ${assessment.network.reachable ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                    <span className="text-sm font-semibold text-[var(--text-primary)]">
                      {assessment.network.reachable ? "Reachable / Responsive" : "Unreachable via standard TCP handshake"}
                    </span>
                  </div>
                </div>

                <div className="rounded-lg border border-[var(--border)] bg-slate-50 p-4">
                  <span className="text-xs font-medium text-[var(--text-secondary)]">DNS Resolution</span>
                  <div className="text-sm font-semibold text-[var(--text-primary)] mt-1">
                    {assessment.network.dns.canonical_name || "N/A"}
                  </div>
                  <div className="text-xs text-[var(--text-secondary)] mt-0.5">
                    IPs: {assessment.network.dns.resolved_ips?.join(", ") || "None"}
                  </div>
                </div>

                <div className="rounded-lg border border-[var(--border)] bg-slate-50 p-4">
                  <span className="text-xs font-medium text-[var(--text-secondary)]">DHCP Observation</span>
                  <div className="text-sm font-semibold text-[var(--text-primary)] mt-1">
                    {assessment.network.dhcp.status}
                  </div>
                  <div className="text-xs text-[var(--text-secondary)] mt-0.5">
                    Primary: {assessment.network.dhcp.primary_interface || "N/A"}
                  </div>
                </div>
              </div>

              {/* Port & Service Observation Table */}
              <div className="mt-6">
                <h4 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[var(--accent-blue)]" />
                  <span>Port & Service Observation (Authorized Target Only)</span>
                </h4>
                <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-slate-50 text-xs font-semibold uppercase text-[var(--text-secondary)] border-b border-[var(--border)]">
                      <tr>
                        <th className="px-4 py-3">Port</th>
                        <th className="px-4 py-3">Protocol</th>
                        <th className="px-4 py-3">Service Name</th>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border)] bg-white font-mono text-xs">
                      {assessment.network.services.map((svc, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                          <td className="px-4 py-3 font-semibold text-[var(--text-primary)]">{svc.port}</td>
                          <td className="px-4 py-3 text-[var(--text-secondary)]">{svc.protocol}</td>
                          <td className="px-4 py-3 text-[var(--text-primary)]">{svc.service}</td>
                          <td className="px-4 py-3">{renderStatusBadge(svc.status)}</td>
                          <td className="px-4 py-3 text-[var(--text-secondary)]">{svc.timestamp}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </AnimatedCard>
      )}

      {/* ── SECTION 2: PORTAL ANALYSIS ───────────────────────────────── */}
      {activeTab === "portal" && assessment?.portal && (
        <AnimatedCard delay={0.05}>
          <div className="space-y-6">
            <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
                <div>
                  <h3 className="text-base font-semibold text-[var(--text-primary)]">
                    Web Application & Portal Flow Analysis
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    Redirect chain, authentication endpoints, and session termination inspection.
                  </p>
                </div>
                {renderStatusBadge(assessment.portal.status)}
              </div>

              {/* Redirect Chain Visualizer */}
              <div className="mt-6">
                <h4 className="text-sm font-semibold text-[var(--text-primary)] mb-4">
                  REDIRECT ANALYSIS FLOW
                </h4>
                <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 p-4 bg-slate-50 rounded-xl border border-[var(--border)]">
                  {assessment.portal.redirect_chain.map((step, idx) => (
                    <div key={idx} className="flex-1 flex flex-col md:flex-row items-center gap-3">
                      <div className="w-full bg-white p-3.5 rounded-lg border border-[var(--border)] shadow-xs">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] font-bold text-[var(--accent-blue)] uppercase">
                            Step {step.step}
                          </span>
                          <span className="text-xs font-mono font-bold text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">
                            {step.status_code}
                          </span>
                        </div>
                        <p className="text-xs font-semibold text-[var(--text-primary)] truncate">
                          {step.label}
                        </p>
                        <p className="text-[11px] font-mono text-[var(--text-secondary)] truncate mt-1" title={step.url}>
                          {step.url}
                        </p>
                      </div>
                      {idx < assessment.portal.redirect_chain.length - 1 && (
                        <div className="flex justify-center text-[var(--text-secondary)]">
                          <ArrowRight className="hidden md:block w-4 h-4 shrink-0" />
                          <ArrowDown className="md:hidden w-4 h-4 shrink-0" />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Portal Endpoints Meta */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                <div className="p-4 rounded-lg border border-[var(--border)] bg-white">
                  <span className="text-xs font-medium text-[var(--text-secondary)]">Authentication Endpoint</span>
                  <p className="text-xs font-mono font-semibold text-[var(--text-primary)] mt-1 truncate">
                    {assessment.portal.auth_endpoint || "/api/v1/auth/login"}
                  </p>
                </div>
                <div className="p-4 rounded-lg border border-[var(--border)] bg-white">
                  <span className="text-xs font-medium text-[var(--text-secondary)]">Logout Behavior</span>
                  <p className="text-xs font-medium text-emerald-700 mt-1">
                    {assessment.portal.logout_behavior || "Active Token Blacklist & Session Revocation"}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </AnimatedCard>
      )}

      {/* ── SECTION 3: HTTP VS HTTPS ─────────────────────────────────── */}
      {activeTab === "http_https" && assessment?.http_https && (
        <AnimatedCard delay={0.05}>
          <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
              <div>
                <h3 className="text-base font-semibold text-[var(--text-primary)]">
                  HTTP vs HTTPS Transport Security Assessment
                </h3>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                  Verification of transport-layer encryption and TLS enforcement.
                </p>
              </div>
              {renderStatusBadge(assessment.http_https.status)}
            </div>

            {/* Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <div className="text-xs font-medium text-[var(--text-secondary)]">HTTPS STATUS</div>
                <div className="mt-2 flex items-center justify-between">
                  <span className="text-sm font-bold text-[var(--text-primary)]">
                    {assessment.http_https.https_supported ? "Active TLS / HTTPS" : "Plain HTTP Listener"}
                  </span>
                  {renderStatusBadge(assessment.http_https.https_status)}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <div className="text-xs font-medium text-[var(--text-secondary)]">HTTP → HTTPS REDIRECT</div>
                <div className="mt-2 flex items-center justify-between">
                  <span className="text-sm font-bold text-[var(--text-primary)]">
                    {assessment.http_https.redirect_status}
                  </span>
                  {renderStatusBadge(assessment.http_https.redirect_status)}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <div className="text-xs font-medium text-[var(--text-secondary)]">LOGIN TRANSPORT</div>
                <div className="mt-2 flex items-center justify-between">
                  <span className="text-sm font-bold text-[var(--text-primary)]">
                    {assessment.http_https.login_transport}
                  </span>
                  {renderStatusBadge(assessment.http_https.login_transport)}
                </div>
              </div>
            </div>

            {/* Explanation Card */}
            <div className="rounded-lg border border-blue-200 bg-blue-50/60 p-4 text-xs text-blue-900 leading-relaxed">
              <p className="font-semibold mb-1">Defense Rationale:</p>
              <p>{assessment.http_https.explanation}</p>
            </div>
          </div>
        </AnimatedCard>
      )}

      {/* ── SECTION 4: SESSION ANALYSIS ──────────────────────────────── */}
      {activeTab === "session" && assessment?.session && (
        <AnimatedCard delay={0.05}>
          <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
              <div>
                <h3 className="text-base font-semibold text-[var(--text-primary)]">
                  Session & Token Security Analysis
                </h3>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                  Inspection of token lifetimes, revocation triggers, and cookie isolation flags.
                </p>
              </div>
              {renderStatusBadge(assessment.session.status)}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Authentication Type</span>
                <p className="text-sm font-bold text-[var(--text-primary)] mt-1">
                  {assessment.session.auth_mechanism}
                </p>
              </div>

              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Token Expiration</span>
                <p className="text-sm font-bold text-[var(--text-primary)] mt-1">
                  {assessment.session.expiration_configured}
                </p>
              </div>

              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Logout Invalidation</span>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-sm font-bold text-[var(--text-primary)]">DB Blacklist Enforced</span>
                  {renderStatusBadge(assessment.session.logout_invalidation)}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Secure Cookie Attribute</span>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-sm font-bold text-[var(--text-primary)]">Bearer Auth / Header</span>
                  {renderStatusBadge(assessment.session.cookie_secure)}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <span className="text-xs font-medium text-[var(--text-secondary)]">HttpOnly Attribute</span>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-sm font-bold text-[var(--text-primary)]">Memory Isolation</span>
                  {renderStatusBadge(assessment.session.cookie_httponly)}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-[var(--border)] bg-slate-50">
                <span className="text-xs font-medium text-[var(--text-secondary)]">SameSite Attribute</span>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-sm font-bold text-[var(--text-primary)]">CORS + Bearer</span>
                  {renderStatusBadge(assessment.session.cookie_samesite)}
                </div>
              </div>
            </div>
          </div>
        </AnimatedCard>
      )}

      {/* ── SECTION 5: ACCESS-CONTROL TESTING ────────────────────────── */}
      {activeTab === "access_control" && assessment?.access_control && (
        <AnimatedCard delay={0.05}>
          <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
              <div>
                <h3 className="text-base font-semibold text-[var(--text-primary)]">
                  Access-Control & RBAC Barrier Verification
                </h3>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                  Validation of least-privilege role boundaries (401 unauth, 403 forbidden, 200 authorized).
                </p>
              </div>
              {renderStatusBadge(assessment.access_control.overall_status)}
            </div>

            <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-50 text-xs font-semibold uppercase text-[var(--text-secondary)] border-b border-[var(--border)]">
                  <tr>
                    <th className="px-4 py-3">Endpoint</th>
                    <th className="px-4 py-3">Test Role</th>
                    <th className="px-4 py-3">Expected Status</th>
                    <th className="px-4 py-3">Actual Status</th>
                    <th className="px-4 py-3">Result</th>
                    <th className="px-4 py-3">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)] bg-white text-xs">
                  {assessment.access_control.test_cases.map((tc, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="px-4 py-3 font-mono font-semibold text-[var(--text-primary)]">
                        {tc.endpoint}
                      </td>
                      <td className="px-4 py-3 font-medium text-slate-700">
                        {tc.test_role}
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--text-secondary)]">
                        {tc.expected}
                      </td>
                      <td className="px-4 py-3 font-mono font-bold text-[var(--text-primary)]">
                        {tc.actual}
                      </td>
                      <td className="px-4 py-3">
                        {renderStatusBadge(tc.result)}
                      </td>
                      <td className="px-4 py-3 text-[var(--text-secondary)]">
                        {tc.details}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </AnimatedCard>
      )}

      {/* ── SECTION 6: NETWORK SEGMENTATION ──────────────────────────── */}
      {activeTab === "segmentation" && assessment?.segmentation && (
        <AnimatedCard delay={0.05}>
          <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
              <div>
                <h3 className="text-base font-semibold text-[var(--text-primary)]">
                  Network Segmentation & Defensive Isolation
                </h3>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                  Evaluation of authorized inter-tier and client isolation paths.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-[var(--text-secondary)]">Client Isolation:</span>
                {renderStatusBadge(assessment.segmentation.client_isolation)}
              </div>
            </div>

            <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-50 text-xs font-semibold uppercase text-[var(--text-secondary)] border-b border-[var(--border)]">
                  <tr>
                    <th className="px-4 py-3">Source Node</th>
                    <th className="px-4 py-3">Destination Node</th>
                    <th className="px-4 py-3">Port / Proto</th>
                    <th className="px-4 py-3">Policy Allowed</th>
                    <th className="px-4 py-3">Isolation Status</th>
                    <th className="px-4 py-3">Notes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)] bg-white text-xs">
                  {assessment.segmentation.authorized_paths.map((p, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="px-4 py-3 font-medium text-[var(--text-primary)]">{p.source}</td>
                      <td className="px-4 py-3 font-medium text-[var(--text-primary)]">{p.destination}</td>
                      <td className="px-4 py-3 font-mono text-[var(--text-secondary)]">
                        {p.port ? `${p.port}/${p.protocol}` : `ALL/${p.protocol}`}
                      </td>
                      <td className="px-4 py-3 font-semibold">
                        {p.allowed ? (
                          <span className="text-emerald-700">ALLOWED</span>
                        ) : (
                          <span className="text-rose-700">BLOCKED</span>
                        )}
                      </td>
                      <td className="px-4 py-3">{renderStatusBadge(p.status)}</td>
                      <td className="px-4 py-3 text-[var(--text-secondary)]">{p.notes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </AnimatedCard>
      )}

      {/* ── SECTION 7: DEFENSIVE HARDENING ───────────────────────────── */}
      {activeTab === "hardening" && assessment?.hardening && (
        <AnimatedCard delay={0.05}>
          <div className="space-y-6">
            {assessment.hardening.categories.map((cat, cIdx) => (
              <div key={cIdx} className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm">
                <div className="flex items-center justify-between pb-3 border-b border-[var(--border)] mb-4">
                  <h4 className="text-sm font-bold tracking-wide uppercase text-[var(--brand-navy)]">
                    {cat.category}
                  </h4>
                  <div className="flex items-center gap-2 text-xs font-semibold">
                    <span className="text-emerald-700">{cat.pass_count} Pass</span>
                    <span className="text-slate-300">•</span>
                    <span className="text-amber-700">{cat.warning_count} Warning</span>
                    <span className="text-slate-300">•</span>
                    <span className="text-rose-700">{cat.fail_count} Fail</span>
                  </div>
                </div>

                <div className="divide-y divide-[var(--border)]">
                  {cat.items.map((item) => (
                    <div key={item.id} className="py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                      <div className="space-y-0.5">
                        <span className="text-xs font-semibold text-[var(--text-primary)]">
                          {item.name}
                        </span>
                        <p className="text-xs text-[var(--text-secondary)]">
                          {item.description}
                        </p>
                        <p className="text-[11px] font-mono text-slate-500">
                          {item.details}
                        </p>
                      </div>
                      <div className="shrink-0">{renderStatusBadge(item.status)}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </AnimatedCard>
      )}

      {/* ── SECTION 8: FINAL SUMMARY & FINDINGS ───────────────────────── */}
      {activeTab === "summary" && summary && (
        <AnimatedCard delay={0.05}>
          <div className="space-y-6">
            {/* Findings Card */}
            <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
                <div>
                  <h3 className="text-base font-semibold text-[var(--text-primary)]">
                    Security Findings & Posture Anomalies
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    Identified areas requiring configuration review or defensive remediation.
                  </p>
                </div>
                {renderStatusBadge(summary.assessment_status)}
              </div>

              {assessment.findings.length === 0 ? (
                <div className="py-8 text-center text-xs text-[var(--text-secondary)]">
                  <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                  No high or critical posture anomalies detected for this target environment.
                </div>
              ) : (
                <div className="divide-y divide-[var(--border)] mt-4">
                  {assessment.findings.map((f, idx) => (
                    <div key={idx} className="py-4 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-[var(--text-primary)]">
                          [{f.section}] {f.title}
                        </span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                          f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-rose-100 text-rose-800' : 'bg-amber-100 text-amber-800'
                        }`}>
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-xs text-[var(--text-secondary)]">{f.finding}</p>
                      <p className="text-xs font-medium text-[var(--accent-blue)]">
                        Recommendation: {f.recommendation}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recommendations Box */}
            <div className="rounded-xl border border-blue-100 bg-blue-50/50 p-6 shadow-sm">
              <h4 className="text-sm font-bold text-blue-900 mb-3 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-blue-700" />
                <span>Defensive Recommendations & Next Steps</span>
              </h4>
              <ul className="space-y-2 text-xs text-blue-900/90">
                {summary.recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </AnimatedCard>
      )}
    </div>
  );
}
