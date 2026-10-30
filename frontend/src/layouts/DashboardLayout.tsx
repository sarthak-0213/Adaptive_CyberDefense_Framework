import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useState } from "react";
import {
  LayoutDashboard,
  TriangleAlert,
  Shield,
  Activity,
  FileBarChart,
  Settings,
  LogOut,
  Search,
  ShieldCheck,
} from "lucide-react";
import { useAuthStore } from "../store/authStore";
import { logoutApi } from "../api/auth";
import { CyberDefenseBackground } from "../components/3d/CyberDefenseBackground";
import { useScrollProgress } from "../components/3d/useScrollProgress";
import { GradientMeshBackground } from "../components/GradientMeshBackground";
import { CommandPalette } from "../components/CommandPalette";
import { PageTransition } from "../components/PageTransition";

const menuItems = [
  { name: "Dashboard", path: "/", icon: LayoutDashboard },
  { name: "Alerts", path: "/alerts", icon: TriangleAlert },
  { name: "Security", path: "/security", icon: Shield },
  { name: "Threat Analytics", path: "/threats", icon: Activity },
  { name: "Security Assessment", path: "/security-assessment", icon: ShieldCheck },
  { name: "Reports", path: "/reports", icon: FileBarChart },
  { name: "Settings", path: "/settings", icon: Settings },
];


export default function DashboardLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const { scrollProgress, scrollRef } = useScrollProgress();
  const [cmdOpen, setCmdOpen] = useState(false);

  const handleLogout = async () => {
    await logoutApi();
    navigate("/login");
  };

  const displayEmail = user?.email || "Unknown user";
  const displayRole = user?.role ? user.role.toUpperCase() : "NO ROLE";
  const avatarLetter = user?.email ? user.email.charAt(0).toUpperCase() : "U";

  const isDensePage = ["/reports", "/security", "/threats", "/alerts", "/security-assessment"].includes(location.pathname);

  return (
    <div className="relative flex h-screen overflow-hidden bg-[var(--background)] text-[var(--text-primary)]">
      {/* Backgrounds */}
      <GradientMeshBackground variant={isDensePage ? "reduced" : "default"} />
      <div className="fixed inset-0 pointer-events-none z-[-1] opacity-30">
        <CyberDefenseBackground scrollProgress={scrollProgress} />
      </div>

      <CommandPalette open={cmdOpen} setOpen={setCmdOpen} />

      {/* ── Icon Rail ──────────────────────────────────────────────── */}
      <aside className="relative z-20 flex w-[68px] shrink-0 flex-col border-r border-[var(--border)] bg-[#FAFAF8]">
        {/* Brand */}
        <div className="flex h-14 items-center justify-center border-b border-[var(--border)]">
          <Shield className="h-6 w-6 text-[var(--brand-navy)]" />
        </div>

        {/* Nav links */}
        <nav className="flex-1 flex flex-col items-center space-y-4 py-6">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const active = location.pathname === item.path;
            return (
              <div key={item.path} className="group relative">
                <Link
                  to={item.path}
                  className={`flex h-12 w-12 items-center justify-center rounded-xl transition-colors ${
                    active
                      ? "bg-[rgba(37,99,235,0.08)] text-[var(--accent-blue)] shadow-[inset_3px_0_0_0_var(--accent-blue)]"
                      : "text-[var(--text-secondary)] hover:bg-[#F0F0EC]"
                  }`}
                  aria-label={item.name}
                >
                  <Icon size={22} className="shrink-0" />
                </Link>
                {/* Tooltip */}
                <div className="absolute left-[calc(100%+8px)] top-1/2 -translate-y-1/2 rounded bg-gray-900 px-2.5 py-1 text-xs font-medium text-white opacity-0 pointer-events-none transition-opacity group-hover:opacity-100 z-50 whitespace-nowrap">
                  {item.name}
                </div>
              </div>
            );
          })}
        </nav>

        {/* Logout — pinned at bottom */}
        <div className="border-t border-[var(--border)] p-3 flex justify-center">
          <div className="group relative">
            <button
              onClick={handleLogout}
              className="flex h-12 w-12 items-center justify-center rounded-xl text-[var(--danger)] transition-colors hover:bg-red-50"
              aria-label="Logout"
            >
              <LogOut size={22} className="shrink-0" />
            </button>
            <div className="absolute left-[calc(100%+8px)] top-1/2 -translate-y-1/2 rounded bg-gray-900 px-2.5 py-1 text-xs font-medium text-white opacity-0 pointer-events-none transition-opacity group-hover:opacity-100 z-50 whitespace-nowrap">
              Logout
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main area ────────────────────────────────────────────── */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col overflow-hidden">
        {/* Top header */}
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-[var(--border)] bg-[var(--surface)] px-6 z-20">
          <div className="flex items-center gap-4">
            <h2 className="truncate text-base font-semibold text-[var(--text-primary)]">
              {menuItems.find((m) => m.path === location.pathname)?.name || "Dashboard"}
            </h2>
          </div>

          <div className="flex items-center gap-6">
            <button
              onClick={() => setCmdOpen(true)}
              className="flex items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-1.5 text-sm text-[var(--text-secondary)] hover:border-gray-300 transition-colors"
              aria-label="Open command palette"
            >
              <Search size={16} />
              <span>Search...</span>
              <kbd className="hidden rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-semibold sm:inline-block">
                ⌘ K
              </kbd>
            </button>

            {/* User identity */}
            <div className="flex min-w-0 shrink items-center gap-3">
              <div className="min-w-0 text-right hidden sm:block">
                <p className="max-w-[180px] truncate text-sm font-medium text-[var(--text-primary)]" title={displayEmail}>
                  {displayEmail}
                </p>
                <p className="text-[11px] font-semibold tracking-wider text-[var(--text-secondary)]">
                  {displayRole}
                </p>
              </div>
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[var(--accent-blue)] text-sm font-bold text-white">
                {avatarLetter}
              </div>
            </div>
          </div>
        </header>

        {/* Scrollable page content */}
        <main ref={scrollRef} className="flex-1 overflow-y-auto overflow-x-hidden relative">
          <div className="mx-auto w-full max-w-screen-2xl p-6">
            <PageTransition>
              <Outlet />
            </PageTransition>
          </div>
        </main>
      </div>
    </div>
  );
}
