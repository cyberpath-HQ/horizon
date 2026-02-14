import { Link, useRouter } from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { useAuth } from "@/context/AuthContext";
import { useTheme } from "@/hooks/useTheme";
import {
    LayoutDashboard,
    FolderKanban,
    Shield,
    Network,
    Building2,
    Users,
    Settings,
    Database,
    Bot,
    Workflow,
    User
} from "lucide-react";

interface NavItem {
    title:  string
    href:   string
    icon:   React.ElementType
    roles?: Array<string>
}

const mainNavItems: Array<NavItem> = [
    {
        title: `Dashboard`,
        href:  `/dashboard`,
        icon:  LayoutDashboard,
    },
    {
        title: `Assets`,
        href:  `/dashboard/assets`,
        icon:  FolderKanban,
    },
    {
        title: `Software`,
        href:  `/dashboard/software`,
        icon:  Database,
    },
    {
        title: `Security`,
        href:  `/dashboard/security`,
        icon:  Shield,
    },
    {
        title: `Network`,
        href:  `/dashboard/network`,
        icon:  Network,
    },
    {
        title: `Vulnerabilities`,
        href:  `/dashboard/vulnerabilities`,
        icon:  Shield,
    },
    {
        title: ` BIA`,
        href:  `/dashboard/bia`,
        icon:  Workflow,
    },
    {
        title: `Vendors`,
        href:  `/dashboard/vendors`,
        icon:  Building2,
    },
    {
        title: `Agents`,
        href:  `/dashboard/agents`,
        icon:  Bot,
    },
];

const settingsNavItems: Array<NavItem> = [
    {
        title: `Users`,
        href:  `/dashboard/settings/users`,
        icon:  User,
    },
    {
        title: `Teams`,
        href:  `/dashboard/settings/teams`,
        icon:  Users,
    },
    {
        title: `Application`,
        href:  `/dashboard/settings`,
        icon:  Settings,
    },
];

export function Sidebar() {
    const router = useRouter();
    const { user } = useAuth();
    const { resolvedTheme } = useTheme();

    const isActive = (href: string) => {
        const pathname = router.state.location.pathname;
        // Exact match for dashboard root
        if (href === `/dashboard`) {
            return pathname === `/dashboard`;
        }
        // For settings, use exact match or check if it's a sub-path
        // /dashboard/settings should only match exactly, not /dashboard/settings/users or /dashboard/settings/teams
        if (href === `/dashboard/settings`) {
            return pathname === `/dashboard/settings`;
        }
        // For other paths, use startsWith
        return pathname.startsWith(href);
    };

    const logoSrc = resolvedTheme === "dark" ? "/logo-white.svg" : "/logo.svg";

    return (
        <div className="flex flex-col h-full w-64 border-r bg-card">
            {/* Logo */}
            <Link to="/dashboard" className="flex items-center gap-3 px-6 py-5 border-b hover:bg-accent/50 transition-colors">
                <img src={logoSrc} alt="Horizon" className="h-8 w-auto" />
            </Link>

            {/* Main Navigation */}
            <nav className="flex-1 overflow-y-auto py-4 px-3">
                <div className="space-y-1">
                    {mainNavItems.map((item) => (
                        <Link
                            key={item.href}
                            to={item.href}
                            className={cn(
                                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200`,
                isActive(item.href)
                  ? `bg-primary/10 text-primary`
                  : `text-muted-foreground hover:bg-accent hover:text-foreground`
                            )}
                        >
                            <item.icon className={cn(`w-4 h-4`, isActive(item.href) && `text-primary`)} />
                            {item.title}
                        </Link>
                    ))}
                </div>

                {/* Settings Section */}
                <div className="mt-8">
                    <div className="px-3 mb-2">
                        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                            Settings
                        </h2>
                    </div>
                    <div className="space-y-1">
                        {settingsNavItems.map((item) => (
                            <Link
                                key={item.href}
                                to={item.href}
                                className={cn(
                                    `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200`,
                  isActive(item.href)
                    ? `bg-primary/10 text-primary`
                    : `text-muted-foreground hover:bg-accent hover:text-foreground`
                                )}
                            >
                                <item.icon className={cn(`w-4 h-4`, isActive(item.href) && `text-primary`)} />
                                {item.title}
                            </Link>
                        ))}
                    </div>
                </div>
            </nav>

            {/* User Info */}
            <div className="px-4 py-3 border-t">
                <Link
                    to="/dashboard/profile"
                    className="flex items-center gap-3 px-2 py-2 rounded-lg hover:bg-accent transition-colors"
                >
                    <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                        <span className="text-xs font-medium text-primary">
                            {user?.displayName?.charAt(0).toUpperCase() || `U`}
                        </span>
                    </div>
                    <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{user?.displayName || `User`}</p>
                        <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                    </div>
                </Link>
            </div>
        </div>
    );
}
