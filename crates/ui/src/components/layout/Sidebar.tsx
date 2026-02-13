import {
    Link, useLocation
} from "react-router-dom";
import { cn } from "@/lib/utils";
import { useAuth } from "@/context/AuthContext";
import {
    LayoutDashboard,
    FolderKanban,
    Shield,
    Network,
    Building2,
    Users,
    Key,
    Settings,
    Bell,
    Database,
    Bot,
    FileSpreadsheet,
    Workflow
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
        href:  `/`,
        icon:  LayoutDashboard,
    },
    {
        title: `Assets`,
        href:  `/assets`,
        icon:  FolderKanban,
    },
    {
        title: `Software`,
        href:  `/software`,
        icon:  Database,
    },
    {
        title: `Security`,
        href:  `/security`,
        icon:  Shield,
    },
    {
        title: `Network`,
        href:  `/network`,
        icon:  Network,
    },
    {
        title: `Vulnerabilities`,
        href:  `/vulnerabilities`,
        icon:  Shield,
    },
    {
        title: ` BIA`,
        href:  `/bia`,
        icon:  Workflow,
    },
    {
        title: `Vendors`,
        href:  `/vendors`,
        icon:  Building2,
    },
];

const settingsNavItems: Array<NavItem> = [
    {
        title: `Teams`,
        href:  `/settings/teams`,
        icon:  Users,
    },
    {
        title: `API Keys`,
        href:  `/settings/api-keys`,
        icon:  Key,
    },
    {
        title: `Notifications`,
        href:  `/settings/notifications`,
        icon:  Bell,
    },
    {
        title: `AI Providers`,
        href:  `/settings/ai`,
        icon:  Bot,
    },
    {
        title: `Import/Export`,
        href:  `/settings/import-export`,
        icon:  FileSpreadsheet,
    },
    {
        title: `Application`,
        href:  `/settings`,
        icon:  Settings,
    },
];

export function Sidebar() {
    const location = useLocation();
    const {
        user,
    } = useAuth();

    const isActive = (href: string) => {
        if (href === `/`) {
            return location.pathname === `/`;
        }
        return location.pathname.startsWith(href);
    };

    return (
        <div className="flex flex-col h-full w-64 border-r bg-card">
            {/* Logo */}
            <div className="flex items-center gap-3 px-6 py-5 border-b">
                <picture>
                    <source srcSet="/logo.svg" media="(prefers-color-scheme: dark)" />
                    <source srcSet="/logo-white.svg" media="(prefers-color-scheme: light)" />
                    <img src="/logo.svg" alt="Horizon" className="w-full" />
                </picture>
            </div>

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
                    to="/profile"
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
