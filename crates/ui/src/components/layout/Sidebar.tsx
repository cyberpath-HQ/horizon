import { Link, useLocation } from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { useAuth } from "@/context/AuthContext";
import { useTheme } from "@/hooks/useTheme";
import { useSettings } from "@/hooks/useApi";
import {
    Users,
    Settings,
    User,
    FolderKanban,
    Package,
    Shield,
    Network,
    Bug,
    Building2,
    Briefcase,
    LayoutDashboard,
    Sparkles,
    ArrowRight
} from "lucide-react";
import { motion } from "motion/react";

interface NavItem {
    title:  string
    href:   string
    icon:   React.ElementType
    moduleKey?: string
    roles?: Array<string>
    search?: Record<string, string>
    gradient?: string
}

const MODULE_CONFIG: Array<NavItem> = [
    { title: `Assets`, href: `/dashboard/assets`, icon: FolderKanban, moduleKey: `module_assets`, gradient: `from-blue-500 to-cyan-500` },
    { title: `Software`, href: `/dashboard/software`, icon: Package, moduleKey: `module_software`, gradient: `from-purple-500 to-pink-500` },
    { title: `Security`, href: `/dashboard/security`, icon: Shield, moduleKey: `module_security`, gradient: `from-green-500 to-emerald-500` },
    { title: `Network`, href: `/dashboard/network`, icon: Network, moduleKey: `module_network`, gradient: `from-orange-500 to-amber-500` },
    { title: `Vulnerabilities`, href: `/dashboard/vulnerabilities`, icon: Bug, moduleKey: `module_vulnerabilities`, gradient: `from-red-500 to-rose-500` },
    { title: `Business Impact`, href: `/dashboard/bia`, icon: Building2, moduleKey: `module_bia`, gradient: `from-indigo-500 to-violet-500` },
    { title: `Vendors`, href: `/dashboard/vendors`, icon: Briefcase, moduleKey: `module_vendors`, gradient: `from-teal-500 to-green-500` },
];

const mainNavItems: Array<NavItem> = [
    {
        title: `Dashboard`,
        href:  `/dashboard`,
        icon:  LayoutDashboard,
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
        search: { tab: "modules" },
    },
];

export function Sidebar() {
    const location = useLocation();
    const pathname = location.pathname;
    const { user } = useAuth();
    const { resolvedTheme } = useTheme();
    const { data: settingsData } = useSettings();

    const isActive = (href: string) => {
        if (href === `/dashboard`) {
            return pathname === `/dashboard`;
        }
        if (href === `/dashboard/settings`) {
            return pathname === `/dashboard/settings` || pathname === `/dashboard/settings/`;
        }
        return pathname.startsWith(href);
    };

    const isModuleEnabled = (moduleKey?: string) => {
        if (!moduleKey || !settingsData?.settings) return true;
        const setting = settingsData.settings.find((s: { key: string }) => s.key === moduleKey);
        return setting?.value === `true`;
    };

    // Get enabled modules
    const enabledModules = MODULE_CONFIG.filter(m => isModuleEnabled(m.moduleKey));
    const filteredMainNavItems = mainNavItems.filter(item => isModuleEnabled(item.moduleKey));

    const logoSrc = resolvedTheme === "dark" ? "/logo-white.svg" : "/logo.svg";

    return (
        <div className="flex flex-col h-full w-64 border-r bg-card/95 backdrop-blur-sm">
            {/* Logo */}
            <Link to="/dashboard" className="flex items-center gap-3 px-5 py-5 border-b hover:bg-accent/50 transition-colors">
                <motion.div 
                    whileHover={{ rotate: 5, scale: 1.05 }}
                    transition={{ type: "spring", stiffness: 300 }}
                >
                    <img src={logoSrc} alt="Horizon" className="h-8 w-auto" />
                </motion.div>
            </Link>

            {/* Main Navigation */}
            <nav className="flex-1 overflow-y-auto py-4 px-3">
                {/* Dashboard */}
                <div className="space-y-1">
                    {filteredMainNavItems.map((item) => (
                        <Link
                            key={item.href}
                            to={item.href}
                            className={cn(
                                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200`,
                                isActive(item.href)
                                  ? `bg-gradient-to-r from-primary/15 to-primary/5 text-primary border-l-2 border-primary`
                                  : `text-muted-foreground hover:bg-accent hover:text-foreground`
                            )}
                        >
                            <motion.div whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.95 }}>
                                <item.icon className={cn(`w-4 h-4`, isActive(item.href) && `text-primary`)} />
                            </motion.div>
                            {item.title}
                        </Link>
                    ))}
                </div>

                {/* Modules Section */}
                {enabledModules.length > 0 && (
                    <div className="mt-6">
                        <div className="px-3 mb-2 flex items-center justify-between">
                            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1">
                                <Sparkles className="w-3 h-3" />
                                Modules
                            </h2>
                        </div>
                        <div className="space-y-1">
                            {enabledModules.map((item, index) => (
                                <motion.div
                                    key={item.href}
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: index * 0.05 }}
                                >
                                    <Link
                                        to={item.href}
                                        className={cn(
                                            `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group`,
                                            isActive(item.href)
                                                ? `bg-gradient-to-r from-primary/15 to-primary/5 text-primary border-l-2 border-primary`
                                                : `text-muted-foreground hover:bg-accent/70 hover:text-foreground`
                                        )}
                                    >
                                        <motion.div 
                                            className={cn(
                                                `p-1.5 rounded-md bg-gradient-to-br shadow-sm`,
                                                item.gradient
                                            )}
                                            whileHover={{ rotate: 5, scale: 1.1 }}
                                            transition={{ type: "spring", stiffness: 300 }}
                                        >
                                            <item.icon className="w-3.5 h-3.5 text-white" />
                                        </motion.div>
                                        <span className="flex-1">{item.title}</span>
                                        <motion.div
                                            initial={{ opacity: 0, x: -5 }}
                                            whileHover={{ opacity: 1, x: 0 }}
                                            className="opacity-0 group-hover:opacity-100 transition-opacity"
                                        >
                                            <ArrowRight className="w-3.5 h-3.5 text-muted-foreground" />
                                        </motion.div>
                                    </Link>
                                </motion.div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Settings Section */}
                <div className="mt-6">
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
                                search={item.search}
                                className={cn(
                                    `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200`,
                                    isActive(item.href)
                                        ? `bg-gradient-to-r from-primary/15 to-primary/5 text-primary border-l-2 border-primary`
                                        : `text-muted-foreground hover:bg-accent hover:text-foreground`
                                )}
                            >
                                <motion.div whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.95 }}>
                                    <item.icon className={cn(`w-4 h-4`, isActive(item.href) && `text-primary`)} />
                                </motion.div>
                                {item.title}
                            </Link>
                        ))}
                    </div>
                </div>
            </nav>

            {/* User Info */}
            <motion.div 
                className="px-4 py-3 border-t"
                whileHover={{ backgroundColor: "rgba(var(--accent), 0.5)" }}
            >
                <Link
                    to="/dashboard/profile"
                    search={{ tab: "profile" }}
                    className="flex items-center gap-3 px-2 py-2 rounded-lg hover:bg-accent transition-colors"
                >
                    <motion.div 
                        className="w-9 h-9 rounded-full bg-gradient-to-br from-amber-400 to-orange-500 flex items-center justify-center shadow-md"
                        whileHover={{ rotate: 5, scale: 1.05 }}
                    >
                        <span className="text-sm font-medium text-white">
                            {user?.displayName?.charAt(0).toUpperCase() || `U`}
                        </span>
                    </motion.div>
                    <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{user?.displayName || `User`}</p>
                        <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                    </div>
                </Link>
            </motion.div>
        </div>
    );
}
