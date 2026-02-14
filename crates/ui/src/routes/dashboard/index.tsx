import { useAuth } from "@/context/AuthContext";
import {
    Card, CardContent, CardHeader, CardTitle
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
    FolderKanban,
    Shield,
    Network,
    AlertTriangle,
    TrendingUp,
    CheckCircle,
    XCircle,
    Loader2,
    Bot,
    Database,
    Circle,
    Activity,
    Sparkles,
    Zap,
    Layers,
    Keyboard,
    Package,
    Building2,
    Bug,
    Briefcase,
    ArrowRight
} from "lucide-react";
import {
    useNavigate, createFileRoute, redirect
} from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { useHealth, useSettings } from "@/hooks/useApi";
import {
    getAccessToken, getStoredUser
} from "@/lib/api";
import { motion, AnimatePresence } from "motion/react";

export const Route = createFileRoute(`/dashboard/`)({
    beforeLoad: () => {
        const token = getAccessToken();
        const user = getStoredUser();

        if (!token || !user) {
            throw redirect({
                to:      `/login`,
                replace: true,
            });
        }
    },
    component: DashboardPage,
});

interface HealthCheck {
    status:    string
    database:  string
    redis:     string
    timestamp: string
}

// Module definitions
const MODULES = [
    {
        key: `module_assets`,
        name: `Assets`,
        description: `Track and manage your IT infrastructure assets`,
        icon: FolderKanban,
        color: `from-blue-500 to-cyan-500`,
        href: `/dashboard/assets`,
    },
    {
        key: `module_software`,
        name: `Software`,
        description: `Manage software inventory and licenses`,
        icon: Package,
        color: `from-purple-500 to-pink-500`,
        href: `/dashboard/software`,
    },
    {
        key: `module_security`,
        name: `Security`,
        description: `Security policies and compliance`,
        icon: Shield,
        color: `from-green-500 to-emerald-500`,
        href: `/dashboard/security`,
    },
    {
        key: `module_network`,
        name: `Network`,
        description: `Network infrastructure mapping`,
        icon: Network,
        color: `from-orange-500 to-amber-500`,
        href: `/dashboard/network`,
    },
    {
        key: `module_vulnerabilities`,
        name: `Vulnerabilities`,
        description: `Track and remediate security vulnerabilities`,
        icon: Bug,
        color: `from-red-500 to-rose-500`,
        href: `/dashboard/vulnerabilities`,
    },
    {
        key: `module_bia`,
        name: `Business Impact`,
        description: `Business impact analysis and continuity`,
        icon: Building2,
        color: `from-indigo-500 to-violet-500`,
        href: `/dashboard/bia`,
    },
    {
        key: `module_vendors`,
        name: `Vendors`,
        description: `Third-party vendor management`,
        icon: Briefcase,
        color: `from-teal-500 to-green-500`,
        href: `/dashboard/vendors`,
    },
];

export default function DashboardPage() {
    const { user } = useAuth();
    const navigate = useNavigate();

    const { data: healthData, isLoading: healthLoading, error: healthError } = useHealth();
    const { data: settingsData } = useSettings();

    // Get enabled modules
    const settings = settingsData?.settings || [];
    const settingsMap = new Map(settings.map(s => [s.key, s.value]));
    const enabledModules = MODULES.filter(m => settingsMap.get(m.key) === `true`);

    const health: HealthCheck | null = healthData
        ? {
            status:    healthData.status || `unknown`,
            database:  healthData.checks?.database?.status || `unknown`,
            redis:     healthData.checks?.redis?.status || `unknown`,
            timestamp: healthData.timestamp || new Date().toISOString(),
        }
        : null;

    const showHealthBanner = healthLoading || healthError || (health && health.status !== `healthy`);

    const stats = [
        { title: `Total Assets`, value: `1,234`, change: `+12%`, changeType: `positive`, icon: FolderKanban },
        { title: `Security Score`, value: `87%`, change: `+5%`, changeType: `positive`, icon: Shield },
        { title: `Active Vulnerabilities`, value: `23`, change: `-8%`, changeType: `positive`, icon: AlertTriangle },
        { title: `Network Devices`, value: `156`, change: `+3%`, changeType: `positive`, icon: Network },
    ];

    return (
        <div className="space-y-8 relative z-10">
            {/* Animated Background Orbs - More Prominent */}
            <div className="fixed inset-0 overflow-hidden pointer-events-none -z-10">
                <motion.div 
                    className="absolute -top-40 -right-40 w-[600px] h-[600px] bg-gradient-to-br from-amber-400/20 via-orange-500/10 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale: [1, 1.3, 1],
                        x: [0, 50, 0],
                        y: [0, -30, 0],
                        opacity: [0.4, 0.7, 0.4],
                    }}
                    transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
                />
                <motion.div 
                    className="absolute -bottom-40 -left-40 w-[500px] h-[500px] bg-gradient-to-tr from-violet-500/15 via-purple-500/10 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale: [1, 1.4, 1],
                        x: [0, -40, 0],
                        y: [0, 40, 0],
                        opacity: [0.3, 0.6, 0.3],
                    }}
                    transition={{ duration: 10, repeat: Infinity, ease: "easeInOut", delay: 2 }}
                />
                <motion.div 
                    className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-gradient-radial from-primary/5 via-transparent to-transparent rounded-full blur-3xl"
                    animate={{
                        scale: [1, 1.2, 1],
                        rotate: [0, 180, 360],
                    }}
                    transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                />
            </div>

            {/* Health Status Banner */}
            <AnimatePresence>
                {showHealthBanner && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.3 }}
                    >
                        <Card className={cn(
                            "overflow-hidden",
                            healthError ? `border-destructive bg-destructive/5` : 
                            health?.status === `healthy` ? `border-green-500 bg-green-500/5` : 
                            `border-yellow-500 bg-yellow-500/5`
                        )}>
                            <CardContent className="py-3">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <motion.div
                                            animate={{ rotate: healthLoading ? 360 : 0 }}
                                            transition={{ duration: 1, repeat: healthLoading ? Infinity : 0, ease: "linear" }}
                                        >
                                            {healthLoading ? (
                                                <Loader2 className="h-5 w-5 text-amber-500" />
                                            ) : healthError ? (
                                                <XCircle className="h-5 w-5 text-destructive" />
                                            ) : health?.status === `healthy` ? (
                                                <CheckCircle className="h-5 w-5 text-green-500" />
                                            ) : (
                                                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                                            )}
                                        </motion.div>
                                        <div>
                                            <p className="font-medium">System Status</p>
                                            <p className="text-sm text-muted-foreground">
                                                {healthLoading
                                                    ? `Checking system health...`
                                                    : healthError
                                                        ? `Unable to connect to server`
                                                        : health?.status === `healthy`
                                                            ? `All systems operational`
                                                            : `Systems degraded`}
                                            </p>
                                        </div>
                                    </div>
                                    {health && (
                                        <div className="flex items-center gap-4 text-sm">
                                            <motion.span 
                                                className="flex items-center gap-1"
                                                initial={{ opacity: 0 }}
                                                animate={{ opacity: 1 }}
                                            >
                                                <Database className="h-3 w-3" />
                                                <span className={health.database === `healthy` ? `text-green-500` : `text-destructive`}>
                                                    {health.database}
                                                </span>
                                            </motion.span>
                                            <motion.span 
                                                className="flex items-center gap-1"
                                                initial={{ opacity: 0 }}
                                                animate={{ opacity: 1 }}
                                                transition={{ delay: 0.1 }}
                                            >
                                                <Circle className="h-3 w-3 fill-current" />
                                                <span className={health.redis === `healthy` ? `text-green-500` : `text-destructive`}>
                                                    {health.redis}
                                                </span>
                                            </motion.span>
                                        </div>
                                    )}
                                </div>
                            </CardContent>
                        </Card>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Welcome Section */}
            <motion.div 
                className="flex flex-col gap-2"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
            >
                <div className="flex items-center gap-3">
                    <motion.h1 
                        className="text-3xl font-bold tracking-tight"
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.1 }}
                    >
                        Welcome back, {user?.displayName?.split(` `)[0] || `User`}
                    </motion.h1>
                    <motion.div
                        initial={{ scale: 0, rotate: -180 }}
                        animate={{ scale: 1, rotate: 0 }}
                        transition={{ delay: 0.3, type: "spring", stiffness: 200 }}
                    >
                        <Sparkles className="h-6 w-6 text-amber-500" />
                    </motion.div>
                </div>
                <p className="text-muted-foreground text-lg">
                    Here's what's happening with your infrastructure today.
                </p>
            </motion.div>

            {/* Overview - Stats Grid */}
            <div>
                <motion.div 
                    className="flex items-center gap-2 mb-4"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.2 }}
                >
                    <Zap className="h-5 w-5 text-primary" />
                    <h2 className="text-xl font-semibold">Overview</h2>
                </motion.div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    {stats.map((stat, index) => (
                        <motion.div
                            key={stat.title}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.1 * index + 0.3, duration: 0.3 }}
                            whileHover={{ scale: 1.02, y: -2 }}
                        >
                            <Card className="hover-lift">
                                <CardHeader className="flex flex-row items-center justify-between pb-2">
                                    <CardTitle className="text-sm font-medium text-muted-foreground">
                                        {stat.title}
                                    </CardTitle>
                                    <motion.div
                                        whileHover={{ rotate: 15, scale: 1.1 }}
                                        transition={{ type: "spring", stiffness: 300 }}
                                    >
                                        <stat.icon className="h-4 w-4 text-muted-foreground" />
                                    </motion.div>
                                </CardHeader>
                                <CardContent>
                                    <motion.div 
                                        className="text-2xl font-bold"
                                        initial={{ scale: 0.8 }}
                                        animate={{ scale: 1 }}
                                        transition={{ delay: 0.4, type: "spring" }}
                                    >
                                        {stat.value}
                                    </motion.div>
                                    <motion.p 
                                        className="text-xs text-muted-foreground flex items-center gap-1 mt-1"
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        transition={{ delay: 0.5 }}
                                    >
                                        <TrendingUp className={cn("h-3 w-3", stat.changeType === `positive` ? `text-green-500` : `text-red-500`)} />
                                        <span className={stat.changeType === `positive` ? `text-green-600` : `text-red-600`}>
                                            {stat.change}
                                        </span>
                                        <span className="text-muted-foreground">from last month</span>
                                    </motion.p>
                                </CardContent>
                            </Card>
                        </motion.div>
                    ))}
                </div>
            </div>

            {/* Your Modules */}
            <div>
                <motion.div 
                    className="flex items-center gap-2 mb-4"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.5 }}
                >
                    <Layers className="h-5 w-5 text-primary" />
                    <h2 className="text-xl font-semibold">Your Modules</h2>
                </motion.div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    {enabledModules.length > 0 ? (
                        enabledModules.map((module, index) => (
                            <motion.div
                                key={module.key}
                                initial={{ opacity: 0, y: 20, scale: 0.95 }}
                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                transition={{ delay: 0.1 * index + 0.6, duration: 0.3 }}
                                whileHover={{ scale: 1.02, y: -4 }}
                                whileTap={{ scale: 0.98 }}
                            >
                                <Card 
                                    className="cursor-pointer overflow-hidden group relative"
                                    onClick={() => navigate({ to: module.href })}
                                >
                                    <div className={cn(
                                        "absolute inset-0 bg-gradient-to-br opacity-0 group-hover:opacity-100 transition-opacity duration-300",
                                        module.color
                                    )} />
                                    <CardHeader className="relative pb-2">
                                        <div className="flex items-center justify-between">
                                            <motion.div 
                                                className={cn(
                                                    "p-2 rounded-lg bg-gradient-to-br shadow-lg",
                                                    module.color
                                                )}
                                                whileHover={{ rotate: 5, scale: 1.1 }}
                                                transition={{ type: "spring", stiffness: 300 }}
                                            >
                                                <module.icon className="h-5 w-5 text-white" />
                                            </motion.div>
                                            <motion.div
                                                initial={{ opacity: 0, x: 10 }}
                                                whileHover={{ opacity: 1, x: 0 }}
                                                className="opacity-0 group-hover:opacity-100 transition-opacity"
                                            >
                                                <ArrowRight className="h-4 w-4 text-white/70" />
                                            </motion.div>
                                        </div>
                                    </CardHeader>
                                    <CardContent className="relative">
                                        <CardTitle className="text-lg mb-1">{module.name}</CardTitle>
                                        <p className="text-sm text-muted-foreground">{module.description}</p>
                                    </CardContent>
                                </Card>
                            </motion.div>
                        ))
                    ) : (
                        <motion.div 
                            className="col-span-full"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: 0.6 }}
                        >
                            <Card className="border-dashed">
                                <CardContent className="py-12 text-center">
                                    <Layers className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                                    <p className="text-lg font-medium">No modules enabled</p>
                                    <p className="text-muted-foreground">Enable modules in Settings to see them here</p>
                                    <Button 
                                        className="mt-4" 
                                        onClick={() => navigate({ to: `/dashboard/settings`, search: { tab: `modules` } })}
                                    >
                                        Enable Modules
                                    </Button>
                                </CardContent>
                            </Card>
                        </motion.div>
                    )}
                </div>
            </div>

            {/* Quick Actions */}
            <div>
                <motion.div 
                    className="flex items-center gap-2 mb-4"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.9 }}
                >
                    <Keyboard className="h-5 w-5 text-primary" />
                    <h2 className="text-xl font-semibold">Quick Actions</h2>
                </motion.div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 1.0 }}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                    >
                        <Card className="cursor-pointer hover-lift" onClick={() => navigate({ to: `/dashboard/agents` })}>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-sm font-medium flex items-center gap-2">
                                    <Bot className="h-4 w-4 text-purple-500" />
                                    Agents
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">Manage collection agents</p>
                            </CardContent>
                        </Card>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.75 }}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                    >
                        <Card className="cursor-pointer hover-lift" onClick={() => navigate({ to: `/dashboard/settings/notifications` })}>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-sm font-medium flex items-center gap-2">
                                    <Activity className="h-4 w-4 text-blue-500" />
                                    Notifications
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">View and manage alerts</p>
                            </CardContent>
                        </Card>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.8 }}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                    >
                        <Card className="cursor-pointer hover-lift" onClick={() => navigate({ to: `/dashboard/profile`, search: { tab: `security` } })}>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-sm font-medium flex items-center gap-2">
                                    <Shield className="h-4 w-4 text-green-500" />
                                    Security
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">MFA and session settings</p>
                            </CardContent>
                        </Card>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.85 }}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                    >
                        <Card className="cursor-pointer hover-lift" onClick={() => navigate({ to: `/dashboard/settings`, search: { tab: `modules` } })}>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-sm font-medium flex items-center gap-2">
                                    <Layers className="h-4 w-4 text-orange-500" />
                                    Modules
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">Configure system modules</p>
                            </CardContent>
                        </Card>
                    </motion.div>
                </div>
            </div>
        </div>
    );
}
