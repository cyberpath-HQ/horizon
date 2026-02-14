import {
    createFileRoute, redirect, useSearch, useNavigate
} from "@tanstack/react-router";
import {
    getAccessToken, getStoredUser
} from "@/lib/api";
import { toastSuccess, toastError } from "@/lib/toast";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Database, Shield as ShieldIcon, Settings2,
    FolderKanban, Package, Shield, Network, Bug, Building2, Briefcase
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { Switch } from "@/components/ui/switch";
import {
    useSettings,
    useUpdateSetting
} from "@/hooks/useApi";
import {
    Loader2, AlertCircle
} from "lucide-react";
import { motion } from "motion/react";
import { cn } from "@/lib/utils";

// Type for tab search params
interface SettingsSearchParams {
    tab?: `modules` | `security` | `database`
}

export const Route = createFileRoute(`/dashboard/settings/`)({
    beforeLoad: () => {
        // Check if user is authenticated
        const token = getAccessToken();
        const user = getStoredUser();

        if (!token || !user) {
            throw redirect({
                to:      `/login`,
                replace: true,
            });
        }
    },
    validateSearch: (search: SettingsSearchParams) => ({
        tab: search.tab || `modules`,
    }),
    component: SettingsPage,
});

interface SystemSetting {
    id:           string
    key:          string
    value:        string
    description?: string
    updated_at:   string
}

// Module definitions with rich metadata
const MODULE_CONFIG = [
    {
        key:             `module_assets`,
        name:            `Assets`,
        description:     `Track and manage your IT infrastructure assets`,
        longDescription: `Comprehensive asset management module for tracking hardware, software, and cloud resources.`,
        color:           `from-blue-500 to-cyan-500`,
        icon:            FolderKanban,
        features:        [
            `Hardware Inventory`,
            `Software Tracking`,
            `Asset Lifecycle`,
            `Depreciation`,
        ],
    },
    {
        key:             `module_software`,
        name:            `Software`,
        description:     `Manage software inventory and licenses`,
        longDescription: `Complete software license management with usage tracking and compliance monitoring.`,
        color:           `from-purple-500 to-pink-500`,
        icon:            Package,
        features:        [
            `License Management`,
            `Usage Analytics`,
            `Compliance`,
            `Cost Tracking`,
        ],
    },
    {
        key:             `module_security`,
        name:            `Security`,
        description:     `Security policies and compliance`,
        longDescription: `Enterprise security configuration management with compliance frameworks.`,
        color:           `from-green-500 to-emerald-500`,
        icon:            Shield,
        features:        [
            `Policy Management`,
            `Compliance Reports`,
            `Security Score`,
            `Audit Logs`,
        ],
    },
    {
        key:             `module_network`,
        name:            `Network`,
        description:     `Network infrastructure mapping`,
        longDescription: `Visual network topology mapping and monitoring with real-time status.`,
        color:           `from-orange-500 to-amber-500`,
        icon:            Network,
        features:        [
            `Topology Maps`,
            `Device Status`,
            `Connection Tracking`,
            `Monitoring`,
        ],
    },
    {
        key:             `module_vulnerabilities`,
        name:            `Vulnerabilities`,
        description:     `Track and remediate security vulnerabilities`,
        longDescription: `Vulnerability management with risk scoring and remediation tracking.`,
        color:           `from-red-500 to-rose-500`,
        icon:            Bug,
        features:        [
            `Vulnerability Scan`,
            `Risk Scoring`,
            `Remediation`,
            `Threat Intel`,
        ],
    },
    {
        key:             `module_bia`,
        name:            `Business Impact`,
        description:     `Business impact analysis and continuity`,
        longDescription: `Business continuity planning with impact analysis and recovery procedures.`,
        color:           `from-indigo-500 to-violet-500`,
        icon:            Building2,
        features:        [
            `Impact Analysis`,
            `Recovery Plans`,
            `Risk Assessment`,
            `Reporting`,
        ],
    },
    {
        key:             `module_vendors`,
        name:            `Vendors`,
        description:     `Third-party vendor management`,
        longDescription: `Comprehensive vendor risk management with contract tracking.`,
        color:           `from-teal-500 to-green-500`,
        icon:            Briefcase,
        features:        [
            `Vendor Directory`,
            `Risk Assessment`,
            `Contract Management`,
            `Performance`,
        ],
    },
];

export default function SettingsPage() {
    // Get tab from search params
    const search = useSearch({
        from: `/dashboard/settings/`,
    });
    const activeTab = search.tab || `modules`;
    const navigate = useNavigate({
        from: `/dashboard/settings/`,
    });

    // Function to change tab via URL
    const setTab = (tab: string) => {
        navigate({
            search: {
                tab: tab as any,
            },
        });
    };

    const {
        user,
    } = useAuth();
    const {
        data: settingsData, isLoading,
    } = useSettings();
    const updateSetting = useUpdateSetting();

    const settings: Array<SystemSetting> = settingsData?.settings || [];

    // Check if user is super admin
    const isSuperAdmin = user?.roles?.includes(`super_admin`) ?? false;

    // Parse settings into a map
    const settingsMap = new Map<string, SystemSetting>();
    settings.forEach((s) => settingsMap.set(s.key, s));

    // Get module settings
    const getModuleValue = (key: string) => {
        const setting = settingsMap.get(key);
        return setting?.value === `true`;
    };

    // Handle module toggle with animation
    const handleModuleToggle = async(moduleKey: string, enabled: boolean) => {
        if (!isSuperAdmin) {
            return;
        }

        try {
            await updateSetting.mutateAsync({
                key:   moduleKey,
                value: enabled.toString(),
            });
            toastSuccess(`${ moduleKey.replace(`module_`, ``) } module ${ enabled ? `enabled` : `disabled` }`);
        }
        catch (err: any) {
            toastError(err.message || `Failed to update ${ moduleKey }`);
        }
    };

    // Handle require MFA toggle
    const handleRequireMfaChange = async(enabled: boolean) => {
        if (!isSuperAdmin) {
            return;
        }

        try {
            await updateSetting.mutateAsync({
                key:   `require_mfa`,
                value: enabled.toString(),
            });
            toastSuccess(`MFA requirement ${ enabled ? `enabled` : `disabled` }`);
        }
        catch (err: any) {
            toastError(err.message || `Failed to update MFA requirement`);
        }
    };

    const tabs = [
        {
            id:    `modules`,
            label: `Modules`,
            icon:  Settings2,
        },
        {
            id:    `security`,
            label: `Security`,
            icon:  ShieldIcon,
        },
        {
            id:    `database`,
            label: `Database`,
            icon:  Database,
        },
    ];

    return (
        <div className="space-y-6 relative z-10">
            {/* Animated Background */}
            <div className="fixed inset-0 overflow-hidden pointer-events-none -z-10">
                <motion.div
                    className="absolute -top-40 -right-40 w-[600px] h-[600px] bg-gradient-to-br from-primary/10 via-primary/5 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale:   [
                            1,
                            1.3,
                            1,
                        ],
                        x:       [
                            0,
                            50,
                            0,
                        ],
                        opacity: [
                            0.3,
                            0.5,
                            0.3,
                        ],
                    }}
                    transition={{
                        duration: 8,
                        repeat:   Infinity,
                        ease:     `easeInOut`,
                    }}
                />
                <motion.div
                    className="absolute -bottom-40 -left-40 w-[500px] h-[500px] bg-gradient-to-tr from-violet-500/10 via-purple-500/5 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale:   [
                            1,
                            1.4,
                            1,
                        ],
                        x:       [
                            0,
                            -40,
                            0,
                        ],
                        opacity: [
                            0.2,
                            0.4,
                            0.2,
                        ],
                    }}
                    transition={{
                        duration: 10,
                        repeat:   Infinity,
                        ease:     `easeInOut`,
                        delay:    2,
                    }}
                />
            </div>

            <motion.div
                initial={{
                    opacity: 0,
                    y:       -10,
                }}
                animate={{
                    opacity: 1,
                    y:       0,
                }}
            >
                <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
                <p className="text-muted-foreground mt-1">
                    Configure application settings and manage system modules.
                </p>
            </motion.div>

            {/* Tab Navigation with animations */}
            <div className="flex gap-1 overflow-x-auto border-b">
                {tabs.map((tab, index) => (
                    <motion.button
                        key={tab.id}
                        onClick={() => setTab(tab.id)}
                        className={cn(
                            `flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap`,
                            activeTab === tab.id
                                ? `border-primary text-primary`
                                : `border-transparent text-muted-foreground hover:text-foreground`
                        )}
                        initial={{
                            opacity: 0,
                            y:       -10,
                        }}
                        animate={{
                            opacity: 1,
                            y:       0,
                        }}
                        transition={{
                            delay: index * 0.05,
                        }}
                        whileHover={{
                            y: -2,
                        }}
                        whileTap={{
                            scale: 0.98,
                        }}
                    >
                        <tab.icon className="w-4 h-4" />
                        {tab.label}
                    </motion.button>
                ))}
            </div>

            {activeTab === `modules` && (
                <motion.div
                    initial={{
                        opacity: 0,
                        y:       10,
                    }}
                    animate={{
                        opacity: 1,
                        y:       0,
                    }}
                    transition={{
                        duration: 0.3,
                    }}
                >
                    {isSuperAdmin ? (
                        <>
                            {isLoading ? (
                                <Card>
                                    <CardContent className="pt-6">
                                        <div className="flex items-center gap-2">
                                            <Loader2 className="h-4 w-4 animate-spin" />
                                            <p className="text-muted-foreground">Loading module settings...</p>
                                        </div>
                                    </CardContent>
                                </Card>
                            ) : (
                                <div className="space-y-6">
                                    {/* Module Cards Grid */}
                                    <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                                        {MODULE_CONFIG.map((module, index) => {
                                            const isEnabled = getModuleValue(module.key);

                                            return (
                                                <motion.div
                                                    key={module.key}
                                                    initial={{
                                                        opacity: 0,
                                                        y:       20,
                                                        scale:   0.95,
                                                    }}
                                                    animate={{
                                                        opacity: 1,
                                                        y:       0,
                                                        scale:   1,
                                                    }}
                                                    transition={{
                                                        delay:    index * 0.1,
                                                        duration: 0.3,
                                                    }}
                                                    whileHover={{
                                                        scale: 1.02,
                                                        y:     -4,
                                                    }}
                                                    whileTap={{
                                                        scale: 0.98,
                                                    }}
                                                >
                                                    <Card className={cn(
                                                        `relative overflow-hidden transition-all duration-300 h-full hover-lift`,
                                                        isEnabled
                                                            ? `border-primary/50 shadow-lg shadow-primary/10`
                                                            : `border-border`
                                                    )}>
                                                        <CardHeader className="relative pb-2">
                                                            <div className="flex items-start justify-between">
                                                                <motion.div
                                                                    className={cn(
                                                                        `p-3 rounded-xl bg-gradient-to-br shadow-lg`,
                                                                        module.color
                                                                    )}
                                                                    whileHover={{
                                                                        rotate: 5,
                                                                        scale:  1.1,
                                                                    }}
                                                                    transition={{
                                                                        type:      `spring`,
                                                                        stiffness: 300,
                                                                    }}
                                                                >
                                                                    {module.icon && <module.icon className="h-6 w-6 text-white" />}
                                                                </motion.div>
                                                                <motion.div
                                                                    whileHover={{
                                                                        scale: 1.1,
                                                                    }}
                                                                    whileTap={{
                                                                        scale: 0.9,
                                                                    }}
                                                                >
                                                                    <Switch
                                                                        id={module.key}
                                                                        checked={isEnabled}
                                                                        onCheckedChange={async(checked) => handleModuleToggle(module.key, checked)}
                                                                        disabled={updateSetting.isPending}
                                                                        className="data-[state=checked]:bg-primary"
                                                                    />
                                                                </motion.div>
                                                            </div>
                                                        </CardHeader>
                                                        <CardContent className="relative">
                                                            <CardTitle className="text-lg mb-1">{module.name}</CardTitle>
                                                            <p className="text-sm text-muted-foreground mb-4">{module.description}</p>

                                                            {/* Features list */}
                                                            <div className="flex flex-wrap gap-1.5">
                                                                {module.features.map((feature, i) => (
                                                                    <span
                                                                        key={i}
                                                                        className={cn(
                                                                            `text-xs px-2 py-0.5 rounded-full`,
                                                                            isEnabled
                                                                                ? `bg-primary/10 text-primary`
                                                                                : `bg-muted text-muted-foreground`
                                                                        )}
                                                                    >
                                                                        {feature}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        </CardContent>

                                                        {/* Status indicator */}
                                                        <motion.div
                                                            className="absolute bottom-0 left-0 right-0 h-1"
                                                            initial={{
                                                                scaleX: 0,
                                                            }}
                                                            animate={{
                                                                scaleX: isEnabled ? 1 : 0,
                                                            }}
                                                            transition={{
                                                                duration: 0.3,
                                                            }}
                                                            style={{
                                                                background: `linear-gradient(90deg, ${ module.color.replace(`from-`, ``).split(` `)[0] }, ${ module.color.replace(`to-`, ``).split(` `)[1] })`,
                                                            }}
                                                        />
                                                    </Card>
                                                </motion.div>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}
                        </>
                    ) : (
                        <Card>
                            <CardContent className="pt-6">
                                <div className="flex items-center gap-3 text-muted-foreground">
                                    <AlertCircle className="h-5 w-5" />
                                    <p>You need super admin privileges to manage module settings.</p>
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </motion.div>
            )}

            {activeTab === `security` && (
                <motion.div
                    initial={{
                        opacity: 0,
                        y:       10,
                    }}
                    animate={{
                        opacity: 1,
                        y:       0,
                    }}
                    transition={{
                        duration: 0.3,
                    }}
                >
                    {isSuperAdmin ? (
                        <>
                            {isLoading ? (
                                <Card>
                                    <CardContent className="pt-6">
                                        <div className="flex items-center gap-2">
                                            <Loader2 className="h-4 w-4 animate-spin" />
                                            <p className="text-muted-foreground">Loading security settings...</p>
                                        </div>
                                    </CardContent>
                                </Card>
                            ) : (
                                <div className="space-y-6">
                                    {/* MFA Enforcement Card */}
                                    <motion.div
                                        initial={{
                                            opacity: 0,
                                            y:       20,
                                        }}
                                        animate={{
                                            opacity: 1,
                                            y:       0,
                                        }}
                                        transition={{
                                            delay: 0.1,
                                        }}
                                    >
                                        <Card className="border-primary/20">
                                            <CardHeader>
                                                <div className="flex items-center gap-3">
                                                    <motion.div
                                                        className="p-2 rounded-lg bg-gradient-to-br from-green-500 to-emerald-500"
                                                        whileHover={{
                                                            scale: 1.1,
                                                        }}
                                                    >
                                                        <ShieldIcon className="h-5 w-5 text-white" />
                                                    </motion.div>
                                                    <div>
                                                        <CardTitle>MFA Enforcement</CardTitle>
                                                        <CardDescription>
                                                            Configure Multi-Factor Authentication requirements
                                                        </CardDescription>
                                                    </div>
                                                </div>
                                            </CardHeader>
                                            <CardContent className="space-y-4">
                                                <motion.div
                                                    className="flex items-center justify-between p-4 rounded-lg bg-muted/50"
                                                    whileHover={{
                                                        scale: 1.01,
                                                    }}
                                                >
                                                    <div className="space-y-1">
                                                        <Label htmlFor="require-mfa" className="text-base">
                                                            Require MFA for all users
                                                        </Label>
                                                        <p className="text-sm text-muted-foreground">
                                                            When enabled, all users must set up MFA before accessing the system.
                                                            Recommended for production environments.
                                                        </p>
                                                    </div>
                                                    <motion.div
                                                        whileHover={{
                                                            scale: 1.05,
                                                        }}
                                                        whileTap={{
                                                            scale: 0.95,
                                                        }}
                                                    >
                                                        <Switch
                                                            id="require-mfa"
                                                            checked={settingsMap.get(`require_mfa`)?.value === `true`}
                                                            onCheckedChange={handleRequireMfaChange}
                                                            disabled={updateSetting.isPending}
                                                            className="data-[state=checked]:bg-green-500"
                                                        />
                                                    </motion.div>
                                                </motion.div>

                                                {/* Info box */}
                                                <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/20">
                                                    <div className="flex items-start gap-3">
                                                        <AlertCircle className="h-5 w-5 text-amber-500 mt-0.5" />
                                                        <div className="text-sm">
                                                            <p className="font-medium text-amber-500">Security Notice</p>
                                                            <p className="text-muted-foreground">
                                                                Enabling MFA enforcement will require all existing users to set up two-factor authentication
                                                                on their next login. Make sure to notify users before enabling this setting.
                                                            </p>
                                                        </div>
                                                    </div>
                                                </div>
                                            </CardContent>
                                        </Card>
                                    </motion.div>
                                </div>
                            )}
                        </>
                    ) : (
                        <Card>
                            <CardContent className="pt-6">
                                <div className="flex items-center gap-3 text-muted-foreground">
                                    <AlertCircle className="h-5 w-5" />
                                    <p>You need super admin privileges to manage security settings.</p>
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </motion.div>
            )}

            {activeTab === `database` && (
                <motion.div
                    initial={{
                        opacity: 0,
                        y:       10,
                    }}
                    animate={{
                        opacity: 1,
                        y:       0,
                    }}
                    transition={{
                        duration: 0.3,
                    }}
                >
                    <Card>
                        <CardHeader>
                            <div className="flex items-center gap-3">
                                <motion.div
                                    className="p-2 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500"
                                    whileHover={{
                                        rotate: 5,
                                        scale:  1.1,
                                    }}
                                >
                                    <Database className="h-5 w-5 text-white" />
                                </motion.div>
                                <div>
                                    <CardTitle>Database Connection</CardTitle>
                                    <CardDescription>
                                        Manage database connection settings
                                    </CardDescription>
                                </div>
                            </div>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Database URL</Label>
                                <Input type="password" value="••••••••••••••••" disabled />
                                <p className="text-xs text-muted-foreground">
                                    Database configuration is managed through environment variables.
                                    Contact your administrator to change database settings.
                                </p>
                            </div>

                            {/* Database Stats */}
                            <div className="grid gap-4 md:grid-cols-3">
                                {[
                                    {
                                        label: `Connection Pool`,
                                        value: `10/100`,
                                    },
                                    {
                                        label: `Query Time`,
                                        value: `12ms avg`,
                                    },
                                    {
                                        label: `Uptime`,
                                        value: `99.9%`,
                                    },
                                ].map((stat, index) => (
                                    <motion.div
                                        key={stat.label}
                                        className="p-4 rounded-lg bg-muted/50"
                                        initial={{
                                            opacity: 0,
                                            y:       10,
                                        }}
                                        animate={{
                                            opacity: 1,
                                            y:       0,
                                        }}
                                        transition={{
                                            delay: index * 0.1,
                                        }}
                                        whileHover={{
                                            scale: 1.02,
                                        }}
                                    >
                                        <p className="text-sm text-muted-foreground">{stat.label}</p>
                                        <p className="text-2xl font-bold">{stat.value}</p>
                                    </motion.div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>
                </motion.div>
            )}
        </div>
    );
}
