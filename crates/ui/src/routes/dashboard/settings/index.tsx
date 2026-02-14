import { useState } from "react";
import { createFileRoute, redirect, useSearch, useNavigate } from "@tanstack/react-router";
import { getAccessToken, getStoredUser } from "@/lib/api";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Database, Shield, MonitorCheck
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { Switch } from "@/components/ui/switch";
import { 
    useSettings, 
    useUpdateSetting 
} from "@/hooks/useApi";
import { Loader2, AlertCircle, CheckCircle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

// Type for tab search params
interface SettingsSearchParams {
    tab?: "modules" | "security" | "database";
}

export const Route = createFileRoute("/dashboard/settings/")({
    beforeLoad: () => {
        // Check if user is authenticated
        const token = getAccessToken();
        const user = getStoredUser();
        
        if (!token || !user) {
            throw redirect({
                to: '/login',
                replace: true,
            });
        }
    },
    validateSearch: (search: SettingsSearchParams) => {
        return {
            tab: search.tab || "modules",
        };
    },
    component: SettingsPage,
});

interface SystemSetting {
    id:           string
    key:          string
    value:        string
    description?: string
    updated_at:   string
}

// Module definitions with descriptions
const MODULE_CONFIG = [
    {
        key: `module_assets`,
        name: `Assets`,
        description: `Enable or disable the Assets management module. This module provides inventory and asset tracking capabilities.`,
    },
    {
        key: `module_software`,
        name: `Software`,
        description: `Enable or disable the Software module. This module manages software inventory and license tracking.`,
    },
    {
        key: `module_security`,
        name: `Security`,
        description: `Enable or disable the Security module. This module provides security configuration and policy management.`,
    },
    {
        key: `module_network`,
        name: `Network`,
        description: `Enable or disable the Network module. This module handles network infrastructure mapping and monitoring.`,
    },
    {
        key: `module_vulnerabilities`,
        name: `Vulnerabilities`,
        description: `Enable or disable the Vulnerabilities module. This module tracks and manages security vulnerabilities.`,
    },
    {
        key: `module_bia`,
        name: `Business Impact Analysis`,
        description: `Enable or disable the Business Impact Analysis module. This module manages BIA assessments and continuity planning.`,
    },
    {
        key: `module_vendors`,
        name: `Vendors`,
        description: `Enable or disable the Vendors module. This module manages vendor relationships and third-party risk.`,
    },
];

export default function SettingsPage() {
    // Get tab from search params
    const search = useSearch({ from: "/dashboard/settings/" });
    const activeTab = search.tab || "modules";
    const navigate = useNavigate({ from: "/dashboard/settings/" });

    // Function to change tab via URL
    const setTab = (tab: string) => {
        navigate({ search: { tab: tab as any } });
    };

    const { user } = useAuth();
    const { data: settingsData, isLoading } = useSettings();
    const updateSetting = useUpdateSetting();
    
    const settings: SystemSetting[] = settingsData?.settings || [];
    
    // Alert state
    const [alert, setAlert] = useState<{ type: "success" | "error"; message: string } | null>(null);

    // Check if user is super admin
    const isSuperAdmin = user?.roles?.includes(`super_admin`) ?? false;

    // Parse settings into a map
    const settingsMap = new Map<string, SystemSetting>();
    settings.forEach(s => settingsMap.set(s.key, s));

    // Get module settings
    const getModuleValue = (key: string) => {
        const setting = settingsMap.get(key);
        return setting?.value === `true`;
    };

    // Handle module toggle
    const handleModuleToggle = async(moduleKey: string, enabled: boolean) => {
        if (!isSuperAdmin) return;
        
        try {
            await updateSetting.mutateAsync({ key: moduleKey, value: enabled.toString() });
            setAlert({ type: "success", message: `${moduleKey.replace('module_', '')} module ${enabled ? 'enabled' : 'disabled'}` });
            setTimeout(() => setAlert(null), 3000);
        }
        catch (err: any) {
            setAlert({ type: "error", message: err.message || `Failed to update ${moduleKey}` });
        }
    };

    // Handle require MFA toggle
    const handleRequireMfaChange = async(enabled: boolean) => {
        if (!isSuperAdmin) return;
        
        try {
            await updateSetting.mutateAsync({ key: `require_mfa`, value: enabled.toString() });
            setAlert({ type: "success", message: `MFA requirement ${enabled ? 'enabled' : 'disabled'}` });
            setTimeout(() => setAlert(null), 3000);
        }
        catch (err: any) {
            setAlert({ type: "error", message: err.message || `Failed to update MFA requirement` });
        }
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
                <p className="text-muted-foreground">
                    Configure application settings.
                </p>
            </div>

            {alert && (
                <Alert variant={alert.type === "error" ? "destructive" : alert.type === "success" ? "default" : "default"} className={alert.type === "success" ? "border-green-500 dark:border-green-600 bg-green-50 dark:bg-green-950/30" : ""}>
                    {alert.type === "success" ? <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-400" /> : <AlertCircle className="h-4 w-4" />}
                    <AlertTitle>{alert.type === "success" ? "Success" : "Error"}</AlertTitle>
                    <AlertDescription>{alert.message}</AlertDescription>
                </Alert>
            )}

            {/* Tab Navigation using search params */}
            <div className="flex gap-1 border-b">
                <button
                    onClick={() => setTab("modules")}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                        activeTab === "modules"
                            ? "border-primary text-primary"
                            : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                >
                    <MonitorCheck className="w-4 h-4" />
                    Modules
                </button>
                <button
                    onClick={() => setTab("security")}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                        activeTab === "security"
                            ? "border-primary text-primary"
                            : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                >
                    <Shield className="w-4 h-4" />
                    Security
                </button>
                <button
                    onClick={() => setTab("database")}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                        activeTab === "database"
                            ? "border-primary text-primary"
                            : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                >
                    <Database className="w-4 h-4" />
                    Database
                </button>
            </div>

            {activeTab === "modules" && (
                <div className="space-y-4">
                    {isSuperAdmin
? (
                            <>
                                {isLoading
? (
                                        <Card>
                                            <CardContent className="pt-6">
                                                <div className="flex items-center gap-2">
                                                    <Loader2 className="h-4 w-4 animate-spin" />
                                                    <p className="text-muted-foreground">Loading module settings...</p>
                                                </div>
                                            </CardContent>
                                        </Card>
                                    )
: (
                                        <Card>
                                            <CardHeader>
                                                <CardTitle>Module Configuration</CardTitle>
                                                <CardDescription>
                                                    Enable or disable system modules. Modules that are disabled will not be accessible to users.
                                                </CardDescription>
                                            </CardHeader>
                                            <CardContent className="space-y-6">
                                                {MODULE_CONFIG.map((module) => (
                                                    <div key={module.key} className="flex items-center justify-between">
                                                        <div className="space-y-1 max-w-md">
                                                            <Label htmlFor={module.key} className="text-base">
                                                                {module.name}
                                                            </Label>
                                                            <p className="text-sm text-muted-foreground">
                                                                {module.description}
                                                            </p>
                                                        </div>
                                                        <Switch
                                                            id={module.key}
                                                            checked={getModuleValue(module.key)}
                                                            onCheckedChange={(checked) => handleModuleToggle(module.key, checked)}
                                                            disabled={updateSetting.isPending}
                                                        />
                                                    </div>
                                                ))}
                                            </CardContent>
                                        </Card>
                                    )}
                            </>
                        )
: (
                                <Card>
                                    <CardContent className="pt-6">
                                        <p className="text-muted-foreground">
                                            You need super admin privileges to manage module settings.
                                        </p>
                                    </CardContent>
                                </Card>
                            )}
                </div>
            )}

            {activeTab === "security" && (
                <div className="space-y-4">
                    {isSuperAdmin
? (
                            <>
                                {isLoading
? (
                                        <Card>
                                            <CardContent className="pt-6">
                                                <div className="flex items-center gap-2">
                                                    <Loader2 className="h-4 w-4 animate-spin" />
                                                    <p className="text-muted-foreground">Loading security settings...</p>
                                                </div>
                                            </CardContent>
                                        </Card>
                                    )
: (
                                        <Card>
                                            <CardHeader>
                                                <CardTitle>MFA Enforcement</CardTitle>
                                                <CardDescription>
                                                    Configure Multi-Factor Authentication requirements for all users.
                                                </CardDescription>
                                            </CardHeader>
                                            <CardContent className="space-y-4">
                                                <div className="flex items-center justify-between">
                                                    <div className="space-y-1 max-w-md">
                                                        <Label htmlFor="require-mfa">Require MFA for all users</Label>
                                                        <p className="text-sm text-muted-foreground">
                                                            When enabled, all users must set up MFA before they can access the system.
                                                            Users without MFA will be prompted to set it up on their next login.
                                                            This is recommended for production environments.
                                                        </p>
                                                    </div>
                                                    <Switch
                                                        id="require-mfa"
                                                        checked={settingsMap.get(`require_mfa`)?.value === `true`}
                                                        onCheckedChange={handleRequireMfaChange}
                                                        disabled={updateSetting.isPending}
                                                    />
                                                </div>
                                            </CardContent>
                                        </Card>
                                    )}
                            </>
                        )
: (
                                <Card>
                                    <CardContent className="pt-6">
                                        <p className="text-muted-foreground">
                                            You need super admin privileges to manage security settings.
                                        </p>
                                    </CardContent>
                                </Card>
                            )}
                </div>
            )}

            {activeTab === "database" && (
                <div className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Database Connection</CardTitle>
                            <CardDescription>
                                Manage database connection settings.
                            </CardDescription>
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
                        </CardContent>
                    </Card>
                </div>
            )}
        </div>
    );
}
