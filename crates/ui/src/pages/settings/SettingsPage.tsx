import {
    useEffect, useState
} from "react";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Tabs, TabsContent, TabsList, TabsTrigger
} from "@/components/ui/tabs";
import {
    Database, Bot, Shield, MonitorCheck
} from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/context/AuthContext";
import { Switch } from "@/components/ui/switch";

interface SystemSetting {
    id:           string
    key:          string
    value:        string
    description?: string
    updated_at:   string
}

export default function SettingsPage() {
    const {
        user,
    } = useAuth();
    const [
        _settings,
        setSettings,
    ] = useState<Array<SystemSetting>>([]);
    const [
        loading,
        setLoading,
    ] = useState(true);
    const [
        saving,
        setSaving,
    ] = useState(false);
    const [
        error,
        setError,
    ] = useState<string | null>(null);
    const [
        requireMfa,
        setRequireMfa,
    ] = useState(false);
    const [
        moduleSettings,
        setModuleSettings,
    ] = useState<Record<string, boolean>>({});

    // Check if user is super admin
    const isSuperAdmin = user?.roles?.includes(`super_admin`) ?? false;

    useEffect(() => {
        if (isSuperAdmin) {
            loadSettings();
        }
        else {
            setLoading(false);
        }
    }, [ isSuperAdmin ]);

    const loadSettings = async() => {
        try {
            setLoading(true);
            setError(null);
            const response = await api.getSettings();
            setSettings(response.settings);

            // Parse settings for UI
            const requireMfaSetting = response.settings.find((s: SystemSetting) => s.key === `require_mfa`);
            setRequireMfa(requireMfaSetting?.value === `true`);

            // Parse module settings
            const modules: Record<string, boolean> = {};
            response.settings.forEach((s: SystemSetting) => {
                if (s.key.startsWith(`module_`)) {
                    modules[s.key] = s.value === `true`;
                }
            });
            setModuleSettings(modules);
        }
        catch (err) {
            console.error(`Failed to load settings:`, err);
            setError(`Failed to load settings`);
        }
        finally {
            setLoading(false);
        }
    };

    const handleRequireMfaChange = async(enabled: boolean) => {
        if (!isSuperAdmin) {
            return;
        }

        try {
            setSaving(true);
            await api.updateSetting(`require_mfa`, enabled.toString());
            setRequireMfa(enabled);
        }
        catch (err) {
            console.error(`Failed to update require_mfa:`, err);
            setError(`Failed to update MFA requirement`);
        }
        finally {
            setSaving(false);
        }
    };

    const handleModuleToggle = async(moduleKey: string, enabled: boolean) => {
        if (!isSuperAdmin) {
            return;
        }

        try {
            setSaving(true);
            await api.updateSetting(moduleKey, enabled.toString());
            setModuleSettings((prev) => ({
                ...prev,
                [moduleKey]: enabled,
            }));
        }
        catch (err) {
            console.error(`Failed to update ${ moduleKey }:`, err);
            setError(`Failed to update ${ moduleKey }`);
        }
        finally {
            setSaving(false);
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

            <Tabs defaultValue="security" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="security" className="gap-2">
                        <Shield className="w-4 h-4" />
                        Security
                    </TabsTrigger>
                    <TabsTrigger value="modules" className="gap-2">
                        <MonitorCheck className="w-4 h-4" />
                        Modules
                    </TabsTrigger>
                    <TabsTrigger value="database" className="gap-2">
                        <Database className="w-4 h-4" />
                        Database
                    </TabsTrigger>
                    <TabsTrigger value="ai" className="gap-2">
                        <Bot className="w-4 h-4" />
                        AI Providers
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="security" className="space-y-4">
                    {isSuperAdmin
? (
                        <>
                            {loading
? (
                                <Card>
                                    <CardContent className="pt-6">
                                        <p className="text-muted-foreground">Loading settings...</p>
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
                                        {error && (
                                            <div className="bg-red-50 border border-red-200 text-red-800 px-4 py-2 rounded">
                                                {error}
                                            </div>
                                        )}
                                        <div className="flex items-center justify-between">
                                            <div className="space-y-1">
                                                <Label htmlFor="require-mfa">Require MFA for all users</Label>
                                                <p className="text-sm text-muted-foreground">
                                                    When enabled, all users must set up MFA before they can access the system.
                                                    Users without MFA will be prompted to set it up on their next login.
                                                </p>
                                            </div>
                                            <Switch
                                                id="require-mfa"
                                                checked={requireMfa}
                                                onCheckedChange={handleRequireMfaChange}
                                                disabled={saving}
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
                </TabsContent>

                <TabsContent value="modules" className="space-y-4">
                    {isSuperAdmin
? (
                        <>
                            {loading
? (
                                <Card>
                                    <CardContent className="pt-6">
                                        <p className="text-muted-foreground">Loading module settings...</p>
                                    </CardContent>
                                </Card>
                            )
: (
                                <Card>
                                    <CardHeader>
                                        <CardTitle>Module Configuration</CardTitle>
                                        <CardDescription>
                                            Enable or disable system modules.
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent className="space-y-4">
                                        {error && (
                                            <div className="bg-red-50 border border-red-200 text-red-800 px-4 py-2 rounded">
                                                {error}
                                            </div>
                                        )}
                                        <div className="space-y-4">
                                            {Object.entries(moduleSettings).map(([
                                                key,
                                                enabled,
                                            ]) => (
                                                <div key={key} className="flex items-center justify-between">
                                                    <div className="space-y-1">
                                                        <Label htmlFor={key}>
                                                            {key.replace(`module_`, ``).charAt(0)
                                                                .toUpperCase() +
                                                                key.replace(`module_`, ``).slice(1)}
                                                        </Label>
                                                        <p className="text-sm text-muted-foreground">
                                                            {key === `module_assets` && `Enable or disable the Assets management module`}
                                                            {key === `module_agents` && `Enable or disable the Agents module`}
                                                            {key === `module_software` && `Enable or disable the Software module`}
                                                            {key === `module_vulnerabilities` && `Enable or disable Vulnerabilities tracking`}
                                                            {key === `module_automation` && `Enable or disable Automation features`}
                                                            {key === `module_notifications` && `Enable or disable Notifications`}
                                                        </p>
                                                    </div>
                                                    <Switch
                                                        id={key}
                                                        checked={enabled}
                                                        onCheckedChange={async(checked) => handleModuleToggle(key, checked)}
                                                        disabled={saving}
                                                    />
                                                </div>
                                            ))}
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
                                    You need super admin privileges to manage module settings.
                                </p>
                            </CardContent>
                        </Card>
                    )}
                </TabsContent>

                <TabsContent value="database" className="space-y-4">
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
                            </div>
                            <p className="text-sm text-muted-foreground">
                                Database configuration is managed through environment variables.
                            </p>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="ai" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>AI Providers</CardTitle>
                            <CardDescription>
                                Configure AI providers for enhanced functionality.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <p className="text-sm text-muted-foreground">
                                AI provider settings will be available in a future update.
                            </p>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>
        </div>
    );
}
