import { useState, useEffect } from "react";
import { useForm } from "@tanstack/react-form";
import { createFileRoute, redirect, useSearch, useNavigate } from "@tanstack/react-router";
import { useAuth } from "@/context/AuthContext";
import { setStoredUser, getAccessToken, getStoredUser } from "@/lib/api";
import { toastSuccess, toastError } from "@/lib/toast";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
    User, Shield, Key, Loader2, Monitor, Trash2, Bell,
    Copy, RefreshCw, Smartphone, ShieldAlert, ShieldCheck, Eye, EyeOff, LogOut, X,
    Clock, Globe, Settings, CheckCircle, AlertCircle
} from "lucide-react";
import { motion } from "motion/react";
import { Badge } from "@/components/ui/badge";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import {
    useProfile,
    useUpdateProfile,
    useChangePassword,
    useApiKeys,
    useCreateApiKey,
    useDeleteApiKey,
    useRotateApiKey,
    useUpdateApiKeyPermissions,
    useApiKeyUsage,
    useSessions,
    useDeleteSession,
    useDeleteAllSessions,
    useMfaStatus,
    useEnableMfa,
    useVerifyMfaSetup,
    useDisableMfa,
    useRegenerateBackupCodes,
} from "@/hooks/useApi";

// Type for tab search params
interface ProfileSearchParams {
    tab?: "profile" | "security" | "notifications" | "apikeys" | "sessions";
}

// Form value interfaces
interface ProfileFormValues {
    full_name: string;
}

interface PasswordFormValues {
    currentPassword: string;
    newPassword: string;
    confirmPassword: string;
}

interface MfaVerifyFormValues {
    mfaCode: string;
}

export const Route = createFileRoute("/dashboard/profile/")({
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
    validateSearch: (search: ProfileSearchParams) => {
        return {
            tab: search.tab || "profile",
        };
    },
    component: ProfilePage,
});

interface ApiKeyFormValues {
    name: string;
}

// Profile Update Form Component
function ProfileUpdateForm({
    initialFullName,
    onSuccess,
}: {
    initialFullName: string;
    onSuccess: () => void;
}) {
    const updateProfile = useUpdateProfile();
    const { user, refreshUser } = useAuth();

    const form = useForm<ProfileFormValues>({
        defaultValues: {
            full_name: initialFullName,
        },
        onSubmit: async ({ value }) => {
            try {
                await updateProfile.mutateAsync({
                    full_name: value.full_name,
                });

                // Update stored user
                const updatedUser = {
                    id: user?.id || "",
                    email: user?.email || "",
                    displayName: value.full_name,
                    roles: user?.roles || [],
                };
                setStoredUser(updatedUser);
                await refreshUser();
                onSuccess();
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Failed to update profile");
            }
        },
    });

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
            className="space-y-4"
        >
            <form.Field
                name="full_name"
                children={(field) => (
                    <div className="space-y-2">
                        <Label htmlFor={field.name}>Full Name</Label>
                        <Input
                            id={field.name}
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                        />
                        <p className="text-xs text-muted-foreground">
                            Your full name as it will appear in the system
                        </p>
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />
            <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" value={user?.email || ""} disabled />
                <p className="text-xs text-muted-foreground">
                    Your email address cannot be changed
                </p>
            </div>
            <Button type="submit" disabled={form.state.isSubmitting}>
                {form.state.isSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Save Changes
            </Button>
        </form>
    );
}

// Password Change Form Component
function PasswordChangeForm({ onSuccess }: { onSuccess: () => void }) {
    const changePassword = useChangePassword();

    const form = useForm<PasswordFormValues>({
        defaultValues: {
            currentPassword: "",
            newPassword: "",
            confirmPassword: "",
        },
        onSubmit: async ({ value }) => {
            if (value.newPassword !== value.confirmPassword) {
                throw new Error("Passwords do not match");
            }
            try {
                await changePassword.mutateAsync({
                    currentPassword: value.currentPassword,
                    newPassword: value.newPassword,
                });
                form.reset();
                onSuccess();
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Failed to change password");
            }
        },
    });

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
            className="space-y-4"
        >
            <form.Field
                name="currentPassword"
                children={(field) => (
                    <div className="space-y-2">
                        <Label htmlFor={field.name}>Current Password</Label>
                        <Input
                            id={field.name}
                            type="password"
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            required
                        />
                        <p className="text-xs text-muted-foreground">
                            Enter your current password to verify your identity
                        </p>
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />
            <form.Field
                name="newPassword"
                children={(field) => (
                    <div className="space-y-2">
                        <Label htmlFor={field.name}>New Password</Label>
                        <Input
                            id={field.name}
                            type="password"
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            required
                        />
                        <p className="text-xs text-muted-foreground">
                            Must be at least 8 characters
                        </p>
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />
            <form.Field
                name="confirmPassword"
                children={(field) => (
                    <div className="space-y-2">
                        <Label htmlFor={field.name}>Confirm New Password</Label>
                        <Input
                            id={field.name}
                            type="password"
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            required
                        />
                        <p className="text-xs text-muted-foreground">
                            Re-enter your new password to confirm
                        </p>
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />
            <Button type="submit" disabled={form.state.isSubmitting}>
                {form.state.isSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Update Password
            </Button>
        </form>
    );
}

// MFA Verify Form Component
function MfaVerifyForm({
    onSuccess,
}: {
    onSuccess: () => void;
}) {
    const verifyMfaSetup = useVerifyMfaSetup();

    const form = useForm<MfaVerifyFormValues>({
        defaultValues: {
            mfaCode: "",
        },
        onSubmit: async ({ value }) => {
            try {
                await verifyMfaSetup.mutateAsync(value.mfaCode);
                form.reset();
                onSuccess();
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Invalid verification code");
            }
        },
    });

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
            className="space-y-2"
        >
            <Label>Enter verification code</Label>
            <form.Field
                name="mfaCode"
                children={(field) => (
                    <>
                        <Input
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            placeholder="123456"
                            required
                        />
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </>
                )}
            />
            <p className="text-xs text-muted-foreground">
                Enter the 6-digit code from your authenticator app
            </p>
            <Button type="submit" disabled={form.state.isSubmitting}>
                {form.state.isSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Verify & Enable
            </Button>
        </form>
    );
}

// API Key Form Component
function CreateApiKeyForm({ onSuccess }: { onSuccess: (key: string) => void }) {
    const createApiKey = useCreateApiKey();

    const form = useForm<ApiKeyFormValues>({
        defaultValues: {
            name: "",
        },
        onSubmit: async ({ value }) => {
            try {
                const result = await createApiKey.mutateAsync({ name: value.name });
                form.reset();
                onSuccess(result.key || "");
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Failed to create API key");
            }
        },
    });

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
            className="flex gap-2"
        >
            <div className="space-y-2 flex-1">
                <form.Field
                    name="name"
                    children={(field) => (
                        <>
                            <Input
                                placeholder="API key name"
                                value={field.state.value}
                                onChange={(e) => field.handleChange(e.target.value)}
                                onBlur={field.handleBlur}
                                required
                            />
                            <p className="text-xs text-muted-foreground">
                                A descriptive name to help you identify this key
                            </p>
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </>
                    )}
                />
            </div>
            <Button type="submit" disabled={form.state.isSubmitting}>
                {form.state.isSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Create
            </Button>
        </form>
    );
}

// API Key Details Dialog Component
function ApiKeyDetailsDialog({ keyId, onClose }: { keyId: string; onClose: () => void }) {
    const { data: apiKeysData } = useApiKeys();
    const { data: usageData, isLoading: usageLoading } = useApiKeyUsage(keyId);
    const updatePermissions = useUpdateApiKeyPermissions();

    const apiKey = apiKeysData?.items.find((k) => k.id === keyId);
    const [editingPermissions, setEditingPermissions] = useState(false);
    const [permissions, setPermissions] = useState<string[]>([]);

    useEffect(() => {
        if (apiKey?.permissions) {
            const perms = apiKey.permissions as Record<string, boolean>;
            setPermissions(Object.keys(perms).filter((p) => perms[p]));
        }
    }, [apiKey]);

    const handleSavePermissions = async() => {
        try {
            await updatePermissions.mutateAsync({
                id: keyId,
                permissions,
            });
            setEditingPermissions(false);
        }
        catch (err) {
            console.error("Failed to update permissions:", err);
        }
    };

    if (!apiKey) {
        return <div className="p-4">Loading...</div>;
    }

    return (
        <div className="space-y-6">
            {/* Key Info */}
            <div className="p-4 bg-muted/50 rounded-xl">
                <div className="flex items-center gap-3 mb-3">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center">
                        <Key className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                        <h3 className="font-semibold text-lg">{apiKey.name}</h3>
                        <p className="text-sm text-muted-foreground font-mono">{apiKey.key_prefix}...</p>
                    </div>
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                        <p className="text-muted-foreground">Created</p>
                        <p>{new Date(apiKey.created_at).toLocaleString()}</p>
                    </div>
                    {apiKey.expires_at && (
                        <div>
                            <p className="text-muted-foreground">Expires</p>
                            <p className="text-amber-600">{new Date(apiKey.expires_at).toLocaleString()}</p>
                        </div>
                    )}
                    {apiKey.last_used_at && (
                        <div>
                            <p className="text-muted-foreground">Last Used</p>
                            <p>{new Date(apiKey.last_used_at).toLocaleString()}</p>
                        </div>
                    )}
                    {apiKey.last_used_ip && (
                        <div>
                            <p className="text-muted-foreground">Last IP</p>
                            <p className="font-mono">{apiKey.last_used_ip}</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Permissions */}
            <div>
                <div className="flex items-center justify-between mb-3">
                    <h4 className="font-medium flex items-center gap-2">
                        <Shield className="w-4 h-4" />
                        Permissions
                    </h4>
                    {!editingPermissions && (
                        <Button variant="outline" size="sm" onClick={() => setEditingPermissions(true)}>
                            Edit
                        </Button>
                    )}
                </div>
                {editingPermissions ? (
                    <div className="space-y-3">
                        {/* User Permissions */}
                        <div>
                            <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wide">Users</p>
                            <div className="flex flex-wrap gap-2">
                                {[
                                    { value: `users:create`, label: `Create` },
                                    { value: `users:read`, label: `Read` },
                                    { value: `users:update`, label: `Update` },
                                    { value: `users:delete`, label: `Delete` },
                                ].map((perm) => (
                                    <Badge
                                        key={perm.value}
                                        variant={permissions.includes(perm.value) ? `default` : `outline`}
                                        className="cursor-pointer transition-all hover:scale-105"
                                        onClick={() => {
                                            setPermissions((prev) => prev.includes(perm.value) ? prev.filter((p) => p !== perm.value) : [...prev, perm.value]);
                                        }}
                                    >
                                        {perm.label}
                                    </Badge>
                                ))}
                            </div>
                        </div>
                        {/* Team Permissions */}
                        <div>
                            <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wide">Teams</p>
                            <div className="flex flex-wrap gap-2">
                                {[
                                    { value: `teams:create`, label: `Create` },
                                    { value: `teams:read`, label: `Read` },
                                    { value: `teams:update`, label: `Update` },
                                    { value: `teams:delete`, label: `Delete` },
                                    { value: `teams:members_read`, label: `Members Read` },
                                    { value: `teams:members_add`, label: `Members Add` },
                                    { value: `teams:members_update`, label: `Members Update` },
                                    { value: `teams:members_remove`, label: `Members Remove` },
                                ].map((perm) => (
                                    <Badge
                                        key={perm.value}
                                        variant={permissions.includes(perm.value) ? `default` : `outline`}
                                        className="cursor-pointer transition-all hover:scale-105"
                                        onClick={() => {
                                            setPermissions((prev) => prev.includes(perm.value) ? prev.filter((p) => p !== perm.value) : [...prev, perm.value]);
                                        }}
                                    >
                                        {perm.label}
                                    </Badge>
                                ))}
                            </div>
                        </div>
                        {/* API Keys Permissions */}
                        <div>
                            <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wide">API Keys</p>
                            <div className="flex flex-wrap gap-2">
                                {[
                                    { value: `api_keys:create`, label: `Create` },
                                    { value: `api_keys:read`, label: `Read` },
                                    { value: `api_keys:update`, label: `Update` },
                                    { value: `api_keys:delete`, label: `Delete` },
                                    { value: `api_keys:rotate`, label: `Rotate` },
                                    { value: `api_keys:usage_read`, label: `Usage Read` },
                                ].map((perm) => (
                                    <Badge
                                        key={perm.value}
                                        variant={permissions.includes(perm.value) ? `default` : `outline`}
                                        className="cursor-pointer transition-all hover:scale-105"
                                        onClick={() => {
                                            setPermissions((prev) => prev.includes(perm.value) ? prev.filter((p) => p !== perm.value) : [...prev, perm.value]);
                                        }}
                                    >
                                        {perm.label}
                                    </Badge>
                                ))}
                            </div>
                        </div>
                        <div className="flex gap-2 pt-2">
                            <Button size="sm" onClick={handleSavePermissions} disabled={updatePermissions.isPending}>
                                {updatePermissions.isPending && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}
                                Save
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => setEditingPermissions(false)}>
                                Cancel
                            </Button>
                        </div>
                    </div>
                ) : (
                    <div className="flex flex-wrap gap-2">
                        {permissions.length > 0 ? (
                            permissions.map((perm) => (
                                <Badge key={perm} variant="secondary">
                                    {perm.replace(`:`, ` - `)}
                                </Badge>
                            ))
                        ) : (
                            <p className="text-sm text-muted-foreground">No specific permissions granted</p>
                        )}
                    </div>
                )}
            </div>

            {/* Usage History */}
            <div>
                <h4 className="font-medium flex items-center gap-2 mb-3">
                    <Clock className="w-4 h-4" />
                    Usage History
                </h4>
                {usageLoading ? (
                    <div className="flex items-center justify-center p-4">
                        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                    </div>
                ) : usageData?.usage && usageData.usage.length > 0 ? (
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                        {usageData.usage.map((entry: { id: string; timestamp: string; ip_address: string; endpoint: string }) => (
                            <div key={entry.id} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg text-sm">
                                <div className="flex items-center gap-3">
                                    <Globe className="w-4 h-4 text-muted-foreground" />
                                    <span className="font-mono text-xs">{entry.endpoint}</span>
                                </div>
                                <div className="flex items-center gap-3 text-muted-foreground">
                                    <span className="font-mono text-xs">{entry.ip_address}</span>
                                    <span>{new Date(entry.timestamp).toLocaleString()}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <p className="text-sm text-muted-foreground">No usage history available</p>
                )}
            </div>

            <div className="flex justify-end">
                <Button onClick={onClose}>Close</Button>
            </div>
        </div>
    );
}

export default function ProfilePage() {
    // Get tab from search params
    const search = useSearch({ from: "/dashboard/profile/" });
    const activeTab = search.tab || "profile";
    const navigate = useNavigate({ from: "/dashboard/profile/" });

    // Function to change tab via URL
    const setTab = (tab: string) => {
        navigate({ search: { tab: tab as any } });
    };

    // Queries
    const { data: profileData } = useProfile();
    const { data: mfaStatus } = useMfaStatus();
    const { data: apiKeysData } = useApiKeys();
    const { data: sessionsData, isLoading: sessionsLoading, error: sessionsError } = useSessions();

    // Mutations
    const enableMfa = useEnableMfa();
    const disableMfa = useDisableMfa();
    const regenerateBackupCodes = useRegenerateBackupCodes();
    const deleteApiKey = useDeleteApiKey();
    const rotateApiKey = useRotateApiKey();
    const deleteSession = useDeleteSession();
    const deleteAllSessions = useDeleteAllSessions();

    // MFA
    const [mfaEnabled, setMfaEnabled] = useState(false);
    const [mfaLoading, setMfaLoading] = useState(false);
    const [mfaSecret, setMfaSecret] = useState(``);
    const [mfaQrCode, setMfaQrCode] = useState(``);
    const [mfaPassword, setMfaPassword] = useState(``);
    const [mfaStep, setMfaStep] = useState<`none` | `enabling` | `verify` | `show_codes`>(`none`);
    const [backupCodes, setBackupCodes] = useState<string[]>([]);
    const [showCodes, setShowCodes] = useState(false);

    // API Keys
    const [newApiKey, setNewApiKey] = useState(``);
    const [showApiKey, setShowApiKey] = useState(false);
    const [selectedApiKeyId, setSelectedApiKeyId] = useState<string | null>(null);
    const [showApiKeyDetails, setShowApiKeyDetails] = useState(false);

    // Notification settings
    const [notificationSettings, setNotificationSettings] = useState({
        email_alerts: true,
        security_alerts: true,
        team_updates: true,
        weekly_digest: true,
    });

    // Initialize MFA status
    useEffect(() => {
        if (mfaStatus) {
            setMfaEnabled(mfaStatus.mfa_enabled ?? false);
        }
    }, [mfaStatus]);

    const apiKeys = apiKeysData?.items || [];
    // Sessions are already sorted by last_used_at DESC from backend
    const sessions = sessionsData?.items || [];
    const currentSessionId = sessionsData?.current_session;

    // Handlers
    const handleProfileSuccess = () => {
        toastSuccess(`Profile updated successfully`);
    };

    const handlePasswordSuccess = () => {
        toastSuccess(`Password changed successfully`);
    };

    const handleEnableMfa = async() => {
        if (!mfaPassword) {
            toastError(`Password is required to enable MFA`);
            return;
        }
        setMfaLoading(true);
        try {
            const result = await enableMfa.mutateAsync(mfaPassword);
            setMfaSecret(result.secret);
            setMfaQrCode(`data:image/png;base64,${result.qr_code_base64}`);
            setBackupCodes(result.backup_codes || []);
            setMfaStep(`enabling`);
            setMfaPassword(``);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || `Failed to enable MFA`);
        }
        finally {
            setMfaLoading(false);
        }
    };

    const handleMfaVerifySuccess = () => {
        setMfaEnabled(true);
        setMfaStep(`show_codes`);
        toastSuccess(`MFA enabled successfully`);
    };

    const handleShowBackupCodes = () => {
        setShowCodes(!showCodes);
    };

    const handleCopyBackupCodes = () => {
        navigator.clipboard.writeText(backupCodes.join(`\n`));
        toastSuccess(`Backup codes copied to clipboard`);
    };

    const handleRegenerateBackupCodes = async() => {
        if (!mfaPassword) {
            toastError(`Password is required to regenerate backup codes`);
            return;
        }
        try {
            const result = await regenerateBackupCodes.mutateAsync(mfaPassword);
            setBackupCodes(result.backup_codes || []);
            toastSuccess(`Backup codes regenerated`);
            setMfaPassword(``);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || `Failed to regenerate backup codes`);
        }
    };

    const handleDisableMfa = async() => {
        setMfaLoading(true);
        try {
            await disableMfa.mutateAsync(mfaPassword);
            setMfaEnabled(false);
            toastSuccess(`MFA disabled successfully`);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || `Failed to disable MFA`);
        }
        finally {
            setMfaLoading(false);
        }
    };

    const handleCreateApiKeySuccess = (key: string) => {
        setNewApiKey(key);
        setShowApiKey(true);
        toastSuccess(`API key created`);
    };

    const handleDeleteApiKey = async(id: string) => {
        try {
            await deleteApiKey.mutateAsync(id);
            toastSuccess(`API key deleted`);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || `Failed to delete API key`);
        }
    };

    const handleRotateApiKey = async(id: string) => {
        try {
            const result = await rotateApiKey.mutateAsync(id);
            setNewApiKey(result.key);
            setShowApiKey(true);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || `Failed to rotate API key`);
        }
    };

    const handleViewApiKeyDetails = (keyId: string) => {
        setSelectedApiKeyId(keyId);
        setShowApiKeyDetails(true);
    };

    const handleDeleteSession = async(sessionId: string) => {
        try {
            await deleteSession.mutateAsync(sessionId);
            toastSuccess(`Session deleted`);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || `Failed to delete session`);
        }
    };

    const handleDeleteAllSessions = async() => {
        try {
            await deleteAllSessions.mutateAsync();
            toastSuccess(`All sessions deleted`);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || `Failed to delete sessions`);
        }
    };

    const handleNotificationSettingChange = (key: keyof typeof notificationSettings) => {
        setNotificationSettings(prev => ({
            ...prev,
            [key]: !prev[key],
        }));
        toastSuccess(`Notification settings updated`);
    };

    return (
        <div className="space-y-6 relative z-10">
            {/* Animated Background Orbs */}
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
            </div>

            <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
            >
                <h1 className="text-3xl font-bold tracking-tight">Profile</h1>
                <p className="text-muted-foreground mt-1">
                    Manage your personal information and security settings.
                </p>
            </motion.div>

            {/* Tab Navigation using search params */}
            <motion.div 
                className="flex gap-1 border-b"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.1 }}
            >
                <button
                    onClick={() => setTab("profile")}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                        activeTab === "profile"
                            ? "border-primary text-primary"
                            : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                >
                    <User className="w-4 h-4" />
                    Profile
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
                    onClick={() => setTab("notifications")}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                        activeTab === "notifications"
                            ? "border-primary text-primary"
                            : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                >
                    <Bell className="w-4 h-4" />
                    Notifications
                </button>
                <button
                    onClick={() => setTab("apikeys")}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                        activeTab === "apikeys"
                            ? "border-primary text-primary"
                            : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                >
                    <Key className="w-4 h-4" />
                    API Keys
                </button>
            </motion.div>

            {/* Tab Content */}
            {activeTab === "profile" && (
                <div className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Profile Information</CardTitle>
                            <CardDescription>
                                Update your personal information.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <ProfileUpdateForm
                                initialFullName={profileData?.user?.full_name || ""}
                                onSuccess={handleProfileSuccess}
                            />
                        </CardContent>
                    </Card>
                </div>
            )}

            {/* Security Tab */}
            {activeTab === "security" && (
                <div className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Change Password</CardTitle>
                            <CardDescription>
                                Update your password to keep your account secure.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <PasswordChangeForm onSuccess={handlePasswordSuccess} />
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Smartphone className="w-5 h-5" />
                                Two-Factor Authentication
                            </CardTitle>
                            <CardDescription>
                                Add an extra layer of security to your account.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            {mfaEnabled
? (
                                <div className="space-y-4">
                                    <div className="flex items-center gap-2 text-green-500">
                                        <ShieldCheck className="w-5 h-5" />
                                        <span className="font-medium">2FA is enabled on your account</span>
                                    </div>
                                    
                                    {/* Password required for backup code operations */}
                                    <div className="space-y-2 p-3 bg-muted/50 rounded-lg">
                                        <Label htmlFor="mfaPasswordOps" className="text-sm">Enter password to manage backup codes</Label>
                                        <Input
                                            id="mfaPasswordOps"
                                            type="password"
                                            value={mfaPassword}
                                            onChange={(e) => setMfaPassword(e.target.value)}
                                            placeholder="Enter your password"
                                        />
                                    </div>
                                    
                                    {/* Backup Codes Section */}
                                    <div className="border rounded-lg p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-2">
                                                <Key className="w-4 h-4 text-muted-foreground" />
                                                <span className="font-medium text-sm">Backup Codes</span>
                                            </div>
                                            <Button variant="outline" size="sm" onClick={handleShowBackupCodes}>
                                                {showCodes ? <EyeOff className="w-4 h-4 mr-1" /> : <Eye className="w-4 h-4 mr-1" />}
                                                {showCodes ? `Hide` : `Show`}
                                            </Button>
                                        </div>
                                        
                                        {showCodes && backupCodes.length > 0 && (
                                            <div className="space-y-2">
                                                <div className="grid grid-cols-2 gap-2">
                                                    {backupCodes.map((code, index) => (
                                                        <code key={index} className="text-xs bg-muted px-2 py-1 rounded font-mono">
                                                            {code}
                                                        </code>
                                                    ))}
                                                </div>
                                                <div className="flex gap-2 pt-2">
                                                    <Button size="sm" variant="outline" onClick={handleCopyBackupCodes}>
                                                        <Copy className="w-4 h-4 mr-1" />
                                                        Copy All
                                                    </Button>
                                                    <Button size="sm" variant="outline" onClick={handleRegenerateBackupCodes} disabled={regenerateBackupCodes.isPending}>
                                                        {regenerateBackupCodes.isPending 
                                                            ? <Loader2 className="w-4 h-4 mr-1 animate-spin" />
                                                            : <RefreshCw className="w-4 h-4 mr-1" />
                                                        }
                                                        Regenerate
                                                    </Button>
                                                </div>
                                                <p className="text-xs text-muted-foreground">
                                                    Store these codes in a safe place. You can use them to access your account if you lose your authenticator.
                                                </p>
                                            </div>
                                        )}
                                        
                                        {showCodes && backupCodes.length === 0 && (
                                            <div className="text-sm text-muted-foreground">
                                                <p>No backup codes available.</p>
                                                <Button 
                                                    variant="link" 
                                                    size="sm" 
                                                    onClick={handleRegenerateBackupCodes} 
                                                    disabled={regenerateBackupCodes.isPending}
                                                    className="p-0 h-auto"
                                                >
                                                    Generate backup codes
                                                </Button>
                                            </div>
                                        )}
                                    </div>
                                    
                                    <Button variant="destructive" onClick={handleDisableMfa} disabled={mfaLoading || !mfaPassword}>
                                        {mfaLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                        Disable 2FA
                                    </Button>
                                </div>
                            )
: mfaStep === `none`
? (
                                <div className="space-y-4">
                                    <div className="flex items-center gap-2 text-muted-foreground">
                                        <ShieldAlert className="w-5 h-5" />
                                        <span className="text-sm">Add an extra layer of security to your account</span>
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="mfaPassword">Enter your password to enable 2FA</Label>
                                        <Input
                                            id="mfaPassword"
                                            type="password"
                                            value={mfaPassword}
                                            onChange={(e) => setMfaPassword(e.target.value)}
                                            placeholder="Enter your password"
                                            required
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            You must verify your password before enabling 2FA
                                        </p>
                                    </div>
                                    <Button onClick={handleEnableMfa} disabled={mfaLoading || !mfaPassword}>
                                        {mfaLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                        Enable 2FA
                                    </Button>
                                </div>
                            )
: mfaStep === `enabling` && mfaQrCode
? (
                                <div className="space-y-4">
                                    <div className="flex justify-center">
                                        <img src={mfaQrCode} alt="QR Code" className="w-48 h-48" />
                                    </div>
                                    <p className="text-sm text-muted-foreground text-center">
                                        Scan this QR code with your authenticator app
                                    </p>
                                    <div className="space-y-2">
                                        <Label>Or enter this secret manually:</Label>
                                        <code className="block p-2 bg-muted rounded text-xs">{mfaSecret}</code>
                                        <p className="text-xs text-muted-foreground">
                                            Write this down somewhere safe - you&apos;ll need it if you lose access to your authenticator
                                        </p>
                                    </div>
                                    <MfaVerifyForm onSuccess={handleMfaVerifySuccess} />
                                </div>
                            )
: mfaStep === `show_codes` && backupCodes.length > 0
? (
                                <div className="space-y-4">
                                    <div className="flex items-center gap-2 text-green-500">
                                        <CheckCircle className="w-5 h-5" />
                                        <span className="font-medium">2FA enabled successfully!</span>
                                    </div>
                                    
                                    <div className="border border-yellow-500/20 bg-yellow-500/10 rounded-lg p-4 space-y-3">
                                        <div className="flex items-center gap-2">
                                            <Key className="w-5 h-5 text-yellow-500" />
                                            <span className="font-medium text-yellow-500">Save your backup codes</span>
                                        </div>
                                        <p className="text-sm text-muted-foreground">
                                            Store these codes in a safe place. You can use them to access your account if you lose your authenticator device.
                                        </p>
                                        <div className="grid grid-cols-2 gap-2">
                                            {backupCodes.map((code, index) => (
                                                <code key={index} className="text-xs bg-background px-2 py-1 rounded font-mono">
                                                    {code}
                                                </code>
                                            ))}
                                        </div>
                                        <div className="flex gap-2">
                                            <Button size="sm" onClick={handleCopyBackupCodes}>
                                                <Copy className="w-4 h-4 mr-1" />
                                                Copy All Codes
                                            </Button>
                                            <Button size="sm" variant="outline" onClick={() => setMfaStep(`none`)}>
                                                Done
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            )
: null}
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center justify-between">
                                <span className="flex items-center gap-2">
                                    <Monitor className="w-5 h-5" />
                                    Active Sessions
                                </span>
                                {(sessions?.length ?? 0) > 0 && (
                                    <Button variant="outline" size="sm" onClick={handleDeleteAllSessions}>
                                        <LogOut className="w-4 h-4 mr-1" />
                                        Logout Everywhere
                                    </Button>
                                )}
                            </CardTitle>
                            <CardDescription>
                                Manage your active sessions across devices.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            {sessionsLoading ? (
                                <div className="flex justify-center py-8">
                                    <motion.div 
                                        animate={{ rotate: 360 }}
                                        transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                                    >
                                        <Loader2 className="w-8 h-8 text-primary" />
                                    </motion.div>
                                </div>
                            ) : sessionsError ? (
                                <motion.div 
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    className="text-center py-8"
                                >
                                    <AlertCircle className="w-10 h-10 mx-auto text-destructive mb-2" />
                                    <p className="text-destructive">Failed to load sessions</p>
                                    <p className="text-xs text-muted-foreground mt-1">{String(sessionsError)}</p>
                                </motion.div>
                            ) : (!sessions || sessions.length === 0) ? (
                                <div className="text-center py-6">
                                    <Monitor className="w-10 h-10 mx-auto text-muted-foreground mb-2" />
                                    <p className="text-muted-foreground text-sm">No active sessions found.</p>
                                    <p className="text-xs text-muted-foreground mt-1">Your current session will appear here.</p>
                                </div>
                            )
: (
                                <div className="space-y-2">
                                    {/* Current Session (first one) */}
                                    <div className="flex items-center gap-2 mb-3">
                                        <span className="text-xs bg-green-500/10 text-green-500 px-2 py-1 rounded-full flex items-center gap-1">
                                            <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
                                            Current Session
                                        </span>
                                    </div>
                                    {sessions.map((session, index) => {
                                        const isCurrentSession = session.id === currentSessionId;
                                        return (
                                        <motion.div 
                                            key={session.id}
                                            initial={{ opacity: 0, x: -10 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: index * 0.05 }}
                                            className="flex items-center justify-between p-3 border rounded-lg bg-card hover:bg-accent/50 transition-colors"
                                        >
                                            <div className="flex items-center gap-3">
                                                {isCurrentSession ? (
                                                    <Monitor className="w-4 h-4 text-green-500" />
                                                ) : (
                                                    <Monitor className="w-4 h-4 text-muted-foreground" />
                                                )}
                                                <div>
                                                    <p className="text-sm font-medium flex items-center gap-2">
                                                        {session.user_agent || `Unknown device`}
                                                        {isCurrentSession && (
                                                            <span className="text-xs bg-green-500/10 text-green-500 px-1.5 py-0.5 rounded">
                                                                Current
                                                            </span>
                                                        )}
                                                    </p>
                                                    <p className="text-xs text-muted-foreground">
                                                        {session.ip_address || `Unknown IP`} • Started {new Date(session.created_at).toLocaleDateString()}
                                                    </p>
                                                </div>
                                            </div>
                                            <Button 
                                                variant="ghost" 
                                                size="sm" 
                                                onClick={() => handleDeleteSession(session.id)}
                                                title="Revoke this session"
                                                className={isCurrentSession ? `text-destructive hover:text-destructive` : ``}
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </Button>
                                        </motion.div>
                                    );})}
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>
            )}

            {/* Notifications Tab */}
            {activeTab === "notifications" && (
                <div className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Bell className="w-5 h-5" />
                                Notification Preferences
                            </CardTitle>
                            <CardDescription>
                                Choose how you want to receive notifications.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div className="space-y-1">
                                    <p className="font-medium">Email Notifications</p>
                                    <p className="text-sm text-muted-foreground">
                                        Receive notifications via email.
                                    </p>
                                </div>
                                <Switch
                                    checked={notificationSettings.email_alerts}
                                    onCheckedChange={() => handleNotificationSettingChange(`email_alerts`)}
                                />
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="space-y-1">
                                    <p className="font-medium">Security Alerts</p>
                                    <p className="text-sm text-muted-foreground">
                                        Get notified about security events and login attempts.
                                    </p>
                                </div>
                                <Switch
                                    checked={notificationSettings.security_alerts}
                                    onCheckedChange={() => handleNotificationSettingChange(`security_alerts`)}
                                />
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="space-y-1">
                                    <p className="font-medium">Team Updates</p>
                                    <p className="text-sm text-muted-foreground">
                                        Get notified about team member changes and invitations.
                                    </p>
                                </div>
                                <Switch
                                    checked={notificationSettings.team_updates}
                                    onCheckedChange={() => handleNotificationSettingChange(`team_updates`)}
                                />
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="space-y-1">
                                    <p className="font-medium">Weekly Digest</p>
                                    <p className="text-sm text-muted-foreground">
                                        Receive a weekly summary of activities.
                                    </p>
                                </div>
                                <Switch
                                    checked={notificationSettings.weekly_digest}
                                    onCheckedChange={() => handleNotificationSettingChange(`weekly_digest`)}
                                />
                            </div>
                        </CardContent>
                    </Card>
                </div>
            )}

            {/* API Keys Tab */}
            {activeTab === "apikeys" && (
                <div className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>API Keys</CardTitle>
                            <CardDescription>
                                Manage API keys for programmatic access.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            {showApiKey && newApiKey && (
                                <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg space-y-3">
                                    <div className="flex items-center gap-2">
                                        <Key className="w-5 h-5 text-yellow-500" />
                                        <p className="font-medium text-yellow-500">Your new API key</p>
                                    </div>
                                    <code className="block p-3 bg-background rounded text-xs break-all font-mono">{newApiKey}</code>
                                    <p className="text-xs text-muted-foreground">
                                        Make sure to copy it now. You won&apos;t be able to see it again!
                                    </p>
                                    <div className="flex gap-2">
                                        <Button 
                                            variant="outline" 
                                            size="sm" 
                                            onClick={() => {
                                                navigator.clipboard.writeText(newApiKey);
                                                toastSuccess(`API key copied to clipboard`);
                                            }}
                                        >
                                            <Copy className="w-4 h-4 mr-1" />
                                            Copy
                                        </Button>
                                        <Button variant="outline" size="sm" onClick={() => { setShowApiKey(false); setNewApiKey(``); }}>
                                            <X className="w-4 h-4 mr-1" />
                                            Done
                                        </Button>
                                    </div>
                                </div>
                            )}

                            <CreateApiKeyForm onSuccess={handleCreateApiKeySuccess} />

                            <div className="space-y-2">
                                {apiKeys.length === 0
? (
                                    <div className="text-center py-6">
                                        <Key className="w-10 h-10 mx-auto text-muted-foreground mb-2" />
                                        <p className="text-muted-foreground text-sm">No API keys yet.</p>
                                        <p className="text-xs text-muted-foreground mt-1">Create an API key to access the platform programmatically.</p>
                                    </div>
)
: (
                                    apiKeys.map((key) => (
                                        <motion.div
                                            key={key.id}
                                            initial={{ opacity: 0, y: 5 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            className="flex items-center justify-between p-4 border rounded-xl hover:bg-accent/50 transition-all duration-200 group"
                                        >
                                            <div className="flex items-center gap-4 flex-1">
                                                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center shadow-sm">
                                                    <Key className="w-6 h-6 text-primary" />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <p className="font-semibold text-foreground">{key.name}</p>
                                                        {key.last_used_at && (
                                                            <Badge variant="outline" className="text-xs gap-1">
                                                                <Clock className="w-3 h-3" />
                                                                Recently used
                                                            </Badge>
                                                        )}
                                                    </div>
                                                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                                                        <span className="font-mono bg-muted px-2 py-1 rounded-md">{key.key_prefix}...</span>
                                                        <span>•</span>
                                                        <span>Created {new Date(key.created_at).toLocaleDateString()}</span>
                                                        {key.expires_at && (
                                                            <>
                                                                <span>•</span>
                                                                <span className="text-amber-600 dark:text-amber-400">Expires {new Date(key.expires_at).toLocaleDateString()}</span>
                                                            </>
                                                        )}
                                                        {key.last_used_ip && (
                                                            <>
                                                                <span>•</span>
                                                                <span className="flex items-center gap-1">
                                                                    <Globe className="w-3 h-3" />
                                                                    {key.last_used_ip}
                                                                </span>
                                                            </>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleViewApiKeyDetails(key.id)}
                                                    title="View API key details"
                                                    className="text-muted-foreground hover:text-foreground"
                                                >
                                                    <Settings className="w-4 h-4" />
                                                </Button>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleRotateApiKey(key.id)}
                                                    disabled={rotateApiKey.isPending}
                                                    title="Rotate API key"
                                                    className="text-muted-foreground hover:text-foreground"
                                                >
                                                    {rotateApiKey.isPending
? (
                                                        <Loader2 className="w-4 h-4 animate-spin" />
                                                    )
: (
                                                        <RefreshCw className="w-4 h-4" />
                                                    )}
                                                </Button>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleDeleteApiKey(key.id)}
                                                    title="Delete API key"
                                                    className="text-destructive hover:text-destructive"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </Button>
                                            </div>
                                        </motion.div>
                                    ))
                                )}
                            </div>

                            {/* API Key Details Dialog */}
                            <Dialog open={showApiKeyDetails} onOpenChange={setShowApiKeyDetails}>
                                <DialogContent className="max-w-2xl">
                                    <DialogHeader>
                                        <DialogTitle className="flex items-center gap-2">
                                            <Key className="w-5 h-5" />
                                            API Key Details
                                        </DialogTitle>
                                        <DialogDescription>
                                            View and manage your API key permissions and usage
                                        </DialogDescription>
                                    </DialogHeader>
                                    {selectedApiKeyId && (
                                        <ApiKeyDetailsDialog
                                            keyId={selectedApiKeyId}
                                            onClose={() => setShowApiKeyDetails(false)}
                                        />
                                    )}
                                </DialogContent>
                            </Dialog>
                        </CardContent>
                    </Card>
                </div>
            )}
        </div>
    );
}
