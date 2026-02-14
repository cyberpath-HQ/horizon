import { useState, useEffect } from "react";
import { useForm } from "@tanstack/react-form";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { useAuth } from "@/context/AuthContext";
import { setStoredUser, getAccessToken, getStoredUser } from "@/lib/api";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Tabs, TabsContent, TabsList, TabsTrigger
} from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
    User, Shield, Key, Loader2, AlertCircle, CheckCircle, Monitor, Trash2, Bell
} from "lucide-react";
import {
    useProfile,
    useUpdateProfile,
    useChangePassword,
    useApiKeys,
    useCreateApiKey,
    useDeleteApiKey,
    useRotateApiKey,
    useSessions,
    useDeleteSession,
    useDeleteAllSessions,
    useMfaStatus,
    useEnableMfa,
    useVerifyMfaSetup,
    useDisableMfa,
} from "@/hooks/useApi";

// Form value interfaces
interface ProfileFormValues {
    first_name: string;
    last_name: string;
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
    component: ProfilePage,
});

interface ApiKeyFormValues {
    name: string;
}

// Profile Update Form Component
function ProfileUpdateForm({
    initialFirstName,
    initialLastName,
    onSuccess,
}: {
    initialFirstName: string;
    initialLastName: string;
    onSuccess: () => void;
}) {
    const updateProfile = useUpdateProfile();
    const { user, refreshUser } = useAuth();

    const form = useForm<ProfileFormValues>({
        defaultValues: {
            first_name: initialFirstName,
            last_name: initialLastName,
        },
        onSubmit: async ({ value }) => {
            try {
                await updateProfile.mutateAsync({
                    first_name: value.first_name,
                    last_name: value.last_name,
                });

                // Update stored user
                const updatedUser = {
                    id: user?.id || "",
                    email: user?.email || "",
                    displayName: `${value.first_name} ${value.last_name}`.trim(),
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
            <div className="grid gap-4 md:grid-cols-2">
                <form.Field
                    name="first_name"
                    children={(field) => (
                        <div className="space-y-2">
                            <Label htmlFor={field.name}>First Name</Label>
                            <Input
                                id={field.name}
                                value={field.state.value}
                                onChange={(e) => field.handleChange(e.target.value)}
                                onBlur={field.handleBlur}
                            />
                            <p className="text-xs text-muted-foreground">
                                Your first name as it will appear in the system
                            </p>
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </div>
                    )}
                />
                <form.Field
                    name="last_name"
                    children={(field) => (
                        <div className="space-y-2">
                            <Label htmlFor={field.name}>Last Name</Label>
                            <Input
                                id={field.name}
                                value={field.state.value}
                                onChange={(e) => field.handleChange(e.target.value)}
                                onBlur={field.handleBlur}
                            />
                            <p className="text-xs text-muted-foreground">
                                Your last name as it will appear in the system
                            </p>
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </div>
                    )}
                />
            </div>
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

export default function ProfilePage() {
    // Queries
    const { data: profileData } = useProfile();
    const { data: mfaStatus } = useMfaStatus();
    const { data: apiKeysData } = useApiKeys();
    const { data: sessionsData, isLoading: sessionsLoading } = useSessions();

    // Mutations
    const enableMfa = useEnableMfa();
    const disableMfa = useDisableMfa();
    const deleteApiKey = useDeleteApiKey();
    const rotateApiKey = useRotateApiKey();
    const deleteSession = useDeleteSession();
    const deleteAllSessions = useDeleteAllSessions();

    // State
    const [message, setMessage] = useState<{ type: `success` | `error`; text: string } | null>(null);
    const [activeTab, setActiveTab] = useState(`profile`);

    // MFA
    const [mfaEnabled, setMfaEnabled] = useState(false);
    const [mfaLoading, setMfaLoading] = useState(false);
    const [mfaSecret, setMfaSecret] = useState(``);
    const [mfaQrCode, setMfaQrCode] = useState(``);
    const [mfaPassword, setMfaPassword] = useState(``);
    const [mfaStep, setMfaStep] = useState<`none` | `enabling` | `verify`>(`none`);

    // API Keys
    const [newApiKey, setNewApiKey] = useState(``);
    const [showApiKey, setShowApiKey] = useState(false);

    // Notification settings
    const [notificationSettings, setNotificationSettings] = useState({
        email_alerts: true,
        security_alerts: true,
        team_updates: true,
        weekly_digest: true,
    });

    // Initialize active tab from localStorage
    useEffect(() => {
        const savedTab = localStorage.getItem(`profile_active_tab`);
        if (savedTab) {
            setActiveTab(savedTab);
        }
    }, []);

    // Save active tab to localStorage
    const handleTabChange = (value: string) => {
        setActiveTab(value);
        localStorage.setItem(`profile_active_tab`, value);
    };

    // Initialize MFA status
    useEffect(() => {
        if (mfaStatus) {
            setMfaEnabled(mfaStatus.enabled);
        }
    }, [mfaStatus]);

    // Auto-dismiss messages
    useEffect(() => {
        if (message) {
            const timer = setTimeout(() => setMessage(null), 5000);
            return () => clearTimeout(timer);
        }
    }, [message]);

    const apiKeys = apiKeysData?.items || [];
    const sessions = sessionsData?.items || [];

    // Handlers
    const handleProfileSuccess = () => {
        setMessage({ type: `success`, text: `Profile updated successfully` });
    };

    const handlePasswordSuccess = () => {
        setMessage({ type: `success`, text: `Password changed successfully` });
    };

    const handleEnableMfa = async() => {
        if (!mfaPassword) {
            setMessage({ type: `error`, text: `Password is required to enable MFA` });
            return;
        }
        setMfaLoading(true);
        try {
            const result = await enableMfa.mutateAsync(mfaPassword);
            setMfaSecret(result.secret);
            setMfaQrCode(`data:image/png;base64,${result.qr_code_base64}`);
            setMfaStep(`enabling`);
            setMfaPassword(``);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setMessage({ type: `error`, text: error.message || `Failed to enable MFA` });
        }
        finally {
            setMfaLoading(false);
        }
    };

    const handleMfaVerifySuccess = () => {
        setMfaEnabled(true);
        setMfaStep(`none`);
        setMessage({ type: `success`, text: `MFA enabled successfully` });
    };

    const handleDisableMfa = async() => {
        setMfaLoading(true);
        try {
            await disableMfa.mutateAsync(mfaPassword);
            setMfaEnabled(false);
            setMessage({ type: `success`, text: `MFA disabled successfully` });
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setMessage({ type: `error`, text: error.message || `Failed to disable MFA` });
        }
        finally {
            setMfaLoading(false);
        }
    };

    const handleCreateApiKeySuccess = (key: string) => {
        setNewApiKey(key);
        setShowApiKey(true);
        setMessage({ type: `success`, text: `API key created` });
    };

    const handleDeleteApiKey = async(id: string) => {
        try {
            await deleteApiKey.mutateAsync(id);
            setMessage({ type: `success`, text: `API key deleted` });
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setMessage({ type: `error`, text: error.message || `Failed to delete API key` });
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
            setMessage({ type: `error`, text: error.message || `Failed to rotate API key` });
        }
    };

    const handleDeleteSession = async(sessionId: string) => {
        try {
            await deleteSession.mutateAsync(sessionId);
            setMessage({ type: `success`, text: `Session deleted` });
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setMessage({ type: `error`, text: error.message || `Failed to delete session` });
        }
    };

    const handleDeleteAllSessions = async() => {
        try {
            await deleteAllSessions.mutateAsync();
            setMessage({ type: `success`, text: `All sessions deleted` });
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setMessage({ type: `error`, text: error.message || `Failed to delete sessions` });
        }
    };

    const handleNotificationSettingChange = (key: keyof typeof notificationSettings) => {
        setNotificationSettings(prev => ({
            ...prev,
            [key]: !prev[key],
        }));
        setMessage({ type: `success`, text: `Notification settings updated` });
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
                <p className="text-muted-foreground">
                    Manage your personal information and security settings.
                </p>
            </div>

            {message && (
                <div className={`p-4 rounded-lg flex items-center gap-2 ${ message.type === `success` ? `bg-green-500/10 text-green-500` : `bg-red-500/10 text-red-500` }`}>
                    {message.type === `success` ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                    {message.text}
                </div>
            )}

            <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-4">
                <TabsList>
                    <TabsTrigger value="profile" className="gap-2">
                        <User className="w-4 h-4" />
                        Profile
                    </TabsTrigger>
                    <TabsTrigger value="security" className="gap-2">
                        <Shield className="w-4 h-4" />
                        Security
                    </TabsTrigger>
                    <TabsTrigger value="notifications" className="gap-2">
                        <Bell className="w-4 h-4" />
                        Notifications
                    </TabsTrigger>
                    <TabsTrigger value="apikeys" className="gap-2">
                        <Key className="w-4 h-4" />
                        API Keys
                    </TabsTrigger>
                </TabsList>

                {/* Profile Tab */}
                <TabsContent value="profile" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Profile Information</CardTitle>
                            <CardDescription>
                                Update your personal information.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <ProfileUpdateForm
                                initialFirstName={profileData?.user?.first_name || ""}
                                initialLastName={profileData?.user?.last_name || ""}
                                onSuccess={handleProfileSuccess}
                            />
                        </CardContent>
                    </Card>
                </TabsContent>

                {/* Security Tab */}
                <TabsContent value="security" className="space-y-4">
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
                            <CardTitle>Two-Factor Authentication</CardTitle>
                            <CardDescription>
                                Add an extra layer of security to your account.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            {mfaEnabled
? (
                                <div className="space-y-4">
                                    <div className="flex items-center gap-2 text-green-500">
                                        <CheckCircle className="w-5 h-5" />
                                        <span>2FA is enabled on your account</span>
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="disablePassword">Password to disable</Label>
                                        <Input
                                            id="disablePassword"
                                            type="password"
                                            value={mfaPassword}
                                            onChange={(e) => setMfaPassword(e.target.value)}
                                            placeholder="Enter password to disable"
                                        />
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
: null}
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center justify-between">
                                Active Sessions
                                {sessions.length > 0 && (
                                    <Button variant="outline" size="sm" onClick={handleDeleteAllSessions}>
                                        <Trash2 className="w-4 h-4 mr-1" />
                                        Logout Everywhere
                                    </Button>
                                )}
                            </CardTitle>
                            <CardDescription>
                                Manage your active sessions across devices.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            {sessionsLoading
? (
                                <div className="flex justify-center py-4">
                                    <Loader2 className="w-6 h-6 animate-spin" />
                                </div>
                            )
: sessions.length === 0
? (
                                <p className="text-muted-foreground text-sm">No active sessions.</p>
                            )
: (
                                <div className="space-y-2">
                                    {sessions.map((session) => (
                                        <div key={session.id} className="flex items-center justify-between p-3 border rounded-lg">
                                            <div className="flex items-center gap-3">
                                                <Monitor className="w-4 w-4 text-muted-foreground" />
                                                <div>
                                                    <p className="text-sm font-medium">{session.user_agent || `Unknown device`}</p>
                                                    <p className="text-xs text-muted-foreground">
                                                        {session.ip_address || `Unknown IP`} • Created {new Date(session.created_at).toLocaleDateString()}
                                                    </p>
                                                </div>
                                            </div>
                                            <Button variant="ghost" size="sm" onClick={() => handleDeleteSession(session.id)}>
                                                <Trash2 className="w-4 h-4" />
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </TabsContent>

                {/* Notifications Tab */}
                <TabsContent value="notifications" className="space-y-4">
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
                </TabsContent>

                {/* API Keys Tab */}
                <TabsContent value="apikeys" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>API Keys</CardTitle>
                            <CardDescription>
                                Manage API keys for programmatic access.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            {showApiKey && newApiKey && (
                                <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg space-y-2">
                                    <p className="font-medium text-yellow-500">Your new API key</p>
                                    <code className="block p-2 bg-background rounded text-xs break-all">{newApiKey}</code>
                                    <p className="text-xs text-muted-foreground">
                                        Make sure to copy it now. You won&apos;t be able to see it again!
                                    </p>
                                    <Button variant="outline" size="sm" onClick={() => { setShowApiKey(false); setNewApiKey(``); }}>
                                        I&apos;ve copied it
                                    </Button>
                                </div>
                            )}

                            <CreateApiKeyForm onSuccess={handleCreateApiKeySuccess} />

                            <div className="space-y-2">
                                {apiKeys.length === 0
? (
                                    <p className="text-muted-foreground text-sm">No API keys yet.</p>
                                )
: (
                                    apiKeys.map((key) => (
                                        <div key={key.id} className="flex items-center justify-between p-3 border rounded-lg">
                                            <div>
                                                <p className="font-medium">{key.name}</p>
                                                <p className="text-xs text-muted-foreground">
                                                    Created {new Date(key.created_at).toLocaleDateString()}
                                                    {key.expires_at && ` • Expires ${ new Date(key.expires_at).toLocaleDateString() }`}
                                                </p>
                                            </div>
                                            <div className="flex gap-1">
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleRotateApiKey(key.id)}
                                                    disabled={rotateApiKey.isPending}
                                                >
                                                    {rotateApiKey.isPending
? (
                                                        <Loader2 className="w-4 h-4 animate-spin" />
                                                    )
: (
                                                        <Trash2 className="w-4 h-4" />
                                                    )}
                                                </Button>
                                                <Button variant="ghost" size="sm" onClick={() => handleDeleteApiKey(key.id)}>
                                                    <Trash2 className="w-4 h-4" />
                                                </Button>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>
        </div>
    );
}
