import {
    useState, useEffect
} from "react";
import { useAuth } from "@/context/AuthContext";
import {
    api, setStoredUser
} from "@/lib/api";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Tabs, TabsContent, TabsList, TabsTrigger
} from "@/components/ui/tabs";
import {
    User, Shield, Key, Loader2, AlertCircle, CheckCircle, Monitor, Trash2, RefreshCw
} from "lucide-react";

export default function ProfilePage() {
    const {
        user, refreshUser,
    } = useAuth();
    const [
        loading,
        setLoading,
    ] = useState(false);
    const [
        message,
        setMessage,
    ] = useState<{ type: `success` | `error`
        text:            string } | null>(null);
    const [
        activeTab,
        setActiveTab,
    ] = useState(`profile`);

    // Profile form
    const [
        firstName,
        setFirstName,
    ] = useState(``);
    const [
        lastName,
        setLastName,
    ] = useState(``);

    // Password change
    const [
        currentPassword,
        setCurrentPassword,
    ] = useState(``);
    const [
        newPassword,
        setNewPassword,
    ] = useState(``);
    const [
        confirmPassword,
        setConfirmPassword,
    ] = useState(``);

    // MFA
    const [
        mfaEnabled,
        setMfaEnabled,
    ] = useState(false);
    const [
        mfaLoading,
        setMfaLoading,
    ] = useState(false);
    const [
        mfaSecret,
        setMfaSecret,
    ] = useState(``);
    const [
        mfaQrCode,
        setMfaQrCode,
    ] = useState(``);
    const [
        mfaCode,
        setMfaCode,
    ] = useState(``);
    const [
        mfaPassword,
        setMfaPassword,
    ] = useState(``);
    const [
        mfaStep,
        setMfaStep,
    ] = useState<`none` | `enabling` | `verify`>(`none`);

    // API Keys
    const [
        apiKeys,
        setApiKeys,
    ] = useState<Array<any>>([]);
    const [
        apiKeyName,
        setApiKeyName,
    ] = useState(``);
    const [
        newApiKey,
        setNewApiKey,
    ] = useState(``);
    const [
        showApiKey,
        setShowApiKey,
    ] = useState(false);
    const [
        rotatingKey,
        setRotatingKey,
    ] = useState<string | null>(null);

    // Sessions
    const [
        sessions,
        setSessions,
    ] = useState<Array<any>>([]);
    const [
        sessionsLoading,
        setSessionsLoading,
    ] = useState(false);

    // Initialize active tab from localStorage
    useEffect(() => {
        const savedTab = localStorage.getItem(`profile_active_tab`);
        if (savedTab) {
            setActiveTab(savedTab);
        }
    }, []);

    // Save active tab to localStorage whenever it changes
    const handleTabChange = (value: string) => {
        setActiveTab(value);
        localStorage.setItem(`profile_active_tab`, value);
    };

    useEffect(() => {
        if (user) {
            const nameParts = user.displayName.split(` `);
            setFirstName(nameParts[0] || ``);
            setLastName(nameParts.slice(1).join(` `) || ``);
        }
        loadMfaStatus();
        loadApiKeys();
        loadSessions();
    }, [ user ]);

    const loadMfaStatus = async() => {
        try {
            const status = await api.getMfaStatus();
            setMfaEnabled(status.enabled);
        }
        catch (err) {
            console.error(`Failed to load MFA status:`, err);
        }
    };

    const loadApiKeys = async() => {
        try {
            console.log(`Loading API keys...`);
            const keys = await api.getApiKeys();
            console.log(`API keys loaded:`, keys);
            setApiKeys(keys.items || []);
        }
        catch (err) {
            console.error(`Failed to load API keys:`, err);
            setMessage({
                type: `error`,
                text: `Failed to load API keys`,
            });
        }
    };

    const loadSessions = async() => {
        setSessionsLoading(true);
        try {
            const result = await api.getSessions();
            setSessions(result.items || []);
        }
        catch (err: any) {
            console.error(`Failed to load sessions:`, err);
        }
        finally {
            setSessionsLoading(false);
        }
    };

    const handleDeleteSession = async(sessionId: string) => {
        try {
            await api.deleteSession(sessionId);
            loadSessions();
            setMessage({
                type: `success`,
                text: `Session deleted`,
            });
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to delete session`,
            });
        }
    };

    const handleDeleteAllSessions = async() => {
        try {
            await api.deleteAllSessions();
            loadSessions();
            setMessage({
                type: `success`,
                text: `All sessions deleted`,
            });
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to delete sessions`,
            });
        }
    };

    const handleRotateApiKey = async(id: string) => {
        setRotatingKey(id);
        try {
            const result = await api.rotateApiKey(id);
            setNewApiKey(result.key);
            setShowApiKey(true);
            loadApiKeys();
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to rotate API key`,
            });
        }
        finally {
            setRotatingKey(null);
        }
    };

    const handleProfileUpdate = async(e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setMessage(null);

        try {
            await api.updateProfile({
                first_name: firstName,
                last_name:  lastName,
            });

            // Fetch fresh user profile to update the display
            const updatedProfile = await api.getProfile();
            if (updatedProfile) {
                // Update the stored user with new display name
                const updatedUser = {
                    ...updatedProfile.user || updatedProfile,
                    displayName: `${ updatedProfile.first_name || `` } ${ updatedProfile.last_name || `` }`.trim(),
                };
                setStoredUser(updatedUser);
                await refreshUser();
            }
            setMessage({
                type: `success`,
                text: `Profile updated successfully`,
            });
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to update profile`,
            });
        }
        finally {
            setLoading(false);
        }
    };

    const handlePasswordChange = async(e: React.FormEvent) => {
        e.preventDefault();
        if (newPassword !== confirmPassword) {
            setMessage({
                type: `error`,
                text: `Passwords do not match`,
            });
            return;
        }
        setLoading(true);
        setMessage(null);

        try {
            await api.changePassword(currentPassword, newPassword);
            setMessage({
                type: `success`,
                text: `Password changed successfully`,
            });
            setCurrentPassword(``);
            setNewPassword(``);
            setConfirmPassword(``);
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to change password`,
            });
        }
        finally {
            setLoading(false);
        }
    };

    const handleEnableMfa = async() => {
        if (!mfaPassword) {
            setMessage({
                type: `error`,
                text: `Password is required to enable MFA`,
            });
            return;
        }
        setMfaLoading(true);
        try {
            const result = await api.enableMfa(mfaPassword);
            setMfaSecret(result.secret);
            setMfaQrCode(`data:image/png;base64,${ result.qr_code_base64 }`);
            setMfaStep(`enabling`);
            setMfaPassword(``);
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to enable MFA`,
            });
        }
        finally {
            setMfaLoading(false);
        }
    };

    const handleVerifyMfa = async(e: React.FormEvent) => {
        e.preventDefault();
        setMfaLoading(true);
        try {
            // Verify and enable MFA
            await api.verifyMfaSetup(mfaCode);
            setMfaEnabled(true);
            setMfaStep(`none`);
            setMfaCode(``);
            setMessage({
                type: `success`,
                text: `MFA enabled successfully`,
            });
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Invalid verification code`,
            });
        }
        finally {
            setMfaLoading(false);
        }
    };

    const handleDisableMfa = async() => {
        setMfaLoading(true);
        try {
            await api.disableMfa(currentPassword);
            setMfaEnabled(false);
            setMessage({
                type: `success`,
                text: `MFA disabled successfully`,
            });
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to disable MFA`,
            });
        }
        finally {
            setMfaLoading(false);
        }
    };

    const handleCreateApiKey = async(e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        try {
            const result = await api.createApiKey({
                name: apiKeyName,
            });
            setNewApiKey(result.key);
            setShowApiKey(true);
            loadApiKeys();
            setApiKeyName(``);
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to create API key`,
            });
        }
        finally {
            setLoading(false);
        }
    };

    const handleDeleteApiKey = async(id: string) => {
        try {
            await api.deleteApiKey(id);
            loadApiKeys();
            setMessage({
                type: `success`,
                text: `API key deleted`,
            });
        }
        catch (err: any) {
            setMessage({
                type: `error`,
                text: err.message || `Failed to delete API key`,
            });
        }
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
                    <TabsTrigger value="apikeys" className="gap-2">
                        <Key className="w-4 h-4" />
                        API Keys
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="profile" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Profile Information</CardTitle>
                            <CardDescription>
                                Update your personal information.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <form onSubmit={handleProfileUpdate} className="space-y-4">
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="firstName">First Name</Label>
                                        <Input
                                            id="firstName"
                                            value={firstName}
                                            onChange={(e) => setFirstName(e.target.value)}
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="lastName">Last Name</Label>
                                        <Input
                                            id="lastName"
                                            value={lastName}
                                            onChange={(e) => setLastName(e.target.value)}
                                        />
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="email">Email</Label>
                                    <Input id="email" value={user?.email || ``} disabled />
                                </div>
                                <Button type="submit" disabled={loading}>
                                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    Save Changes
                                </Button>
                            </form>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="security" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Change Password</CardTitle>
                            <CardDescription>
                                Update your password to keep your account secure.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <form onSubmit={handlePasswordChange} className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="currentPassword">Current Password</Label>
                                    <Input
                                        id="currentPassword"
                                        type="password"
                                        value={currentPassword}
                                        onChange={(e) => setCurrentPassword(e.target.value)}
                                        required
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="newPassword">New Password</Label>
                                    <Input
                                        id="newPassword"
                                        type="password"
                                        value={newPassword}
                                        onChange={(e) => setNewPassword(e.target.value)}
                                        required
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="confirmPassword">Confirm New Password</Label>
                                    <Input
                                        id="confirmPassword"
                                        type="password"
                                        value={confirmPassword}
                                        onChange={(e) => setConfirmPassword(e.target.value)}
                                        required
                                    />
                                </div>
                                <Button type="submit" disabled={loading}>
                                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    Update Password
                                </Button>
                            </form>
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
                    <Button variant="destructive" onClick={handleDisableMfa} disabled={mfaLoading}>
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
                    </div>
                    <form onSubmit={handleVerifyMfa} className="space-y-2">
                        <Label>Enter verification code</Label>
                        <Input
                            value={mfaCode}
                            onChange={(e) => setMfaCode(e.target.value)}
                            placeholder="123456"
                            required
                        />
                        <Button type="submit" disabled={mfaLoading}>
                            {mfaLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            Verify & Enable
                        </Button>
                    </form>
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
                                <Monitor className="w-4 h-4 text-muted-foreground" />
                                <div>
                                    <p className="text-sm font-medium">{session.user_agent || `Unknown device`}</p>
                                    <p className="text-xs text-muted-foreground">
                                        {session.ip_address || `Unknown IP`} • Created {new Date(session.created_at).toLocaleDateString()}
                                    </p>
                                </div>
                            </div>
                            <Button variant="ghost" size="sm" onClick={async() => handleDeleteSession(session.id)}>
                                <Trash2 className="w-4 h-4" />
                            </Button>
                        </div>
                    ))}
                </div>
              )}
                        </CardContent>
                    </Card>
                </TabsContent>

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
                                        Make sure to copy it now. You won't be able to see it again!
                                    </p>
                                    <Button variant="outline" size="sm" onClick={() => {
                                        setShowApiKey(false); setNewApiKey(``);
                                    }}>
                                        I've copied it
                                    </Button>
                                </div>
                            )}

                            <form onSubmit={handleCreateApiKey} className="flex gap-2">
                                <Input
                                    placeholder="API key name"
                                    value={apiKeyName}
                                    onChange={(e) => setApiKeyName(e.target.value)}
                                    required
                                />
                                <Button type="submit" disabled={loading}>
                                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    Create
                                </Button>
                            </form>

                            <div className="space-y-2">
                                {apiKeys.length === 0
? (
                    <p className="text-muted-foreground text-sm">No API keys yet.</p>
                  )
: (
                    apiKeys.map((key, index) => (
                        <div key={key.id} className={`flex items-center justify-between p-3 border rounded-lg animate-stagger-${ Math.min(index + 1, 5) }`}>
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
                                    onClick={async() => handleRotateApiKey(key.id)}
                                    disabled={rotatingKey === key.id}
                                >
                                    {rotatingKey === key.id
? (
                              <Loader2 className="w-4 h-4 animate-spin" />
                            )
: (
                              <RefreshCw className="w-4 h-4" />
                            )}
                                </Button>
                                <Button variant="ghost" size="sm" onClick={async() => handleDeleteApiKey(key.id)}>
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
