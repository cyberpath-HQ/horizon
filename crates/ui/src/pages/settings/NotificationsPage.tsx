import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Bell, AlertTriangle, CheckCircle } from "lucide-react";

export default function NotificationsPage() {
  const [settings, setSettings] = useState({
    emailAlerts: true,
    securityAlerts: true,
    teamUpdates: true,
    productUpdates: false,
    weeklyDigest: true,
  });
  const [saved, setSaved] = useState(false);

  const handleToggle = (key: keyof typeof settings) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
    setSaved(false);
  };

  const Toggle = ({ enabled, onClick }: { enabled: boolean; onClick: () => void }) => (
    <button
      type="button"
      onClick={onClick}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
        enabled ? "bg-primary" : "bg-muted"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          enabled ? "translate-x-6" : "translate-x-1"
        }`}
      />
    </button>
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Notifications</h1>
        <p className="text-muted-foreground">
          Configure how you receive notifications.
        </p>
      </div>

      {saved && (
        <div className="p-4 rounded-lg flex items-center gap-2 bg-green-500/10 text-green-500">
          <CheckCircle className="w-4 h-4" />
          Settings saved successfully
        </div>
      )}

      <div className="grid gap-6 max-w-2xl">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bell className="w-5 h-5" />
              Notification Channels
            </CardTitle>
            <CardDescription>
              Choose what types of notifications you want to receive.
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
              <Toggle enabled={settings.emailAlerts} onClick={() => handleToggle('emailAlerts')} />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <p className="font-medium">Weekly Digest</p>
                <p className="text-sm text-muted-foreground">
                  Receive a weekly summary of activities.
                </p>
              </div>
              <Toggle enabled={settings.weeklyDigest} onClick={() => handleToggle('weeklyDigest')} />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5" />
              Alert Types
            </CardTitle>
            <CardDescription>
              Choose which types of alerts you want to receive.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <p className="font-medium">Security Alerts</p>
                <p className="text-sm text-muted-foreground">
                  Get notified about security events and login attempts.
                </p>
              </div>
              <Toggle enabled={settings.securityAlerts} onClick={() => handleToggle('securityAlerts')} />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <p className="font-medium">Team Updates</p>
                <p className="text-sm text-muted-foreground">
                  Get notified about team member changes and invitations.
                </p>
              </div>
              <Toggle enabled={settings.teamUpdates} onClick={() => handleToggle('teamUpdates')} />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <p className="font-medium">Product Updates</p>
                <p className="text-sm text-muted-foreground">
                  Get notified about new features and improvements.
                </p>
              </div>
              <Toggle enabled={settings.productUpdates} onClick={() => handleToggle('productUpdates')} />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
