import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Bell, Palette, Database, CheckCircle, AlertCircle } from "lucide-react";
import { useTheme } from "@/hooks/useTheme";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const handleThemeChange = (newTheme: "light" | "dark" | "system") => {
    setTheme(newTheme);
    setMessage({ type: "success", text: "Theme updated" });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">
          Configure application settings and preferences.
        </p>
      </div>

      {message && (
        <div className={`p-4 rounded-lg flex items-center gap-2 ${message.type === "success" ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500"}`}>
          {message.type === "success" ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
          {message.text}
        </div>
      )}

      <Tabs defaultValue="appearance" className="space-y-4">
        <TabsList>
          <TabsTrigger value="appearance" className="gap-2">
            <Palette className="w-4 h-4" />
            Appearance
          </TabsTrigger>
          <TabsTrigger value="notifications" className="gap-2">
            <Bell className="w-4 h-4" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="database" className="gap-2">
            <Database className="w-4 h-4" />
            Database
          </TabsTrigger>
        </TabsList>

        <TabsContent value="appearance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Theme</CardTitle>
              <CardDescription>
                Choose how Horizon looks to you.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-3">
                <button
                  onClick={() => handleThemeChange("light")}
                  className={`p-4 border-2 rounded-lg text-center transition-all ${
                    theme === "light" ? "border-primary bg-primary/5" : "border-border hover:border-primary/50"
                  }`}
                >
                  <div className="w-16 h-12 mx-auto mb-2 bg-white border rounded flex items-center justify-center">
                    <div className="w-8 h-8 bg-gray-200 rounded-full" />
                  </div>
                  <p className="text-sm font-medium">Light</p>
                </button>
                <button
                  onClick={() => handleThemeChange("dark")}
                  className={`p-4 border-2 rounded-lg text-center transition-all ${
                    theme === "dark" ? "border-primary bg-primary/5" : "border-border hover:border-primary/50"
                  }`}
                >
                  <div className="w-16 h-12 mx-auto mb-2 bg-gray-900 border border-gray-700 rounded flex items-center justify-center">
                    <div className="w-8 h-8 bg-gray-700 rounded-full" />
                  </div>
                  <p className="text-sm font-medium">Dark</p>
                </button>
                <button
                  onClick={() => handleThemeChange("system")}
                  className={`p-4 border-2 rounded-lg text-center transition-all ${
                    theme === "system" ? "border-primary bg-primary/5" : "border-border hover:border-primary/50"
                  }`}
                >
                  <div className="w-16 h-12 mx-auto mb-2 bg-gradient-to-r from-white to-gray-900 border rounded flex items-center justify-center">
                    <div className="w-8 h-8 bg-gradient-to-r from-gray-200 to-gray-700 rounded-full" />
                  </div>
                  <p className="text-sm font-medium">System</p>
                </button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Notification Preferences</CardTitle>
              <CardDescription>
                Choose how you want to receive notifications.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Notification settings will be available in a future update.
              </p>
            </CardContent>
          </Card>
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
      </Tabs>
    </div>
  );
}
