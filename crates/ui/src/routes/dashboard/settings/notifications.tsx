import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Bell } from "lucide-react";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { getAccessToken, getStoredUser } from "@/lib/api";

export const Route = createFileRoute("/dashboard/settings/notifications")({
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
    component: NotificationsPage,
});

export default function NotificationsPage() {
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-semibold tracking-tight">Notifications</h1>
                <p className="text-muted-foreground">
                    View and manage your notifications.
                </p>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Bell className="w-5 h-5" />
                        Notifications
                    </CardTitle>
                    <CardDescription>
                        Stay updated with system events
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                        <Bell className="h-16 w-16 text-muted-foreground mb-4" />
                        <h3 className="text-lg font-semibold mb-2">Coming Soon</h3>
                        <p className="text-muted-foreground max-w-md">
                            The Notifications module is currently under development.
                            This module will allow you to view and manage notifications from the system.
                        </p>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
