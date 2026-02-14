import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Bot } from "lucide-react";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { getAccessToken, getStoredUser } from "@/lib/api";

export const Route = createFileRoute("/dashboard/agents")({
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
    component: AgentsPage,
});

export default function AgentsPage() {
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
                <p className="text-muted-foreground">
                    Manage and configure collection agents.
                </p>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Bot className="w-5 h-5" />
                        Agents Module
                    </CardTitle>
                    <CardDescription>
                        Collection agents for data gathering
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                        <Bot className="h-16 w-16 text-muted-foreground mb-4" />
                        <h3 className="text-lg font-semibold mb-2">Coming Soon</h3>
                        <p className="text-muted-foreground max-w-md">
                            The Agents module is currently under development. 
                            This module will allow you to deploy collection agents to gather data from various sources.
                        </p>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
