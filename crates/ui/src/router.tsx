import {
    createBrowserRouter, Navigate
} from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { MainLayout } from "@/components/layout/MainLayout";
import LoginPage from "@/pages/auth/LoginPage";
import SetupPage from "@/pages/auth/SetupPage";
import MfaVerifyPage from "@/pages/auth/MfaVerifyPage";
import DashboardPage from "@/pages/DashboardPage";
import SettingsPage from "@/pages/settings/SettingsPage";
import ProfilePage from "@/pages/profile/ProfilePage";
import TeamsPage from "@/pages/settings/TeamsPage";
import NotificationsPage from "@/pages/settings/NotificationsPage";

// Protected route wrapper
function ProtectedRoute({
    children,
}: { children: React.ReactNode }) {
    const {
        isAuthenticated, isLoading,
    } = useAuth();

    if (isLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    <span className="text-muted-foreground">Loading...</span>
                </div>
            </div>
        );
    }

    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    return <>{children}</>;
}

// Public route wrapper (redirect if already authenticated)
function PublicRoute({
    children,
}: { children: React.ReactNode }) {
    const {
        isAuthenticated, isLoading,
    } = useAuth();

    if (isLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    <span className="text-muted-foreground">Loading...</span>
                </div>
            </div>
        );
    }

    if (isAuthenticated) {
        return <Navigate to="/" replace />;
    }

    return <>{children}</>;
}

const router = createBrowserRouter([
    {
    // Public routes (no auth required)
        path:    `/login`,
        element: (
            <PublicRoute>
                <LoginPage />
            </PublicRoute>
        ),
    },
    {
        path:    `/setup`,
        element: (
            <PublicRoute>
                <SetupPage />
            </PublicRoute>
        ),
    },
    {
        path:    `/mfa-verify`,
        element: (
            <PublicRoute>
                <MfaVerifyPage />
            </PublicRoute>
        ),
    },
    {
    // Protected routes (require auth)
        element: (
            <ProtectedRoute>
                <MainLayout />
            </ProtectedRoute>
        ),
        children: [
            {
                path:    `/`,
                element: <DashboardPage />,
            },
            {
                path:    `/profile`,
                element: <ProfilePage />,
            },
            {
                path:    `/settings`,
                element: <SettingsPage />,
            },
            {
                path:    `/settings/teams`,
                element: <TeamsPage />,
            },
            {
                path:    `/settings/api-keys`,
                element: <Navigate to="/profile" replace />,
            },
            {
                path:    `/settings/notifications`,
                element: <NotificationsPage />,
            },
            {
                path:    `/settings/ai`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">AI Providers</h1>
                        <p className="text-muted-foreground">AI provider configuration coming soon.</p>
                    </div>
                ),
            },
            {
                path:    `/settings/import-export`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Import/Export</h1>
                        <p className="text-muted-foreground">Import/Export functionality coming soon.</p>
                    </div>
                ),
            },

            // Placeholder routes for main nav items
            {
                path:    `/assets`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Assets</h1>
                        <p className="text-muted-foreground">Asset management coming soon.</p>
                    </div>
                ),
            },
            {
                path:    `/software`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Software</h1>
                        <p className="text-muted-foreground">Software management coming soon.</p>
                    </div>
                ),
            },
            {
                path:    `/security`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Security</h1>
                        <p className="text-muted-foreground">Security configuration coming soon.</p>
                    </div>
                ),
            },
            {
                path:    `/network`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Network</h1>
                        <p className="text-muted-foreground">Network mapping coming soon.</p>
                    </div>
                ),
            },
            {
                path:    `/vulnerabilities`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Vulnerabilities</h1>
                        <p className="text-muted-foreground">Vulnerability management coming soon.</p>
                    </div>
                ),
            },
            {
                path:    `/bia`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Business Impact Analysis</h1>
                        <p className="text-muted-foreground">BIA management coming soon.</p>
                    </div>
                ),
            },
            {
                path:    `/vendors`,
                element: (
                    <div className="space-y-4">
                        <h1 className="text-2xl font-semibold">Vendors</h1>
                        <p className="text-muted-foreground">Vendor management coming soon.</p>
                    </div>
                ),
            },
        ],
    },
    {
    // Catch all - redirect to home
        path:    `*`,
        element: <Navigate to="/" replace />,
    },
]);

export default router;
