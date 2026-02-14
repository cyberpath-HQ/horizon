import {
    createFileRoute, redirect
} from "@tanstack/react-router";
import { MainLayout } from "@/components/layout/MainLayout";
import {
    getAccessToken, getStoredUser
} from "@/lib/api";

export const Route = createFileRoute(`/dashboard`)({
    beforeLoad: () => {
        const token = getAccessToken();
        const user = getStoredUser();

        if (!token || !user) {
            throw redirect({
                to:      `/login`,
                replace: true,
            });
        }
    },
    component: DashboardLayout,
});

function DashboardLayout() {
    return (
        <MainLayout />
    );
}
