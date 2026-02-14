import {
    Outlet, createRootRoute, redirect, isRedirect
} from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import { ThemeProvider } from "@/hooks/useTheme";
import { AuthProvider } from "@/context/AuthContext";
import {
    QueryClient, QueryClientProvider
} from "@tanstack/react-query";
import { useState } from "react";
import { checkSystemSetup } from "@/lib/api";

let setupCheckDone = false;
let cachedNeedsSetup: boolean | null = null;

export const Route = createRootRoute({
    beforeLoad: async() => {
        const currentPath = window.location.pathname;

        const publicPaths = [
            `/setup`,
            `/mfa-verify`,
        ];
        if (publicPaths.some((path) => currentPath === path || currentPath.startsWith(path + `/`))) {
            return;
        }

        if (setupCheckDone && cachedNeedsSetup !== null) {
            if (cachedNeedsSetup) {
                throw redirect({
                    to: `/setup`,
                });
            }
            return;
        }

        try {
            const needsSetup = await checkSystemSetup();
            cachedNeedsSetup = needsSetup;
            setupCheckDone = true;

            if (needsSetup) {
                throw redirect({
                    to: `/setup`,
                });
            }
        }
        catch (error) {
            if (isRedirect(error)) {
                throw error;
            }
            cachedNeedsSetup = true;
            setupCheckDone = true;
            throw redirect({
                to: `/setup`,
            });
        }
    },
    component: RootComponent,
});

function RootComponent() {
    const [ queryClient ] = useState(
        () => new QueryClient({
            defaultOptions: {
                queries: {
                    staleTime:            1000 * 60 * 5,
                    retry:                1,
                    refetchOnWindowFocus: true,
                },
            },
        })
    );

    return (
        <QueryClientProvider client={queryClient}>
            <ThemeProvider>
                <AuthProvider>
                    <div className="min-h-screen">
                        <Outlet />
                        {import.meta.env.DEV && <TanStackRouterDevtools />}
                    </div>
                </AuthProvider>
            </ThemeProvider>
        </QueryClientProvider>
    );
}
