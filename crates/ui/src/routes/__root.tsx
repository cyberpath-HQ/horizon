import { Outlet, createRootRoute } from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import { ThemeProvider } from "@/hooks/useTheme";
import { AuthProvider } from "@/context/AuthContext";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

export const Route = createRootRoute({
    component: RootComponent,
});

function RootComponent() {
    const [queryClient] = useState(
        () =>
            new QueryClient({
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
