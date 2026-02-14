import {
    createRouter
} from "@tanstack/react-router";

// Import routes
import { routeTree } from './routeTree.gen';

// Create the router
export const router = createRouter({
    routeTree,
});

// Re-export hooks
export {
    useRouter
} from "@tanstack/react-router";

declare module '@tanstack/react-router' {
    interface Register {
    // This infers the type of our router and registers it across your code
        router: typeof router
    }
}
