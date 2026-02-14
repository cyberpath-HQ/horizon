import {
    createRouter
} from "@tanstack/react-router";

// Import routes
import { routeTree } from './routeTree.gen';
import { Route as R404Route } from './routes/404';

// Create the router
export const router = createRouter({
    routeTree,
    defaultPreload: 'intent',
    // Handle 404 - redirect unknown routes to the 404 page
    notFoundRoute: R404Route,
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
