import { createFileRoute, redirect } from "@tanstack/react-router";
import { getStoredUser } from "@/lib/api";

export const Route = createFileRoute(`/`)({
    beforeLoad: () => {
        const user = getStoredUser();
        if (user) {
            throw redirect({
                to: `/dashboard`,
            });
        }
    },
    component: IndexPage,
});

export default function IndexPage() {
    return (
        <div>
            <h1>Index Page</h1>
            <p>This is the index page.</p>
        </div>
    );
}
