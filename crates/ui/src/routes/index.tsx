import {
    createFileRoute
} from "@tanstack/react-router";

export const Route = createFileRoute(`/`)({
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
