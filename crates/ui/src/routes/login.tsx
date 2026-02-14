import {
    useState, useEffect
} from "react";
import {
    useNavigate, createFileRoute, redirect
} from "@tanstack/react-router";
import { useForm } from "@tanstack/react-form";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle
} from "@/components/ui/card";
import {
    checkSystemSetup, ApiError, getStoredUser
} from "@/lib/api";
import {
    Leaf, Loader2
} from "lucide-react";

export const Route = createFileRoute(`/login`)({
    beforeLoad: () => {
        const user = getStoredUser();
        if (user) {
            throw redirect({
                to: `/dashboard`,
            });
        }
    },
    component: LoginPage,
});

interface LoginFormValues {
    email:    string
    password: string
}

export default function LoginPage() {
    const [
        needsSetup,
        setNeedsSetup,
    ] = useState<boolean | null>(null);

    const {
        login,
    } = useAuth();
    const navigate = useNavigate();

    const form = useForm<LoginFormValues>({
        defaultValues: {
            email:    ``,
            password: ``,
        },
        onSubmit: async({
            value,
        }) => {
            try {
                const response = await login(value.email, value.password);

                if (response.success) {
                    navigate({
                        to: `/`,
                    });
                }
                else if (response.tokens?.tokenType === `MfaPending`) {
                    navigate({
                        to: `/mfa-verify`,
                    });
                }
                else {
                    throw new Error(response.user?.displayName || `Login failed`);
                }
            }
            catch (err) {
                if (err instanceof ApiError) {
                    throw new Error(err.message);
                }
                throw err;
            }
        },
    });

    useEffect(() => {
        // Check if system needs setup
        checkSystemSetup().then((isSetup) => {
            setNeedsSetup(isSetup);
            if (isSetup) {
                navigate({
                    to: `/setup`,
                });
            }
        });
    }, [ navigate ]);

    if (needsSetup === null) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="flex items-center gap-2">
                    <Loader2 className="h-6 w-6 animate-spin text-primary" />
                    <span className="text-muted-foreground">Loading...</span>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4 relative overflow-hidden auth-gradient">
            {/* Amber glow decoration */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="absolute -top-40 -right-40 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
                <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-secondary/10 rounded-full blur-3xl" />
            </div>

            <Card className="w-full max-w-md relative z-10 border-border/50 shadow-xl">
                <CardHeader className="space-y-4 text-center pb-2">
                    <div className="mx-auto w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                        <Leaf className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                        <CardTitle className="text-2xl font-semibold tracking-tight">
                            Welcome back
                        </CardTitle>
                        <CardDescription className="mt-2">
                            Sign in to your Horizon account
                        </CardDescription>
                    </div>
                </CardHeader>
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        form.handleSubmit();
                    }}
                >
                    <CardContent className="space-y-4 pt-4">
                        <form.Field
                            name="email"
                            children={(field) => (
                                <div className="space-y-2">
                                    <Label htmlFor={field.name}>Email</Label>
                                    <Input
                                        id={field.name}
                                        name={field.name}
                                        type="email"
                                        placeholder="name@company.com"
                                        value={field.state.value}
                                        onChange={(e) => field.handleChange(e.target.value)}
                                        onBlur={field.handleBlur}
                                        required
                                        autoComplete="email"
                                        className="h-10"
                                    />
                                    {field.state.meta.errors
? (
                                        <p className="text-sm text-destructive">
                                            {field.state.meta.errors.join(`, `)}
                                        </p>
                                    )
: null}
                                </div>
                            )}
                        />
                        <form.Field
                            name="password"
                            children={(field) => (
                                <div className="space-y-2">
                                    <Label htmlFor={field.name}>Password</Label>
                                    <Input
                                        id={field.name}
                                        name={field.name}
                                        type="password"
                                        value={field.state.value}
                                        onChange={(e) => field.handleChange(e.target.value)}
                                        onBlur={field.handleBlur}
                                        required
                                        autoComplete="current-password"
                                        className="h-10"
                                    />
                                    {field.state.meta.errors
? (
                                        <p className="text-sm text-destructive">
                                            {field.state.meta.errors.join(`, `)}
                                        </p>
                                    )
: null}
                                </div>
                            )}
                        />
                    </CardContent>
                    <CardFooter className="flex flex-col gap-4 pt-2">
                        <Button
                            type="submit"
                            className="w-full h-10"
                            disabled={form.state.isSubmitting}
                        >
                            {form.state.isSubmitting
? (
                                <>
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    Signing in...
                                </>
                            )
: (
                                `Sign in`
                            )}
                        </Button>
                        <p className="text-xs text-center text-muted-foreground">
                            Self-hostable CMDB for your infrastructure
                        </p>
                    </CardFooter>
                </form>
            </Card>
        </div>
    );
}
