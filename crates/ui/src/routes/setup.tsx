import {
    useState, useEffect
} from "react";
import {
    useNavigate, createFileRoute
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
    checkSystemSetup, ApiError
} from "@/lib/api";
import {
    Leaf, Loader2, ShieldCheck
} from "lucide-react";

export const Route = createFileRoute(`/setup`)({
    component: SetupPage,
});

interface SetupFormValues {
    displayName:     string
    email:           string
    password:        string
    confirmPassword: string
}

export default function SetupPage() {
    const [
        isChecking,
        setIsChecking,
    ] = useState(true);

    const {
        setup,
    } = useAuth();
    const navigate = useNavigate();

    const form = useForm<SetupFormValues>({
        defaultValues: {
            displayName:     ``,
            email:           ``,
            password:        ``,
            confirmPassword: ``,
        },
        onSubmit: async({
            value,
        }) => {
            if (value.password !== value.confirmPassword) {
                throw new Error(`Passwords do not match`);
            }

            if (value.password.length < 12) {
                throw new Error(`Password must be at least 12 characters`);
            }

            try {
                const response = await setup(value.email, value.password, value.displayName);

                if (response.success) {
                    navigate({
                        to: `/`,
                    });
                }
                else {
                    throw new Error(`Setup failed. Please try again.`);
                }
            }
            catch (err) {
                if (err instanceof ApiError) {
                    const displayMessage = err.message;

                    if (err.code === `VALIDATION_ERROR`) {
                        if (err.message.includes(`email`)) {
                            throw new Error(`Please enter a valid email address`);
                        }
                        else if (err.message.includes(`password`)) {
                            throw new Error(`Password must be 12-256 characters`);
                        }
                        else if (err.message.includes(`display_name`)) {
                            throw new Error(`Display name is required (1-255 characters)`);
                        }
                        else {
                            throw new Error(`Please check your input: ${ err.message }`);
                        }
                    }
                    else if (err.code === `CONFLICT`) {
                        throw new Error(`System is already configured. Please use the login page.`);
                    }

                    throw new Error(displayMessage);
                }

                throw err;
            }
        },
    });

    useEffect(() => {
        // Check if system is already set up
        checkSystemSetup().then((isSetup) => {
            setIsChecking(false);
            if (!isSetup) {
                // System is already set up, redirect to login
                navigate({
                    to: `/login`,
                });
            }
        });
    }, [ navigate ]);

    if (isChecking) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="flex items-center gap-2">
                    <Loader2 className="h-6 w-6 animate-spin text-primary" />
                    <span className="text-muted-foreground">Checking configuration...</span>
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
                    <div className="mx-auto w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center">
                        <ShieldCheck className="w-7 h-7 text-primary" />
                    </div>
                    <div>
                        <CardTitle className="text-2xl font-semibold tracking-tight">
                            Initialize Horizon
                        </CardTitle>
                        <CardDescription className="mt-2">
                            Create your administrator account to get started
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
                            name="displayName"
                            children={(field) => (
                                <div className="space-y-2">
                                    <Label htmlFor={field.name}>Full Name</Label>
                                    <Input
                                        id={field.name}
                                        name={field.name}
                                        type="text"
                                        placeholder="John Doe"
                                        value={field.state.value}
                                        onChange={(e) => field.handleChange(e.target.value)}
                                        onBlur={field.handleBlur}
                                        required
                                        autoComplete="name"
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
                            name="email"
                            children={(field) => (
                                <div className="space-y-2">
                                    <Label htmlFor={field.name}>Email</Label>
                                    <Input
                                        id={field.name}
                                        name={field.name}
                                        type="email"
                                        placeholder="admin@company.com"
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
                                        autoComplete="new-password"
                                        placeholder="Min. 12 characters"
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
                            name="confirmPassword"
                            children={(field) => (
                                <div className="space-y-2">
                                    <Label htmlFor={field.name}>Confirm Password</Label>
                                    <Input
                                        id={field.name}
                                        name={field.name}
                                        type="password"
                                        value={field.state.value}
                                        onChange={(e) => field.handleChange(e.target.value)}
                                        onBlur={field.handleBlur}
                                        required
                                        autoComplete="new-password"
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
                                    Creating account...
                                </>
                            )
: (
                                <>
                                    <Leaf className="w-4 h-4" />
                                    Create Account
                                </>
                            )}
                        </Button>
                        <p className="text-xs text-center text-muted-foreground">
                            Choose a strong password with at least 12 characters
                        </p>
                    </CardFooter>
                </form>
            </Card>
        </div>
    );
}
