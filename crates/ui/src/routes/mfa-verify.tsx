import { useState } from "react";
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
import { ApiError } from "@/lib/api";
import {
    Loader2, Shield, KeyRound, RotateCcw
} from "lucide-react";

export const Route = createFileRoute(`/mfa-verify`)({
    component: MfaVerifyPage,
});

interface MfaFormValues {
    code: string
}

export default function MfaVerifyPage() {
    const [
        isBackupMode,
        setIsBackupMode,
    ] = useState(false);
    const [
        attempts,
        setAttempts,
    ] = useState(0);

    const {
        verifyMfa, verifyMfaBackupCode,
    } = useAuth();
    const navigate = useNavigate();

    const form = useForm<MfaFormValues>({
        defaultValues: {
            code: ``,
        },
        onSubmit: async({
            value,
        }) => {
            try {
                const response = isBackupMode
                    ? await verifyMfaBackupCode(value.code)
                    : await verifyMfa(value.code);

                if (response.success) {
                    navigate({
                        to: `/`,
                    });
                }
                else {
                    setAttempts((prev) => prev + 1);
                    throw new Error(`Invalid code. Please try again.`);
                }
            }
            catch (err) {
                setAttempts((prev) => prev + 1);
                if (err instanceof ApiError) {
                    throw new Error(err.message);
                }
                throw err;
            }
        },
    });

    const toggleMode = () => {
        setIsBackupMode(!isBackupMode);
        form.reset();
    };

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
                        <Shield className="w-7 h-7 text-primary" />
                    </div>
                    <div>
                        <CardTitle className="text-2xl font-semibold tracking-tight">
                            Two-Factor Authentication
                        </CardTitle>
                        <CardDescription className="mt-2">
                            {isBackupMode
                                ? `Enter one of your backup codes`
                                : `Enter the 6-digit code from your authenticator app`
                            }
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
                            name="code"
                            children={(field) => (
                                <div className="space-y-2">
                                    <Label htmlFor={field.name}>
                                        {isBackupMode ? `Backup Code` : `Authentication Code`}
                                    </Label>
                                    <Input
                                        id={field.name}
                                        name={field.name}
                                        type="text"
                                        inputMode={isBackupMode ? `text` : `numeric`}
                                        placeholder={isBackupMode ? `XXXX-XXXX` : `000000`}
                                        value={field.state.value}
                                        onChange={(e) => field.handleChange(isBackupMode ? e.target.value : e.target.value.replace(/\D/g, ``).slice(0, 6))}
                                        onBlur={field.handleBlur}
                                        required
                                        autoComplete={isBackupMode ? `off` : `one-time-code`}
                                        className="h-12 text-center text-lg tracking-widest font-mono"
                                        maxLength={isBackupMode ? 9 : 6}
                                    />
                                    {field.state.meta.errors
? (
                                        <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
                                            {field.state.meta.errors.join(`, `)}
                                            {attempts > 2 && (
                                                <button
                                                    type="button"
                                                    onClick={toggleMode}
                                                    className="block mt-2 text-sm underline hover:text-destructive/80"
                                                >
                                                    Try using a backup code instead
                                                </button>
                                            )}
                                        </div>
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
                                    Verifying...
                                </>
                            )
: (
                                <>
                                    <KeyRound className="w-4 h-4" />
                                    Verify
                                </>
                            )}
                        </Button>

                        <div className="flex items-center justify-center gap-2 text-sm">
                            <button
                                type="button"
                                onClick={toggleMode}
                                className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
                            >
                                <RotateCcw className="w-3 h-3" />
                                {isBackupMode ? `Use authenticator code` : `Use backup code`}
                            </button>
                        </div>
                    </CardFooter>
                </form>
            </Card>
        </div>
    );
}
