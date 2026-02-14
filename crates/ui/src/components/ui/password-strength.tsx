import * as React from "react";
import { cn } from "@/lib/utils";

interface PasswordRequirement {
    label: string
    test:  (password: string) => boolean
}

const passwordRequirements: Array<PasswordRequirement> = [
    {
        label: `At least 12 characters`,
        test:  (p) => p.length >= 12,
    },
    {
        label: `Contains uppercase letter`,
        test:  (p) => /[A-Z]/.test(p),
    },
    {
        label: `Contains lowercase letter`,
        test:  (p) => /[a-z]/.test(p),
    },
    {
        label: `Contains number`,
        test:  (p) => /[0-9]/.test(p),
    },
    {
        label: `Contains special character`,
        test:  (p) => /[!@#$%^&*(),.?":{}|<>]/.test(p),
    },
];

interface PasswordStrengthProps extends React.HTMLAttributes<HTMLDivElement> {
    password: string
}

export function PasswordStrength({
    password, className, ...props
}: PasswordStrengthProps) {
    const [
        requirements,
        setRequirements,
    ] = React.useState<Array<boolean>>(
        passwordRequirements.map(() => false)
    );

    React.useEffect(() => {
        setRequirements(passwordRequirements.map((req) => req.test(password)));
    }, [ password ]);

    const passedCount = requirements.filter(Boolean).length;
    const strength = passedCount === 0 ? 0 : passedCount / passwordRequirements.length;

    const getStrengthColor = () => {
        if (strength <= 0.2) {
            return `bg-red-500`;
        }
        if (strength <= 0.4) {
            return `bg-orange-500`;
        }
        if (strength <= 0.6) {
            return `bg-yellow-500`;
        }
        if (strength <= 0.8) {
            return `bg-green-400`;
        }
        return `bg-green-500`;
    };

    const getStrengthText = () => {
        if (strength === 0) {
            return `No password`;
        }
        if (strength <= 0.2) {
            return `Very weak`;
        }
        if (strength <= 0.4) {
            return `Weak`;
        }
        if (strength <= 0.6) {
            return `Fair`;
        }
        if (strength <= 0.8) {
            return `Good`;
        }
        return `Strong`;
    };

    return (
        <div className={cn(`space-y-2`, className)} {...props}>
            <div className="flex gap-1">
                {[
                    0,
                    1,
                    2,
                    3,
                    4,
                ].map((index) => (
                    <div
                        key={index}
                        className={cn(
                            `h-1 flex-1 rounded-full transition-colors`,
                            index < passedCount ? getStrengthColor() : `bg-muted`
                        )}
                    />
                ))}
            </div>
            <div className="flex justify-between items-center">
                <span className="text-xs text-muted-foreground">
                    Password strength: {getStrengthText()}
                </span>
                <span className="text-xs text-muted-foreground">
                    {passedCount}/{passwordRequirements.length} requirements met
                </span>
            </div>
            <ul className="space-y-1">
                {passwordRequirements.map((req, index) => (
                    <li
                        key={req.label}
                        className={cn(
                            `text-xs flex items-center gap-2`,
                            requirements[index] ? `text-green-600` : `text-muted-foreground`
                        )}
                    >
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            className={cn(
                                `h-3 w-3`,
                                requirements[index] ? `text-green-600` : `text-muted-foreground/50`
                            )}
                        >
                            {requirements[index]
? (
                                <>
                                    <polyline points="20 6 9 17 4 12" />
                                </>
                            )
: (
                                <>
                                    <circle cx="12" cy="12" r="10" />
                                </>
                            )}
                        </svg>
                        {req.label}
                    </li>
                ))}
            </ul>
        </div>
    );
}
