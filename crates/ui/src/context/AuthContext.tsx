import {
    createContext,
    useContext,
    useState,
    useEffect,
    useCallback,
    type ReactNode
} from "react";
import {
    api,
    getAccessToken,
    getStoredUser,
    clearTokens,
    type AuthenticatedUser,
    type AuthSuccessResponse
} from "@/lib/api";

interface AuthContextType {
    user:                AuthenticatedUser | null
    isLoading:           boolean
    isAuthenticated:     boolean
    login:               (email: string, password: string) => Promise<AuthSuccessResponse>
    setup:               (email: string, password: string, displayName: string) => Promise<AuthSuccessResponse>
    logout:              () => Promise<void>
    verifyMfa:           (code: string) => Promise<AuthSuccessResponse>
    verifyMfaBackupCode: (code: string) => Promise<AuthSuccessResponse>
    refreshUser:         () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({
    children,
}: { children: ReactNode }) {
    const [
        user,
        setUser,
    ] = useState<AuthenticatedUser | null>(null);
    const [
        isLoading,
        setIsLoading,
    ] = useState(true);

    // Initialize auth state from storage
    useEffect(() => {
        const token = getAccessToken();
        const storedUser = getStoredUser();

        if (token && storedUser) {
            setUser(storedUser);
        }
        setIsLoading(false);
    }, []);

    // Listen for logout events from other tabs
    useEffect(() => {
        const handleLogout = () => {
            clearTokens();
            setUser(null);
            window.location.href = `/login`;
        };

        window.addEventListener(`auth:logout`, handleLogout);
        return () => window.removeEventListener(`auth:logout`, handleLogout);
    }, []);

    // Storage event listener for cross-tab sync
    useEffect(() => {
        const handleStorageChange = (e: StorageEvent) => {
            if (e.key === `horizon_access_token` && !e.newValue) {
                // Token was removed in another tab
                clearTokens();
                setUser(null);
                window.dispatchEvent(new CustomEvent(`auth:logout`, {
                    detail: {
                        reason: `logged_out_elsewhere`,
                    },
                }));
            }
        };

        window.addEventListener(`storage`, handleStorageChange);
        return () => window.removeEventListener(`storage`, handleStorageChange);
    }, []);

    const login = useCallback(async(email: string, password: string) => {
        const response = await api.login(email, password);
        if (response.success && response.user) {
            setUser(response.user);
        }
        return response;
    }, []);

    const setup = useCallback(async(email: string, password: string, displayName: string) => {
        const response = await api.setup(email, password, displayName);
        if (response.success && response.user) {
            setUser(response.user);
        }
        return response;
    }, []);

    const logout = useCallback(async() => {
        try {
            await api.logout();
        }
        finally {
            clearTokens();
            setUser(null);
        }
    }, []);

    const verifyMfa = useCallback(async(code: string) => {
        const response = await api.verifyMfa(code);
        if (response.success && response.user) {
            setUser(response.user);
        }
        return response;
    }, []);

    const verifyMfaBackupCode = useCallback(async(code: string) => {
        const response = await api.verifyMfaBackupCode(code);
        if (response.success && response.user) {
            setUser(response.user);
        }
        return response;
    }, []);

    const refreshUser = useCallback(() => {
        const storedUser = getStoredUser();
        if (storedUser) {
            setUser(storedUser);
        }
    }, []);

    return (
        <AuthContext.Provider
            value={{
                user,
                isLoading,
                isAuthenticated: Boolean(user),
                login,
                setup,
                logout,
                verifyMfa,
                verifyMfaBackupCode,
                refreshUser,
            }}
        >
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error(`useAuth must be used within an AuthProvider`);
    }
    return context;
}
