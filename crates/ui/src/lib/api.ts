// API Configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || `http://localhost:3000`;

// Types matching the backend DTOs
export interface AuthTokens {
    access_token:  string
    refresh_token: string
    expires_in:    number
    tokenType:     string
}

export interface AuthenticatedUser {
    id:          string
    email:       string
    displayName: string
    roles:       Array<string>
}

export interface AuthSuccessResponse {
    success: boolean
    user:    AuthenticatedUser
    tokens?: AuthTokens | null
}

export interface LoginRequest {
    email:    string
    password: string
}

export interface SetupRequest {
    email:        string
    password:     string
    display_name: string
}

export interface RefreshRequest {
    refresh_token: string
}

export interface SuccessResponse {
    success: boolean
    message: string
}

// API Error handling
export class ApiError extends Error {
    constructor(
        public status: number,
        public code: string,
        message: string
    ) {
        super(message);
        this.name = `ApiError`;
    }
}

// Token storage - using localStorage for web
const TOKEN_KEY = `horizon_access_token`;
const REFRESH_TOKEN_KEY = `horizon_refresh_token`;
const USER_KEY = `horizon_user`;

export function getAccessToken(): string | null {
    return localStorage.getItem(TOKEN_KEY);
}

export function getRefreshToken(): string | null {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem(TOKEN_KEY, accessToken);
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

export function clearTokens(): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
}

export function getStoredUser(): AuthenticatedUser | null {
    const userStr = localStorage.getItem(USER_KEY);
    if (!userStr) {
        return null;
    }
    try {
        return JSON.parse(userStr);
    }
    catch {
        return null;
    }
}

export function setStoredUser(user: AuthenticatedUser): void {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
}

// API Client
class ApiClient {
    private readonly baseUrl:        string;

    private isRefreshing = false;

    private refreshPromise: Promise<string | null> | null = null;

    constructor(baseUrl: string = API_BASE_URL) {
        this.baseUrl = baseUrl;
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<T> {
        const url = `${ this.baseUrl }${ endpoint }`;
        const accessToken = getAccessToken();

        const headers: HeadersInit = {
            "Content-Type": `application/json`,
            ...options.headers,
        };

        if (accessToken) {
            (headers as Record<string, string>).Authorization = `Bearer ${ accessToken }`;
        }

        const response = await fetch(url, {
            ...options,
            headers,
        });

        // Handle 401 - try to refresh token
        if (response.status === 401 && accessToken) {
            const newToken = await this.refreshAccessToken();
            if (newToken) {
                // Retry the request with new token
                (headers as Record<string, string>).Authorization = `Bearer ${ newToken }`;
                const retryResponse = await fetch(url, {
                    ...options,
                    headers,
                });
                return this.handleResponse(retryResponse);
            }

            // Refresh failed, clear tokens and redirect to login
            clearTokens();
            window.dispatchEvent(new CustomEvent(`auth:logout`, {
                detail: {
                    reason: `session_expired`,
                },
            }));
            throw new ApiError(401, `UNAUTHORIZED`, `Session expired`);

        }

        return this.handleResponse(response);
    }

    private async handleResponse<T>(response: Response): Promise<T> {
        const data = await response.json().catch(() => null);

        if (!response.ok) {
            const code = data?.code || `UNKNOWN_ERROR`;
            const message = data?.message || `An error occurred`;
            throw new ApiError(response.status, code, message);
        }

        return data as T;
    }

    private async refreshAccessToken(): Promise<string | null> {
        if (this.isRefreshing) {
            return this.refreshPromise;
        }

        this.isRefreshing = true;
        const refreshToken = getRefreshToken();

        if (!refreshToken) {
            this.isRefreshing = false;
            return null;
        }

        this.refreshPromise = (async() => {
            try {
                const response = await fetch(`${ this.baseUrl }/api/v1/auth/refresh`, {
                    method:  `POST`,
                    headers: {
                        "Content-Type": `application/json`,
                    },
                    body:    JSON.stringify({
                        refresh_token: refreshToken,
                    }),
                });

                if (!response.ok) {
                    clearTokens();
                    return null;
                }

                const data: AuthSuccessResponse = await response.json();
                if (data.tokens) {
                    setTokens(data.tokens.access_token, data.tokens.refresh_token);
                    return data.tokens.access_token;
                }
                return null;
            }
            catch {
                clearTokens();
                return null;
            }
            finally {
                this.isRefreshing = false;
                this.refreshPromise = null;
            }
        })();

        return this.refreshPromise;
    }

    // Auth endpoints
    async login(email: string, password: string): Promise<AuthSuccessResponse> {
        const response = await this.request<AuthSuccessResponse>(`/api/v1/auth/login`, {
            method: `POST`,
            body:   JSON.stringify({
                email,
                password,
            }),
        });

        if (response.tokens) {
            setTokens(response.tokens.access_token, response.tokens.refresh_token);
        }
        if (response.user) {
            setStoredUser(response.user);
        }

        return response;
    }

    async setup(email: string, password: string, displayName: string): Promise<AuthSuccessResponse> {
        const response = await this.request<AuthSuccessResponse>(`/api/v1/auth/setup`, {
            method: `POST`,
            body:   JSON.stringify({
                email,
                password,
                display_name: displayName,
            }),
        });

        if (response.tokens) {
            setTokens(response.tokens.access_token, response.tokens.refresh_token);
        }
        if (response.user) {
            setStoredUser(response.user);
        }

        return response;
    }

    async logout(): Promise<void> {
        try {
            await this.request<SuccessResponse>(`/api/v1/auth/logout`, {
                method: `POST`,
            });
        }
        finally {
            clearTokens();
        }
    }

    async verifyMfa(code: string): Promise<AuthSuccessResponse> {
        const mfaToken = getAccessToken();
        const response = await this.request<AuthSuccessResponse>(`/api/v1/auth/mfa/verify`, {
            method:  `POST`,
            headers: {
                Authorization: `Bearer ${ mfaToken }`,
            },
            body: JSON.stringify({
                code,
            }),
        });

        if (response.tokens) {
            setTokens(response.tokens.access_token, response.tokens.refresh_token);
        }
        if (response.user) {
            setStoredUser(response.user);
        }

        return response;
    }

    async verifyMfaBackupCode(code: string): Promise<AuthSuccessResponse> {
        const mfaToken = getAccessToken();
        const response = await this.request<AuthSuccessResponse>(`/api/v1/auth/mfa/verify-backup`, {
            method:  `POST`,
            headers: {
                Authorization: `Bearer ${ mfaToken }`,
            },
            body: JSON.stringify({
                code,
            }),
        });

        if (response.tokens) {
            setTokens(response.tokens.access_token, response.tokens.refresh_token);
        }
        if (response.user) {
            setStoredUser(response.user);
        }

        return response;
    }

    async getMfaStatus(): Promise<{ enabled: boolean }> {
        return this.request<{ enabled: boolean }>(`/api/v1/auth/mfa/status`, {
            method: `GET`,
        });
    }

    async enableMfa(password: string): Promise<{ success: boolean
        secret:                                           string
        qr_code_base64:                                   string
        backup_codes:                                     Array<string> }> {
        return this.request<{ success: boolean
            secret:                    string
            qr_code_base64:            string
            backup_codes:              Array<string> }>(`/api/v1/auth/mfa/enable`, {
            method: `POST`,
            body:   JSON.stringify({
                password,
            }),
        });
    }

    async verifyMfaSetup(code: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/auth/mfa/verify-setup`, {
            method: `POST`,
            body:   JSON.stringify({
                code,
            }),
        });
    }

    async disableMfa(password: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/auth/mfa/disable`, {
            method: `POST`,
            body:   JSON.stringify({
                password,
            }),
        });
    }

    // User endpoints
    async getProfile(): Promise<any> {
        return this.request<any>(`/api/v1/users/me`, {
            method: `GET`,
        });
    }

    async updateProfile(data: { first_name?: string
        last_name?:                          string }): Promise<any> {
        return this.request<any>(`/api/v1/users/me`, {
            method: `PUT`,
            body:   JSON.stringify(data),
        });
    }

    async changePassword(currentPassword: string, newPassword: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/users/me/password`, {
            method: `PUT`,
            body:   JSON.stringify({
                current_password: currentPassword,
                new_password:     newPassword,
            }),
        });
    }

    // Team endpoints
    async getTeams(): Promise<any> {
        const response = await this.request<{ success: boolean
            teams:                                     Array<any>
            pagination:                                any }>(`/api/v1/teams`, {
            method: `GET`,
        });
        return {
            items:      response.teams,
            pagination: response.pagination,
        };
    }

    async createTeam(data: { name: string
        description?:              string }): Promise<any> {
        return this.request<any>(`/api/v1/teams`, {
            method: `POST`,
            body:   JSON.stringify(data),
        });
    }

    async getTeamMembers(teamId: string): Promise<any> {
        const response = await this.request<{ success: boolean
            members:                                   Array<any>
            pagination:                                any }>(`/api/v1/teams/${ teamId }/members`, {
            method: `GET`,
        });
        return {
            items:      response.members,
            pagination: response.pagination,
        };
    }

    // API Key endpoints
    async getApiKeys(): Promise<any> {
        const response = await this.request<{ success: boolean
            api_keys:                                  Array<any>
            pagination:                                any }>(`/api/v1/auth/api-keys`, {
            method: `GET`,
        });
        return {
            items:      response.api_keys,
            pagination: response.pagination,
        };
    }

    async createApiKey(data: { name: string
        permissions?:                Array<string>
        expires_at?:                 string }): Promise<any> {
        return this.request<any>(`/api/v1/auth/api-keys`, {
            method: `POST`,
            body:   JSON.stringify(data),
        });
    }

    async deleteApiKey(id: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/auth/api-keys/${ id }`, {
            method: `DELETE`,
        });
    }

    // Health check
    async healthCheck(): Promise<any> {
        return fetch(`${ this.baseUrl }/api/v1/health`).then(async(res) => res.json());
    }

    // Session management
    async getSessions(): Promise<any> {
        return this.request<any>(`/api/v1/auth/sessions`, {
            method: `GET`,
        });
    }

    async deleteSession(sessionId: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/auth/sessions/${ sessionId }`, {
            method: `DELETE`,
        });
    }

    async deleteAllSessions(): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/auth/sessions`, {
            method: `DELETE`,
        });
    }

    // MFA
    async regenerateBackupCodes(password: string): Promise<any> {
        return this.request<any>(`/api/v1/auth/mfa/regenerate-backup-codes`, {
            method: `POST`,
            body:   JSON.stringify({
                password,
            }),
        });
    }

    // User management
    async createUser(data: { email: string
        username?:                  string
        password?:                  string
        first_name?:                string
        last_name?:                 string
        role?:                      string }): Promise<any> {
        // Generate username from email if not provided
        const username = data.username || data.email.split(`@`)[0];
        return this.request<any>(`/api/v1/users`, {
            method: `POST`,
            body:   JSON.stringify({
                email:      data.email,
                username,
                password:   data.password,
                first_name: data.first_name,
                last_name:  data.last_name,
                role:       data.role || `viewer`,
            }),
        });
    }

    async listUsers(query?: { page?: number
        per_page?:                   number
        search?:                     string }): Promise<any> {
        const params = new URLSearchParams();
        if (query?.page) {
            params.append(`page`, String(query.page));
        }
        if (query?.per_page) {
            params.append(`per_page`, String(query.per_page));
        }
        if (query?.search) {
            params.append(`search`, query.search);
        }
        const response = await this.request<{ success: boolean
            users:                                     Array<any>
            pagination:                                any }>(`/api/v1/users?${ params }`, {
            method: `GET`,
        });
        return {
            items:      response.users,
            pagination: response.pagination,
        };
    }

    async updateUser(userId: string, data: { role?: string
        first_name?:                  string
        last_name?:                   string }): Promise<any> {
        return this.request<any>(`/api/v1/users/${ userId }`, {
            method: `PUT`,
            body:   JSON.stringify(data),
        });
    }

    async deleteUser(userId: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/users/${ userId }`, {
            method: `DELETE`,
        });
    }

    // Team management - additional methods
    async getTeam(teamId: string): Promise<any> {
        return this.request<any>(`/api/v1/teams/${ teamId }`, {
            method: `GET`,
        });
    }

    async updateTeam(teamId: string, data: { name?: string
        description?:                               string }): Promise<any> {
        return this.request<any>(`/api/v1/teams/${ teamId }`, {
            method: `PUT`,
            body:   JSON.stringify(data),
        });
    }

    async deleteTeam(teamId: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/teams/${ teamId }`, {
            method: `DELETE`,
        });
    }

    async addTeamMember(teamId: string, data: { user_id: string
        role?:                                           string }): Promise<any> {
        return this.request<any>(`/api/v1/teams/${ teamId }/members`, {
            method: `POST`,
            body:   JSON.stringify(data),
        });
    }

    async updateTeamMember(teamId: string, memberId: string, data: { role: string }): Promise<any> {
        return this.request<any>(`/api/v1/teams/${ teamId }/members/${ memberId }`, {
            method: `PUT`,
            body:   JSON.stringify(data),
        });
    }

    async removeTeamMember(teamId: string, memberId: string): Promise<SuccessResponse> {
        return this.request<SuccessResponse>(`/api/v1/teams/${ teamId }/members/${ memberId }`, {
            method: `DELETE`,
        });
    }

    // API Key management - additional methods
    async getApiKey(id: string): Promise<any> {
        return this.request<any>(`/api/v1/auth/api-keys/${ id }`, {
            method: `GET`,
        });
    }

    async rotateApiKey(id: string): Promise<any> {
        return this.request<any>(`/api/v1/auth/api-keys/${ id }/rotate`, {
            method: `POST`,
        });
    }

    async updateApiKeyPermissions(id: string, permissions: Array<string>): Promise<any> {
        return this.request<any>(`/api/v1/auth/api-keys/${ id }/permissions`, {
            method: `PUT`,
            body:   JSON.stringify({
                permissions,
            }),
        });
    }

    async getApiKeyUsage(id: string): Promise<any> {
        return this.request<any>(`/api/v1/auth/api-keys/${ id }/usage`, {
            method: `GET`,
        });
    }

    // Settings endpoints
    async getSettings(): Promise<{ settings: Array<{ id: string
        key:          string
        value:        string
        description?: string
        updated_at:   string }> }> {
        return this.request<{ settings: Array<{ id: string
            key:           string
            value:         string
            description?:  string
            updated_at:    string }> }>(`/api/v1/settings`, {
            method: `GET`,
        });
    }

    async getSetting(key: string): Promise<{ id: string
        key:         string
        value:       string
        description?: string
        updated_at:  string }> {
        return this.request<{ id: string
            key:          string
            value:        string
            description?: string
            updated_at:   string }>(`/api/v1/settings/${ key }`, {
            method: `GET`,
        });
    }

    async updateSetting(key: string, value: string): Promise<{ id: string
        key:         string
        value:       string
        description?: string
        updated_at:  string }> {
        return this.request<{ id: string
            key:          string
            value:        string
            description?: string
            updated_at:   string }>(`/api/v1/settings/${ key }`, {
            method: `PUT`,
            body:   JSON.stringify({
                value,
            }),
        });
    }
}

export const api = new ApiClient();

// Check if system needs setup
export async function checkSystemSetup(): Promise<boolean> {
    try {
        const response = await fetch(`${ API_BASE_URL }/health`);
        const data = await response.json();
        return data.needs_setup === true;
    }
    catch {
        return true;
    }
}
