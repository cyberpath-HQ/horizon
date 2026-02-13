// API Configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:3000";

// Types matching the backend DTOs
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  tokenType: string;
}

export interface AuthenticatedUser {
  id: string;
  email: string;
  displayName: string;
  roles: string[];
}

export interface AuthSuccessResponse {
  success: boolean;
  user: AuthenticatedUser;
  tokens?: AuthTokens | null;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface SetupRequest {
  email: string;
  password: string;
  display_name: string;
}

export interface RefreshRequest {
  refresh_token: string;
}

export interface SuccessResponse {
  success: boolean;
  message: string;
}

// API Error handling
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// Token storage - using localStorage for web
const TOKEN_KEY = "horizon_access_token";
const REFRESH_TOKEN_KEY = "horizon_refresh_token";
const USER_KEY = "horizon_user";

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
  if (!userStr) return null;
  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
}

export function setStoredUser(user: AuthenticatedUser): void {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

// API Client
class ApiClient {
  private baseUrl: string;
  private isRefreshing = false;
  private refreshPromise: Promise<string | null> | null = null;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const accessToken = getAccessToken();

    const headers: HeadersInit = {
      "Content-Type": "application/json",
      ...options.headers,
    };

    if (accessToken) {
      (headers as Record<string, string>)["Authorization"] = `Bearer ${accessToken}`;
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
        (headers as Record<string, string>)["Authorization"] = `Bearer ${newToken}`;
        const retryResponse = await fetch(url, {
          ...options,
          headers,
        });
        return this.handleResponse(retryResponse);
      } else {
        // Refresh failed, clear tokens and redirect to login
        clearTokens();
        window.dispatchEvent(new CustomEvent("auth:logout", { detail: { reason: "session_expired" } }));
        throw new ApiError(401, "UNAUTHORIZED", "Session expired");
      }
    }

    return this.handleResponse(response);
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const code = data?.code || "UNKNOWN_ERROR";
      const message = data?.message || "An error occurred";
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

    this.refreshPromise = (async () => {
      try {
        const response = await fetch(`${this.baseUrl}/api/v1/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: refreshToken }),
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
      } catch {
        clearTokens();
        return null;
      } finally {
        this.isRefreshing = false;
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  // Auth endpoints
  async login(email: string, password: string): Promise<AuthSuccessResponse> {
    const response = await this.request<AuthSuccessResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
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
    const response = await this.request<AuthSuccessResponse>("/api/v1/auth/setup", {
      method: "POST",
      body: JSON.stringify({ email, password, display_name: displayName }),
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
      await this.request<SuccessResponse>("/api/v1/auth/logout", {
        method: "POST",
      });
    } finally {
      clearTokens();
    }
  }

  async verifyMfa(code: string): Promise<AuthSuccessResponse> {
    const mfaToken = getAccessToken();
    const response = await this.request<AuthSuccessResponse>("/api/v1/auth/mfa/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${mfaToken}`,
      },
      body: JSON.stringify({ code }),
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
    const response = await this.request<AuthSuccessResponse>("/api/v1/auth/mfa/verify-backup", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${mfaToken}`,
      },
      body: JSON.stringify({ code }),
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
    return this.request<{ enabled: boolean }>("/api/v1/auth/mfa/status", {
      method: "GET",
    });
  }

  async enableMfa(password: string): Promise<{ success: boolean; secret: string; qr_code_base64: string; backup_codes: string[] }> {
    return this.request<{ success: boolean; secret: string; qr_code_base64: string; backup_codes: string[] }>("/api/v1/auth/mfa/enable", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
  }

  async verifyMfaSetup(code: string): Promise<SuccessResponse> {
    return this.request<SuccessResponse>("/api/v1/auth/mfa/verify-setup", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  async disableMfa(password: string): Promise<SuccessResponse> {
    return this.request<SuccessResponse>("/api/v1/auth/mfa/disable", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
  }

  // User endpoints
  async getProfile(): Promise<any> {
    return this.request<any>("/api/v1/users/me", {
      method: "GET",
    });
  }

  async updateProfile(data: { first_name?: string; last_name?: string }): Promise<any> {
    return this.request<any>("/api/v1/users/me", {
      method: "PUT",
      body: JSON.stringify(data),
    });
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<SuccessResponse> {
    return this.request<SuccessResponse>("/api/v1/users/me/password", {
      method: "PUT",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  }

  // Team endpoints
  async getTeams(): Promise<any> {
    return this.request<any>("/api/v1/teams", {
      method: "GET",
    });
  }

  async createTeam(data: { name: string; description?: string }): Promise<any> {
    return this.request<any>("/api/v1/teams", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async getTeamMembers(teamId: string): Promise<any> {
    return this.request<any>(`/api/v1/teams/${teamId}/members`, {
      method: "GET",
    });
  }

  // API Key endpoints
  async getApiKeys(): Promise<any> {
    return this.request<any>("/api/v1/auth/api-keys", {
      method: "GET",
    });
  }

  async createApiKey(data: { name: string; permissions?: string[]; expires_at?: string }): Promise<any> {
    return this.request<any>("/api/v1/auth/api-keys", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async deleteApiKey(id: string): Promise<SuccessResponse> {
    return this.request<SuccessResponse>(`/api/v1/auth/api-keys/${id}`, {
      method: "DELETE",
    });
  }

  // Health check
  async healthCheck(): Promise<any> {
    return fetch(`${this.baseUrl}/health`).then((res) => res.json());
  }
}

export const api = new ApiClient();

// Check if system needs setup
export async function checkSystemSetup(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const data = await response.json();
    return data.needs_setup === true;
  } catch {
    return true;
  }
}
