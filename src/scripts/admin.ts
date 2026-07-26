interface AdminUser {
  id: string;
  email: string;
  roles: string[];
}

interface SessionResponse {
  authenticated: boolean;
  user?: AdminUser;
}

const API_BASE_URL = "https://api.andrewforcouncil.com";
const LOGIN_URL = `${import.meta.env.BASE_URL}admin/login/`;

function redirectToLogin(reason: string): void {
  const loginUrl = new URL(LOGIN_URL, window.location.origin);

  // Return the user to the requested admin page after login.
  const returnTo =
    window.location.pathname + window.location.search + window.location.hash;

  loginUrl.searchParams.set("returnTo", returnTo);
  loginUrl.searchParams.set("reason", reason);

  window.location.replace(loginUrl.toString());
}

async function requireAdmin(): Promise<void> {
  const controller = new AbortController();

  // Do not leave the page stuck forever if the API is unavailable.
  const timeoutId = window.setTimeout(() => {
    controller.abort();
  }, 8_000);

  try {
    const response = await fetch(`${API_BASE_URL}/auth/session`, {
      method: "GET",

      // Required so the browser sends the session cookie to your API.
      credentials: "include",

      headers: {
        Accept: "application/json",
      },

      cache: "no-store",
      signal: controller.signal,
    });

    if (response.status === 401) {
      redirectToLogin("signed-out");
      return;
    }

    if (response.status === 403) {
      redirectToLogin("not-authorized");
      return;
    }

    if (!response.ok) {
      throw new Error(`Session check failed with ${response.status}`);
    }

    const session = (await response.json()) as SessionResponse;

    const isAdmin =
      session.authenticated === true &&
      session.user !== undefined &&
      Array.isArray(session.user.roles) &&
      session.user.roles.includes("admin");

    if (!isAdmin) {
      redirectToLogin("not-authorized");
      return;
    }

    // Authentication succeeded. Reveal the admin panel.
    document.documentElement.removeAttribute("data-auth-pending");

    // Optional: admin controls can listen for this event.
    window.dispatchEvent(
      new CustomEvent<AdminUser>("admin:authenticated", {
        detail: session.user,
      }),
    );
  } catch (error) {
    console.error("Unable to verify the admin session:", error);
    redirectToLogin("auth-check-failed");
  } finally {
    window.clearTimeout(timeoutId);
  }
}

void requireAdmin();
