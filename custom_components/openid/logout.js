const LOGOUT_SESSION_ENDPOINT = "/auth/openid/session";

let handlingLogout = false;

const findHass = () => document.querySelector("home-assistant")?.hass;

const waitForHass = async () => {
  while (true) {
    const hass = findHass();
    if (hass?.auth) {
      return hass;
    }
    await new Promise((resolve) => window.setTimeout(resolve, 250));
  }
};

const loadLogoutSession = async (hass) => {
  try {
    let response;

    if (hass?.fetchWithAuth) {
      response = await hass.fetchWithAuth(LOGOUT_SESSION_ENDPOINT);
    } else {
      const token = hass?.auth?.accessToken || hass?.auth?.data?.access_token;
      if (!token) {
        return null;
      }

      response = await fetch(LOGOUT_SESSION_ENDPOINT, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
    }

    if (response.status === 204) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`session endpoint returned HTTP ${response.status}`);
    }

    const metadata = await response.json();
    return metadata?.logout_url ? metadata : null;
  } catch (err) {
    console.warn("hass-openid: failed to preload logout metadata", err);
    return null;
  }
};

const buildLogoutUrl = (metadata) => {
  if (!metadata?.logout_url) {
    return null;
  }

  try {
    const target = new URL(metadata.logout_url, window.location.origin);
    const params = metadata.parameters || {};

    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") {
        target.searchParams.set(key, value);
      }
    });

    return target.toString();
  } catch (err) {
    console.warn("hass-openid: invalid logout URL", err);
    return null;
  }
};

const performLogout = async (hass, redirectUrl) => {
  try {
    await hass.auth.revoke();
  } catch (err) {
    console.warn("hass-openid: Home Assistant token revocation failed", err);
  }

  try {
    hass.connection?.close?.();
  } catch (err) {
    console.warn("hass-openid: connection close failed", err);
  }

  window.location.assign(redirectUrl);
};

const initializeLogoutOverride = async () => {
  const hass = await waitForHass();
  const metadata = await loadLogoutSession(hass);
  const redirectUrl = buildLogoutUrl(metadata);

  // When no end-session endpoint is configured, leave Home Assistant's native
  // logout handling completely untouched.
  if (!redirectUrl) {
    return;
  }

  window.addEventListener(
    "hass-logout",
    async (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();

      if (handlingLogout) {
        return;
      }

      handlingLogout = true;

      try {
        await performLogout(findHass() || hass, redirectUrl);
      } finally {
        handlingLogout = false;
      }
    },
    { capture: true },
  );
};

void initializeLogoutOverride();
