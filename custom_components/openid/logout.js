const LOGOUT_SESSION_ENDPOINT = "/auth/openid/session";
let handlingLogout = false;

const findHass = () => document.querySelector("home-assistant")?.hass;

const waitForHass = async () => {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const hass = findHass();
    if (hass?.auth) return hass;
    await new Promise((resolve) => window.setTimeout(resolve, 250));
  }
  return null;
};

const loadLogoutPath = async (hass) => {
  try {
    let response;
    if (hass?.fetchWithAuth) {
      response = await hass.fetchWithAuth(LOGOUT_SESSION_ENDPOINT);
    } else {
      const token = hass?.auth?.accessToken || hass?.auth?.data?.access_token;
      if (!token) return null;
      response = await fetch(LOGOUT_SESSION_ENDPOINT, {
        headers: { Authorization: `Bearer ${token}` },
        cache: "no-store",
      });
    }
    if (response.status === 204) return null;
    if (!response.ok) throw new Error(`session endpoint returned ${response.status}`);
    const payload = await response.json();
    return typeof payload?.logout_path === "string" ? payload.logout_path : null;
  } catch (err) {
    console.warn("hass-openid: failed to prepare provider logout", err);
    return null;
  }
};

const performLogout = async (hass, logoutPath) => {
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
  window.location.assign(logoutPath);
};

const initializeLogoutOverride = async () => {
  const hass = await waitForHass();
  if (!hass) return;
  const logoutPath = await loadLogoutPath(hass);
  if (!logoutPath) return;

  window.addEventListener(
    "hass-logout",
    async (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      if (handlingLogout) return;
      handlingLogout = true;
      try {
        await performLogout(findHass() || hass, logoutPath);
      } finally {
        handlingLogout = false;
      }
    },
    { capture: true },
  );
};

void initializeLogoutOverride();
