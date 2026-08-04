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

const authenticatedFetch = async (hass, url) => {
  if (hass?.fetchWithAuth) return hass.fetchWithAuth(url);
  const token = hass?.auth?.accessToken || hass?.auth?.data?.access_token;
  if (!token) return null;
  return fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
};

const providerLogoutEnabled = async (hass) => {
  try {
    const response = await authenticatedFetch(
      hass,
      `${LOGOUT_SESSION_ENDPOINT}?probe=1`,
    );
    if (!response?.ok || response.status === 204) return false;
    const payload = await response.json();
    return payload?.enabled === true;
  } catch (_err) {
    return false;
  }
};

const createLogoutTicket = async (hass) => {
  try {
    const response = await authenticatedFetch(hass, LOGOUT_SESSION_ENDPOINT);
    if (!response?.ok) return null;
    const payload = await response.json();
    return typeof payload?.logout_path === "string" ? payload.logout_path : null;
  } catch (err) {
    console.warn("hass-openid: failed to prepare provider logout", err);
    return null;
  }
};

const revokeHomeAssistantSession = async (hass) => {
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
};

const initializeLogoutOverride = async () => {
  const hass = await waitForHass();
  if (!hass || !(await providerLogoutEnabled(hass))) return;

  window.addEventListener(
    "hass-logout",
    async (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      if (handlingLogout) return;
      handlingLogout = true;
      try {
        const activeHass = findHass() || hass;
        const logoutPath = await createLogoutTicket(activeHass);
        await revokeHomeAssistantSession(activeHass);
        window.location.assign(logoutPath || "/");
      } finally {
        handlingLogout = false;
      }
    },
    { capture: true },
  );
};

void initializeLogoutOverride();
