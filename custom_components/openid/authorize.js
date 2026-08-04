(() => {
  "use strict";

  const originalFetch = window.fetch.bind(window);
  const getFetchUrl = (input) => {
    if (typeof input === "string") {
      return input;
    }
    if (input instanceof URL) {
      return input.href;
    }
    if (typeof Request !== "undefined" && input instanceof Request) {
      return input.url;
    }
    return String(input ?? "");
  };

  window.fetch = async (...args) => {
    const response = await originalFetch(...args);
    if (!getFetchUrl(args[0]).includes("/auth/login_flow")) {
      return response;
    }

    window.fetch = originalFetch;

    let responseBody;
    try {
      responseBody = await response.clone().json();
    } catch {
      return response;
    }

    if (responseBody.block_login) {
      redirectOpenIdLogin();
      return response;
    }

    ensureOpenIdButton(responseBody.openid_text || "Login with OpenID");
    showStoredAlert();
    return response;
  };

  function showStoredAlert() {
    const authFlow = document.getElementsByClassName("card-content")[0];
    const alertType = sessionStorage.getItem("openidAlertType");
    const alertMessage = sessionStorage.getItem("openidAlertMessage");
    sessionStorage.removeItem("openidAlertType");
    sessionStorage.removeItem("openidAlertMessage");
    if (!alertType || !authFlow) {
      return;
    }

    const alertNode = document.createElement("ha-alert");
    alertNode.setAttribute("alert-type", alertType);
    alertNode.textContent = alertMessage || "OpenID sign-in failed";
    authFlow.prepend(alertNode);
  }

  function redirectOpenIdLogin({ selectAccount = false } = {}) {
    const urlParams = new URLSearchParams(window.location.search);
    const clientId = urlParams.get("client_id");
    const redirectUri = urlParams.get("redirect_uri");
    const state = urlParams.get("state");

    if (!clientId || !redirectUri) {
      return;
    }

    const authUrl = new URL("/auth/openid/authorize", window.location.origin);
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    if (state) {
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("client_state", state);
    }
    if (selectAccount) {
      authUrl.searchParams.set("prompt", "select_account");
    }

    window.location.assign(authUrl);
  }

  function ensureOpenIdButton(openIdText) {
    const candidateSelector = "ha-list-item, mwc-list-item";
    let stopped = false;

    const collectCandidates = (root) => {
      if (!root?.querySelectorAll) {
        return [];
      }
      const result = Array.from(root.querySelectorAll(candidateSelector));
      for (const node of root.querySelectorAll("*")) {
        if (node.shadowRoot) {
          result.push(...collectCandidates(node.shadowRoot));
        }
      }
      return result;
    };

    const resolveButton = () => {
      if (stopped) {
        return false;
      }
      const button = collectCandidates(document).find((item) => {
        if (!item) {
          return false;
        }
        if (item.dataset?.openidButton === "1") {
          return true;
        }
        const providerId =
          item.dataset?.providerId ||
          item.getAttribute("data-provider-id") ||
          item.value ||
          "";
        const text = (item.textContent || "").toLocaleLowerCase();
        return providerId.toLocaleLowerCase().includes("openid") || text.includes("openid");
      });
      if (!button) {
        return false;
      }
      if (button.dataset?.openidButton === "1") {
        return true;
      }

      const cleanedButton = button.cloneNode(false);
      cleanedButton.dataset.openidButton = "1";
      cleanedButton.textContent = openIdText;
      const icon = document.createElement("ha-icon-next");
      icon.setAttribute("slot", "meta");
      cleanedButton.append(" ", icon);
      cleanedButton.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        redirectOpenIdLogin({ selectAccount: event.shiftKey });
      });
      button.parentNode?.replaceChild(cleanedButton, button);
      return true;
    };

    if (resolveButton()) {
      return;
    }

    const observer = new MutationObserver(() => {
      if (resolveButton()) {
        stopped = true;
        observer.disconnect();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
    window.setTimeout(() => {
      stopped = true;
      observer.disconnect();
    }, 30_000);
  }
})();
