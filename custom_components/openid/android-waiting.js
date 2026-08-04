(() => {
  "use strict";

  const authorizeUrl = document.body.dataset.authorizeUrl;
  const transactionId = document.body.dataset.transactionId;
  const authorizeLink = document.getElementById("openid-authorize-link");

  if (!authorizeUrl || !transactionId) {
    return;
  }

  if (authorizeLink) {
    authorizeLink.href = authorizeUrl;
  }

  const opened = window.open(authorizeUrl, "_blank", "noopener,noreferrer");
  if (!opened) {
    window.location.assign(authorizeUrl);
    return;
  }

  const startedAt = Date.now();
  const timeoutMs = 10 * 60 * 1000;

  const poll = async () => {
    if (Date.now() - startedAt > timeoutMs) {
      return;
    }

    try {
      const url = new URL("/auth/openid/android/status", window.location.origin);
      url.searchParams.set("transaction", transactionId);
      url.searchParams.set("_", String(Date.now()));
      const response = await fetch(url, {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (response.ok) {
        const data = await response.json();
        if (data.status === "completed" && data.callback_url) {
          window.location.assign(data.callback_url);
          return;
        }
        if (data.status === "expired" || data.status === "error") {
          return;
        }
      }
    } catch {
      // Ignore a transient same-origin polling failure.
    }

    window.setTimeout(poll, 2000);
  };

  void poll();
})();
