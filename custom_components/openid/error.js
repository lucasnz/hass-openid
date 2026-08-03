(() => {
  "use strict";
  const alertType = document.body.dataset.alertType;
  const alertMessage = document.body.dataset.alertMessage;
  if (alertType) {
    sessionStorage.setItem("openidAlertType", alertType);
  }
  if (alertMessage) {
    sessionStorage.setItem("openidAlertMessage", alertMessage);
  }
})();
