// Scam Link Detector - options.js

document.addEventListener("DOMContentLoaded", () => {

  const protectionToggle =
    document.getElementById("protection-toggle");

  const aggressiveToggle =
    document.getElementById("aggressive-toggle");

  const popupToggle =
    document.getElementById("popup-toggle");

  const downloadToggle =
    document.getElementById("download-toggle");

  const clearHistoryButton =
    document.getElementById("clear-history-button");

  loadSettings();

  protectionToggle.addEventListener("change", saveSettings);
  aggressiveToggle.addEventListener("change", saveSettings);
  popupToggle.addEventListener("change", saveSettings);
  downloadToggle.addEventListener("change", saveSettings);

  clearHistoryButton.addEventListener("click", clearHistory);

  function loadSettings() {

    chrome.storage.local.get(
      [
        "protectionEnabled",
        "aggressiveDetection",
        "popupProtection",
        "downloadProtection"
      ],
      (data) => {

        protectionToggle.checked =
          data.protectionEnabled !== false;

        aggressiveToggle.checked =
          data.aggressiveDetection !== false;

        popupToggle.checked =
          data.popupProtection !== false;

        downloadToggle.checked =
          data.downloadProtection !== false;
      }
    );
  }

  function saveSettings() {

    chrome.storage.local.set({

      protectionEnabled:
        protectionToggle.checked,

      aggressiveDetection:
        aggressiveToggle.checked,

      popupProtection:
        popupToggle.checked,

      downloadProtection:
        downloadToggle.checked

    }, () => {

      showSavedMessage();

    });
  }

  function clearHistory() {

    chrome.storage.local.set({
      scanHistory: []
    }, () => {

      alert("Scan history cleared.");

    });
  }

  function showSavedMessage() {

    let existingMessage =
      document.getElementById("saved-message");

    if (existingMessage) {
      existingMessage.remove();
    }

    const message =
      document.createElement("p");

    message.id = "saved-message";

    message.textContent =
      "Settings saved successfully.";

    message.style.color = "#5eead4";
    message.style.marginTop = "12px";
    message.style.fontWeight = "bold";

    document.body.appendChild(message);

    setTimeout(() => {

      message.remove();

    }, 2500);
  }

});
