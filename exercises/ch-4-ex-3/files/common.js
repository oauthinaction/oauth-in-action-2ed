"use strict";

const copyLabelTimers = new WeakMap();

function announceCopyResult(status, message) {
  status.textContent = "";
  window.setTimeout(() => {
    status.textContent = message;
  }, 10);
}

function showTemporaryCopyLabel(button, label) {
  const originalLabel = button.dataset.copyLabel || button.getAttribute("aria-label");
  const currentTimer = copyLabelTimers.get(button);

  button.dataset.copyLabel = originalLabel;
  button.setAttribute("aria-label", label);
  window.clearTimeout(currentTimer);
  copyLabelTimers.set(button, window.setTimeout(() => {
    button.setAttribute("aria-label", originalLabel);
    copyLabelTimers.delete(button);
  }, 2000));
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-copy-button]");

  if (!button) {
    return;
  }

  const container = button.closest("[data-copy-container]");
  const value = container && container.querySelector("[data-copy-value]");
  const status = document.querySelector("[data-copy-status]");

  if (!value || !status) {
    return;
  }

  try {
    await navigator.clipboard.writeText(value.textContent || "");
    showTemporaryCopyLabel(button, "Copied");
    announceCopyResult(status, "Copied to clipboard.");
  } catch (error) {
    showTemporaryCopyLabel(button, "Copy failed");
    announceCopyResult(status, "Copy failed. Select and copy the value manually.");
  }
});
