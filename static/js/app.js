/*
 * UI polish only. NO security decisions live here — authorization is enforced
 * exclusively server-side by the Django authorization engine.
 */
(function () {
  "use strict";

  // Uppercase Officer ID as the officer types (cosmetic).
  var officerInput = document.getElementById("id_officer_id");
  if (officerInput) {
    officerInput.addEventListener("input", function () {
      var start = officerInput.selectionStart;
      var end = officerInput.selectionEnd;
      var upper = officerInput.value.toUpperCase();
      if (upper !== officerInput.value) {
        officerInput.value = upper;
        officerInput.setSelectionRange(start, end);
      }
    });
  }

  // Prevent accidental double-submit on authentication forms.
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    var btn = form.querySelector("button[type=submit]");
    if (btn && btn.dataset && btn.dataset.submitting === "1") {
      event.preventDefault();
      return;
    }
    if (btn) {
      btn.dataset.submitting = "1";
      window.setTimeout(function () { delete btn.dataset.submitting; }, 3000);
    }
  });
})();
