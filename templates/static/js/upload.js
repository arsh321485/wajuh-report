// static/js/upload.js
document.addEventListener("DOMContentLoaded", function() {
  const form = document.getElementById("uploadForm");
  form.addEventListener("submit", function() {
    const btn = form.querySelector("button[type='submit']");
    btn.disabled = true;
    btn.innerText = "Uploading...";
  });
});