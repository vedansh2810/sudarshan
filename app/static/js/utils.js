/**
 * SUDARSHAN — Shared Frontend Utilities
 */

/**
 * Sanitize a string for safe insertion into DOM.
 * Prevents XSS by escaping HTML special characters.
 * @param {string} str - The raw string to sanitize
 * @returns {string} - HTML-safe string
 */
function sanitizeHTML(str) {
  if (str == null) return '';
  const s = String(str);
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return s.replace(/[&<>"']/g, c => map[c]);
}

/**
 * Toggle password field visibility.
 * @param {string} inputId - The id of the password input
 * @param {HTMLElement} btn - The toggle button element
 */
function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  const icon = btn.querySelector('.material-symbols-outlined');
  if (icon) {
    icon.textContent = isPassword ? 'visibility_off' : 'visibility';
  }
}
