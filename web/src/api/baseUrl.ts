declare global {
  interface Window {
    baseUrl?: string;
  }
}

// Fix for authentication redirection issue
// Use window.baseUrl if it exists, otherwise default to "/"
// Ensure we don't append undefined or null values
export const baseUrl = `${window.location.protocol}//${window.location.host}${window.baseUrl ? window.baseUrl : "/"}`;
