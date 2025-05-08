export const capitalizeFirstLetter = (text: string): string => {
  return text.charAt(0).toUpperCase() + text.slice(1);
};

export const capitalizeAll = (text: string): string => {
  return text
    .replaceAll("_", " ")
    .split(" ")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
};

/**
 * Normalizes a TOTP code by removing spaces and non-digit characters.
 * @param code The TOTP code to normalize
 * @returns The normalized TOTP code
 */
export const normalizeTotpCode = (code: string): string => {
  return code.replace(/\s+/g, "").replace(/[^0-9]/g, "");
};

/**
 * Normalizes a recovery code by removing spaces, hyphens, and converting to uppercase.
 * @param code The recovery code to normalize
 * @returns The normalized recovery code
 */
export const normalizeRecoveryCode = (code: string): string => {
  return code.replace(/[\s-]+/g, "").toUpperCase();
};
