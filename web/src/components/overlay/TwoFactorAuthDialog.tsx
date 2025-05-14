"use client";

import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  // DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";
import {
  normalizeTotpCode,
  normalizeRecoveryCode,
} from "@/utils/stringUtil.ts";
import { QRCodeSVG } from "qrcode.react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { Label } from "../ui/label";
import {
  LuShieldCheck,
  LuShieldAlert,
  LuKey,
  LuSquarePen,
  LuCheck,
  LuX,
} from "react-icons/lu";
import { useTranslation } from "react-i18next";
import axios from "axios";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";

type TwoFactorAuthDialogProps = {
  show: boolean;
  onClose: () => void;
  username?: string;
};

export default function TwoFactorAuthDialog({
  show,
  onClose,
  username: _username,
}: TwoFactorAuthDialogProps) {
  const { t } = useTranslation(["views/settings", "common"]);
  const [activeTab, setActiveTab] = useState<string>("setup");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isTwoFactorEnabled, setIsTwoFactorEnabled] = useState<boolean>(false);

  // Setup tab state
  const [qrCodeUri, setQrCodeUri] = useState<string>("");
  const [secret, setSecret] = useState<string>("");
  const [setupPassword, setSetupPassword] = useState<string>("");
  const [setupCode, setSetupCode] = useState<string>("");

  // Disable tab state
  const [disablePassword, setDisablePassword] = useState<string>("");
  const [disableCode, setDisableCode] = useState<string>("");
  const [disableUseRecoveryCode, setDisableUseRecoveryCode] =
    useState<boolean>(false);
  const [disableRecoveryCode, setDisableRecoveryCode] = useState<string>("");

  // Recovery codes tab state
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [recoveryPassword, setRecoveryPassword] = useState<string>("");
  const [showRecoveryCodes, setShowRecoveryCodes] = useState<boolean>(false);

  // Password change tab state
  const [password, setPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [passwordStrength, setPasswordStrength] = useState<number>(0);

  // Reset state when the dialog opens/closes
  useEffect(() => {
    if (show) {
      setActiveTab("password");
      setError(null);
      setSetupPassword("");
      setSetupCode("");
      setDisablePassword("");
      setDisableCode("");
      setDisableUseRecoveryCode(false);
      setDisableRecoveryCode("");
      setRecoveryPassword("");
      setShowRecoveryCodes(false);
      setRecoveryCodes([]);
      setPassword("");
      setConfirmPassword("");
      setPasswordStrength(0);

      // Check if 2FA is already enabled
      checkTwoFactorStatus().then(() => {});
    }
  }, [show]);

  const checkTwoFactorStatus = async () => {
    const response = await axios.get("/api/profile", {
      baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
    });
    // If the API returns 2FA status, we can use it to determine which tab to show
    if (response.data.two_factor_enabled) {
      setIsTwoFactorEnabled(true);
    } else {
      setIsTwoFactorEnabled(false);
    }
  };

  const handleSetupInit = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await axios.post(
        "/api/two-factor/setup",
        {},
        {
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
          headers: { "X-CSRF-TOKEN": "1" }, // Add CSRF token header
        },
      );
      setSecret(response.data.secret);
      setQrCodeUri(response.data.uri);
    } catch (error) {
      setError(t("twoFactor.errors.setupFailed"));
    } finally {
      setIsLoading(false);
    }
  };

  const handleSetupSubmit = async () => {
    if (!setupPassword || !setupCode || !secret) {
      setError(t("twoFactor.errors.missingFields"));
      return;
    }

    setIsLoading(true);
    setError(null);

    // Normalize the TOTP code
    const normalizedCode = normalizeTotpCode(setupCode);

    try {
      const response = await axios.post(
        "/api/two-factor/enable",
        {
          password: setupPassword,
          totp_code: normalizedCode,
          secret: secret,
        },
        {
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
          headers: { "X-CSRF-TOKEN": "1" }, // Add CSRF token header
        },
      );

      if (response.data.success) {
        setRecoveryCodes(response.data.recovery_codes);
        setShowRecoveryCodes(true);
        setIsTwoFactorEnabled(true);
        toast.success(t("twoFactor.toast.success.enabled"), {
          position: "top-center",
        });
        setActiveTab("recoveryCodes");
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response) {
        setError(
          error.response.data.message || t("twoFactor.errors.enableFailed"),
        );
      } else {
        setError(t("twoFactor.errors.enableFailed"));
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisableSubmit = async () => {
    if (!disablePassword || (!disableCode && !disableRecoveryCode)) {
      setError(t("twoFactor.errors.missingFields"));
      return;
    }

    setIsLoading(true);
    setError(null);

    // Normalize the TOTP code
    const normalizedCode = disableCode ? normalizeTotpCode(disableCode) : "";

    // Normalize the recovery code
    const normalizedRecoveryCode = disableRecoveryCode
      ? normalizeRecoveryCode(disableRecoveryCode)
      : "";

    try {
      const response = await axios.post(
        "/api/two-factor/disable",
        {
          password: disablePassword,
          totp_code: disableUseRecoveryCode ? undefined : normalizedCode,
          recovery_code: disableUseRecoveryCode
            ? normalizedRecoveryCode
            : undefined,
        },
        {
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
          headers: { "X-CSRF-TOKEN": "1" }, // Add CSRF token header
        },
      );

      if (response.data.success) {
        setIsTwoFactorEnabled(false);
        toast.success(t("twoFactor.toast.success.disabled"), {
          position: "top-center",
        });
        onClose();
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response) {
        setError(
          error.response.data.message || t("twoFactor.errors.disableFailed"),
        );
      } else {
        setError(t("twoFactor.errors.disableFailed"));
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleGenerateRecoveryCodes = async () => {
    if (!recoveryPassword) {
      setError(t("twoFactor.errors.passwordRequired"));
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await axios.post(
        "/api/two-factor/recovery-codes",
        {
          password: recoveryPassword,
        },
        {
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
          headers: { "X-CSRF-TOKEN": "1" }, // Add CSRF token header
        },
      );

      if (response.data.success) {
        setRecoveryCodes(response.data.recovery_codes);
        setShowRecoveryCodes(true);
        toast.success(t("twoFactor.toast.success.recoveryCodesGenerated"), {
          position: "top-center",
        });
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response) {
        setError(
          error.response.data.message ||
            t("twoFactor.errors.generateRecoveryCodesFailed"),
        );
      } else {
        setError(t("twoFactor.errors.generateRecoveryCodesFailed"));
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Simple password strength calculation
  useEffect(() => {
    if (!password) {
      setPasswordStrength(0);
      return;
    }

    let strength = 0;
    // Length check
    if (password.length >= 8) strength += 1;
    // Contains number
    if (/\d/.test(password)) strength += 1;
    // Contains special char
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength += 1;
    // Contains uppercase
    if (/[A-Z]/.test(password)) strength += 1;

    setPasswordStrength(strength);
  }, [password]);

  const getStrengthLabel = () => {
    if (!password) return "";
    if (passwordStrength <= 1)
      return t("users.dialog.form.password.strength.weak");
    if (passwordStrength === 2)
      return t("users.dialog.form.password.strength.medium");
    if (passwordStrength === 3)
      return t("users.dialog.form.password.strength.strong");
    return t("users.dialog.form.password.strength.veryStrong");
  };

  const getStrengthColor = () => {
    if (!password) return "bg-gray-200";
    if (passwordStrength <= 1) return "bg-red-500";
    if (passwordStrength === 2) return "bg-yellow-500";
    if (passwordStrength === 3) return "bg-green-500";
    return "bg-green-600";
  };

  const handlePasswordChange = async () => {
    if (!password) {
      setError(t("users.dialog.form.password.required"));
      return;
    }

    if (password !== confirmPassword) {
      setError(t("users.dialog.form.password.notMatch"));
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await axios.put(
        `/api/users/${_username}/password`,
        { password },
        {
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
          headers: { "X-CSRF-TOKEN": "1" }, // Add CSRF token header
        },
      );

      if (response.status === 200) {
        toast.success(t("users.toast.success.updatePassword"), {
          position: "top-center",
        });
        setPassword("");
        setConfirmPassword("");
        setPasswordStrength(0);
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response) {
        setError(
          error.response.data.message ||
            t("users.toast.error.setPasswordFailed", {
              errorMessage: "Unknown error",
            }),
        );
      } else {
        setError(
          t("users.toast.error.setPasswordFailed", {
            errorMessage: "Unknown error",
          }),
        );
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={show} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader className="space-y-2">
          <DialogTitle>{t("menu.user.security", { ns: "common" })}</DialogTitle>
          <DialogDescription>{t("twoFactor.description")}</DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList
            className={`grid w-full ${isTwoFactorEnabled ? "grid-cols-3" : "grid-cols-2"}`}
          >
            <TabsTrigger value="password">
              <LuSquarePen className="mr-2 h-4 w-4" />
              {t("users.dialog.passwordSetting.setPassword")}
            </TabsTrigger>
            {!isTwoFactorEnabled && (
              <TabsTrigger value="setup">
                <LuShieldCheck className="mr-2 h-4 w-4" />
                {t("twoFactor.tabs.setup")}
              </TabsTrigger>
            )}
            {isTwoFactorEnabled && (
              <TabsTrigger value="disable">
                <LuShieldAlert className="mr-2 h-4 w-4" />
                {t("twoFactor.tabs.disable")}
              </TabsTrigger>
            )}
            {isTwoFactorEnabled && (
              <TabsTrigger value="recoveryCodes">
                <LuKey className="mr-2 h-4 w-4" />
                {t("twoFactor.tabs.recoveryCodes")}
              </TabsTrigger>
            )}
          </TabsList>

          {/* Password Change Tab */}
          <TabsContent value="password" className="space-y-4 py-4">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="password">
                  {t("users.dialog.form.newPassword.title")}
                </Label>
                <Input
                  id="password"
                  className="h-10"
                  type="password"
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    setError(null);
                  }}
                  placeholder={t("users.dialog.form.newPassword.placeholder")}
                  autoFocus
                />

                {/* Password strength indicator */}
                {password && (
                  <div className="mt-2 space-y-1">
                    <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-secondary-foreground">
                      <div
                        className={`${getStrengthColor()} transition-all duration-300`}
                        style={{ width: `${(passwordStrength / 3) * 100}%` }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {t("users.dialog.form.password.strength.title")}
                      <span className="font-medium">{getStrengthLabel()}</span>
                    </p>
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirm-password">
                  {t("users.dialog.form.password.confirm.title")}
                </Label>
                <Input
                  id="confirm-password"
                  className="h-10"
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => {
                    setConfirmPassword(event.target.value);
                    setError(null);
                  }}
                  placeholder={t(
                    "users.dialog.form.newPassword.confirm.placeholder",
                  )}
                />

                {/* Password match indicator */}
                {password && confirmPassword && (
                  <div className="mt-1 flex items-center gap-1.5 text-xs">
                    {password === confirmPassword ? (
                      <>
                        <LuCheck className="size-3.5 text-green-500" />
                        <span className="text-green-600">
                          {t("users.dialog.form.password.match")}
                        </span>
                      </>
                    ) : (
                      <>
                        <LuX className="size-3.5 text-red-500" />
                        <span className="text-red-600">
                          {t("users.dialog.form.password.notMatch")}
                        </span>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>

            <Button
              className="w-full"
              onClick={handlePasswordChange}
              disabled={isLoading || !password || password !== confirmPassword}
            >
              {isLoading
                ? t("button.loading")
                : t("users.dialog.passwordSetting.updateButton")}
            </Button>
          </TabsContent>

          {/* Setup Tab */}
          <TabsContent value="setup" className="space-y-4 py-4">
            {!qrCodeUri ? (
              <div className="flex flex-col items-center justify-center space-y-4">
                <p>{t("twoFactor.setup.intro")}</p>
                <Button onClick={handleSetupInit} disabled={isLoading}>
                  {isLoading
                    ? t("button.loading")
                    : t("twoFactor.setup.startButton")}
                </Button>
              </div>
            ) : (
              <>
                <div className="space-y-4">
                  <Alert>
                    <AlertTitle>{t("twoFactor.setup.scanQrTitle")}</AlertTitle>
                    <AlertDescription>
                      {t("twoFactor.setup.scanQrDescription")}
                    </AlertDescription>
                  </Alert>

                  <div className="flex justify-center py-4">
                    <div className="border border-border p-4">
                      {qrCodeUri ? (
                        <QRCodeSVG
                          value={qrCodeUri}
                          size={192}
                          className="h-48 w-48"
                        />
                      ) : (
                        <div className="flex h-48 w-48 items-center justify-center">
                          <p className="text-center text-sm text-muted-foreground">
                            {t("twoFactor.setup.qrPlaceholder")}
                          </p>
                        </div>
                      )}
                      <p className="mt-2 break-all text-xs text-muted-foreground">
                        {t("twoFactor.setup.manualCode")}:{" "}
                        <span className="font-mono font-bold">{secret}</span>
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="setup-password">
                      {t("twoFactor.setup.password")}
                    </Label>
                    <Input
                      id="setup-password"
                      type="password"
                      value={setupPassword}
                      onChange={(e) => setSetupPassword(e.target.value)}
                      placeholder={t("twoFactor.setup.passwordPlaceholder")}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="setup-code">
                      {t("twoFactor.setup.verificationCode")}
                    </Label>
                    <Input
                      id="setup-code"
                      value={setupCode}
                      onChange={(e) => setSetupCode(e.target.value)}
                      placeholder={t(
                        "twoFactor.setup.verificationCodePlaceholder",
                      )}
                    />
                  </div>
                </div>

                <Button
                  className="w-full"
                  onClick={handleSetupSubmit}
                  disabled={isLoading || !setupPassword || !setupCode}
                >
                  {isLoading
                    ? t("button.loading")
                    : t("twoFactor.setup.enableButton")}
                </Button>
              </>
            )}
          </TabsContent>

          {/* Disable Tab */}
          <TabsContent value="disable" className="space-y-4 py-4">
            <Alert variant="destructive">
              <AlertTitle>{t("twoFactor.disable.warning")}</AlertTitle>
              <AlertDescription>
                {t("twoFactor.disable.warningDescription")}
              </AlertDescription>
            </Alert>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="disable-password">
                  {t("twoFactor.disable.password")}
                </Label>
                <Input
                  id="disable-password"
                  type="password"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                  placeholder={t("twoFactor.disable.passwordPlaceholder")}
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="disable-code">
                    {disableUseRecoveryCode
                      ? t("twoFactor.disable.recoveryCode")
                      : t("twoFactor.disable.verificationCode")}
                  </Label>
                  <Button
                    variant="link"
                    className="h-auto p-0 text-xs"
                    onClick={() =>
                      setDisableUseRecoveryCode(!disableUseRecoveryCode)
                    }
                  >
                    {disableUseRecoveryCode
                      ? t("twoFactor.disable.useVerificationCode")
                      : t("twoFactor.disable.useRecoveryCode")}
                  </Button>
                </div>

                {disableUseRecoveryCode ? (
                  <Input
                    id="disable-recovery-code"
                    value={disableRecoveryCode}
                    onChange={(e) => setDisableRecoveryCode(e.target.value)}
                    placeholder={t("twoFactor.disable.recoveryCodePlaceholder")}
                  />
                ) : (
                  <Input
                    id="disable-code"
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value)}
                    placeholder={t(
                      "twoFactor.disable.verificationCodePlaceholder",
                    )}
                  />
                )}
              </div>
            </div>

            <Button
              variant="destructive"
              className="w-full"
              onClick={handleDisableSubmit}
              disabled={
                isLoading ||
                !disablePassword ||
                (!disableCode && !disableRecoveryCode)
              }
            >
              {isLoading
                ? t("button.loading")
                : t("twoFactor.disable.disableButton")}
            </Button>
          </TabsContent>

          {/* Recovery Codes Tab */}
          <TabsContent value="recoveryCodes" className="space-y-4 py-4">
            {showRecoveryCodes ? (
              <div className="space-y-4">
                <Alert>
                  <AlertTitle>
                    {t("twoFactor.recoveryCodes.saveTitle")}
                  </AlertTitle>
                  <AlertDescription>
                    {t("twoFactor.recoveryCodes.saveDescription")}
                  </AlertDescription>
                </Alert>

                <Card>
                  <CardHeader>
                    <CardTitle>{t("twoFactor.recoveryCodes.title")}</CardTitle>
                    <CardDescription>
                      {t("twoFactor.recoveryCodes.description")}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-2">
                      {recoveryCodes.map((code, index) => (
                        <div key={index} className="font-mono text-sm">
                          {code}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                  <CardFooter>
                    <Button
                      className="w-full"
                      onClick={() => {
                        setShowRecoveryCodes(false);
                        setRecoveryCodes([]);
                        setRecoveryPassword("");
                      }}
                    >
                      {t("twoFactor.recoveryCodes.doneButton")}
                    </Button>
                  </CardFooter>
                </Card>
              </div>
            ) : (
              <div className="space-y-4">
                <p>{t("twoFactor.recoveryCodes.generateIntro")}</p>

                <div className="space-y-2">
                  <Label htmlFor="recovery-password">
                    {t("twoFactor.recoveryCodes.password")}
                  </Label>
                  <Input
                    id="recovery-password"
                    type="password"
                    value={recoveryPassword}
                    onChange={(e) => setRecoveryPassword(e.target.value)}
                    placeholder={t(
                      "twoFactor.recoveryCodes.passwordPlaceholder",
                    )}
                  />
                </div>

                <Button
                  className="w-full"
                  onClick={handleGenerateRecoveryCodes}
                  disabled={isLoading || !recoveryPassword}
                >
                  {isLoading
                    ? t("button.loading")
                    : t("twoFactor.recoveryCodes.generateButton")}
                </Button>
              </div>
            )}
          </TabsContent>
        </Tabs>

        {error && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {error}
          </div>
        )}

        {/*<DialogFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">*/}
        {/*  <Button*/}
        {/*    className="flex flex-1 sm:flex-none"*/}
        {/*    onClick={onClose}*/}
        {/*    type="button"*/}
        {/*  >*/}
        {/*    {t("button.close", { ns: "common" })}*/}
        {/*  </Button>*/}
        {/*</DialogFooter>*/}
      </DialogContent>
    </Dialog>
  );
}
