import * as React from "react";
import { cn } from "@/lib/utils";
import { normalizeTotpCode, normalizeRecoveryCode } from "@/utils/stringUtil";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import ActivityIndicator from "@/components/indicators/activity-indicator";
import axios, { AxiosError } from "axios";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import { baseUrl } from "@/api/baseUrl.ts";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormDescription,
} from "@/components/ui/form";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { AuthContext } from "@/context/auth-context";
import { useTranslation } from "react-i18next";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface TwoFactorFormProps extends React.HTMLAttributes<HTMLDivElement> {
  username: string;
}

export function TwoFactorForm({
  className,
  username,
  ...props
}: TwoFactorFormProps) {
  const { t } = useTranslation(["components/auth"]);
  const [isLoading, setIsLoading] = React.useState<boolean>(false);
  const { login } = React.useContext(AuthContext);
  const [, setActiveTab] = React.useState<string>("totp");

  const totpFormSchema = z.object({
    totp_code: z.string().min(6, t("form.errors.totpRequired")).max(8),
    remember_device: z.boolean().default(false),
  });

  const recoveryFormSchema = z.object({
    recovery_code: z.string().min(10, t("form.errors.recoveryCodeRequired")),
    remember_device: z.boolean().default(false),
  });

  const totpForm = useForm<z.infer<typeof totpFormSchema>>({
    resolver: zodResolver(totpFormSchema),
    mode: "onChange",
    defaultValues: { totp_code: "", remember_device: false },
  });

  const recoveryForm = useForm<z.infer<typeof recoveryFormSchema>>({
    resolver: zodResolver(recoveryFormSchema),
    mode: "onChange",
    defaultValues: { recovery_code: "", remember_device: false },
  });

  const onSubmitTotp = async (values: z.infer<typeof totpFormSchema>) => {
    setIsLoading(true);
    try {
      // Normalize the TOTP code
      const normalizedCode = normalizeTotpCode(values.totp_code);

      const response = await axios.post(
        "/api/verify-totp",
        {
          user: username,
          totp_code: normalizedCode,
          remember_device: values.remember_device,
        },
        {
          headers: { "X-CSRF-TOKEN": "1" }, // Ensure a consistent string format
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
        },
      );
      response.status;

      const profileRes = await axios.get("/api/profile", {
        withCredentials: true,
        baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
      });
      login({
        username: profileRes.data.username,
        role: profileRes.data.role || "viewer",
      });
      window.location.href = baseUrl;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const err = error as AxiosError;
        if (err.response?.status === 429) {
          toast.error(t("form.errors.rateLimit"), {
            position: "top-center",
          });
        } else if (err.response?.status === 401) {
          toast.error(t("form.errors.invalidCode"), {
            position: "top-center",
          });
        } else {
          toast.error(t("form.errors.unknownError"), {
            position: "top-center",
          });
        }
      } else {
        toast.error(t("form.errors.webUnknownError"), {
          position: "top-center",
        });
      }

      setIsLoading(false);
    }
  };

  const onSubmitRecovery = async (
    values: z.infer<typeof recoveryFormSchema>,
  ) => {
    setIsLoading(true);
    try {
      // Normalize the recovery code
      const normalizedCode = normalizeRecoveryCode(values.recovery_code);

      const response = await axios.post(
        "/api/verify-recovery-code",
        {
          user: username,
          recovery_code: normalizedCode,
          remember_device: values.remember_device,
        },
        {
          headers: { "X-CSRF-TOKEN": "1" }, // Ensure a consistent string format
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
        },
      );
      response.status;

      const profileRes = await axios.get("/api/profile", {
        withCredentials: true,
        baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
      });
      login({
        username: profileRes.data.username,
        role: profileRes.data.role || "viewer",
      });
      window.location.href = baseUrl;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const err = error as AxiosError;
        if (err.response?.status === 429) {
          toast.error(t("form.errors.rateLimit"), {
            position: "top-center",
          });
        } else if (err.response?.status === 401) {
          toast.error(t("form.errors.invalidRecoveryCode"), {
            position: "top-center",
          });
        } else {
          toast.error(t("form.errors.unknownError"), {
            position: "top-center",
          });
        }
      } else {
        toast.error(t("form.errors.webUnknownError"), {
          position: "top-center",
        });
      }

      setIsLoading(false);
    }
  };

  return (
    <div className={cn("grid gap-6", className)} {...props}>
      <h2 className="text-2xl font-bold">{t("form.twoFactorTitle")}</h2>
      <p className="text-muted-foreground">{t("form.twoFactorDescription")}</p>

      <Tabs defaultValue="totp" onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="totp">{t("form.authApp")}</TabsTrigger>
          <TabsTrigger value="recovery">{t("form.recoveryCode")}</TabsTrigger>
        </TabsList>
        <TabsContent value="totp">
          <Form {...totpForm}>
            <form
              onSubmit={totpForm.handleSubmit(onSubmitTotp)}
              className="space-y-4"
            >
              <FormField
                name="totp_code"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t("form.verificationCode")}</FormLabel>
                    <FormControl>
                      <Input
                        className="text-md w-full border border-input bg-background p-2 hover:bg-accent hover:text-accent-foreground dark:[color-scheme:dark]"
                        autoFocus
                        placeholder="123456"
                        {...field}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
              <FormField
                name="remember_device"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-start space-x-3 space-y-0 pt-4">
                    <FormControl>
                      <Checkbox
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                    <div className="space-y-1 leading-none">
                      <FormLabel>{t("form.rememberDevice")}</FormLabel>
                      <FormDescription>
                        {t("form.rememberDeviceDescription")}
                      </FormDescription>
                    </div>
                  </FormItem>
                )}
              />
              <div className="flex flex-row gap-2 pt-5">
                <Button
                  variant="select"
                  disabled={isLoading}
                  className="flex flex-1"
                  aria-label={t("form.verify")}
                >
                  {isLoading && <ActivityIndicator className="mr-2 h-4 w-4" />}
                  {t("form.verify")}
                </Button>
              </div>
            </form>
          </Form>
        </TabsContent>
        <TabsContent value="recovery">
          <Form {...recoveryForm}>
            <form
              onSubmit={recoveryForm.handleSubmit(onSubmitRecovery)}
              className="space-y-4"
            >
              <FormField
                name="recovery_code"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t("form.recoveryCode")}</FormLabel>
                    <FormControl>
                      <Input
                        className="text-md w-full border border-input bg-background p-2 hover:bg-accent hover:text-accent-foreground dark:[color-scheme:dark]"
                        autoFocus
                        placeholder="XXXX-XXXX-XX"
                        {...field}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
              <FormField
                name="remember_device"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-start space-x-3 space-y-0 pt-4">
                    <FormControl>
                      <Checkbox
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                    <div className="space-y-1 leading-none">
                      <FormLabel>{t("form.rememberDevice")}</FormLabel>
                      <FormDescription>
                        {t("form.rememberDeviceDescription")}
                      </FormDescription>
                    </div>
                  </FormItem>
                )}
              />
              <div className="flex flex-row gap-2 pt-5">
                <Button
                  variant="select"
                  disabled={isLoading}
                  className="flex flex-1"
                  aria-label={t("form.verify")}
                >
                  {isLoading && <ActivityIndicator className="mr-2 h-4 w-4" />}
                  {t("form.verify")}
                </Button>
              </div>
            </form>
          </Form>
        </TabsContent>
      </Tabs>
      <Toaster />
    </div>
  );
}
