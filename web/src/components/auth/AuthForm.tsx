"use client";

import * as React from "react";

import { baseUrl } from "@/api/baseUrl";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import ActivityIndicator from "@/components/indicators/activity-indicator";
import axios, { AxiosError } from "axios";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
} from "@/components/ui/form";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { AuthContext } from "@/context/auth-context";
import { useTranslation } from "react-i18next";
import { TwoFactorForm } from "./TwoFactorForm";

interface UserAuthFormProps extends React.HTMLAttributes<HTMLDivElement> {}

export function UserAuthForm({ className, ...props }: UserAuthFormProps) {
  const { t } = useTranslation(["components/auth"]);
  const [isLoading, setIsLoading] = React.useState<boolean>(false);
  const [requires2FA, setRequires2FA] = React.useState<boolean>(false);
  const [username2FA, setUsername2FA] = React.useState<string>("");
  const { login } = React.useContext(AuthContext);

  const formSchema = z.object({
    user: z.string().min(1, t("form.errors.usernameRequired")),
    password: z.string().min(1, t("form.errors.passwordRequired")),
  });

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    mode: "onChange",
    defaultValues: { user: "", password: "" },
  });

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    setIsLoading(true);
    try {
      const response = await axios.post(
        "/api/login",
        {
          user: values.user,
          password: values.password,
        },
        {
          headers: { "X-CSRF-TOKEN": 1 },
          baseURL: window.location.origin, // Use absolute URL to bypass axios baseURL
        },
      );

      // Check if 2FA is required - handle both snake_case and camelCase property names
      if (response.data.requires_2fa || response.data.requires2fa) {
        setRequires2FA(true);
        // Handle both snake_case and camelCase property names for the user
        setUsername2FA(response.data.user);
        setIsLoading(false);
        return;
      }

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
          toast.error(t("form.errors.loginFailed"), {
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
      {requires2FA ? (
        <TwoFactorForm username={username2FA} />
      ) : (
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              name="user"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t("form.user")}</FormLabel>
                  <FormControl>
                    <Input
                      className="text-md w-full border border-input bg-background p-2 hover:bg-accent hover:text-accent-foreground dark:[color-scheme:dark]"
                      autoFocus
                      autoCapitalize="off"
                      autoCorrect="off"
                      spellCheck="false"
                      {...field}
                    />
                  </FormControl>
                </FormItem>
              )}
            />
            <FormField
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t("form.password")}</FormLabel>
                  <FormControl>
                    <Input
                      className="text-md w-full border border-input bg-background p-2 hover:bg-accent hover:text-accent-foreground dark:[color-scheme:dark]"
                      type="password"
                      {...field}
                    />
                  </FormControl>
                </FormItem>
              )}
            />
            <div className="flex flex-row gap-2 pt-5">
              <Button
                variant="select"
                disabled={isLoading}
                className="flex flex-1"
                aria-label={t("form.login")}
              >
                {isLoading && <ActivityIndicator className="mr-2 h-4 w-4" />}
                {t("form.login")}
              </Button>
            </div>
          </form>
        </Form>
      )}
      <Toaster />
    </div>
  );
}
