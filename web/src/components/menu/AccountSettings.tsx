import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { baseUrl } from "@/api/baseUrl.ts";
import { cn } from "@/lib/utils";
import { TooltipPortal } from "@radix-ui/react-tooltip";
import { isDesktop } from "react-device-detect";
import { VscAccount } from "react-icons/vsc";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Drawer,
  DrawerContent,
  DrawerTrigger,
  DrawerClose,
} from "@/components/ui/drawer";
import { LuLogOut, LuShieldCheck } from "react-icons/lu";
import useSWR from "swr";

import { useState } from "react";
import TwoFactorAuthDialog from "../overlay/TwoFactorAuthDialog";
import { useTranslation } from "react-i18next";

type AccountSettingsProps = {
  className?: string;
};

export default function AccountSettings({ className }: AccountSettingsProps) {
  const { t } = useTranslation(["views/settings", "common"]);
  const { data: profile } = useSWR("profile");
  const { data: config } = useSWR("config");
  const logoutUrl = config?.proxy?.logout_url || `${baseUrl}api/logout`;

  const [twoFactorDialogOpen, setTwoFactorDialogOpen] = useState(false);

  const Container = isDesktop ? DropdownMenu : Drawer;
  const Trigger = isDesktop ? DropdownMenuTrigger : DrawerTrigger;
  const Content = isDesktop ? DropdownMenuContent : DrawerContent;
  const MenuItem = isDesktop ? DropdownMenuItem : DrawerClose;

  return (
    <Container modal={!isDesktop}>
      <Tooltip>
        <Trigger asChild>
          <TooltipTrigger asChild>
            <div
              className={cn(
                "flex flex-col items-center justify-center",
                isDesktop
                  ? "cursor-pointer rounded-lg bg-secondary text-secondary-foreground hover:bg-muted"
                  : "text-secondary-foreground",
                className,
              )}
            >
              <VscAccount className="size-5 md:m-[6px]" />
            </div>
          </TooltipTrigger>
        </Trigger>
        <TooltipPortal>
          <TooltipContent side="right" sideOffset={5}>
            <p>{t("menu.user.account", { ns: "common" })}</p>
          </TooltipContent>
        </TooltipPortal>
      </Tooltip>

      <Content
        className={cn(
          isDesktop ? "mr-5 w-72" : "max-h-[75dvh] overflow-hidden p-4",
        )}
      >
        <div className="scrollbar-container w-full flex-col overflow-y-auto overflow-x-hidden">
          <DropdownMenuLabel className="flex flex-col gap-1.5">
            <div>
              {t("menu.user.current", {
                ns: "common",
                user:
                  profile?.username ||
                  t("menu.user.anonymous", { ns: "common" }),
              })}{" "}
              {t("role." + profile?.role) &&
                `(${t("role." + profile?.role, { ns: "common" })})`}
            </div>
          </DropdownMenuLabel>

          <DropdownMenuSeparator className={isDesktop ? "my-2" : "my-2"} />

          {profile?.username && profile.username !== "anonymous" && (
            <MenuItem
              className={cn(
                "flex w-full items-center gap-2",
                isDesktop ? "cursor-pointer" : "p-2 text-sm",
              )}
              aria-label={t("menu.user.security", { ns: "common" })}
              onClick={() => setTwoFactorDialogOpen(true)}
            >
              <LuShieldCheck className="mr-2 size-4" />
              <span>{t("menu.user.security", { ns: "common" })}</span>
            </MenuItem>
          )}

          <MenuItem
            className={cn(
              "flex w-full items-center gap-2",
              isDesktop ? "cursor-pointer" : "p-2 text-sm",
            )}
            asChild
            aria-label={t("menu.user.logout", { ns: "common" })}
          >
            <a href={logoutUrl} className="flex items-center gap-2">
              <LuLogOut className="mr-2 size-4" />
              <span>{t("menu.user.logout", { ns: "common" })}</span>
            </a>
          </MenuItem>
        </div>
      </Content>
      <TwoFactorAuthDialog
        show={twoFactorDialogOpen}
        onClose={() => setTwoFactorDialogOpen(false)}
        username={profile?.username}
      />
    </Container>
  );
}
