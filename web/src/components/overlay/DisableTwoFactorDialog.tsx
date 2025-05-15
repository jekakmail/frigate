import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Button } from "../ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from "../ui/dialog";
import { DialogDescription } from "@radix-ui/react-dialog";
import { Input } from "../ui/input";
import { Label } from "../ui/label";

type DisableTwoFactorDialogProps = {
  show: boolean;
  username: string;
  onConfirm: () => void;
  onCancel: () => void;
};

export default function DisableTwoFactorDialog({
  show,
  username,
  onConfirm,
  onCancel,
}: DisableTwoFactorDialogProps) {
  const { t } = useTranslation(["views/settings"]);
  const [inputUsername, setInputUsername] = useState("");
  const [error, setError] = useState(false);

  const handleConfirm = () => {
    if (inputUsername === username) {
      onConfirm();
      setInputUsername("");
      setError(false);
    } else {
      setError(true);
    }
  };

  const handleCancel = () => {
    setInputUsername("");
    setError(false);
    onCancel();
  };

  return (
    <Dialog open={show} onOpenChange={handleCancel}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader className="flex flex-col items-center gap-2 sm:items-start">
          <div className="space-y-1 text-center sm:text-left">
            {t("twoFactor.dialog.disable.title")}
            <DialogDescription>
              {t("twoFactor.dialog.disable.desc")}
            </DialogDescription>
          </div>
        </DialogHeader>

        <div className="my-4 rounded-md border border-amber-500/20 bg-amber-500/5 p-4 text-center text-sm">
          <p className="font-medium text-amber-600">
            <Trans
              i18nKey="twoFactor.dialog.disable.warn"
              ns="views/settings"
              values={{ username }}
              components={{
                strong: <span className="font-medium" />,
              }}
            />
          </p>
        </div>

        <div className="grid gap-4 py-4">
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="username" className="col-span-4">
              {t("twoFactor.dialog.disable.confirmLabel")}
            </Label>
            <Input
              id="username"
              className={`col-span-4 ${error ? "border-red-500" : ""}`}
              value={inputUsername}
              onChange={(e) => {
                setInputUsername(e.target.value);
                if (error) setError(false);
              }}
              placeholder={t("twoFactor.dialog.disable.confirmPlaceholder")}
            />
            {error && (
              <p className="col-span-4 text-sm text-red-500">
                {t("twoFactor.dialog.disable.error")}
              </p>
            )}
          </div>
        </div>

        <DialogFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <div className="flex flex-1 flex-col justify-end">
            <div className="flex flex-row gap-2 pt-5">
              <Button
                className="flex flex-1"
                aria-label={t("button.cancel", { ns: "common" })}
                onClick={handleCancel}
                type="button"
              >
                {t("button.cancel", { ns: "common" })}
              </Button>
              <Button
                variant="destructive"
                aria-label={t("twoFactor.dialog.disable.confirmButton")}
                className="flex flex-1 bg-amber-500 hover:bg-amber-600"
                onClick={handleConfirm}
              >
                {t("twoFactor.dialog.disable.confirmButton")}
              </Button>
            </div>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
