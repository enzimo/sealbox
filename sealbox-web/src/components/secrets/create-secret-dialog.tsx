"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";

interface CreateSecretDialogProps {
  children?: React.ReactNode;
}

export function CreateSecretDialog({ children }: CreateSecretDialogProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [newSecret, setNewSecret] = useState({ name: "" });

  const handleAddSecret = async () => {
    if (!newSecret.name) {
      toast.error(t("secrets.dialog.missingFields"), {
        description: t("secrets.dialog.name"),
      });
      return;
    }

    toast.info(t("secrets.decryptHint.title"), {
      description: `sealbox-cli secret set ${newSecret.name}`,
      duration: 5000,
    });

    setNewSecret({ name: "" });
    setOpen(false);
  };

  const handleCancel = () => {
    setNewSecret({ name: "" });
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{children}</DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-lg">
            {t("secrets.dialog.addNewSecret")}
          </DialogTitle>
          <DialogDescription className="text-sm">
            {t("secrets.dialog.addNewSecretDescription")}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label htmlFor="name" className="text-xs">
              {t("secrets.dialog.name")}
            </Label>
            <Input
              id="name"
              placeholder={t("secrets.dialog.nameHelp")}
              value={newSecret.name}
              onChange={(e) =>
                setNewSecret({ ...newSecret, name: e.target.value })
              }
              className="h-8"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={handleCancel} size="sm">
            {t("common.cancel")}
          </Button>
          <Button onClick={handleAddSecret} size="sm">
            {t("secrets.controls.addSecret")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
