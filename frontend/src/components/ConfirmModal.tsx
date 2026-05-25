import * as Dialog from "@radix-ui/react-dialog";
import { cn } from "@/lib/cn";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  destructive?: boolean;
}

export function ConfirmModal({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  onConfirm,
  destructive = false,
}: Props) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-50" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-card border border-border rounded-lg p-6 w-full max-w-md shadow-xl">
          <Dialog.Title className="text-sm font-semibold text-foreground mb-2">
            {title}
          </Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground mb-6">
            {description}
          </Dialog.Description>
          <div className="flex justify-end gap-3">
            <Dialog.Close asChild>
              <button className="px-4 py-2 text-sm rounded bg-secondary hover:bg-accent transition-colors">
                {cancelLabel}
              </button>
            </Dialog.Close>
            <button
              onClick={() => {
                onConfirm();
                onOpenChange(false);
              }}
              className={cn(
                "px-4 py-2 text-sm rounded transition-colors",
                destructive
                  ? "bg-destructive text-destructive-foreground hover:bg-destructive/80"
                  : "bg-primary text-primary-foreground hover:bg-primary/80"
              )}
            >
              {confirmLabel}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
