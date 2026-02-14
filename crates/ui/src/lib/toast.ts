import { toast as sonnerToast } from "sonner";

type ToastType = "success" | "error" | "info" | "warning";

export function toast(type: ToastType, message: string) {
    switch (type) {
        case "success":
            sonnerToast.success(message);
            break;
        case "error":
            sonnerToast.error(message);
            break;
        case "warning":
            sonnerToast.warning(message);
            break;
        case "info":
        default:
            sonnerToast.info(message);
            break;
    }
}

export function toastSuccess(message: string) {
    sonnerToast.success(message);
}

export function toastError(message: string) {
    sonnerToast.error(message);
}

export function toastInfo(message: string) {
    sonnerToast.info(message);
}

export function toastWarning(message: string) {
    sonnerToast.warning(message);
}
