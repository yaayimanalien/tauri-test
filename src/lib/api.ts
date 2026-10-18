import { invoke } from "@tauri-apps/api/core";

export type Status = {
  exists: boolean;
  unlocked: boolean;
  biometricAvailable: boolean;
  biometricEnabled: boolean;
  driveConnected: boolean;
  lastBackup: number | null;
};
export type SyncResult = { uploaded: number; downloaded: number; removed: number; unchanged: number; at: number };
export type RawEntry = { id: string; title: string; body: string; created_at: number; updated_at: number };

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const errMsg = (e: unknown) =>
  typeof e === "string" ? e : (e as { message?: string })?.message || "Something went wrong";

const call = <T>(cmd: string, args?: Record<string, unknown>) => invoke<T>(cmd, args);

export const api = {
  status: () => call<Status>("vault_status"),
  setup: (password: string) => call<void>("setup_vault", { password }),
  unlock: (password: string) => call<void>("unlock", { password }),
  unlockBiometric: () => call<void>("unlock_biometric"),
  lock: () => call<void>("lock"),
  setBiometric: (enabled: boolean) => call<void>("set_biometric", { enabled }),
  changePassword: (old: string, next: string) => call<void>("change_password", { old, new: next }),
  list: () => call<RawEntry[]>("list_entries"),
  create: (title: string, body: string, id?: string, createdAt?: number) =>
    call<RawEntry>("create_entry", { title, body, id, createdAt }),
  update: (id: string, title: string, body: string) => call<RawEntry>("update_entry", { id, title, body }),
  remove: (id: string) => call<void>("delete_entry", { id }),
  driveConnect: (clientId: string, clientSecret: string) =>
    call<void>("drive_connect", { clientId, clientSecret }),
  driveDisconnect: () => call<void>("drive_disconnect"),
  sync: () => call<SyncResult>("sync_now"),
  restore: (clientId: string, clientSecret: string, password: string) =>
    call<number>("restore_from_drive", { clientId, clientSecret, password }),
};
