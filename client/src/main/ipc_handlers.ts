import { ipcMain } from "electron";

export function registerIpcHandlers() {
  ipcMain.handle("hello-world", async (event, arg: string) => {
    return `Hello, ${arg}! This is a response from the main process.`;
  });
}
