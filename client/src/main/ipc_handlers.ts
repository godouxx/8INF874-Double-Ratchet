import { BrowserWindow, ipcMain } from "electron";
import { userSession } from "./services/user_session";

export function registerIpcHandlers(mainWindow: BrowserWindow, base: string) {
  ipcMain.handle("go-to-chat", (event, username, contactPerson) => {
    userSession.username = username;
    userSession.contactPerson = contactPerson;
    mainWindow.loadURL(`${base}/chat.html`);
  });

  ipcMain.handle("get-contact-name", () => {
    return userSession.contactPerson;
  });
}
