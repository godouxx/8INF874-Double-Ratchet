import { BrowserWindow, ipcMain } from "electron";
import { userSession } from "./services/user_session";

export function registerIpcHandlers(mainWindow: BrowserWindow, base: string) {
  ipcMain.handle("set-username", (event, username) => {
    userSession.username = username;

    userSession.onMessage((from, content) => {
      mainWindow.webContents.send("incoming-message", { from, content });
    });
  });

  ipcMain.handle("go-to-chat", (event, contactPerson) => {
    userSession.contactPerson = contactPerson;
    mainWindow.loadURL(`${base}/chat.html`);
  });

  ipcMain.handle("get-username", () => {
    return userSession.username;
  });

  ipcMain.handle("get-contact-name", () => {
    return userSession.contactPerson;
  });

  ipcMain.on("send-message", (event, { to, content }) => {
    userSession.sendMessage(to, content);
  });
}
