import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("nativeAPI", {
  goToChat: (username: string, contactPerson: string) =>
    ipcRenderer.invoke("go-to-chat", username, contactPerson),
  getContactName: () => ipcRenderer.invoke("get-contact-name"),
});
