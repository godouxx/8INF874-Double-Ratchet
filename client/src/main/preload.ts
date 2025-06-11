import { contextBridge, ipcRenderer } from "electron";

// prettier-ignore
contextBridge.exposeInMainWorld("nativeAPI", {
  goToChat: (contactPerson: string) => ipcRenderer.invoke("go-to-chat", contactPerson),
  getContactName: () => ipcRenderer.invoke("get-contact-name"),
  getUsername: () => ipcRenderer.invoke("get-username"),
  setUsername: (username: string) => ipcRenderer.invoke("set-username", username),
  sendToContact: (to: string, content: string) => ipcRenderer.send("send-message", { to, content }),
  onIncomingMessage: (callback: (from: string, text: string) => void) =>
    ipcRenderer.on("incoming-message", (event, { from, content }) => {
      callback(from, content)
    }),
});
