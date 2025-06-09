import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("nativeAPI", {
  getPlatform: () => process.platform,
  helloWorld: (arg: string) => ipcRenderer.invoke("hello-world", arg),
});
