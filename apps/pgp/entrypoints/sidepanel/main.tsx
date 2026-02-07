import ReactDOM from "react-dom/client";
import { Toaster } from "sonner";

import App from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");
ReactDOM.createRoot(root).render(
  <>
    <App />
    <Toaster
      theme="dark"
      position="bottom-center"
      closeButton
      style={
        {
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "var(--border)",
        } as React.CSSProperties
      }
    />
  </>,
);
