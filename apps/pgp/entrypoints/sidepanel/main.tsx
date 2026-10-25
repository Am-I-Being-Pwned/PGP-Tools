import "../../lib/network-lockdown";

import ReactDOM from "react-dom/client";

import { ToastHost } from "../../components/shared/ToastHost";
import App from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");
ReactDOM.createRoot(root).render(
  <>
    <App />
    <ToastHost />
  </>,
);
