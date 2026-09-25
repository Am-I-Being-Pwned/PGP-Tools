import "../../lib/network-lockdown";

import ReactDOM from "react-dom/client";

import { Reader } from "./Reader";

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");
ReactDOM.createRoot(root).render(<Reader />);
