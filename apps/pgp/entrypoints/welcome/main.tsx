import "../../lib/network-lockdown";

import ReactDOM from "react-dom/client";

import { Welcome } from "./Welcome";

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");
ReactDOM.createRoot(root).render(<Welcome />);
