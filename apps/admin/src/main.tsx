import React from "react";
import ReactDOM from "react-dom/client";
import "./styles.css";
import { AdminApp } from "./admin/AdminApp";

// Release provenance is public metadata, not an authentication mechanism.
const sourceCommitMeta = document.createElement("meta");
sourceCommitMeta.name = "launcher-source-commit";
sourceCommitMeta.content = __LAUNCHER_SOURCE_COMMIT__;
document.head.appendChild(sourceCommitMeta);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AdminApp />
  </React.StrictMode>,
);
