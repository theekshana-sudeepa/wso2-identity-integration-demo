const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const identityConfig = require("./config/identityConfig");
const apiRoutes = require("./routes/apiRoutes");

const app = express();

app.use(helmet());
app.use(
  cors({
    origin: identityConfig.corsOrigin,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type"]
  })
);
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    environment: identityConfig.nodeEnv,
    jwksUri: identityConfig.jwksUri,
    uptimeSeconds: Math.round(process.uptime())
  });
});

app.use("/api/v1", apiRoutes);

app.use((_req, res) => {
  res.status(404).json({
    error: "not_found",
    message: "Requested API endpoint does not exist."
  });
});

app.use((err, _req, res, _next) => {
  console.error("[API Error]", err.message);
  res.status(500).json({
    error: "internal_server_error",
    message: "An unexpected server error occurred."
  });
});

app.listen(identityConfig.port, () => {
  console.log(
    `[WSO2 Resource Server] Listening on http://localhost:${identityConfig.port} (Issuer: ${identityConfig.issuer})`
  );
});
