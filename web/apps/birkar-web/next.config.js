const path = require("path");

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactCompiler: true,
  turbopack: {
    // Absolute path to monorepo root
    root: path.resolve(__dirname, "../../../"),
  },
};

module.exports = nextConfig;
