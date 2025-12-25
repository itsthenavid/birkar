import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  turbopack: {
    // repo root (where pnpm-lock.yaml lives) when running via turbo/pnpm
    root: process.cwd(),
  },
};

export default nextConfig;
