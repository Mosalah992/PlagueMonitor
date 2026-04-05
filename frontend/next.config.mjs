/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    // Only apply localhost rewrites in development
    if (process.env.NODE_ENV === "development") {
      return [
        {
          source: "/api/beacon/:path*",
          destination: "http://localhost:8001/api/beacon/:path*",
        },
      ]
    }
    return []
  },
}

export default nextConfig
