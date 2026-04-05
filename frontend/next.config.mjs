/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    return [
      {
        source: "/api/beacon/:path*",
        destination: "http://localhost:8001/api/beacon/:path*",
      },
    ]
  },
}

export default nextConfig
