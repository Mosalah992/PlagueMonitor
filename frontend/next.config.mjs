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
        source: "/api/simulation/:path*",
        destination: "http://localhost:8001/api/:path*",
      },
    ]
  },
}

export default nextConfig
