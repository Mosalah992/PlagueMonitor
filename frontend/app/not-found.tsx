import Link from 'next/link'
import { FileQuestion, Home } from 'lucide-react'

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4 text-center">
      <div className="rounded-3xl border border-white/10 glass p-12 shadow-2xl transition-all hover:scale-[1.02]">
        <div className="mb-6 flex justify-center">
          <div className="rounded-2xl bg-destructive/20 p-4 drop-shadow-[0_0_20px_rgba(var(--destructive),0.4)]">
            <FileQuestion className="h-16 w-16 text-destructive" />
          </div>
        </div>
        <h1 className="mb-2 text-4xl font-extrabold tracking-tight text-foreground">
          404 - Diagnostic Route
        </h1>
        <p className="mb-8 text-muted-foreground/80">
          If you see this page, Next.js is **running correctly** but 
          could not find the route you requested.
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-2 rounded-xl bg-primary px-6 py-3 font-bold text-primary-foreground transition-all hover:scale-105 hover:bg-primary/90"
        >
          <Home className="h-5 w-5" />
          Return Home
        </Link>
      </div>
      <div className="mt-8 text-xs text-muted-foreground/40 font-mono italic">
        Status: Next.js App Router Active
      </div>
    </div>
  )
}
