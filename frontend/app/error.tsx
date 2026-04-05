'use client'

import { useEffect } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error('Next.js Diagnostic Error:', error)
  }, [error])

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4 text-center">
      <div className="rounded-3xl border border-white/10 glass p-12 shadow-2xl transition-all hover:scale-[1.02]">
        <div className="mb-6 flex justify-center">
          <div className="rounded-2xl bg-destructive/20 p-4 drop-shadow-[0_0_20px_rgba(var(--destructive),0.4)]">
            <AlertTriangle className="h-16 w-16 text-destructive" />
          </div>
        </div>
        <h1 className="mb-2 text-4xl font-extrabold tracking-tight text-foreground">
          Render Error Detected
        </h1>
        <p className="mb-8 text-muted-foreground/80">
          An error occurred during the root render of the application. 
          Error digest: <code className="rounded bg-black/40 px-2 py-1 font-mono text-xs">{error.digest || 'no-digest'}</code>
        </p>
        <button
          onClick={() => reset()}
          className="inline-flex items-center gap-2 rounded-xl bg-primary px-6 py-3 font-bold text-primary-foreground transition-all hover:scale-105 hover:bg-primary/90"
        >
          <RefreshCw className="h-5 w-5" />
          Attempt Recovery
        </button>
      </div>
      <div className="mt-8 text-xs text-muted-foreground/40 font-mono italic max-w-md">
        Note: If you see this, Next.js is **successfully loading** but 
        hitting a runtime exception in layout/page logic.
      </div>
    </div>
  )
}
