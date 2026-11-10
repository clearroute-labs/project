import { useEffect, useRef, type ReactNode } from 'react'

export function DesertHero({ children }: { children: ReactNode }) {
  const hero = useRef<HTMLElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const image = useRef<HTMLImageElement>(null)
  useEffect(() => {
    let disposed = false
    let cleanup: (() => void) | undefined
    const start = () => {
      void import('../lib/duneGrain').then(({ startDuneGrain }) => {
        if (!disposed && hero.current && canvas.current && image.current) cleanup = startDuneGrain(hero.current, canvas.current, image.current)
      })
    }
    const source = image.current
    if (source?.complete) start()
    else source?.addEventListener('load', start, { once: true })
    return () => { disposed = true; source?.removeEventListener('load', start); cleanup?.() }
  }, [])
  return <section ref={hero} id="desert-hero" className="landing-hero" aria-labelledby="landing-title">
    <img ref={image} className="dune-image" src="/clear-dunes.webp" srcSet="/clear-dunes-mobile.webp 840w, /clear-dunes.webp 1672w" sizes="100vw" alt="" fetchPriority="high" width="1672" height="941" />
    <canvas ref={canvas} id="dune-grain" aria-hidden="true" />
    {children}
  </section>
}
