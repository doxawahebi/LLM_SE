interface Props {
  connected: boolean
}

export function SSEStatusIndicator({ connected }: Props) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <div
        className={`w-1.5 h-1.5 rounded-full ${
          connected ? 'bg-green-400' : 'bg-yellow-400 animate-pulse'
        }`}
      />
      <span className="text-muted-foreground">
        {connected ? 'Live' : 'Connecting…'}
      </span>
    </div>
  )
}
