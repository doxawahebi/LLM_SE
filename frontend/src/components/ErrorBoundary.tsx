import { Component, type ReactNode } from 'react';

interface Props { children: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-screen items-center justify-center bg-background">
          <div className="max-w-md text-center p-6 bg-card border border-border rounded-lg">
            <p className="text-destructive-foreground text-sm font-semibold mb-2">
              Something went wrong
            </p>
            <p className="text-muted-foreground text-xs font-mono mb-4">
              {this.state.error.message}
            </p>
            <button
              onClick={() => { this.setState({ error: null }); window.location.reload(); }}
              className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors"
            >
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
