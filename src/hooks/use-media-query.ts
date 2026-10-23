import { useState, useEffect } from 'react';

export function useMediaQuery(query: string): boolean {
    const [state, setState] = useState(() => ({
        query,
        matches: window.matchMedia(query).matches,
    }));

    // Adjust during render when the query changes so the value is never
    // stale for a different query (React's "adjust state when props change"
    // pattern; the effect below still runs unconditionally).
    let matches = state.matches;
    if (state.query !== query) {
        matches = window.matchMedia(query).matches;
        setState({ query, matches });
    }

    useEffect(() => {
        const mql = window.matchMedia(query);
        const handler = (event: MediaQueryListEvent) =>
            setState({ query, matches: event.matches });
        mql.addEventListener('change', handler);
        return () => mql.removeEventListener('change', handler);
    }, [query]);

    return matches;
}
