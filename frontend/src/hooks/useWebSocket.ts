import { useEffect, useRef, useState } from 'react';
import { WSPayload } from '@/types';

interface UseWebSocketOptions {
  onMessage?: (payload: WSPayload) => void;
  enabled?: boolean;
}

export function useWebSocket({
  onMessage,
  enabled = true,
}: UseWebSocketOptions) {
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WSPayload | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const handlerRef = useRef(onMessage);
  handlerRef.current = onMessage;

  useEffect(() => {
    if (!enabled) return;

    const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`;
    let disposed = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let ws: WebSocket | null = null;

    const connect = () => {
      if (disposed) return;
      const socket = new WebSocket(WS_URL);
      wsRef.current = socket;

      socket.onopen = () => {
        if (disposed) return;
        setConnected(true);
      };

      socket.onmessage = (event) => {
        if (disposed) return;
        try {
          const parsed = JSON.parse(event.data as string) as WSPayload;
          setLastMessage(parsed);
          if (handlerRef.current) {
            handlerRef.current(parsed);
          }
        } catch {
          // ignore malformed frames
        }
      };

      socket.onclose = () => {
        if (disposed) return;
        setConnected(false);
        retryTimer = setTimeout(connect, 2000);
      };

      socket.onerror = () => {
        socket.close();
      };
    };

    connect();

    return () => {
      disposed = true;
      if (retryTimer) clearTimeout(retryTimer);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
      wsRef.current = null;
    };
  }, [enabled]);

  const send = (data: unknown) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  };

  return { connected, lastMessage, send };
}