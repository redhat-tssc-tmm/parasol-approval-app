import { useEffect, useRef, useState } from 'react';
import { WSMessage } from '../types';

type MessageHandler = (msg: WSMessage) => void;

export function useWebSocket(tenant: string | null, handlers: Record<string, MessageHandler>) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    if (!tenant) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/ws?tenant=${encodeURIComponent(tenant)}`;
    console.log('[ws] Connecting to', url);

    let reconnectTimeout: ReturnType<typeof setTimeout>;
    let ws: WebSocket;

    function connect() {
      ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[ws] Connected');
        setConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg: WSMessage = JSON.parse(event.data);
          console.log('[ws] Received:', msg.type, msg.data);
          const handler = handlersRef.current[msg.type];
          if (handler) {
            handler(msg);
          }
        } catch (err) {
          console.error('[ws] Failed to parse message:', err);
        }
      };

      ws.onclose = (event) => {
        console.log('[ws] Disconnected, code:', event.code, 'reason:', event.reason);
        setConnected(false);
        reconnectTimeout = setTimeout(() => {
          console.log('[ws] Reconnecting...');
          connect();
        }, 3000);
      };

      ws.onerror = (err) => {
        console.error('[ws] Error:', err);
      };
    }

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [tenant]);

  return { connected };
}
