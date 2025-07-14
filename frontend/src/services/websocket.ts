import { io, Socket } from 'socket.io-client';
import type {
  WebSocketMessage,
  NewLogMessage,
  NewAlertMessage,
  AlertUpdatedMessage,
  StatsUpdateMessage,
} from '../types/api';

type WebSocketEventHandler<T = unknown> = (data: T) => void;

class WebSocketService {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;

  connect(token: string): void {
    if (this.socket?.connected) {
      return;
    }

    this.socket = io('/ws', {
      auth: {
        token,
      },
      transports: ['websocket'],
      upgrade: false,
    });

    this.socket.on('connect', () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
    });

    this.socket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
      if (reason === 'io server disconnect') {
        // Server initiated disconnect, don't reconnect
        return;
      }
      this.handleReconnect();
    });

    this.socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      this.handleReconnect();
    });
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.reconnectAttempts = 0;
  }

  private handleReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
      
      console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
      
      setTimeout(() => {
        if (this.socket && !this.socket.connected) {
          this.socket.connect();
        }
      }, delay);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }

  // Event listeners
  onNewLog(handler: WebSocketEventHandler<NewLogMessage['data']>): void {
    this.socket?.on('new_log', handler);
  }

  onNewAlert(handler: WebSocketEventHandler<NewAlertMessage['data']>): void {
    this.socket?.on('new_alert', handler);
  }

  onAlertUpdated(handler: WebSocketEventHandler<AlertUpdatedMessage['data']>): void {
    this.socket?.on('alert_updated', handler);
  }

  onStatsUpdate(handler: WebSocketEventHandler<StatsUpdateMessage['data']>): void {
    this.socket?.on('stats_update', handler);
  }

  // Remove event listeners
  offNewLog(handler?: WebSocketEventHandler<NewLogMessage['data']>): void {
    this.socket?.off('new_log', handler);
  }

  offNewAlert(handler?: WebSocketEventHandler<NewAlertMessage['data']>): void {
    this.socket?.off('new_alert', handler);
  }

  offAlertUpdated(handler?: WebSocketEventHandler<AlertUpdatedMessage['data']>): void {
    this.socket?.off('alert_updated', handler);
  }

  offStatsUpdate(handler?: WebSocketEventHandler<StatsUpdateMessage['data']>): void {
    this.socket?.off('stats_update', handler);
  }

  // Generic message handler
  onMessage(handler: WebSocketEventHandler<WebSocketMessage>): void {
    this.socket?.onAny((event, data) => {
      handler({ type: event, data });
    });
  }

  // Connection status
  get isConnected(): boolean {
    return this.socket?.connected ?? false;
  }

  get connectionState(): string {
    if (!this.socket) return 'disconnected';
    if (this.socket.connected) return 'connected';
    return 'disconnected';
  }
}

export const websocketService = new WebSocketService();