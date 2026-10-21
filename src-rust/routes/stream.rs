use std::sync::Arc;
use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};

use crate::state::AppState;
use crate::auth;

/// GET /api/stream — upgrade to a WebSocket connection.
pub async fn handle_stream(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    if !auth::is_authenticated(&state.db, &headers).await {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state)).into_response()
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.ws_sender.subscribe();

    // A channel to send messages from the receive task to the send task
    // (so we can send "pong" back to the specific client without broadcasting)
    let (tx_direct, mut rx_direct) = tokio::sync::mpsc::channel::<String>(10);

    let mut send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Forward broadcast messages
                Ok(msg) = rx.recv() => {
                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                // Forward direct messages (e.g. "pong")
                Some(msg) = rx_direct.recv() => {
                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(t) = msg {
                if t == "ping" {
                    let _ = tx_direct.send("pong".to_string()).await;
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }
}
