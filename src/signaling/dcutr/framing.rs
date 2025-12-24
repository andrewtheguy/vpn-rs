//! Length-prefixed message framing for DCUtR signaling protocol.
//!
//! Message format:
//! ```text
//! ┌─────────────────┬──────────────────────────┐
//! │ Length (4 bytes)│ JSON-RPC Message (N bytes)│
//! │  big-endian u32 │                          │
//! └─────────────────┴──────────────────────────┘
//! ```

use anyhow::{anyhow, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size (1 MB)
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// Read a length-prefixed JSON message from a stream.
pub async fn read_message<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    // Read 4-byte length prefix (big-endian)
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    // Validate message size
    if len > MAX_MESSAGE_SIZE {
        return Err(anyhow!(
            "Message too large: {} bytes (max {})",
            len,
            MAX_MESSAGE_SIZE
        ));
    }

    if len == 0 {
        return Err(anyhow!("Empty message"));
    }

    // Read message body
    let mut msg_buf = vec![0u8; len as usize];
    reader.read_exact(&mut msg_buf).await?;

    // Parse JSON
    let message: T = serde_json::from_slice(&msg_buf)?;
    Ok(message)
}

/// Write a length-prefixed JSON message to a stream.
pub async fn write_message<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    // Serialize to JSON
    let json_bytes = serde_json::to_vec(message)?;

    // Validate message size
    if json_bytes.len() > MAX_MESSAGE_SIZE as usize {
        return Err(anyhow!(
            "Message too large: {} bytes (max {})",
            json_bytes.len(),
            MAX_MESSAGE_SIZE
        ));
    }

    // Write length prefix (big-endian)
    let len = json_bytes.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write message body
    writer.write_all(&json_bytes).await?;

    // Flush to ensure message is sent immediately
    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
    struct TestMessage {
        foo: String,
        bar: u32,
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let msg = TestMessage {
            foo: "hello".to_string(),
            bar: 42,
        };

        // Write to buffer
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        // Read back
        let mut cursor = Cursor::new(buf);
        let decoded: TestMessage = read_message(&mut cursor).await.unwrap();

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn test_message_format() {
        let msg = TestMessage {
            foo: "test".to_string(),
            bar: 123,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        // Check length prefix
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(len as usize, buf.len() - 4);

        // Check JSON content
        let json_str = std::str::from_utf8(&buf[4..]).unwrap();
        assert!(json_str.contains("\"foo\":\"test\""));
        assert!(json_str.contains("\"bar\":123"));
    }
}
