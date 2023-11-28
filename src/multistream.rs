//! multistream-select protocol negotiation
//!
//! A simple and minimal multistream-select initiator

use std::io::Error;
use std::io::ErrorKind;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

const MULTISTREAM_PROTOCOL: &str = "/multistream/1.0.0";

/// Serialise a multistream variable-length integer into a caller-provided byte vector
fn serialise_varint(dst: &mut Vec<u8>, value: u64) {
    let mut val: [u8; 10] = [0; 10];

    val[0] = TryInto::<u8>::try_into(0x80 | ((value >> 63) & 0x1)).unwrap();
    val[1] = TryInto::<u8>::try_into(0x80 | ((value >> 56) & 0x7f)).unwrap();
    val[2] = TryInto::<u8>::try_into(0x80 | ((value >> 49) & 0x7f)).unwrap();
    val[3] = TryInto::<u8>::try_into(0x80 | ((value >> 42) & 0x7f)).unwrap();
    val[4] = TryInto::<u8>::try_into(0x80 | ((value >> 35) & 0x7f)).unwrap();
    val[5] = TryInto::<u8>::try_into(0x80 | ((value >> 28) & 0x7f)).unwrap();
    val[6] = TryInto::<u8>::try_into(0x80 | ((value >> 21) & 0x7f)).unwrap();
    val[7] = TryInto::<u8>::try_into(0x80 | ((value >> 14) & 0x7f)).unwrap();
    val[8] = TryInto::<u8>::try_into(0x80 | ((value >> 7) & 0x7f)).unwrap();
    val[9] = TryInto::<u8>::try_into(value & 0x7f).unwrap();

    for i in 0..10 {
        if val[i] != 0x80 {
            dst.extend_from_slice(&val[i..10]);
            break;
        }
    }
}

/// Serialise a multistream (length-prefixed) line into a caller-provided byte vector
fn serialise_varint_line(dst: &mut Vec<u8>, line: &str) -> Result<(), Error> {
    serialise_varint(
        dst,
        (line.len() + 1).try_into().map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                format!(
                    "varint line serialisation error: invalid length {}",
                    line.len()
                ),
            )
        })?,
    );
    dst.extend_from_slice(line.as_bytes());
    dst.extend_from_slice("\n".as_bytes());

    Ok(())
}

/// Deserialise a multistream variable-length integer from the given stream
///
/// This returns the deserialised integer, or an error in case of an I/O or variable-length
/// integer parsing error.
async fn deserialise_varint<T>(stream: &mut T) -> Result<u64, Error>
where
    T: AsyncReadExt + Unpin,
{
    let mut value: u64 = 0;

    for i in 0..10 {
        let mut byte = 0;

        stream.read_exact(std::slice::from_mut(&mut byte)).await?;

        if i == 0 && byte == 0x80 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "varint parsing error: initial byte is 0x80",
            ));
        }

        value = (value << 7) | TryInto::<u64>::try_into(byte & 0x7f).unwrap();

        if (byte & 0x80) == 0 {
            return Ok(value);
        }
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "varint parsing error: varint is oversized",
    ))
}

/// Deserialise a multistream (length-prefixed) line from the given stream
///
/// This returns the deserialised line as a `String`, or an error in case of an I/O or parsing
/// error.
async fn deserialise_varint_line<T>(stream: &mut T) -> Result<String, Error>
where
    T: AsyncReadExt + Unpin,
{
    let len = deserialise_varint(stream).await?;

    if len == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "varint line parsing error: length is zero",
        ));
    }

    let len: usize = len.try_into().map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            format!("varint line parsing error: invalid length {}", len),
        )
    })?;

    let mut buf = vec![0; len];
    stream.read_exact(&mut buf).await?;

    if buf.pop() != Some('\n'.try_into().unwrap()) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "varint line parsing error: line doesn't end in newline",
        ));
    }

    String::from_utf8(buf).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "varint line parsing error: line is not valid UTF-8",
        )
    })
}

/// Perform multistream-select negotiation as the initiator
///
/// A list of protocols as UTF-8 strings is provided to this function in preference order, where
/// the first protocol is the most preferred protocol, and the last is the least preferred
/// protocol.
///
/// This function returns `Ok(Some(i))` in case of a successful negotation where `i` is the integer
/// index into the caller-provided array of the protocol that was successfully negotiated,
/// `Ok(None)` in case the initiator and responder speak no common protocols, or an error in case
/// of an I/O or parsing error.
pub async fn initiate<T>(stream: &mut T, protocols: &[&str]) -> Result<Option<usize>, Error>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    if protocols.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "empty protocol list"));
    }

    // We want to send the multistream protocol version and the first
    // offered sub-protocol in the same write() call, so that they go
    // out in the same TCP segment, hence the additional complexity.
    let mut handshake_message = Vec::<u8>::new();

    serialise_varint_line(&mut handshake_message, MULTISTREAM_PROTOCOL)?;

    for (i, protocol) in protocols.iter().enumerate() {
        serialise_varint_line(&mut handshake_message, protocol)?;
        stream.write_all(&handshake_message).await?;
        handshake_message.clear();

        let mut resp = deserialise_varint_line(stream).await?;
        if i == 0 {
            if resp != MULTISTREAM_PROTOCOL {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "remote offers unexpected multistream protocol version",
                ));
            }

            resp = deserialise_varint_line(stream).await?;
        }

        if resp == *protocol {
            return Ok(Some(i));
        }

        if resp != "na" {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "remote replied with unexpected protocol specifier",
            ));
        }
    }

    Ok(None)
}

/*
pub async fn respond<T>(
    stream: &mut T,
    protocols: &[&str],
) -> Result<Option<usize>, Error>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    todo!()
}
*/
