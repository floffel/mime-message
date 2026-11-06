//! Streaming parse surface: chunk boundaries, transport errors and the same
//! limit pair as the whole-buffer parser.

use std::fmt::Write as _;
use std::io::{self, Cursor, Read};

use mime_message::{parse, parse_with_limits, stream, Error, Limits, Message};

/// In-memory transport: every `read` returns at most the next queued chunk.
///
/// No socket, no file and no async: the test decides exactly where chunks split.
struct ChunkReader {
    chunks: Vec<Vec<u8>>,
    next: usize,
    offset: usize,
}

impl ChunkReader {
    fn split(raw: &str, sizes: &[usize]) -> Self {
        let bytes = raw.as_bytes();
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        for size in sizes {
            let end = (offset + size).min(bytes.len());
            chunks.push(bytes[offset..end].to_vec());
            offset = end;
        }
        if offset < bytes.len() {
            chunks.push(bytes[offset..].to_vec());
        }
        Self {
            chunks,
            next: 0,
            offset: 0,
        }
    }
}

impl Read for ChunkReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let Some(chunk) = self.chunks.get(self.next) else {
            return Ok(0);
        };
        let remaining = &chunk[self.offset..];
        let take = remaining.len().min(out.len());
        out[..take].copy_from_slice(&remaining[..take]);
        self.offset += take;
        if self.offset == chunk.len() {
            self.next += 1;
            self.offset = 0;
        }
        Ok(take)
    }
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "mock transport reset",
        ))
    }
}

fn with_from(content: &str) -> String {
    format!("From: a@example.com\r\n{content}")
}

fn base64_of(text: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(text.as_bytes())
}

#[test]
fn chunked_reader_equals_the_whole_buffer_parser_through_boundaries() {
    let attachment = base64_of("attachment bytes");
    let raw = with_from(concat!(
        "Subject: chunked\r\n",
        "Content-Type: multipart/mixed; boundary=b\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "body text\r\n",
        "--b\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
    )) + &attachment
        + "\r\n--b--\r\n";

    let expected = parse(&raw).expect("whole-buffer parse");
    let reader = ChunkReader::split(&raw, &[1, 2, 3, 5, 8, 13, 21, 34]);
    assert_eq!(
        stream::parse_reader(reader).expect("streamed parse"),
        expected
    );
}

#[test]
fn push_parser_accepts_chunks_inside_crlf_and_boundaries() {
    let raw = with_from(concat!(
        "Subject: chunks\r\n",
        "Content-Type: multipart/mixed; boundary=b\r\n",
        "\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n",
    ));
    let split_at = raw.find("\r\n--b--").expect("closing boundary") + 1;
    let mut parser = stream::StreamParser::new();
    parser
        .push(&raw.as_bytes()[..split_at])
        .expect("first half");
    parser
        .push(&raw.as_bytes()[split_at..])
        .expect("second half");
    assert_eq!(parser.finish().expect("parse"), parse(&raw).expect("whole"));
}

#[test]
fn byte_limit_pair_is_enforced_before_buffering_the_over_limit_chunk() {
    let raw = "From: a@example.com\r\n\r\nhello";
    let mut at_limit = Limits::default();
    at_limit.max_bytes = raw.len();
    assert_eq!(
        stream::parse_reader_with_limits(Cursor::new(raw.as_bytes()), &at_limit)
            .expect("at the byte limit"),
        parse_with_limits(raw, &at_limit).expect("whole-buffer at the byte limit")
    );

    let mut over_limit = Limits::default();
    over_limit.max_bytes = raw.len() - 1;
    let expected = Error::InputTooLarge {
        limit: over_limit.max_bytes,
        size: raw.len(),
    };
    assert_eq!(
        parse_with_limits(raw, &over_limit).expect_err("whole-buffer over the byte limit"),
        expected
    );
    assert_eq!(
        stream::parse_reader_with_limits(Cursor::new(raw.as_bytes()), &over_limit)
            .expect_err("streamed over the byte limit"),
        expected
    );
}

#[test]
fn push_parser_reports_the_same_byte_limit() {
    let mut limits = Limits::default();
    limits.max_bytes = 4;
    let mut parser = stream::StreamParser::with_limits(limits);
    parser.push(b"abcd").expect("exactly the limit");
    assert_eq!(parser.bytes_received(), 4);
    assert_eq!(
        parser.push(b"e").expect_err("one byte over the limit"),
        Error::InputTooLarge { limit: 4, size: 5 }
    );
    assert_eq!(parser.bytes_received(), 4);
}

#[test]
fn message_helpers_mirror_the_stream_functions() {
    let raw = with_from("Subject: helper\r\n\r\nbody");
    assert_eq!(
        Message::parse_reader(Cursor::new(raw.as_bytes())).expect("reader helper"),
        stream::parse_reader(Cursor::new(raw.as_bytes())).expect("free reader function")
    );

    let mut limits = Limits::default();
    limits.max_bytes = 1024;
    assert_eq!(
        Message::parse_reader_with_limits(Cursor::new(raw.as_bytes()), &limits)
            .expect("bounded reader helper"),
        stream::parse_reader_with_limits(Cursor::new(raw.as_bytes()), &limits)
            .expect("bounded free reader function")
    );
}

#[test]
fn depth_limit_pair_is_the_same_on_a_stream() {
    fn chain(containers: usize) -> String {
        let mut raw = String::new();
        for level in 0..containers {
            write!(
                raw,
                "Content-Type: multipart/mixed; boundary=b{level}\r\n\r\n--b{level}\r\n"
            )
            .expect("writing to a String cannot fail");
        }
        raw.push_str("Content-Type: text/plain\r\n\r\nleaf\r\n");
        for level in (0..containers).rev() {
            write!(raw, "--b{level}--\r\n").expect("writing to a String cannot fail");
        }
        with_from(&raw)
    }

    let mut limits = Limits::default();
    limits.max_depth = 1;
    let inside = chain(2);
    assert_eq!(
        stream::parse_reader_with_limits(Cursor::new(inside.as_bytes()), &limits)
            .expect("inside depth limit"),
        parse_with_limits(&inside, &limits).expect("whole-buffer inside depth limit")
    );

    let outside = chain(3);
    let expected = Error::LimitExceeded {
        what: "nesting depth",
        limit: 1,
    };
    assert_eq!(
        parse_with_limits(&outside, &limits).expect_err("whole-buffer outside depth limit"),
        expected
    );
    assert_eq!(
        stream::parse_reader_with_limits(Cursor::new(outside.as_bytes()), &limits)
            .expect_err("streamed outside depth limit"),
        expected
    );
}

#[test]
fn part_limit_pair_is_the_same_on_a_stream() {
    fn multipart(children: usize) -> String {
        let mut raw = String::from("Content-Type: multipart/mixed; boundary=b\r\n\r\n");
        for index in 0..children {
            write!(
                raw,
                "--b\r\nContent-Type: text/plain\r\n\r\npart {index}\r\n"
            )
            .expect("writing to a String cannot fail");
        }
        raw.push_str("--b--\r\n");
        with_from(&raw)
    }

    let mut limits = Limits::default();
    limits.max_parts = 3;
    let inside = multipart(2);
    assert_eq!(
        stream::parse_reader_with_limits(Cursor::new(inside.as_bytes()), &limits)
            .expect("inside part limit"),
        parse_with_limits(&inside, &limits).expect("whole-buffer inside part limit")
    );

    let outside = multipart(3);
    let expected = Error::LimitExceeded {
        what: "part count",
        limit: 3,
    };
    assert_eq!(
        parse_with_limits(&outside, &limits).expect_err("whole-buffer outside part limit"),
        expected
    );
    assert_eq!(
        stream::parse_reader_with_limits(Cursor::new(outside.as_bytes()), &limits)
            .expect_err("streamed outside part limit"),
        expected
    );
}

#[test]
fn invalid_utf8_and_read_failures_are_typed() {
    let mut parser = stream::StreamParser::new();
    parser.push(&[0xff]).expect("below byte limit");
    assert_eq!(
        parser.finish().expect_err("invalid UTF-8"),
        Error::InvalidUtf8 { offset: 0 }
    );

    assert_eq!(
        stream::parse_reader(FailingReader).expect_err("mock read failure"),
        Error::Read {
            kind: io::ErrorKind::ConnectionReset,
        }
    );
}

#[test]
fn stream_parser_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<stream::StreamParser>();
    assert_send_sync::<Message>();
}
