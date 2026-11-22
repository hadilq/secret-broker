//! Replace known secret values in a byte stream with `[REDACTED]`.
//! Defence in depth only: a child that transforms a value (base64, splitting,
//! reversing) before printing it is not caught.

use zeroize::Zeroizing;

pub const MIN_LEN: usize = 4;
pub const MASK: &[u8] = b"[REDACTED]";

pub struct Redactor {
    secrets: Vec<Zeroizing<Vec<u8>>>, // longest first
    buf: Zeroizing<Vec<u8>>,
}

impl Redactor {
    pub fn new(secrets: &[Zeroizing<Vec<u8>>]) -> Self {
        let mut s: Vec<Zeroizing<Vec<u8>>> = secrets
            .iter()
            .filter(|x| x.len() >= MIN_LEN)
            .cloned()
            .collect();
        s.sort_by_key(|x| std::cmp::Reverse(x.len()));
        Redactor {
            secrets: s,
            buf: Zeroizing::new(Vec::new()),
        }
    }

    /// Feed a chunk; returns what can be emitted now.
    pub fn write(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return chunk.to_vec();
        }
        self.buf.extend_from_slice(chunk);
        self.process(false)
    }

    /// End of stream; returns the rest.
    pub fn flush(&mut self) -> Vec<u8> {
        self.process(true)
    }

    // Emit everything that can no longer become part of a secret. Unless
    // `last`, a tail that is a proper prefix of some secret is held back.
    fn process(&mut self, last: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buf.len());
        let mut i = 0usize;
        'scan: while let Some(rest) = self.buf.get(i..) {
            if rest.is_empty() {
                break;
            }
            if !last
                && self
                    .secrets
                    .iter()
                    .any(|s| s.len() > rest.len() && s.starts_with(rest))
            {
                break;
            }
            for s in &self.secrets {
                if rest.starts_with(s) {
                    out.extend_from_slice(MASK);
                    i = i.saturating_add(s.len());
                    continue 'scan;
                }
            }
            if let Some(b) = rest.first() {
                out.push(*b);
            }
            i = i.saturating_add(1);
        }
        let cut = i.min(self.buf.len());
        self.buf.drain(..cut);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(secrets: &[&str], chunks: &[&str]) -> String {
        let s: Vec<Zeroizing<Vec<u8>>> = secrets
            .iter()
            .map(|x| Zeroizing::new(x.as_bytes().to_vec()))
            .collect();
        let mut r = Redactor::new(&s);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(r.write(c.as_bytes()));
        }
        out.extend(r.flush());
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn redacts() {
        assert_eq!(
            run(&["supersecret"], &["a supersecret b"]),
            "a [REDACTED] b"
        );
        let input = "x=supersecret;y=supersecret\n";
        let chunks: Vec<String> = input.chars().map(|c| c.to_string()).collect();
        let refs: Vec<&str> = chunks.iter().map(|s| s.as_str()).collect();
        assert_eq!(run(&["supersecret"], &refs), "x=[REDACTED];y=[REDACTED]\n");
        assert_eq!(run(&["abc"], &["abc"]), "abc");
        assert_eq!(
            run(&["tok-1", "tok-12345"], &["tok-12", "345 tok-1"]),
            "[REDACTED] [REDACTED]"
        );
        assert_eq!(run(&["secret"], &["secr"]), "secr");
    }
}
