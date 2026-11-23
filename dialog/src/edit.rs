//! The secret field's text and cursor. The text lives in one zeroized
//! buffer reserved up front, so editing never reallocates (and never leaves
//! a stale copy of the secret in freed memory). The cursor is a byte index
//! that always sits on a char boundary.

use zeroize::{Zeroize, Zeroizing};

pub struct Editor {
    text: Zeroizing<String>,
    cursor: usize,
    max_chars: usize,
}

impl Editor {
    pub fn new(max_chars: usize) -> Self {
        Editor {
            text: Zeroizing::new(String::with_capacity(max_chars.saturating_mul(4))),
            cursor: 0,
            max_chars,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn chars(&self) -> usize {
        self.text.chars().count()
    }

    /// Characters before the cursor.
    pub fn cursor_chars(&self) -> usize {
        self.text.get(..self.cursor).map_or(0, |s| s.chars().count())
    }

    /// Hand the text over (Enter) and start empty.
    pub fn take(&mut self) -> Zeroizing<String> {
        self.cursor = 0;
        let fresh = Zeroizing::new(String::with_capacity(self.max_chars.saturating_mul(4)));
        std::mem::replace(&mut self.text, fresh)
    }

    pub fn clear(&mut self) {
        self.text.zeroize();
        self.cursor = 0;
    }

    /// Insert at the cursor. Refuses (false) if it would go over the limit.
    pub fn insert(&mut self, s: &str) -> bool {
        if self.chars().saturating_add(s.chars().count()) > self.max_chars {
            return false;
        }
        self.text.insert_str(self.cursor, s);
        self.cursor = self.cursor.saturating_add(s.len());
        true
    }

    fn prev(&self, at: usize) -> usize {
        self.text.get(..at).and_then(|s| s.char_indices().next_back()).map_or(0, |(i, _)| i)
    }

    fn next(&self, at: usize) -> usize {
        self.text
            .get(at..)
            .and_then(|s| s.chars().next())
            .map_or(at, |c| at.saturating_add(c.len_utf8()))
    }

    fn char_before(&self, at: usize) -> Option<char> {
        self.text.get(..at).and_then(|s| s.chars().next_back())
    }

    fn char_at(&self, at: usize) -> Option<char> {
        self.text.get(at..).and_then(|s| s.chars().next())
    }

    /// Start of the word before `at` (skip spaces, then non-spaces).
    fn word_left_of(&self, mut at: usize) -> usize {
        while self.char_before(at).is_some_and(char::is_whitespace) {
            at = self.prev(at);
        }
        while self.char_before(at).is_some_and(|c| !c.is_whitespace()) {
            at = self.prev(at);
        }
        at
    }

    /// End of the word after `at` (skip spaces, then non-spaces).
    fn word_right_of(&self, mut at: usize) -> usize {
        while self.char_at(at).is_some_and(char::is_whitespace) {
            at = self.next(at);
        }
        while self.char_at(at).is_some_and(|c| !c.is_whitespace()) {
            at = self.next(at);
        }
        at
    }

    pub fn left(&mut self) {
        self.cursor = self.prev(self.cursor);
    }
    pub fn right(&mut self) {
        self.cursor = self.next(self.cursor);
    }
    pub fn home(&mut self) {
        self.cursor = 0;
    }
    pub fn end(&mut self) {
        self.cursor = self.text.len();
    }
    pub fn word_left(&mut self) {
        self.cursor = self.word_left_of(self.cursor);
    }
    pub fn word_right(&mut self) {
        self.cursor = self.word_right_of(self.cursor);
    }

    /// Remove `from..to` (byte range on char boundaries).
    fn remove(&mut self, from: usize, to: usize) {
        if from < to && to <= self.text.len() {
            self.text.replace_range(from..to, "");
            self.cursor = from;
        }
    }

    pub fn backspace(&mut self) {
        let p = self.prev(self.cursor);
        self.remove(p, self.cursor);
    }
    pub fn delete(&mut self) {
        let n = self.next(self.cursor);
        let c = self.cursor;
        self.remove(c, n);
    }
    /// Ctrl+W / Ctrl+Backspace.
    pub fn delete_word_left(&mut self) {
        let w = self.word_left_of(self.cursor);
        self.remove(w, self.cursor);
    }
    /// Ctrl+Delete.
    pub fn delete_word_right(&mut self) {
        let w = self.word_right_of(self.cursor);
        let c = self.cursor;
        self.remove(c, w);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ed(s: &str) -> Editor {
        let mut e = Editor::new(16);
        assert!(e.insert(s));
        e
    }

    #[test]
    fn insert_in_the_middle() {
        let mut e = ed("hunter");
        e.home();
        e.right();
        assert!(e.insert("X"));
        assert_eq!(e.as_str(), "hXunter");
        assert_eq!(e.cursor_chars(), 2);
        e.end();
        assert!(e.insert("2"));
        assert_eq!(e.as_str(), "hXunter2");
    }

    #[test]
    fn backspace_and_delete_at_cursor() {
        let mut e = ed("abcd");
        e.left();
        e.left();
        e.backspace();
        assert_eq!((e.as_str(), e.cursor_chars()), ("acd", 1));
        e.delete();
        assert_eq!((e.as_str(), e.cursor_chars()), ("ad", 1));
        e.home();
        e.backspace(); // nothing before
        e.end();
        e.delete(); // nothing after
        assert_eq!(e.as_str(), "ad");
    }

    #[test]
    fn unicode_boundaries() {
        let mut e = ed("pä✓ss");
        e.left();
        e.left();
        assert_eq!(e.cursor_chars(), 3);
        e.backspace();
        assert_eq!(e.as_str(), "päss");
        e.left();
        assert!(e.insert("ö"));
        assert_eq!(e.as_str(), "pöäss");
        e.home();
        e.right();
        e.right();
        e.delete();
        assert_eq!(e.as_str(), "pöss");
    }

    #[test]
    fn words() {
        let mut e = Editor::new(64);
        assert!(e.insert("correct horse  battery"));
        e.word_left();
        assert_eq!(e.cursor_chars(), 15);
        e.word_left();
        assert_eq!(e.cursor_chars(), 8);
        e.word_right();
        assert_eq!(e.cursor_chars(), 13);
        e.delete_word_right(); // "  battery"
        assert_eq!(e.as_str(), "correct horse");
        e.delete_word_left();
        assert_eq!((e.as_str(), e.cursor_chars()), ("correct ", 8));
        e.home();
        e.delete_word_left();
        assert_eq!(e.as_str(), "correct ");
    }

    #[test]
    fn limit_and_take() {
        let mut e = ed("0123456789");
        assert!(!e.insert("abcdefg")); // 17 > 16: refused whole
        assert!(e.insert("abcdef"));
        assert_eq!(e.chars(), 16);
        assert!(!e.insert("x"));
        let t = e.take();
        assert_eq!(t.as_str(), "0123456789abcdef");
        assert!(e.is_empty());
        assert_eq!(e.cursor_chars(), 0);
        assert!(e.insert("y"));
        e.clear();
        assert!(e.is_empty());
    }
}
