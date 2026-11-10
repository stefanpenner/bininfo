/*
---
why: This file folds one bininfo page into a spine.
uses: bininfo
how: The bininfo command calls this file when stdout is a terminal.
A short group starts open.
A long list starts closed.
A pipe does not call this file.
A list with a count shows that count.
graft attaches one opened file under a member row.
---
*/

//! Fold a rendered page. The page text stays the source of each line.

use std::collections::HashSet;

const PAD: usize = 10;
const LIST_CAP: usize = 3;
const ROW_CAP: usize = 4;

pub(crate) fn interactive(tty: bool, json: bool) -> bool {
    tty && !json
}

/// A terminal loads symbol rows. `--symbols` loads them on a pipe too.
pub(crate) fn with_rows(flag: bool, tty: bool, json: bool) -> bool {
    flag || interactive(tty, json)
}

struct Item {
    parent: Option<usize>,
    children: Vec<usize>,
    indent: usize,
    key: String,
    value: String,
    dash: bool,
    raw: String,
}

pub(crate) struct View {
    items: Vec<Item>,
    open: HashSet<usize>,
    cursor: usize,
    query: String,
    hit: usize,
    // While a search is being typed: the hits and their ancestors, the only rows drawn.
    shown: Option<HashSet<usize>>,
    origin: usize,
}

enum Slot {
    Item(usize),
    Gap,
}

impl View {
    pub(crate) fn spine(page: &str) -> Self {
        let items = parse(page);
        let cursor = items
            .iter()
            .position(|item| item.key == "load")
            .unwrap_or(0);
        let open = (0..items.len())
            .filter(|&id| starts_open(&items, id))
            .collect();
        Self {
            items,
            open,
            cursor,
            query: String::new(),
            hit: 0,
            shown: None,
            origin: cursor,
        }
    }

    pub(crate) fn open(&mut self) {
        let id = self.cursor;
        if self
            .items
            .get(id)
            .is_none_or(|item| item.children.is_empty())
        {
            return;
        }
        if self.open.contains(&id) {
            if let Some(&child) = self.items[id].children.first() {
                self.cursor = child;
            }
            return;
        }
        self.open.insert(id);
    }

    pub(crate) fn close(&mut self) {
        let id = self.cursor;
        if self.open.contains(&id) {
            self.open.remove(&id);
            return;
        }
        let mut parent = self.items.get(id).and_then(|item| item.parent);
        while let Some(pid) = parent {
            if self.open.contains(&pid) {
                self.open.remove(&pid);
                self.cursor = pid;
                return;
            }
            parent = self.items[pid].parent;
        }
    }

    pub(crate) fn down(&mut self) {
        self.move_cursor(1);
    }

    pub(crate) fn up(&mut self) {
        self.move_cursor(-1);
    }

    pub(crate) fn top(&mut self) {
        self.edge(false);
    }

    pub(crate) fn bottom(&mut self) {
        self.edge(true);
    }

    /// Move by many rows, stopping at the first or last.
    pub(crate) fn jump(&mut self, rows: isize) {
        for _ in 0..rows.unsigned_abs() {
            let before = self.cursor;
            self.move_cursor(rows.signum());
            if self.cursor == before {
                break;
            }
        }
    }

    fn edge(&mut self, last: bool) {
        let ids: Vec<usize> = self
            .slots()
            .iter()
            .filter_map(|slot| match slot {
                Slot::Item(id) => Some(*id),
                Slot::Gap => None,
            })
            .collect();
        let pick = if last { ids.last() } else { ids.first() };
        if let Some(&id) = pick {
            self.cursor = id;
        }
    }

    pub(crate) fn find(&mut self, query: &str) {
        self.query = query.to_lowercase();
        self.hit = 0;
        self.goto_hit();
    }

    /// Start a search: remember where the cursor was so cancel can return to it.
    pub(crate) fn begin_search(&mut self) {
        self.origin = self.cursor;
    }

    /// Re-run the search on every key: show only the hits and the path down to each, cursor on the first.
    pub(crate) fn live(&mut self, query: &str) {
        self.query = query.to_lowercase();
        self.hit = 0;
        let hits = self.hits();
        if self.query.is_empty() {
            self.shown = None;
            self.cursor = self.origin;
            return;
        }
        let mut shown = HashSet::new();
        for &id in &hits {
            shown.insert(id);
            let mut parent = self.items[id].parent;
            while let Some(pid) = parent {
                shown.insert(pid);
                parent = self.items[pid].parent;
            }
        }
        self.shown = Some(shown);
        if let Some(&first) = hits.first() {
            self.cursor = first;
        }
    }

    /// Enter: leave the filtered view, keep the cursor on the hit with its parents open, so `n` walks on.
    pub(crate) fn accept_search(&mut self) {
        self.shown = None;
        self.goto_hit();
    }

    /// Esc: drop the search and put the cursor back.
    pub(crate) fn cancel_search(&mut self) {
        self.shown = None;
        self.query.clear();
        self.cursor = self.origin;
    }

    pub(crate) fn searching_none(&self) -> bool {
        matches!(&self.shown, Some(s) if s.is_empty())
    }

    pub(crate) fn next(&mut self) {
        if self.query.is_empty() {
            return;
        }
        self.hit = self.hit.saturating_add(1);
        self.goto_hit();
    }

    /// Put the cursor on the top-level item with this key and open it.
    pub(crate) fn focus(&mut self, key: &str) {
        let found = self
            .items
            .iter()
            .position(|item| item.parent.is_none() && item.key == key);
        if let Some(id) = found {
            self.cursor = id;
            if !self.items[id].children.is_empty() {
                self.open.insert(id);
            }
        }
    }

    /// Plain text of the selected row and every row under it.
    pub(crate) fn cursor_block(&self) -> String {
        let mut out = Vec::new();
        let mut stack = vec![self.cursor];
        while let Some(id) = stack.pop() {
            let Some(item) = self.items.get(id) else {
                continue;
            };
            out.push(strip_ansi(&item.raw));
            stack.extend(item.children.iter().rev());
        }
        out.join("\n")
    }

    pub(crate) fn cursor_key(&self) -> &str {
        self.items
            .get(self.cursor)
            .map(|item| item.key.as_str())
            .unwrap_or("")
    }

    pub(crate) fn body(&self) -> String {
        self.slots()
            .iter()
            .map(|slot| match slot {
                Slot::Gap => String::new(),
                Slot::Item(id) => self.text(*id),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(crate) fn marked(&self) -> String {
        self.slots()
            .iter()
            .map(|slot| match slot {
                Slot::Gap => String::new(),
                Slot::Item(id) => {
                    let mark = if *id == self.cursor { '*' } else { ' ' };
                    format!("{mark}{}", self.text(*id))
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(crate) fn slots_text(&self) -> Vec<String> {
        self.slots()
            .iter()
            .map(|slot| match slot {
                Slot::Gap => String::new(),
                Slot::Item(id) => self.text(*id),
            })
            .collect()
    }

    pub(crate) fn cursor_slot(&self) -> usize {
        self.slots()
            .iter()
            .position(|slot| matches!(slot, Slot::Item(id) if *id == self.cursor))
            .unwrap_or(0)
    }

    fn move_cursor(&mut self, step: isize) {
        let slots = self.slots();
        let ids: Vec<usize> = slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Item(id) => Some(*id),
                Slot::Gap => None,
            })
            .collect();
        let pos = ids.iter().position(|id| *id == self.cursor).unwrap_or(0);
        let next = pos as isize + step;
        if next >= 0 && (next as usize) < ids.len() {
            self.cursor = ids[next as usize];
        }
    }

    fn goto_hit(&mut self) {
        let hits = self.hits();
        if hits.is_empty() {
            return;
        }
        let id = hits[self.hit % hits.len()];
        let mut parent = self.items[id].parent;
        while let Some(pid) = parent {
            if !self.items[pid].children.is_empty() {
                self.open.insert(pid);
            }
            parent = self.items[pid].parent;
        }
        self.cursor = id;
    }

    fn hits(&self) -> Vec<usize> {
        if self.query.is_empty() {
            return Vec::new();
        }
        self.items
            .iter()
            .enumerate()
            .filter(|(id, _)| self.search_text(*id).contains(&self.query))
            .map(|(id, _)| id)
            .collect()
    }

    fn search_text(&self, id: usize) -> String {
        let mut text = strip_ansi(&self.items[id].raw).to_lowercase();
        if !self.items[id].children.is_empty() {
            text.push(' ');
            text.push_str(&self.label(id).to_lowercase());
        }
        text
    }

    fn slots(&self) -> Vec<Slot> {
        let mut out = Vec::new();
        let mut gapped = false;
        let mut saw_header = false;
        for id in 0..self.items.len() {
            if self.items[id].parent.is_some() || !self.is_shown(id) {
                continue;
            }
            if is_header(&self.items[id]) {
                saw_header = true;
                out.push(Slot::Item(id));
                continue;
            }
            if saw_header && !gapped {
                out.push(Slot::Gap);
                gapped = true;
            }
            self.push_node(&mut out, id);
        }
        out
    }

    fn push_node(&self, out: &mut Vec<Slot>, id: usize) {
        out.push(Slot::Item(id));
        if self.items[id].children.is_empty() || (self.shown.is_none() && !self.open.contains(&id))
        {
            return;
        }
        for &child in &self.items[id].children {
            if self.is_shown(child) {
                self.push_node(out, child);
            }
        }
    }

    fn is_shown(&self, id: usize) -> bool {
        self.shown.as_ref().is_none_or(|shown| shown.contains(&id))
    }

    fn text(&self, id: usize) -> String {
        let item = &self.items[id];
        if item.children.is_empty() {
            return item.raw.clone();
        }
        let open = self.open.contains(&id);
        let mark = if open { "v" } else { ">" };
        if item.dash && open {
            return insert_mark(&item.raw, item.indent, mark);
        }
        let indent = " ".repeat(item.indent);
        tint_marks(&format!("{indent}{mark} {}", self.label(id)))
    }

    fn label(&self, id: usize) -> String {
        let item = &self.items[id];
        if item.dash {
            if item.key.is_empty() {
                return format!("- {}", item.value);
            }
            return format!("- {}: {}", item.key, item.value);
        }
        if list_like(&self.items, id) {
            let shown = if item.value.is_empty() {
                item.children.len().to_string()
            } else {
                item.value.clone()
            };
            return format!("{:<PAD$}{}", item.key, shown);
        }
        format!("{:<PAD$}{}", item.key, self.rung_summary(id))
            .trim_end()
            .to_string()
    }

    fn rung_summary(&self, id: usize) -> String {
        let key = self.items[id].key.as_str();
        match key {
            "load" => self.load_summary(id),
            "type" => self.type_summary(id),
            "build" => dots([
                self.bare(id, "platform"),
                self.field(id, "minos").unwrap_or("").to_string(),
            ]),
            "symbols" => self.symbols_summary(id),
            "sizes" => self.sizes_summary(id),
            "where" => self.where_summary(id),
            "sections" => self.sections_summary(id),
            _ => self.fallback(id),
        }
    }

    fn load_summary(&self, id: usize) -> String {
        let kind = self.field(id, "kind").unwrap_or("").to_string();
        let interp = match self.field(id, "interp") {
            Some("null") | None => "no loader".to_string(),
            Some(path) => path.rsplit(['/', '\\']).next().unwrap_or(path).to_string(),
        };
        let needed = self
            .list_len(id, "needed")
            .map(|count| format!("{count} needed"))
            .unwrap_or_default();
        dots([kind, interp, needed])
    }

    fn type_summary(&self, id: usize) -> String {
        let kind = self
            .field(id, "filetype")
            .or_else(|| self.field(id, "e_type"))
            .or_else(|| self.field(id, "signature"))
            .unwrap_or("")
            .to_string();
        let cpu = self
            .field(id, "cputype_name")
            .or_else(|| self.field(id, "e_machine_name"))
            .or_else(|| self.field(id, "machine_name"))
            .map(bare_word)
            .unwrap_or("")
            .to_string();
        dots([kind, cpu])
    }

    fn symbols_summary(&self, id: usize) -> String {
        let mut parts = Vec::new();
        for key in ["bind", "exports", "undef", "defined"] {
            if let Some(value) = self.field(id, key) {
                parts.push(format!("{key} {value}"));
            }
        }
        if parts.is_empty() {
            return self.fallback(id);
        }
        dots(parts)
    }

    fn sizes_summary(&self, id: usize) -> String {
        if let Some(count) = self.field(id, "ncmds") {
            return format!("{count} commands");
        }
        if let Some(ph) = self.field(id, "e_phnum") {
            return format!("{ph} ph");
        }
        self.fallback(id)
    }

    fn where_summary(&self, id: usize) -> String {
        if let Some(name) = self.field(id, "entry_name") {
            if name != "null" {
                return name.to_string();
            }
        }
        if let Some(entry) = self
            .field(id, "entry")
            .or_else(|| self.field(id, "e_entry"))
        {
            return entry.to_string();
        }
        self.fallback(id)
    }

    fn sections_summary(&self, id: usize) -> String {
        if let Some(count) = self.field(id, "e_shnum") {
            return format!("{count} sh");
        }
        if let Some(count) = self.field(id, "nsyms") {
            return format!("{count} symbols");
        }
        if let Some(flag) = self.field(id, "symtab") {
            return if flag == "true" {
                "symtab".to_string()
            } else {
                "no symtab".to_string()
            };
        }
        self.fallback(id)
    }

    fn fallback(&self, id: usize) -> String {
        let mut parts = Vec::new();
        for &child in &self.items[id].children {
            let item = &self.items[child];
            if item.dash || item.value.is_empty() {
                continue;
            }
            parts.push(format!("{} {}", item.key, bare_word(&item.value)));
            if parts.len() == 2 {
                break;
            }
        }
        dots(parts)
    }

    fn bare(&self, id: usize, key: &str) -> String {
        self.field(id, key).map(bare_word).unwrap_or("").to_string()
    }

    fn field(&self, id: usize, key: &str) -> Option<&str> {
        self.items[id].children.iter().find_map(|&child| {
            let item = &self.items[child];
            if item.key == key && !item.value.is_empty() {
                Some(item.value.as_str())
            } else {
                None
            }
        })
    }

    fn list_len(&self, id: usize, key: &str) -> Option<usize> {
        for &child in &self.items[id].children {
            if self.items[child].key != key {
                continue;
            }
            if self.items[child].value == "[]" {
                return Some(0);
            }
            if list_like(&self.items, child) {
                return Some(self.items[child].children.len());
            }
        }
        None
    }

    /// The member row under the cursor, and each name from the outer file to it.
    pub(crate) fn step_target(&self) -> Option<(usize, Vec<String>)> {
        let id = self.cursor;
        if !self.is_step_row(id) {
            return None;
        }
        let mut names = Vec::new();
        let mut cur = Some(id);
        while let Some(at) = cur {
            if self.is_step_row(at) {
                names.push(dash_name(&self.items[at].raw));
            }
            cur = self.items[at].parent;
        }
        names.reverse();
        Some((id, names))
    }

    /// Find one member row by the same name path `step_target` builds.
    pub(crate) fn find_member(&self, path: &[String]) -> Option<usize> {
        let mut ancestor = None;
        let mut found = 0usize;
        if path.is_empty() {
            return None;
        }
        for name in path {
            found = self
                .items
                .iter()
                .enumerate()
                .find(|(id, _)| {
                    self.is_step_row(*id)
                        && dash_name(&self.items[*id].raw) == *name
                        && self.is_under(*id, ancestor)
                })?
                .0;
            ancestor = Some(found);
        }
        Some(found)
    }

    /// Attach one rendered file under a member row. The new rows stay in this view.
    pub(crate) fn graft(&mut self, parent: usize, page: &str) {
        if self.items.get(parent).is_none() {
            return;
        }
        let shift = self.items[parent].indent.saturating_add(2);
        let mut extra = parse(page);
        if extra.is_empty() {
            return;
        }
        let base = self.items.len();
        let pad = " ".repeat(shift);
        for item in &mut extra {
            if let Some(pid) = item.parent.as_mut() {
                *pid += base;
            }
            for child in &mut item.children {
                *child += base;
            }
            item.indent += shift;
            item.raw.insert_str(0, &pad);
        }
        self.items.append(&mut extra);
        let mut roots = Vec::new();
        for id in base..self.items.len() {
            if self.items[id].parent.is_none() {
                self.items[id].parent = Some(parent);
                roots.push(id);
            }
        }
        self.items[parent].children.extend(roots);
        for id in base..self.items.len() {
            if starts_open(&self.items, id) {
                self.open.insert(id);
            }
        }
    }

    fn is_step_row(&self, id: usize) -> bool {
        let Some(item) = self.items.get(id) else {
            return false;
        };
        if !item.dash {
            return false;
        }
        let Some(pid) = item.parent else {
            return false;
        };
        matches!(
            self.items[pid].key.as_str(),
            "members" | "layers" | "files" | "parts" | "icons"
        )
    }

    fn is_under(&self, id: usize, ancestor: Option<usize>) -> bool {
        let Some(ancestor) = ancestor else {
            return true;
        };
        let mut cur = self.items[id].parent;
        while let Some(pid) = cur {
            if pid == ancestor {
                return true;
            }
            cur = self.items[pid].parent;
        }
        false
    }
}

fn is_header(item: &Item) -> bool {
    item.parent.is_none() && !item.value.is_empty()
}

fn list_like(items: &[Item], id: usize) -> bool {
    let children = &items[id].children;
    !children.is_empty() && children.iter().all(|&child| items[child].dash)
}

fn starts_open(items: &[Item], id: usize) -> bool {
    let item = &items[id];
    if item.children.is_empty() {
        return false;
    }
    if item.dash {
        let Some(parent) = item.parent else {
            return false;
        };
        return list_fits(items, parent) && item.children.len() <= ROW_CAP;
    }
    if list_like(items, id) {
        return list_fits(items, id);
    }
    true
}

fn list_fits(items: &[Item], id: usize) -> bool {
    let children = &items[id].children;
    children.len() <= LIST_CAP
        && children
            .iter()
            .all(|&child| items[child].children.len() <= ROW_CAP)
}

fn dots(parts: impl IntoIterator<Item = String>) -> String {
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

fn bare_word(value: &str) -> &str {
    value.split(" (").next().unwrap_or(value)
}

fn insert_mark(raw: &str, indent: usize, mark: &str) -> String {
    let pad = " ".repeat(indent);
    if raw.starts_with(&pad) {
        format!("{pad}{mark} {}", &raw[indent..])
    } else {
        format!("{mark} {raw}")
    }
}

fn dash_name(raw: &str) -> String {
    let plain = strip_ansi(raw);
    let body = plain.trim();
    let body = body.strip_prefix("- ").unwrap_or(body).trim();
    if let Some(name) = unquote(body) {
        return name;
    }
    body.split(" # ").next().unwrap_or(body).trim().to_string()
}

fn unquote(body: &str) -> Option<String> {
    if !body.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = body[1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

fn parse(page: &str) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    for line in page.lines() {
        let plain = strip_ansi(line);
        if plain.trim().is_empty() {
            continue;
        }
        let (indent, dash, key, value) = split_line(&plain);
        while let Some(&top) = stack.last() {
            if items[top].indent < indent {
                break;
            }
            stack.pop();
        }
        let parent = stack.last().copied();
        let id = items.len();
        items.push(Item {
            parent,
            children: Vec::new(),
            indent,
            key,
            value,
            dash,
            raw: line.to_string(),
        });
        if let Some(pid) = parent {
            items[pid].children.push(id);
        }
        stack.push(id);
    }
    items
}

fn split_line(plain: &str) -> (usize, bool, String, String) {
    let indent = plain.chars().take_while(|c| *c == ' ').count();
    let mut body: String = plain.chars().skip(indent).collect();
    if let Some(at) = body.find(" # ") {
        body.truncate(at);
    }
    let body = body.trim_end();
    let (dash, body) = if let Some(rest) = body.strip_prefix("- ") {
        (true, rest)
    } else {
        (false, body)
    };
    if let Some((key, value)) = body.split_once(':') {
        (
            indent,
            dash,
            key.trim().to_string(),
            value.trim().to_string(),
        )
    } else {
        (indent, dash, String::new(), body.trim().to_string())
    }
}

// A folded row is rebuilt from plain text, so the cert marks get their colour back.
fn tint_marks(line: &str) -> String {
    line.replace('✓', "\x1b[1;38;2;37;190;106m✓\x1b[0m")
        .replace('✗', "\x1b[1;38;2;255;92;92m✗\x1b[0m")
        .replace('‼', "\x1b[1;38;2;255;45;149m‼\x1b[0m")
        .replace('⊘', "\x1b[1;38;2;255;92;92m⊘\x1b[0m")
        .replace('◷', "\x1b[1;38;2;245;176;66m◷\x1b[0m")
}

pub(crate) fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "\
file: a                         # Path of this file.
format: macho                   # elf, macho, or pe.

type:                           # Rung 1.
  filetype: DYLIB               # 4 bytes.
  cputype_name: AArch64 (16777228)  # Word.

load:                           # How this file starts.
  kind: shared                  # A shared library.
  interp: /usr/lib/dyld         # Path of the loader.
  needed:                       # Libraries.
    - /usr/lib/libSystem.B.dylib  # libc.
      compat: 1.0.0
      current: 2.0.0
  pie: false                    # MH_PIE.
";

    #[test]
    fn top_bottom_and_jump_move_the_cursor() {
        let mut view = View::spine(PAGE);
        view.bottom();
        let last = view.cursor_slot();
        assert!(last > 0);
        view.top();
        assert_eq!(view.cursor_slot(), 0);
        view.jump(1000);
        assert_eq!(view.cursor_slot(), last);
        view.jump(-1000);
        assert_eq!(view.cursor_slot(), 0);
    }

    #[test]
    fn folded_cert_rows_keep_green_and_red_marks() {
        let text = tint_marks("  > - ✓ cn: a\n  > - ✗ cn: b");
        assert!(text.contains("38;2;37;190;106m✓"), "{text}");
        assert!(text.contains("38;2;255;92;92m✗"), "{text}");
    }

    #[test]
    fn a_terminal_folds_and_json_stays_text() {
        assert!(interactive(true, false));
        assert!(!interactive(false, false));
        assert!(!interactive(true, true));
        assert!(with_rows(false, true, false));
        assert!(!with_rows(false, false, false));
        assert!(!with_rows(false, true, true));
        assert!(with_rows(true, false, true));
    }

    #[test]
    fn a_count_stays_on_a_closed_list() {
        let page = "\
symbols:
  exports: 9
    - a
    - b
    - c
    - d
    - e
    - more: 4
";
        let mut view = View::spine(page);
        assert!(view.body().contains("> exports   9"), "{}", view.body());
        assert!(!view.body().contains("- a"), "{}", view.body());
        view.down();
        assert_eq!(view.cursor_key(), "exports");
        view.open();
        assert!(view.body().contains("- a"), "{}", view.body());
        assert!(view.body().contains("more: 4"), "{}", view.body());
    }

    #[test]
    fn enter_on_a_segment_shows_its_sections() {
        let page = "\
regions:
  - __TEXT: 1 KiB
    - __text: 4 B
    - __stubs: 4 B
    - __const: 4 B
    - __cstring: 4 B
    - __unwind: 4 B
";
        let mut view = View::spine(page);
        view.open();
        assert!(!view.body().contains("__text"), "{}", view.body());
        view.down();
        assert_eq!(view.cursor_key(), "__TEXT");
        view.open();
        assert!(view.body().contains("__text"), "{}", view.body());
    }

    #[test]
    fn short_groups_start_open_and_the_cursor_sits_on_load() {
        let view = View::spine(PAGE);
        let text = view.marked();
        assert!(text.contains(" file: a"), "{text}");
        assert!(text.contains(" format: macho"), "{text}");
        assert!(text.contains("v type      DYLIB · AArch64"), "{text}");
        assert!(text.contains("filetype: DYLIB"), "{text}");
        assert!(
            text.contains("*v load      shared · dyld · 1 needed"),
            "{text}"
        );
        assert!(text.contains("kind: shared"), "{text}");
        assert!(text.contains("compat: 1.0.0"), "{text}");
    }

    #[test]
    fn a_long_list_stays_closed_until_enter() {
        let page = "\
type:
  filetype: DYLIB
load:
  kind: shared
  needed:
    - a.dylib
    - b.dylib
    - c.dylib
    - d.dylib
  pie: false
slices:
  - cputype_name: x86-64 (7)
    kind: dynamic
    interp: /usr/lib/dyld
    pie: true
    ncmds: 3
    entry: 1
  - cputype_name: AArch64 (12)
    kind: dynamic
    interp: /usr/lib/dyld
    pie: true
    ncmds: 3
    entry: 1
symbols:
  exports:
    - one
    - two
    - three
    - four
    - five
";
        let mut view = View::spine(page);
        let text = view.body();
        assert!(text.contains("filetype: DYLIB"), "{text}");
        assert!(text.contains("> needed    4"), "{text}");
        assert!(!text.contains("a.dylib"), "{text}");
        assert!(text.contains("> slices    2"), "{text}");
        assert!(!text.contains("cputype_name:"), "{text}");
        assert!(text.contains("v symbols"), "{text}");
        assert!(text.contains("> exports   5"), "{text}");
        assert!(!text.contains("- one"), "{text}");
        view.down();
        view.down();
        assert_eq!(view.cursor_key(), "needed");
        view.open();
        assert!(view.body().contains("a.dylib"), "{}", view.body());
        assert!(!view.body().contains("cputype_name:"), "{}", view.body());
    }

    #[test]
    fn h_closes_the_row_then_the_list() {
        let mut view = View::spine(PAGE);
        view.down();
        view.down();
        view.down();
        view.down();
        view.down();
        assert_eq!(view.cursor_key(), "compat");
        view.close();
        assert!(!view.body().contains("compat:"), "{}", view.body());
        assert!(view.body().contains("libSystem"), "{}", view.body());
        view.close();
        assert!(!view.body().contains("libSystem"), "{}", view.body());
        assert!(view.body().contains("kind: shared"), "{}", view.body());
    }

    #[test]
    fn search_opens_each_closed_parent() {
        let mut view = View::spine(PAGE);
        view.find("compat");
        let text = view.marked();
        assert!(
            text.contains("*") && text.contains("compat: 1.0.0"),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|line| line.starts_with('*') && line.contains("compat")),
            "{text}"
        );
        assert!(text.contains("v load"), "{text}");
        assert!(text.contains("v needed"), "{text}");
    }

    #[test]
    fn typing_shows_only_the_tree_down_to_each_hit() {
        let mut view = View::spine(PAGE);
        view.begin_search();
        view.live("compat");
        let text = view.body();
        assert!(text.contains("compat: 1.0.0"), "{text}");
        assert!(!text.contains("kind: shared"), "{text}");
        view.live("");
        assert!(view.body().contains("kind: shared"), "{}", view.body());
    }

    #[test]
    fn cancel_restores_the_cursor_and_accept_keeps_the_hit() {
        let mut view = View::spine(PAGE);
        let start = view.cursor_key().to_string();
        view.begin_search();
        view.live("compat");
        assert_eq!(view.cursor_key(), "compat");
        view.cancel_search();
        assert_eq!(view.cursor_key(), start);
        view.begin_search();
        view.live("compat");
        view.accept_search();
        assert_eq!(view.cursor_key(), "compat");
        assert!(view.body().contains("kind: shared"), "{}", view.body());
    }

    #[test]
    fn n_walks_hits_and_wraps() {
        let page = "\
type:
  a: ZZ
  b: ZZ
load:
  kind: static
";
        let mut view = View::spine(page);
        view.find("ZZ");
        assert_eq!(view.cursor_key(), "a");
        view.next();
        assert_eq!(view.cursor_key(), "b");
        view.next();
        assert_eq!(view.cursor_key(), "a");
        let mut fresh = View::spine(page);
        fresh.next();
        assert_eq!(fresh.cursor_key(), "load");
    }

    #[test]
    fn a_real_elf_page_folds_behind_the_same_spine() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16] = 2;
        bytes[18] = 62;
        let file = bininfo::open(&bytes, false).unwrap();
        let page = bininfo::render("t.elf", &file, false, false);
        let view = View::spine(&page);
        let text = view.body();
        assert!(text.contains("v type      EXEC · x86-64"), "{text}");
        assert!(text.contains("class:"), "{text}");
        assert!(
            text.contains("v load      static · no loader · 0 needed"),
            "{text}"
        );
        assert!(text.contains("kind: static"), "{text}");
        assert!(text.contains("e_ehsize"), "{text}");
        let mut found = View::spine(&page);
        found.find("e_ehsize");
        assert_eq!(found.cursor_key(), "e_ehsize");
    }

    #[test]
    fn color_bytes_still_fold() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16] = 2;
        bytes[18] = 62;
        let file = bininfo::open(&bytes, false).unwrap();
        let page = bininfo::render("t.elf", &file, false, true);
        let view = View::spine(&page);
        let text = strip_ansi(&view.body());
        assert!(
            text.contains("v load      static · no loader · 0 needed"),
            "{text}"
        );
        assert!(text.contains("kind: static"), "{text}");
    }

    #[test]
    fn graft_puts_one_file_under_the_member() {
        let page = "\
format: zip

members:
  - photo.jpg
    method: store (0)
  - readme.txt
    method: store (0)
";
        let mut view = View::spine(page);
        let photo = view
            .items
            .iter()
            .position(|item| item.dash && dash_name(&item.raw) == "photo.jpg")
            .unwrap();
        view.cursor = photo;
        let (id, path) = view.step_target().unwrap();
        assert_eq!(id, photo);
        assert_eq!(path, vec!["photo.jpg".to_string()]);
        view.graft(id, "file: photo.jpg\nformat: jpeg\nwidth: 3\n");
        let raw: String = view.items.iter().map(|item| item.raw.as_str()).collect();
        assert!(raw.contains("format: jpeg"), "{raw}");
        assert!(view.find_member(&path).is_some());
        let readme = view
            .items
            .iter()
            .position(|item| item.dash && dash_name(&item.raw) == "readme.txt")
            .unwrap();
        view.cursor = readme;
        assert_eq!(
            view.step_target().map(|(_, names)| names),
            Some(vec!["readme.txt".to_string()])
        );
        view.cursor = view.items[photo].children[0];
        assert!(view.step_target().is_none());
    }

    #[test]
    fn graft_keeps_a_nested_row_with_its_parent() {
        let page = "\
format: dmg

parts:
  - \"disk (Apple_HFS : 4)\"
    blocks: 1
";
        let mut view = View::spine(page);
        let part = view
            .items
            .iter()
            .position(|item| item.dash && dash_name(&item.raw).contains("Apple_HFS"))
            .unwrap();
        view.cursor = part;
        view.graft(
            part,
            "\
file: disk (Apple_HFS : 4)
format: hfs

files:
  more: true
  - readme.txt
    size: 4
",
        );
        let nested = view
            .items
            .iter()
            .position(|item| item.key == "size")
            .unwrap();
        let parent = view.items[nested].parent.expect("size has a parent");
        assert!(
            view.items[parent].children.contains(&nested),
            "parent {} children {:?}",
            view.items[parent].key,
            view.items[parent].children
        );
        let block = view.cursor_block();
        assert!(block.contains("size: 4"), "{block}");
        assert!(block.contains("format: hfs"), "{block}");
    }

    #[test]
    fn a_quoted_digest_is_the_step_name() {
        let page = "\
layers:
  - \"sha256:abc\"
    media: tar
";
        let mut view = View::spine(page);
        let id = view.items.iter().position(|item| item.dash).unwrap();
        view.cursor = id;
        let (_, path) = view.step_target().unwrap();
        assert_eq!(path, vec!["sha256:abc".to_string()]);
    }

    #[test]
    fn a_part_dash_is_a_step() {
        let page = "\
parts:
  - \"disk (Apple_HFS : 4)\"
    blocks: 1
";
        let mut view = View::spine(page);
        let id = view.items.iter().position(|item| item.dash).unwrap();
        view.cursor = id;
        let (_, path) = view.step_target().unwrap();
        assert_eq!(path, vec!["disk (Apple_HFS : 4)".to_string()]);
    }

    #[test]
    fn an_icon_dash_is_a_step() {
        let page = "\
icons:
  - ic08
    size: 8
";
        let mut view = View::spine(page);
        let id = view.items.iter().position(|item| item.dash).unwrap();
        view.cursor = id;
        let (_, path) = view.step_target().unwrap();
        assert_eq!(path, vec!["ic08".to_string()]);
    }
}
