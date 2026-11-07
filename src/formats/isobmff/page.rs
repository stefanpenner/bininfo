/*
---
why: This file writes one ISOBMFF movie as one text page.
uses: bininfo
how: bininfo calls this file after parse returns a movie.
This file does not read file bytes.
---
*/

//! One page for one ISOBMFF movie.
//! Each line is `key: value  # note`. This file does not read media bytes.

use super::Movie;
use crate::formats::chrome;
use crate::style::{self, Json};

/// Write one text page for one movie.
pub fn render(file: &str, movie: &Movie, color: bool) -> String {
    let mut out = String::new();
    chrome::head(
        &mut out,
        color,
        file,
        &movie.format,
        "This media file has no start claim.",
    );
    movie_rung(&mut out, movie, color);
    out
}

/// Write one JSON object for one movie.
pub fn render_json(file: &str, movie: &Movie) -> String {
    let mut out = Json::new();
    chrome::json_head(&mut out, file, &movie.format);
    out.str("brand", &movie.brand);
    out.u64("minor", u64::from(movie.minor));
    out.strings("brands", &movie.brands);
    opt_u64(&mut out, "timescale", movie.timescale);
    opt_u64(&mut out, "duration", movie.duration);
    out.u64("tracks", movie.tracks);
    opt_u64(&mut out, "width", movie.width);
    opt_u64(&mut out, "height", movie.height);
    out.u64("video", movie.video);
    out.u64("audio", movie.audio);
    out.strings("codecs", &movie.codecs);
    out.flag("more", movie.more);
    out.finish()
}

fn movie_rung(out: &mut String, movie: &Movie, color: bool) {
    style::rung(
        out,
        color,
        "movie",
        "Brand, time, tracks, and codecs.",
        style::GREEN,
        true,
    );
    style::field(
        out,
        color,
        2,
        "brand",
        &movie.brand,
        "Major brand in the file type box.",
        style::FG,
        true,
    );
    style::field(
        out,
        color,
        2,
        "minor",
        &movie.minor.to_string(),
        "Minor version in the file type box.",
        style::FG,
        false,
    );
    style::list_field(
        out,
        color,
        2,
        "brands",
        &movie.brands,
        "Compatible brands in the file type box.",
        style::FG,
        false,
    );
    number_field(
        out,
        color,
        "timescale",
        movie.timescale,
        "Time units in one second.",
    );
    number_field(
        out,
        color,
        "duration",
        movie.duration,
        "Duration in timescale units.",
    );
    count_field(
        out,
        color,
        "tracks",
        movie.tracks,
        "Track boxes in this file.",
    );
    number_field(out, color, "width", movie.width, "Width in pixels.");
    number_field(out, color, "height", movie.height, "Height in pixels.");
    count_field(out, color, "video", movie.video, "Video handler count.");
    count_field(out, color, "audio", movie.audio, "Audio handler count.");
    style::list_field(
        out,
        color,
        2,
        "codecs",
        &movie.codecs,
        "First sample entry of each track.",
        style::FG,
        false,
    );
    style::field(
        out,
        color,
        2,
        "more",
        bool_word(movie.more),
        "True when the walk stops early.",
        flag_tone(movie.more),
        false,
    );
}

fn number_field(out: &mut String, color: bool, key: &str, value: Option<u64>, note: &str) {
    let text = match value {
        Some(number) => number.to_string(),
        None => "null".to_string(),
    };
    let (fg, bold) = match value {
        Some(number) => style::number_tone(number, style::FG, false),
        None => (style::LABEL, false),
    };
    style::field(out, color, 2, key, &text, note, fg, bold);
}

fn count_field(out: &mut String, color: bool, key: &str, value: u64, note: &str) {
    let (fg, bold) = style::number_tone(value, style::FG, false);
    style::field(out, color, 2, key, &value.to_string(), note, fg, bold);
}

fn opt_u64(out: &mut Json, key: &str, value: Option<u64>) {
    match value {
        Some(number) => out.u64(key, number),
        None => out.raw(key, "null"),
    }
}

fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn flag_tone(value: bool) -> style::Rgb {
    if value {
        style::PINK
    } else {
        style::LABEL
    }
}
