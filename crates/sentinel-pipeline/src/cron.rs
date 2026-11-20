//! UTC cron schedules, five fields, minute resolution.
//!
//! Everything here is UTC: a schedule has no local time and no zone, so there is no daylight-saving
//! gap where an occurrence is skipped and no repeated hour where one fires twice. An occurrence's
//! instant is its identity — the store keys every occurrence by the minute it names — so the same
//! instant computed by two controllers, by a restarted one, or after a clock step is one occurrence.

pub const MAX_CRON_BYTES: usize = 128;

const MINUTE_MS: i64 = 60_000;
const MINUTES_PER_DAY: i64 = 1_440;
/// How far a search walks before it reports no occurrence: eight years is longer than any gap a
/// five-field expression has (`0 0 29 2 *` waits four, or eight around a skipped century leap day).
const MAX_DAYS: u32 = 3_660;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Empty,
    TooLong,
    Fields,
    Field(&'static str),
    Step(&'static str),
    Range(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("empty cron expression"),
            Self::TooLong => write!(f, "cron expression longer than {MAX_CRON_BYTES} bytes"),
            Self::Fields => f.write_str(
                "a cron expression has five fields: minute hour day-of-month month day-of-week",
            ),
            Self::Field(name) => write!(f, "invalid {name} field"),
            Self::Step(name) => write!(f, "invalid step in the {name} field"),
            Self::Range(name) => write!(f, "reversed range in the {name} field"),
        }
    }
}

/// A parsed five-field expression. Each field's accepted values are one bitmask, so a day is tested
/// with three shifts and a minute search is a trailing-zero count, not a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cron {
    minute: u64,
    hour: u64,
    dom: u64,
    month: u64,
    dow: u64,
    /// `*` in the day-of-month field: with both day fields starred every day matches, and with one
    /// starred the other decides.
    dom_any: bool,
    dow_any: bool,
}

impl Cron {
    /// `minute hour day-of-month month day-of-week`. Values are decimal; `*`, `a`, `a-b`, `*/n`,
    /// `a-b/n` and `a/n` are accepted, comma-separated. Day-of-week takes 0–7, where 0 and 7 are
    /// Sunday. No names, no seconds, no year field.
    pub fn parse(text: &str) -> Result<Cron, Error> {
        if text.is_empty() {
            return Err(Error::Empty);
        }
        if text.len() > MAX_CRON_BYTES {
            return Err(Error::TooLong);
        }
        let mut fields = text.split_ascii_whitespace();
        let (Some(minute), Some(hour), Some(dom), Some(month), Some(dow), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(Error::Fields);
        };
        let dow_mask = field(dow, "day-of-week", 0, 7)?;
        Ok(Cron {
            minute: field(minute, "minute", 0, 59)?,
            hour: field(hour, "hour", 0, 23)?,
            dom: field(dom, "day-of-month", 1, 31)?,
            month: field(month, "month", 1, 12)?,
            // 7 is a second spelling of Sunday, so it folds into bit 0.
            dow: (dow_mask & 0x7f) | (dow_mask >> 7),
            dom_any: dom == "*",
            dow_any: dow == "*",
        })
    }

    /// The first occurrence strictly after `after_ms`, in UTC milliseconds.
    pub fn next_after(&self, after_ms: i64) -> Option<i64> {
        let mut minute = after_ms.div_euclid(MINUTE_MS) + 1;
        for _ in 0..MAX_DAYS {
            let day = minute.div_euclid(MINUTES_PER_DAY);
            let in_day = (minute - day * MINUTES_PER_DAY) as u32;
            if self.day_matches(day)
                && let Some(at) = self.next_in_day(in_day)
            {
                return Some((day * MINUTES_PER_DAY + i64::from(at)) * MINUTE_MS);
            }
            minute = (day + 1) * MINUTES_PER_DAY;
        }
        None
    }

    /// The last occurrence at or before `at_ms`, in UTC milliseconds.
    pub fn prev_at_or_before(&self, at_ms: i64) -> Option<i64> {
        let mut minute = at_ms.div_euclid(MINUTE_MS);
        for _ in 0..MAX_DAYS {
            let day = minute.div_euclid(MINUTES_PER_DAY);
            let in_day = (minute - day * MINUTES_PER_DAY) as u32;
            if self.day_matches(day)
                && let Some(at) = self.prev_in_day(in_day)
            {
                return Some((day * MINUTES_PER_DAY + i64::from(at)) * MINUTE_MS);
            }
            minute = day * MINUTES_PER_DAY - 1;
        }
        None
    }

    /// At most `limit` occurrence instants in `(after_ms, at_ms]`, ascending, with whether more exist.
    /// The walk stops at `limit`, so a year of missed minutes costs one bound, not a year of steps.
    pub fn span(&self, after_ms: i64, at_ms: i64, limit: usize) -> (Vec<i64>, bool) {
        let mut out = Vec::new();
        let mut cursor = after_ms;
        while out.len() <= limit {
            let Some(next) = self.next_after(cursor) else {
                return (out, false);
            };
            if next > at_ms {
                break;
            }
            out.push(next);
            cursor = next;
        }
        let more = out.len() > limit;
        out.truncate(limit);
        (out, more)
    }

    fn day_matches(&self, day: i64) -> bool {
        let (_, month, dom) = civil(day);
        if self.month & (1 << month) == 0 {
            return false;
        }
        let dom_ok = self.dom & (1 << dom) != 0;
        let dow_ok = self.dow & (1 << weekday(day)) != 0;
        // Vixie's rule: a restricted day-of-month and day-of-week match either way; a starred one
        // does not constrain the other.
        if self.dom_any && self.dow_any {
            true
        } else if self.dom_any {
            dow_ok
        } else if self.dow_any {
            dom_ok
        } else {
            dom_ok || dow_ok
        }
    }

    fn next_in_day(&self, from: u32) -> Option<u32> {
        let (mut hour, mut minute) = (from / 60, u64::from(from % 60));
        loop {
            let hours = self.hour & (!0 << hour);
            if hours == 0 {
                return None;
            }
            hour = hours.trailing_zeros();
            let minutes = self.minute & (!0 << minute);
            if minutes != 0 {
                return Some(hour * 60 + minutes.trailing_zeros());
            }
            hour += 1;
            minute = 0;
            if hour >= 24 {
                return None;
            }
        }
    }

    fn prev_in_day(&self, from: u32) -> Option<u32> {
        let (mut hour, mut minute) = (from / 60, u64::from(from % 60));
        loop {
            let hours = self.hour & ((2u64 << hour) - 1);
            if hours == 0 {
                return None;
            }
            hour = 63 - hours.leading_zeros();
            let minutes = self.minute & ((2u64 << minute) - 1);
            if minutes != 0 {
                return Some(hour * 60 + (63 - minutes.leading_zeros()));
            }
            if hour == 0 {
                return None;
            }
            hour -= 1;
            minute = 59;
        }
    }
}

fn field(text: &str, name: &'static str, min: u64, max: u64) -> Result<u64, Error> {
    let mut mask = 0u64;
    for part in text.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => (range, Some(step)),
            None => (part, None),
        };
        let step = match step {
            Some(step) => step.parse::<u64>().map_err(|_| Error::Step(name))?,
            None => 1,
        };
        if step == 0 || step > max {
            return Err(Error::Step(name));
        }
        let (low, high) = if range == "*" {
            (min, max)
        } else if let Some((low, high)) = range.split_once('-') {
            (value(low, name, min, max)?, value(high, name, min, max)?)
        } else {
            let at = value(range, name, min, max)?;
            // `5/15` starts at 5 and steps to the field's end; a bare `5` is 5 alone.
            (at, if step > 1 { max } else { at })
        };
        if low > high {
            return Err(Error::Range(name));
        }
        let mut at = low;
        while at <= high {
            mask |= 1 << at;
            at += step;
        }
    }
    Ok(mask)
}

fn value(text: &str, name: &'static str, min: u64, max: u64) -> Result<u64, Error> {
    match text.parse::<u64>() {
        Ok(value) if (min..=max).contains(&value) => Ok(value),
        _ => Err(Error::Field(name)),
    }
}

/// The UTC date of a day count since 1970-01-01, by Howard Hinnant's civil-from-days.
fn civil(day: i64) -> (i64, u32, u32) {
    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let day = doy - (153 * mp + 2) / 5 + 1;
    (year, month as u32, day as u32)
}

/// 1970-01-01 was a Thursday.
const fn weekday(day: i64) -> u32 {
    ((day + 4).rem_euclid(7)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: i64 = 60_000;

    fn at(text: &str) -> i64 {
        // `YYYY-MM-DDTHH:MM` as UTC milliseconds, checked day by day (no dependency, no locale).
        let (date, time) = text.split_once('T').unwrap();
        let mut date = date.split('-');
        let year: i64 = date.next().unwrap().parse().unwrap();
        let month: i64 = date.next().unwrap().parse().unwrap();
        let dom: i64 = date.next().unwrap().parse().unwrap();
        let mut time = time.split(':');
        let hour: i64 = time.next().unwrap().parse().unwrap();
        let minute: i64 = time.next().unwrap().parse().unwrap();
        // Days-from-civil is civil-from-days inverted; the test only needs the inverse of `civil`.
        let year = year - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let yoe = year - era * 400;
        let mp = if month > 2 { month - 3 } else { month + 9 };
        let doy = (153 * mp + 2) / 5 + dom - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let day = era * 146_097 + doe - 719_468;
        (day * MINUTES_PER_DAY + hour * 60 + minute) * MINUTE
    }

    fn fmt(ms: i64) -> String {
        let minute = ms.div_euclid(MINUTE);
        let day = minute.div_euclid(MINUTES_PER_DAY);
        let (year, month, dom) = civil(day);
        let in_day = minute - day * MINUTES_PER_DAY;
        format!(
            "{year:04}-{month:02}-{dom:02}T{:02}:{:02}",
            in_day / 60,
            in_day % 60
        )
    }

    #[test]
    fn the_date_half_round_trips_through_the_civil_calendar() {
        for text in [
            "1970-01-01T00:00",
            "1999-12-31T23:59",
            "2000-02-29T12:30",
            "2024-03-01T00:00",
            "2026-11-20T09:15",
        ] {
            assert_eq!(fmt(at(text)), text);
        }
        assert_eq!(weekday(0), 4, "1970-01-01 was a Thursday");
    }

    #[test]
    fn every_marched_field_lands_on_the_minutes_it_names() {
        assert_eq!(
            fmt(Cron::parse("*/15 * * * *")
                .unwrap()
                .next_after(at("2026-01-01T00:00"))
                .unwrap()),
            "2026-01-01T00:15"
        );
        assert_eq!(
            fmt(Cron::parse("5/20 * * * *").unwrap().next_after(0).unwrap()),
            "1970-01-01T00:05"
        );
        assert_eq!(
            fmt(Cron::parse("0 9 * * *")
                .unwrap()
                .next_after(at("2026-01-01T09:00"))
                .unwrap()),
            "2026-01-02T09:00"
        );
        assert_eq!(
            fmt(Cron::parse("30 2-4 * * *")
                .unwrap()
                .next_after(at("2026-01-01T02:00"))
                .unwrap()),
            "2026-01-01T02:30"
        );
        assert_eq!(
            fmt(Cron::parse("0 0 1 * *")
                .unwrap()
                .next_after(at("2026-01-15T00:00"))
                .unwrap()),
            "2026-02-01T00:00"
        );
        assert_eq!(
            fmt(Cron::parse("0 0 * 12 *")
                .unwrap()
                .next_after(at("2026-01-01T00:00"))
                .unwrap()),
            "2026-12-01T00:00"
        );
        assert_eq!(
            fmt(Cron::parse("0 0 * * 1")
                .unwrap()
                .next_after(at("2026-11-20T00:00"))
                .unwrap()),
            "2026-11-23T00:00"
        );
    }

    #[test]
    fn sunday_is_zero_and_seven() {
        let zero = Cron::parse("0 0 * * 0").unwrap();
        let seven = Cron::parse("0 0 * * 7").unwrap();
        assert_eq!(zero, seven);
        assert_eq!(
            fmt(zero.next_after(at("2026-11-20T00:00")).unwrap()),
            "2026-11-22T00:00"
        );
    }

    #[test]
    fn a_restricted_day_of_month_or_week_matches_either_way() {
        // The 13th *or* any Friday: 2026-11-13 is both, so the next after it is the 20th.
        let cron = Cron::parse("0 0 13 * 5").unwrap();
        assert_eq!(
            fmt(cron.next_after(at("2026-11-13T00:00")).unwrap()),
            "2026-11-20T00:00"
        );
        // A starred day-of-month leaves only the weekday.
        let cron = Cron::parse("0 0 * * 5").unwrap();
        assert_eq!(
            fmt(cron.next_after(at("2026-11-20T00:00")).unwrap()),
            "2026-11-27T00:00"
        );
    }

    #[test]
    fn the_nearest_leap_day_is_found_past_three_ordinary_years() {
        let cron = Cron::parse("0 0 29 2 *").unwrap();
        assert_eq!(
            fmt(cron.next_after(at("2026-11-20T00:00")).unwrap()),
            "2028-02-29T00:00"
        );
        assert_eq!(
            fmt(cron.next_after(at("2028-02-29T00:00")).unwrap()),
            "2032-02-29T00:00"
        );
        // 2100 is not a leap year, so the gap either side of it is eight years.
        assert_eq!(
            fmt(cron.next_after(at("2096-02-29T00:00")).unwrap()),
            "2104-02-29T00:00"
        );
    }

    #[test]
    fn the_previous_occurrence_is_the_last_one_at_or_before_now() {
        let cron = Cron::parse("*/10 * * * *").unwrap();
        let now = at("2026-11-20T09:09");
        assert_eq!(
            fmt(cron.prev_at_or_before(now).unwrap()),
            "2026-11-20T09:00"
        );
        let now = at("2026-11-20T09:10");
        assert_eq!(
            fmt(cron.prev_at_or_before(now).unwrap()),
            "2026-11-20T09:10"
        );
        let cron = Cron::parse("0 0 1 1 *").unwrap();
        assert_eq!(
            fmt(cron.prev_at_or_before(at("2026-11-20T00:00")).unwrap()),
            "2026-01-01T00:00"
        );
    }

    #[test]
    fn a_span_is_bounded_and_says_when_it_stopped_early() {
        let cron = Cron::parse("* * * * *").unwrap();
        let (every, more) = cron.span(at("2026-01-01T00:00"), at("2026-01-01T00:05"), 8);
        assert_eq!(every.len(), 5);
        assert!(!more);
        let (some, more) = cron.span(at("2026-01-01T00:00"), at("2026-01-01T01:00"), 3);
        assert_eq!(some.len(), 3);
        assert!(more);
        assert_eq!(fmt(some[0]), "2026-01-01T00:01");
        let (none, more) = cron.span(at("2026-01-01T00:00"), at("2026-01-01T00:00"), 8);
        assert!(none.is_empty() && !more);
    }

    #[test]
    fn malformed_expressions_are_refused_by_name() {
        for (text, expected) in [
            ("", Error::Empty),
            ("* * * *", Error::Fields),
            ("* * * * * *", Error::Fields),
            ("60 * * * *", Error::Field("minute")),
            ("* 24 * * *", Error::Field("hour")),
            ("* * 0 * *", Error::Field("day-of-month")),
            ("* * * 13 *", Error::Field("month")),
            ("* * * * 8", Error::Field("day-of-week")),
            ("5-1 * * * *", Error::Range("minute")),
            ("*/0 * * * *", Error::Step("minute")),
            ("*/x * * * *", Error::Step("minute")),
            ("1,,2 * * * *", Error::Field("minute")),
            ("-1 * * * *", Error::Field("minute")),
        ] {
            assert_eq!(Cron::parse(text), Err(expected), "{text:?}");
        }
        assert_eq!(
            Cron::parse(&"*".repeat(MAX_CRON_BYTES + 1)),
            Err(Error::TooLong)
        );
    }
}
