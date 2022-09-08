use chrono::{
    Datelike, Duration, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Weekday,
};
use simple_error::SimpleResult;
use std::ops::Add;

// TimeOfDay represents the time of day
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimeOfDay {
    hour: isize,
    minute: isize,
    second: isize,
    d: Duration,
}

const SHORT_FORM: &'static str = "%H:%M:%S";

impl TimeOfDay {
    // new returns a newly initialized TimeOfDay
    pub fn new(hour: isize, minute: isize, second: isize) -> Self {
        let d = Duration::seconds(second as i64)
            + Duration::minutes(minute as i64)
            + Duration::hours(hour as i64);

        Self {
            hour,
            minute,
            second,
            d,
        }
    }

    pub fn parse(input: &str) -> SimpleResult<Self> {
        let parsed = NaiveTime::parse_from_str(input, SHORT_FORM);
        let t = map_err_with!(parsed, "time must be in the format HH:MM:SS")?;
        Ok(Self::new(
            t.hour() as isize,
            t.minute() as isize,
            t.second() as isize,
        ))
    }
}

// TimeRange represents a time band in a given time zone
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimeRange {
    start_time: TimeOfDay,
    end_time: TimeOfDay,
    start_day: Option<Weekday>,
    end_day: Option<Weekday>,
    loc: FixedOffset,
}

impl TimeRange {
    // new_utc returns a time range in UTC
    pub fn new_utc(start_time: TimeOfDay, end_time: TimeOfDay) -> Self {
        Self::new_in_location(start_time, end_time, FixedOffset::west(0))
    }

    // new_in_location returns a time range in a given location
    pub fn new_in_location(start_time: TimeOfDay, end_time: TimeOfDay, loc: FixedOffset) -> Self {
        Self {
            start_time,
            end_time,
            start_day: None,
            end_day: None,
            loc,
        }
    }

    // new_utc_week_range returns a weekly TimeRange
    pub fn new_utc_week_range(
        start_time: TimeOfDay,
        end_time: TimeOfDay,
        start_day: Weekday,
        end_day: Weekday,
    ) -> TimeRange {
        Self::new_week_range_in_location(
            start_time,
            end_time,
            start_day,
            end_day,
            FixedOffset::west(0),
        )
    }

    // new_week_range_in_location returns a time range in a given location
    pub fn new_week_range_in_location(
        start_time: TimeOfDay,
        end_time: TimeOfDay,
        start_day: Weekday,
        end_day: Weekday,
        loc: FixedOffset,
    ) -> TimeRange {
        let mut r = Self::new_in_location(start_time, end_time, loc);
        r.start_day = Some(start_day);
        r.end_day = Some(end_day);

        r
    }
}

impl TimeRange {
    fn is_in_time_range(&self, t: &NaiveDateTime) -> bool {
        let new_t = t.add(self.loc);
        let ts = TimeOfDay::new(
            new_t.hour() as isize,
            new_t.minute() as isize,
            new_t.second() as isize,
        )
        .d;

        if self.start_time.d < self.end_time.d {
            return self.start_time.d <= ts && ts <= self.end_time.d;
        }

        !(self.end_time.d < ts && ts < self.start_time.d)
    }

    fn is_in_week_range(&self, t: &NaiveDateTime) -> bool {
        let new_t = t.add(self.loc);
        let day = new_t.weekday().num_days_from_sunday();
        let start_day = self.start_day.unwrap().num_days_from_sunday();
        let end_day = self.end_day.unwrap().num_days_from_sunday();

        if start_day == end_day {
            if day == start_day {
                return self.is_in_time_range(&new_t);
            }

            if self.start_time.d < self.end_time.d {
                return false;
            }
            return true;
        }

        if start_day < end_day {
            if day < start_day || end_day < day {
                return false;
            }
        } else {
            if end_day < day && day < start_day {
                return false;
            }
        }

        let time_of_day = TimeOfDay::new(
            new_t.hour() as isize,
            new_t.minute() as isize,
            new_t.second() as isize,
        );

        if day == start_day {
            return time_of_day.d >= self.start_time.d;
        }

        if day == end_day {
            return time_of_day.d <= self.end_time.d;
        }

        true
    }

    // is_in_range returns true if time t is within in the time range
    pub fn is_in_range(&self, t: &NaiveDateTime) -> bool {
        if self.start_day.is_none() {
            return self.is_in_time_range(t);
        }
        self.is_in_week_range(t)
    }

    // is_in_same_range &determines if &two points in time are in the same time range
    pub fn is_in_same_range(&self, t1: &NaiveDateTime, t2: &NaiveDateTime) -> bool {
        if !(self.is_in_range(t1) && self.is_in_range(t2)) {
            return false;
        }

        let mut tmp1 = t1;
        let mut tmp2 = t2;

        if t2.lt(t1) {
            (tmp1, tmp2) = (t2, t1);
        }

        let tmp1 = &tmp1.add(self.loc);
        let t1_hour = tmp1.hour() as isize;
        let t1_minute = tmp1.minute() as isize;
        let t1_second = tmp1.second() as isize;

        let t1_time = TimeOfDay::new(t1_hour, t1_minute, t1_second);
        let mut day_offset = 0;

        if self.end_day.is_none() {
            if self.start_time.d >= self.end_time.d && t1_time.d >= self.start_time.d {
                day_offset = 1
            }
        } else {
            let end_day = self.end_day.unwrap().num_days_from_sunday();
            let t1_weekday = t1.weekday().num_days_from_sunday();
            if end_day < t1_weekday {
                day_offset = 7 + (end_day - t1_weekday) as i64
            } else if t1_weekday == end_day {
                if self.end_time.d <= t1_time.d {
                    day_offset = 7;
                }
            } else {
                day_offset = (end_day - t1_weekday) as i64;
            }
        }

        let session_end = NaiveDate::from_ymd(tmp1.year(), tmp1.month(), tmp1.day()).and_hms(
            self.end_time.hour as u32,
            self.end_time.minute as u32,
            self.end_time.second as u32,
        );
        let session_end = session_end.add(self.loc);
        let session_end = session_end.add(Duration::days(day_offset));

        tmp2.lt(&session_end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_time_of_day() {
        let to = TimeOfDay::new(12, 34, 4);
        assert_eq!(12, to.hour);
        assert_eq!(34, to.minute);
        assert_eq!(4, to.second);
        assert_eq!(Duration::seconds(45244), to.d);
    }

    #[test]
    fn test_parse_time() {
        let to = TimeOfDay::parse("12:34:04");
        assert!(to.is_ok());
        assert_eq!(TimeOfDay::new(12, 34, 4), to.unwrap());

        // let err = TimeOfDay::parse("0:0:0");
        // assert!(err.is_err());

        let err = TimeOfDay::parse("00:00");
        assert!(err.is_err());

        let err = TimeOfDay::parse("0000:00");
        assert!(err.is_err());
    }

    #[test]
    fn test_new_utc_time_range() {
        let r = TimeRange::new_utc(TimeOfDay::new(3, 0, 0), TimeOfDay::new(18, 0, 0));
        assert_eq!(TimeOfDay::new(3, 0, 0), r.start_time);
        assert_eq!(TimeOfDay::new(18, 0, 0), r.end_time);
        assert!(r.start_day.is_none());
        assert!(r.end_day.is_none());
        assert_eq!(FixedOffset::east(0), r.loc);
    }

    #[test]
    fn test_new_time_range_in_location() {
        let r = TimeRange::new_in_location(
            TimeOfDay::new(3, 0, 0),
            TimeOfDay::new(18, 0, 0),
            FixedOffset::east(9 * 3600),
        );
        assert_eq!(TimeOfDay::new(3, 0, 0), r.start_time);
        assert_eq!(TimeOfDay::new(18, 0, 0), r.end_time);
        assert!(r.start_day.is_none());
        assert!(r.end_day.is_none());
        assert_eq!(FixedOffset::east(9 * 3600), r.loc);
    }

    #[test]
    fn test_new_utc_week_range() {
        let r = TimeRange::new_utc_week_range(
            TimeOfDay::new(3, 0, 0),
            TimeOfDay::new(18, 0, 0),
            Weekday::Mon,
            Weekday::Wed,
        );
        assert_eq!(TimeOfDay::new(3, 0, 0), r.start_time);
        assert_eq!(TimeOfDay::new(18, 0, 0), r.end_time);
        assert!(r.start_day.is_some());
        assert!(r.end_day.is_some());
        assert_eq!(Weekday::Mon, r.start_day.unwrap());
        assert_eq!(Weekday::Wed, r.end_day.unwrap());
        assert_eq!(FixedOffset::east(0), r.loc);
    }

    #[test]
    fn test_new_week_range_in_location() {
        let r = TimeRange::new_week_range_in_location(
            TimeOfDay::new(3, 0, 0),
            TimeOfDay::new(18, 0, 0),
            Weekday::Mon,
            Weekday::Wed,
            FixedOffset::east(9 * 3600),
        );
        assert_eq!(TimeOfDay::new(3, 0, 0), r.start_time);
        assert_eq!(TimeOfDay::new(18, 0, 0), r.end_time);
        assert!(r.start_day.is_some());
        assert!(r.end_day.is_some());
        assert_eq!(Weekday::Mon, r.start_day.unwrap());
        assert_eq!(Weekday::Wed, r.end_day.unwrap());
        assert_eq!(FixedOffset::east(9 * 3600), r.loc);
    }

    #[test]
    fn test_time_range_is_in_range() {
        let mut start = TimeOfDay::new(3, 0, 0);
        let mut end = TimeOfDay::new(18, 0, 0);

        let mut now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(18, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(19, 0, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(18, 0, 1)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        start = TimeOfDay::new(18, 0, 0);
        end = TimeOfDay::new(3, 0, 0);
        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(18, 0, 0)
            .add(FixedOffset::east(0));
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(4, 0, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(17, 0, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        // var tr *TimeRange
        // assert!(
        //     !tr.is_in_range(&now),
        //     "always in range if time range is nil"
        // );

        let loc = FixedOffset::west(60);
        start = TimeOfDay::new(3, 0, 0);
        end = TimeOfDay::new(5, 0, 0);

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_in_location(start, end, loc).is_in_range(&now));

        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(3, 1, 0)
            .add(FixedOffset::east(0));
        assert!(TimeRange::new_in_location(start, end, loc).is_in_range(&now));

        start = TimeOfDay::new(0, 0, 0);
        end = TimeOfDay::new(0, 0, 0);
        now = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(18, 0, 0)
            .add(FixedOffset::east(0));
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));
    }

    #[test]
    fn test_time_range_is_in_range_with_day() {
        let mut start_time = TimeOfDay::new(3, 0, 0);
        let mut end_time = TimeOfDay::new(18, 0, 0);
        let mut start_day = Weekday::Mon;
        let mut end_day = Weekday::Thu;

        let mut now = NaiveDate::from_ymd(2004, 7, 28)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );
        now = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(18, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 26)
            .and_hms(2, 59, 59)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 29)
            .and_hms(18, 0, 1)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        start_day = Weekday::Thu;
        end_day = Weekday::Mon;

        now = NaiveDate::from_ymd(2004, 7, 24)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 28)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 22)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 26)
            .and_hms(18, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 22)
            .and_hms(2, 59, 59)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2004, 7, 26)
            .and_hms(18, 0, 1)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        start_time = TimeOfDay::new(9, 1, 0);
        end_time = TimeOfDay::new(8, 59, 0);
        start_day = Weekday::Sun;
        end_day = Weekday::Sun;

        now = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(8, 59, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(8, 59, 1)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(9, 1, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(9, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 4)
            .and_hms(8, 59, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 4)
            .and_hms(8, 59, 1)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 4)
            .and_hms(9, 1, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 4)
            .and_hms(9, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        start_time = TimeOfDay::new(8, 59, 0);
        end_time = TimeOfDay::new(9, 1, 0);
        start_day = Weekday::Sun;
        end_day = Weekday::Sun;

        now = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(8, 59, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(9, 1, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = NaiveDate::from_ymd(2006, 12, 4)
            .and_hms(8, 59, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );
    }

    #[test]
    fn test_time_range_is_in_same_range() {
        // start time is less than end time
        let mut start = TimeOfDay::new(3, 0, 0);
        let mut end = TimeOfDay::new(18, 0, 0);

        // same time
        let mut time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));
        let mut time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // time 2 in same session but greater
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(11, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // time 2 in same session but less
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(11, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // time 1 not in session
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(19, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // time 2 not in session
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // start time is greater than end time
        start = TimeOfDay::new(18, 0, 0);
        end = TimeOfDay::new(3, 0, 0);

        // same session same day
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(19, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(20, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // same session time 2 is in next day
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(19, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 11)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // same session time 1 is in next day
        time1 = NaiveDate::from_ymd(2016, 8, 11)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(19, 0, 0)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // time1 is 25 hours greater than time2
        time1 = NaiveDate::from_ymd(2016, 8, 11)
            .and_hms(21, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(20, 0, 0)
            .add(FixedOffset::east(0));

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        // start time is greater than end time
        start = TimeOfDay::new(6, 0, 0);
        end = TimeOfDay::new(6, 0, 0);

        time1 = NaiveDate::from_ymd(2016, 1, 13)
            .and_hms(19, 10, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 1, 14)
            .and_hms(19, 6, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        start = TimeOfDay::new(0, 0, 0);
        end = TimeOfDay::new(2, 0, 0);
        let loc = FixedOffset::west(60);

        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(0, 1, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(0, 1, 0)
            .add(FixedOffset::east(0));
        assert!(TimeRange::new_in_location(start, end, loc).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_in_location(start, end, loc).is_in_same_range(&time2, &time1));

        start = TimeOfDay::new(2, 0, 0);
        end = TimeOfDay::new(0, 0, 0);
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(2, 1, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(2, 1, 0)
            .add(FixedOffset::east(0));
        assert!(TimeRange::new_in_location(start, end, loc).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_in_location(start, end, loc).is_in_same_range(&time2, &time1));

        // var tr *TimeRange
        // assert!(tr.is_in_same_range(&time1, &time2), "always in same range if time range is nil");

        start = TimeOfDay::new(0, 0, 0);
        end = TimeOfDay::new(0, 0, 0);
        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(0, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 11)
            .and_hms(0, 0, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_in_location(start, end, loc).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_in_location(start, end, loc).is_in_same_range(&time2, &time1));

        time1 = NaiveDate::from_ymd(2016, 8, 10)
            .and_hms(23, 59, 59)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 11)
            .and_hms(0, 0, 0)
            .add(FixedOffset::east(0));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        start = TimeOfDay::new(1, 49, 0);
        end = TimeOfDay::new(1, 49, 0);
        time1 = NaiveDate::from_ymd(2016, 8, 16)
            .and_hms(1, 48, 21)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 16)
            .and_hms(1, 49, 02)
            .add(FixedOffset::east(0));

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        start = TimeOfDay::new(1, 49, 0);
        end = TimeOfDay::new(1, 49, 0);
        time1 = NaiveDate::from_ymd(2016, 8, 16)
            .and_hms(13, 48, 21)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 16)
            .and_hms(13, 49, 02)
            .add(FixedOffset::east(0));

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));

        start = TimeOfDay::new(13, 49, 0);
        end = TimeOfDay::new(13, 49, 0);
        time1 = NaiveDate::from_ymd(2016, 8, 16)
            .and_hms(13, 48, 21)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2016, 8, 16)
            .and_hms(13, 49, 02)
            .add(FixedOffset::east(0));

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time1, &time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&time2, &time1));
    }

    #[test]
    fn test_time_range_is_in_same_range_with_day() {
        let mut start_time = TimeOfDay::new(3, 0, 0);
        let mut end_time = TimeOfDay::new(18, 0, 0);
        let mut start_day = Weekday::Mon;
        let mut end_day = Weekday::Thu;

        let mut time1 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        let mut time2 = NaiveDate::from_ymd(2004, 7, 25)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time1 = NaiveDate::from_ymd(2004, 7, 31)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time1 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time1 = NaiveDate::from_ymd(2004, 7, 26)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time1 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2004, 7, 29)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time1 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(10, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2004, 7, 20)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time1 = NaiveDate::from_ymd(2004, 7, 27)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2004, 7, 20)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time1 = NaiveDate::from_ymd(2004, 7, 26)
            .and_hms(2, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2004, 7, 19)
            .and_hms(3, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        // Reset start/end time so that they fall within an hour of midnight
        start_time = TimeOfDay::new(0, 5, 0);
        end_time = TimeOfDay::new(23, 45, 0);

        // Make it a week-long session
        start_day = Weekday::Sun;
        end_day = Weekday::Sat;

        // Check that ST-->DST (Sunday is missing one hour) is handled
        time1 = NaiveDate::from_ymd(2006, 4, 4)
            .and_hms(0, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2006, 4, 3)
            .and_hms(1, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        // Check that DST-->ST (Sunday has an extra hour) is handled
        time1 = NaiveDate::from_ymd(2006, 10, 30)
            .and_hms(0, 0, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2006, 10, 31)
            .and_hms(1, 0, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        // Check that everything works across a year boundary
        time1 = NaiveDate::from_ymd(2006, 12, 31)
            .and_hms(10, 10, 10)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2007, 1, 1)
            .and_hms(10, 10, 10)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        // Session days are the same
        start_day = Weekday::Sun;
        end_day = Weekday::Sun;
        start_time = TimeOfDay::new(9, 1, 0);
        end_time = TimeOfDay::new(8, 59, 0);
        time1 = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(9, 1, 0)
            .add(FixedOffset::east(0));
        time2 = NaiveDate::from_ymd(2006, 12, 3)
            .and_hms(9, 1, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time2 = NaiveDate::from_ymd(2006, 12, 10)
            .and_hms(9, 1, 0)
            .add(FixedOffset::east(0));
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );

        time2 = NaiveDate::from_ymd(2006, 12, 4)
            .and_hms(9, 1, 0)
            .add(FixedOffset::east(0));
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&time1, &time2)
        );
    }
}
