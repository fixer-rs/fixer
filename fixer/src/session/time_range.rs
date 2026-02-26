use jiff::{
    civil::{self, Weekday},
    tz::TimeZone,
    SignedDuration, Zoned,
};
use simple_error::SimpleResult;

// TimeOfDay represents the time of day
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimeOfDay {
    hour: isize,
    minute: isize,
    second: isize,
    d: SignedDuration,
}

const SHORT_FORM: &str = "%H:%M:%S";

pub fn utc() -> TimeZone {
    TimeZone::UTC
}

pub fn gen_now() -> Zoned {
    Zoned::now()
}

impl TimeOfDay {
    // new returns a newly initialized TimeOfDay
    pub fn new(hour: isize, minute: isize, second: isize) -> Self {
        let d = SignedDuration::from_secs(second as i64)
            + SignedDuration::from_mins(minute as i64)
            + SignedDuration::from_hours(hour as i64);

        Self {
            hour,
            minute,
            second,
            d,
        }
    }

    pub fn hour(&self) -> isize {
        self.hour
    }

    pub fn minute(&self) -> isize {
        self.minute
    }

    pub fn second(&self) -> isize {
        self.second
    }

    pub fn parse(input: &str) -> SimpleResult<Self> {
        let parsed = civil::Time::strptime(SHORT_FORM, input);
        let t = map_err_with!(parsed, "time must be in the format HH:MM:SS")?;
        Ok(Self::new(
            t.hour() as isize,
            t.minute() as isize,
            t.second() as isize,
        ))
    }
}

// TimeRange represents a time band in a given time zone
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeRange {
    pub start_time: TimeOfDay,
    pub end_time: TimeOfDay,
    pub weekdays: Vec<Weekday>,
    pub start_day: Option<Weekday>,
    pub end_day: Option<Weekday>,
    pub loc: TimeZone,
}

impl TimeRange {
    // new_utc returns a time range in UTC
    pub fn new_utc(start_time: TimeOfDay, end_time: TimeOfDay) -> Self {
        Self::new_in_location(start_time, end_time, utc())
    }

    // new_utc_with_weekdays returns a time range in UTC with specific weekdays
    pub fn new_utc_with_weekdays(
        start_time: TimeOfDay,
        end_time: TimeOfDay,
        weekdays: Vec<Weekday>,
    ) -> Self {
        Self::new_in_location_with_weekdays(start_time, end_time, weekdays, utc())
    }

    // new_in_location returns a time range in a given location
    pub fn new_in_location(start_time: TimeOfDay, end_time: TimeOfDay, loc: TimeZone) -> Self {
        Self::new_in_location_with_weekdays(start_time, end_time, vec![], loc)
    }

    // new_in_location_with_weekdays returns a time range in a given location with specific weekdays
    pub fn new_in_location_with_weekdays(
        start_time: TimeOfDay,
        end_time: TimeOfDay,
        weekdays: Vec<Weekday>,
        loc: TimeZone,
    ) -> Self {
        Self {
            start_time,
            end_time,
            weekdays,
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
        Self::new_week_range_in_location(start_time, end_time, start_day, end_day, utc())
    }

    // new_week_range_in_location returns a time range in a given location
    pub fn new_week_range_in_location(
        start_time: TimeOfDay,
        end_time: TimeOfDay,
        start_day: Weekday,
        end_day: Weekday,
        loc: TimeZone,
    ) -> TimeRange {
        let mut r = Self::new_in_location_with_weekdays(start_time, end_time, vec![], loc);
        r.start_day = Some(start_day);
        r.end_day = Some(end_day);

        r
    }

    fn is_in_weekdays(&self, day: Weekday) -> bool {
        if !self.weekdays.is_empty() {
            return self.weekdays.contains(&day);
        }
        true
    }

    fn add_weekday_offset(day: Weekday, offset: i8) -> Weekday {
        let val = (day.to_sunday_zero_offset() + offset).rem_euclid(7);
        Weekday::from_sunday_zero_offset(val).unwrap()
    }

    fn is_in_time_range(&self, t: &Zoned) -> bool {
        let new_t = t.with_time_zone(self.loc.clone());
        let ts = TimeOfDay::new(
            new_t.hour() as isize,
            new_t.minute() as isize,
            new_t.second() as isize,
        )
        .d;

        if self.start_time.d < self.end_time.d {
            if self.is_in_weekdays(new_t.weekday()) {
                return self.start_time.d <= ts && ts <= self.end_time.d;
            }
            return false;
        }

        if ts <= self.end_time.d {
            return self.is_in_weekdays(Self::add_weekday_offset(new_t.weekday(), -1));
        }

        if ts >= self.start_time.d {
            return self.is_in_weekdays(new_t.weekday());
        }

        false
    }

    fn is_in_week_range(&self, t: &Zoned) -> bool {
        let new_t = t.with_time_zone(self.loc.clone());
        let day = new_t.weekday().to_sunday_zero_offset();
        let start_day = self.start_day.unwrap().to_sunday_zero_offset();
        let end_day = self.end_day.unwrap().to_sunday_zero_offset();

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
        } else if end_day < day && day < start_day {
            return false;
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
    pub fn is_in_range(&self, t: &Zoned) -> bool {
        if self.start_day.is_some() {
            return self.is_in_week_range(t);
        }
        self.is_in_time_range(t)
    }

    // is_in_same_range &determines if &two points in time are in the same time range
    #[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
    pub fn is_in_same_range(
        &self,
        t1: &mut Zoned,
        t2: &mut Zoned,
    ) -> bool {
        if !(self.is_in_range(t1) && self.is_in_range(t2)) {
            return false;
        }

        if t2 < t1 {
            std::mem::swap(t1, t2);
        }

        let t1 = &t1.with_time_zone(self.loc.clone());
        let t1_hour = t1.hour() as isize;
        let t1_minute = t1.minute() as isize;
        let t1_second = t1.second() as isize;

        let t1_time = TimeOfDay::new(t1_hour, t1_minute, t1_second);
        let mut day_offset: i64 = 0;

        if let Some(end_day_val) = self.end_day {
            let end_day = end_day_val.to_sunday_zero_offset();
            let t1_weekday = t1.weekday().to_sunday_zero_offset();

            match end_day.cmp(&t1_weekday) {
                std::cmp::Ordering::Less => day_offset = 7 + (i64::from(end_day) - i64::from(t1_weekday)),
                std::cmp::Ordering::Equal => {
                    if self.end_time.d <= t1_time.d {
                        day_offset = 7;
                    }
                }
                std::cmp::Ordering::Greater => day_offset = i64::from(end_day) - i64::from(t1_weekday),
            }
        } else if self.start_time.d >= self.end_time.d && t1_time.d >= self.start_time.d {
            day_offset = 1;
        }

        let session_end = civil::date(
            t1.year(),
            t1.month(),
            t1.day(),
        )
        .at(
            self.end_time.hour as i8,
            self.end_time.minute as i8,
            self.end_time.second as i8,
            0,
        )
        .to_zoned(self.loc.clone())
        .unwrap()
        .checked_add(SignedDuration::from_hours(day_offset * 24))
        .unwrap();

        *t2 < session_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::tz::Offset;

    fn zdt(year: i16, month: i8, day: i8, hour: i8, minute: i8, second: i8) -> Zoned {
        civil::date(year, month, day)
            .at(hour, minute, second, 0)
            .to_zoned(TimeZone::UTC)
            .unwrap()
    }

    #[test]
    fn test_new_time_of_day() {
        let to = TimeOfDay::new(12, 34, 4);
        assert_eq!(12, to.hour);
        assert_eq!(34, to.minute);
        assert_eq!(4, to.second);
        assert_eq!(SignedDuration::from_secs(45244), to.d);
    }

    #[test]
    fn test_parse_time() {
        let to = TimeOfDay::parse("12:34:04");
        assert!(to.is_ok());
        assert_eq!(TimeOfDay::new(12, 34, 4), to.unwrap());

        let err = TimeOfDay::parse("0:0:0");
        assert!(err.is_ok());

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
        assert_eq!(TimeZone::UTC, r.loc);
    }

    #[test]
    fn test_new_time_range_in_location() {
        let r = TimeRange::new_in_location(
            TimeOfDay::new(3, 0, 0),
            TimeOfDay::new(18, 0, 0),
            Offset::from_seconds(9 * 3600).unwrap().to_time_zone(),
        );
        assert_eq!(TimeOfDay::new(3, 0, 0), r.start_time);
        assert_eq!(TimeOfDay::new(18, 0, 0), r.end_time);
        assert!(r.start_day.is_none());
        assert!(r.end_day.is_none());
        assert_eq!(Offset::from_seconds(9 * 3600).unwrap().to_time_zone(), r.loc);
    }

    #[test]
    fn test_new_utc_week_range() {
        let r = TimeRange::new_utc_week_range(
            TimeOfDay::new(3, 0, 0),
            TimeOfDay::new(18, 0, 0),
            Weekday::Monday,
            Weekday::Wednesday,
        );
        assert_eq!(TimeOfDay::new(3, 0, 0), r.start_time);
        assert_eq!(TimeOfDay::new(18, 0, 0), r.end_time);
        assert!(r.start_day.is_some());
        assert!(r.end_day.is_some());
        assert_eq!(Weekday::Monday, r.start_day.unwrap());
        assert_eq!(Weekday::Wednesday, r.end_day.unwrap());
        assert_eq!(TimeZone::UTC, r.loc);
    }

    #[test]
    fn test_new_week_range_in_location() {
        let r = TimeRange::new_week_range_in_location(
            TimeOfDay::new(3, 0, 0),
            TimeOfDay::new(18, 0, 0),
            Weekday::Monday,
            Weekday::Wednesday,
            Offset::from_seconds(9 * 3600).unwrap().to_time_zone(),
        );
        assert_eq!(TimeOfDay::new(3, 0, 0), r.start_time);
        assert_eq!(TimeOfDay::new(18, 0, 0), r.end_time);
        assert!(r.start_day.is_some());
        assert!(r.end_day.is_some());
        assert_eq!(Weekday::Monday, r.start_day.unwrap());
        assert_eq!(Weekday::Wednesday, r.end_day.unwrap());
        assert_eq!(Offset::from_seconds(9 * 3600).unwrap().to_time_zone(), r.loc);
    }

    #[test]
    fn test_time_range_is_in_range() {
        let mut start = TimeOfDay::new(3, 0, 0);
        let mut end = TimeOfDay::new(18, 0, 0);

        let mut now = zdt(2016, 8, 10, 10, 0, 0);
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = zdt(2016, 8, 10, 18, 0, 0);
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = zdt(2016, 8, 10, 2, 0, 0);
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        now = zdt(2016, 8, 10, 19, 0, 0);
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        now = zdt(2016, 8, 10, 18, 0, 1);
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        start = TimeOfDay::new(18, 0, 0);
        end = TimeOfDay::new(3, 0, 0);
        now = zdt(2016, 8, 10, 18, 0, 0);
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = zdt(2016, 8, 10, 3, 0, 0);
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));

        now = zdt(2016, 8, 10, 4, 0, 0);
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        now = zdt(2016, 8, 10, 17, 0, 0);
        assert!(!TimeRange::new_utc(start, end).is_in_range(&now));

        let loc = Offset::from_seconds(-60).unwrap().to_time_zone();
        start = TimeOfDay::new(3, 0, 0);
        end = TimeOfDay::new(5, 0, 0);

        now = zdt(2016, 8, 10, 3, 0, 0);
        assert!(!TimeRange::new_in_location(start, end, loc.clone()).is_in_range(&now));

        now = zdt(2016, 8, 10, 3, 1, 0);
        assert!(TimeRange::new_in_location(start, end, loc).is_in_range(&now));

        start = TimeOfDay::new(0, 0, 0);
        end = TimeOfDay::new(0, 0, 0);
        now = zdt(2016, 8, 10, 18, 0, 0);
        assert!(TimeRange::new_utc(start, end).is_in_range(&now));
    }

    #[test]
    fn test_time_range_is_in_range_with_day() {
        let mut start_time = TimeOfDay::new(3, 0, 0);
        let mut end_time = TimeOfDay::new(18, 0, 0);
        let mut start_day = Weekday::Monday;
        let mut end_day = Weekday::Thursday;

        let mut now = zdt(2004, 7, 28, 2, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );
        now = zdt(2004, 7, 27, 18, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 27, 3, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 26, 2, 59, 59);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 29, 18, 0, 1);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        start_day = Weekday::Thursday;
        end_day = Weekday::Monday;

        now = zdt(2004, 7, 24, 2, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 28, 2, 0, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 22, 3, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 26, 18, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 22, 2, 59, 59);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2004, 7, 26, 18, 0, 1);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        start_time = TimeOfDay::new(9, 1, 0);
        end_time = TimeOfDay::new(8, 59, 0);
        start_day = Weekday::Sunday;
        end_day = Weekday::Sunday;

        now = zdt(2006, 12, 3, 8, 59, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 3, 8, 59, 1);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 3, 9, 1, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 3, 9, 0, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 4, 8, 59, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 4, 8, 59, 1);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 4, 9, 1, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 4, 9, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        start_time = TimeOfDay::new(8, 59, 0);
        end_time = TimeOfDay::new(9, 1, 0);
        start_day = Weekday::Sunday;
        end_day = Weekday::Sunday;

        now = zdt(2006, 12, 3, 8, 59, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 3, 9, 1, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_range(&now)
        );

        now = zdt(2006, 12, 4, 8, 59, 0);
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
        let mut time1 = zdt(2016, 8, 10, 10, 0, 0);
        let mut time2 = zdt(2016, 8, 10, 10, 0, 0);

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // time 2 in same session but greater
        time1 = zdt(2016, 8, 10, 10, 0, 0);
        time2 = zdt(2016, 8, 10, 11, 0, 0);

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // time 2 in same session but less
        time1 = zdt(2016, 8, 10, 11, 0, 0);
        time2 = zdt(2016, 8, 10, 10, 0, 0);

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // time 1 not in session
        time1 = zdt(2016, 8, 10, 19, 0, 0);
        time2 = zdt(2016, 8, 10, 10, 0, 0);

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // time 2 not in session
        time1 = zdt(2016, 8, 10, 10, 0, 0);
        time2 = zdt(2016, 8, 10, 2, 0, 0);

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // start time is greater than end time
        start = TimeOfDay::new(18, 0, 0);
        end = TimeOfDay::new(3, 0, 0);

        // same session same day
        time1 = zdt(2016, 8, 10, 19, 0, 0);
        time2 = zdt(2016, 8, 10, 20, 0, 0);

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // same session time 2 is in next day
        time1 = zdt(2016, 8, 10, 19, 0, 0);
        time2 = zdt(2016, 8, 11, 2, 0, 0);

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // same session time 1 is in next day
        time1 = zdt(2016, 8, 11, 2, 0, 0);
        time2 = zdt(2016, 8, 10, 19, 0, 0);

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // time1 is 25 hours greater than time2
        time1 = zdt(2016, 8, 11, 21, 0, 0);
        time2 = zdt(2016, 8, 10, 20, 0, 0);

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        // start time is greater than end time
        start = TimeOfDay::new(6, 0, 0);
        end = TimeOfDay::new(6, 0, 0);

        time1 = zdt(2016, 1, 13, 19, 10, 0);
        time2 = zdt(2016, 1, 14, 19, 6, 0);
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        start = TimeOfDay::new(0, 0, 0);
        end = TimeOfDay::new(2, 0, 0);
        let loc = Offset::from_seconds(-60).unwrap().to_time_zone();

        time1 = zdt(2016, 8, 10, 0, 1, 0);
        time2 = zdt(2016, 8, 10, 0, 1, 0);
        assert!(
            TimeRange::new_in_location(start, end, loc.clone()).is_in_same_range(&mut time1, &mut time2)
        );
        assert!(
            TimeRange::new_in_location(start, end, loc.clone()).is_in_same_range(&mut time2, &mut time1)
        );

        start = TimeOfDay::new(2, 0, 0);
        end = TimeOfDay::new(0, 0, 0);
        time1 = zdt(2016, 8, 10, 2, 1, 0);
        time2 = zdt(2016, 8, 10, 2, 1, 0);
        assert!(
            TimeRange::new_in_location(start, end, loc.clone()).is_in_same_range(&mut time1, &mut time2)
        );
        assert!(
            TimeRange::new_in_location(start, end, loc.clone()).is_in_same_range(&mut time2, &mut time1)
        );

        start = TimeOfDay::new(0, 0, 0);
        end = TimeOfDay::new(0, 0, 0);
        time1 = zdt(2016, 8, 10, 0, 0, 0);
        time2 = zdt(2016, 8, 11, 0, 0, 0);
        assert!(
            !TimeRange::new_in_location(start, end, loc.clone()).is_in_same_range(&mut time1, &mut time2)
        );
        assert!(
            !TimeRange::new_in_location(start, end, loc).is_in_same_range(&mut time2, &mut time1)
        );

        time1 = zdt(2016, 8, 10, 23, 59, 59);
        time2 = zdt(2016, 8, 11, 0, 0, 0);
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        start = TimeOfDay::new(1, 49, 0);
        end = TimeOfDay::new(1, 49, 0);
        time1 = zdt(2016, 8, 16, 1, 48, 21);
        time2 = zdt(2016, 8, 16, 1, 49, 2);

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        start = TimeOfDay::new(1, 49, 0);
        end = TimeOfDay::new(1, 49, 0);
        time1 = zdt(2016, 8, 16, 13, 48, 21);
        time2 = zdt(2016, 8, 16, 13, 49, 2);

        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));

        start = TimeOfDay::new(13, 49, 0);
        end = TimeOfDay::new(13, 49, 0);
        time1 = zdt(2016, 8, 16, 13, 48, 21);
        time2 = zdt(2016, 8, 16, 13, 49, 2);

        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time1, &mut time2));
        assert!(!TimeRange::new_utc(start, end).is_in_same_range(&mut time2, &mut time1));
    }

    #[test]
    fn test_time_range_is_in_same_range_with_day() {
        let mut start_time = TimeOfDay::new(3, 0, 0);
        let mut end_time = TimeOfDay::new(18, 0, 0);
        let mut start_day = Weekday::Monday;
        let mut end_day = Weekday::Thursday;

        let mut time1 = zdt(2004, 7, 27, 3, 0, 0);
        let mut time2 = zdt(2004, 7, 25, 3, 0, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time1 = zdt(2004, 7, 31, 3, 0, 0);
        time2 = zdt(2004, 7, 27, 3, 0, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time1 = zdt(2004, 7, 27, 3, 0, 0);
        time2 = zdt(2004, 7, 27, 3, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time1 = zdt(2004, 7, 26, 10, 0, 0);
        time2 = zdt(2004, 7, 27, 3, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time1 = zdt(2004, 7, 27, 10, 0, 0);
        time2 = zdt(2004, 7, 29, 2, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time1 = zdt(2004, 7, 27, 10, 0, 0);
        time2 = zdt(2004, 7, 20, 3, 0, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time1 = zdt(2004, 7, 27, 2, 0, 0);
        time2 = zdt(2004, 7, 20, 3, 0, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time1 = zdt(2004, 7, 26, 2, 0, 0);
        time2 = zdt(2004, 7, 19, 3, 0, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        // Reset start/end time so that they fall within an hour of midnight
        start_time = TimeOfDay::new(0, 5, 0);
        end_time = TimeOfDay::new(23, 45, 0);

        // Make it a week-long session
        start_day = Weekday::Sunday;
        end_day = Weekday::Saturday;

        // Check that ST-->DST (Sunday is missing one hour) is handled
        time1 = zdt(2006, 4, 4, 0, 0, 0);
        time2 = zdt(2006, 4, 3, 1, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        // Check that DST-->ST (Sunday has an extra hour) is handled
        time1 = zdt(2006, 10, 30, 0, 0, 0);
        time2 = zdt(2006, 10, 31, 1, 0, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        // Check that everything works across a year boundary
        time1 = zdt(2006, 12, 31, 10, 10, 10);
        time2 = zdt(2007, 1, 1, 10, 10, 10);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        // Session days are the same
        start_day = Weekday::Sunday;
        end_day = Weekday::Sunday;
        start_time = TimeOfDay::new(9, 1, 0);
        end_time = TimeOfDay::new(8, 59, 0);
        time1 = zdt(2006, 12, 3, 9, 1, 0);
        time2 = zdt(2006, 12, 3, 9, 1, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time2 = zdt(2006, 12, 10, 9, 1, 0);
        assert!(
            !TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );

        time2 = zdt(2006, 12, 4, 9, 1, 0);
        assert!(
            TimeRange::new_utc_week_range(start_time, end_time, start_day, end_day)
                .is_in_same_range(&mut time1, &mut time2)
        );
    }
}
