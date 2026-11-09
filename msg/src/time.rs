// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! `PtypTime` (FILETIME) and `PtypFloatingTime` (OLE automation date) helpers.

/// FILETIME ticks (100 ns) between 1601-01-01 and 1970-01-01.
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// A FILETIME (100-nanosecond intervals since 1601-01-01 00:00 UTC) as Unix time: whole
/// seconds (negative before 1970) and nanoseconds `0..1_000_000_000`.
pub fn filetime_to_unix(ticks: i64) -> (i64, u32) {
    let since = i128::from(ticks) - i128::from(UNIX_EPOCH_TICKS);
    let secs = since.div_euclid(10_000_000);
    let nanos = (since.rem_euclid(10_000_000) * 100) as u32;
    (secs as i64, nanos)
}

/// A FILETIME as RFC 3339 in UTC with 100-ns precision, for example
/// `2015-08-05T12:02:22.0000000Z`. Every value is formatted (years before 1601 or after 9999
/// included), so nothing is hidden.
pub fn format_filetime(ticks: i64) -> String {
    let (secs, nanos) = filetime_to_unix(ticks);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:07}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        nanos / 100
    )
}

/// An OLE automation date (`PtypFloatingTime`: days since 1899-12-30, the absolute fraction is
/// the time of day) as FILETIME ticks, rounded to the nearest tick; `None` if not finite or out
/// of the FILETIME range.
pub fn floating_time_to_filetime(days: f64) -> Option<i64> {
    // 1899-12-30 is 109205 days after 1601-01-01.
    const TICKS_PER_DAY: i128 = 864_000_000_000;
    const OLE_EPOCH_TICKS: i128 = 94_353_120_000_000_000;
    // The whole part is a signed day number and the absolute value of the fraction the time of
    // day (https://learn.microsoft.com/en-us/cpp/atl-mfc-shared/date-type): the timeline is not
    // continuous before 1899-12-30, where -1.25 is 06:00 on 1899-12-29, not 18:00 on 1899-12-28.
    if !days.is_finite() {
        return None;
    }
    // Keep the day and epoch arithmetic exact. Adding the epoch as f64 first loses
    // several ticks even when the source DATE represents that fraction precisely.
    let whole = (days.trunc() as i128).checked_mul(TICKS_PER_DAY)?;
    // A binary fraction is significand / 2^shift. Scale and round it with integers:
    // a floating multiplication can round a value just below .5 up to .5 first.
    let bits = days.fract().abs().to_bits();
    let exponent = ((bits >> 52) & 0x7FF) as u32;
    let significand = bits & 0x000F_FFFF_FFFF_FFFF;
    let (significand, shift) = if exponent == 0 {
        (significand, 1074)
    } else {
        (significand | (1 << 52), 1075u32.checked_sub(exponent)?)
    };
    let numerator = u128::from(significand).checked_mul(TICKS_PER_DAY as u128)?;
    let fraction = if shift >= 128 {
        // The numerator has at most 93 bits, so this is well below half a tick.
        0
    } else {
        let half = 1u128.checked_shl(shift.checked_sub(1)?)?;
        i128::try_from(numerator.checked_add(half)?.checked_shr(shift)?).ok()?
    };
    let ticks = OLE_EPOCH_TICKS.checked_add(whole)?.checked_add(fraction)?;
    i64::try_from(ticks).ok()
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift to 0000-03-01 so that leap days end each 400-year era.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_ole_dates_do_not_lose_ticks_when_the_epoch_is_added() {
        // One f64 step at 25569 days is 2^-38 days = 3.143213689... FILETIME ticks.
        let day = 25_569.0f64;
        assert_eq!(
            floating_time_to_filetime(f64::from_bits(day.to_bits() + 1)),
            Some(UNIX_EPOCH_TICKS + 3)
        );
        assert_eq!(
            floating_time_to_filetime(f64::from_bits(day.to_bits() + 3)),
            Some(UNIX_EPOCH_TICKS + 9)
        );
        assert_eq!(
            floating_time_to_filetime(f64::from_bits(day.to_bits() - 1)),
            Some(UNIX_EPOCH_TICKS - 3)
        );
        // Modern dates have a 2^-37-day step, which rounds to six ticks.
        let day = 45_000.0f64;
        assert_eq!(
            floating_time_to_filetime(f64::from_bits(day.to_bits() + 1)),
            Some(133_233_120_000_000_006)
        );
        // The exact binary fraction is just below a half tick. Multiplying it in f64
        // rounds it to .5 before the integer rounding, incorrectly adding another tick.
        assert_eq!(
            floating_time_to_filetime(45_000.94533170203),
            Some(133_233_936_766_590_554)
        );
        // The absolute fractional-time rule still applies before the OLE epoch.
        let day = -25_569.0f64;
        assert_eq!(
            floating_time_to_filetime(f64::from_bits(day.to_bits() + 1)),
            Some(72_261_504_000_000_003)
        );
    }

    #[test]
    fn floating_times_use_the_absolute_fraction_for_the_time_of_day() {
        // DATE: the integer selects the day and the absolute fractional part
        // selects the time. In particular, -0.5 and +0.5 are the same instant.
        for (days, expected) in [
            (-0.5, "1899-12-30T12:00:00.0000000Z"),
            (0.5, "1899-12-30T12:00:00.0000000Z"),
            (-1.25, "1899-12-29T06:00:00.0000000Z"),
            (-2.5, "1899-12-28T12:00:00.0000000Z"),
            (-1.0, "1899-12-29T00:00:00.0000000Z"),
            (-0.0, "1899-12-30T00:00:00.0000000Z"),
        ] {
            assert_eq!(
                floating_time_to_filetime(days)
                    .map(format_filetime)
                    .as_deref(),
                Some(expected),
                "OLE DATE {days}"
            );
        }
        for days in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            -f64::MAX,
        ] {
            assert_eq!(floating_time_to_filetime(days), None);
        }
    }

    #[test]
    fn filetimes() {
        assert_eq!(filetime_to_unix(UNIX_EPOCH_TICKS), (0, 0));
        assert_eq!(format_filetime(0), "1601-01-01T00:00:00.0000000Z");
        assert_eq!(
            format_filetime(130_832_497_420_000_000),
            "2015-08-05T12:02:22.0000000Z"
        );
        assert_eq!(
            format_filetime(UNIX_EPOCH_TICKS - 1),
            "1969-12-31T23:59:59.9999999Z"
        );
        // Far-future dates format too.
        assert_eq!(
            format_filetime(915_045_983_400_000_000),
            "4500-08-31T23:59:00.0000000Z"
        );
        // Every value formats.
        let _ = format_filetime(i64::MIN);
        let _ = format_filetime(i64::MAX);
        assert_eq!(floating_time_to_filetime(0.0), Some(94_353_120_000_000_000));
        assert_eq!(
            floating_time_to_filetime(25_569.5)
                .map(format_filetime)
                .as_deref(),
            Some("1970-01-01T12:00:00.0000000Z")
        );
        assert_eq!(floating_time_to_filetime(f64::NAN), None);
        assert_eq!(floating_time_to_filetime(1e300), None);
    }
}
