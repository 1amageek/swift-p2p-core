// DERTime.swift
// Foundation-free UTC time rendering for X.509 validity (write-only).
// `Date`/`DateFormatter` are the only Foundation use in the reference
// ASN1Builder.utcTime; we replace them with pure integer civil-from-days
// (Howard Hinnant's algorithm). We never PARSE a peer's validity dates — libp2p
// binding is cryptographic, not temporal — so only the encode side exists here.

/// Pure-integer UTC time rendering. RFC 5280 §4.1.2.5:
/// - `UTCTime` for years 1950..2049 (2-digit year, `"yyMMddHHmmssZ"`).
/// - `GeneralizedTime` for years >= 2050 (4-digit year, `"yyyyMMddHHmmssZ"`).
enum DERTime {

    /// Broken-down UTC components derived from a Unix epoch second count.
    struct Components {
        var year: Int
        var month: Int   // 1...12
        var day: Int     // 1...31
        var hour: Int    // 0...23
        var minute: Int  // 0...59
        var second: Int  // 0...59
    }

    /// Converts epoch seconds (UTC) to broken-down calendar components using
    /// Howard Hinnant's `civil_from_days`. Handles negative epochs (pre-1970)
    /// with floor-division so the date table stays correct in either direction.
    static func components(epochSeconds: Int64) -> Components {
        let secondsPerDay: Int64 = 86_400
        // Floor-divide seconds into whole days + remainder in [0, 86400).
        var days = epochSeconds / secondsPerDay
        var rem = epochSeconds % secondsPerDay
        if rem < 0 {
            rem += secondsPerDay
            days -= 1
        }

        let hour = Int(rem / 3_600)
        let minute = Int((rem % 3_600) / 60)
        let second = Int(rem % 60)

        // civil_from_days: days since 1970-01-01 -> (year, month, day).
        let z = days + 719_468
        let era: Int64 = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097                                  // [0, 146096]
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365  // [0, 399]
        let y = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)           // [0, 365]
        let mp = (5 * doy + 2) / 153                                 // [0, 11]
        let d = doy - (153 * mp + 2) / 5 + 1                         // [1, 31]
        let m = mp < 10 ? mp + 3 : mp - 9                            // [1, 12]
        let year = Int(m <= 2 ? y + 1 : y)

        return Components(
            year: year, month: Int(m), day: Int(d),
            hour: hour, minute: minute, second: second
        )
    }

    /// Renders the two-digit zero-padded ASCII of `value` (0...99).
    private static func twoDigits(_ value: Int) -> (UInt8, UInt8) {
        let v = value % 100
        let tens = UInt8(48 + (v / 10))
        let ones = UInt8(48 + (v % 10))
        return (tens, ones)
    }

    /// `"yyMMddHHmmssZ"` (13 ASCII bytes). Valid for years 1950..2049.
    static func utcTimeBytes(epochSeconds: Int64) -> [UInt8] {
        let c = components(epochSeconds: epochSeconds)
        var out = [UInt8]()
        out.reserveCapacity(13)
        let yy = twoDigits(c.year)
        let mm = twoDigits(c.month)
        let dd = twoDigits(c.day)
        let hh = twoDigits(c.hour)
        let mi = twoDigits(c.minute)
        let ss = twoDigits(c.second)
        out.append(yy.0); out.append(yy.1)
        out.append(mm.0); out.append(mm.1)
        out.append(dd.0); out.append(dd.1)
        out.append(hh.0); out.append(hh.1)
        out.append(mi.0); out.append(mi.1)
        out.append(ss.0); out.append(ss.1)
        out.append(0x5A) // 'Z'
        return out
    }

    /// `"yyyyMMddHHmmssZ"` (15 ASCII bytes). Used for years >= 2050.
    static func generalizedTimeBytes(epochSeconds: Int64) -> [UInt8] {
        let c = components(epochSeconds: epochSeconds)
        var out = [UInt8]()
        out.reserveCapacity(15)
        let century = twoDigits(c.year / 100)
        let yy = twoDigits(c.year)
        let mm = twoDigits(c.month)
        let dd = twoDigits(c.day)
        let hh = twoDigits(c.hour)
        let mi = twoDigits(c.minute)
        let ss = twoDigits(c.second)
        out.append(century.0); out.append(century.1)
        out.append(yy.0); out.append(yy.1)
        out.append(mm.0); out.append(mm.1)
        out.append(dd.0); out.append(dd.1)
        out.append(hh.0); out.append(hh.1)
        out.append(mi.0); out.append(mi.1)
        out.append(ss.0); out.append(ss.1)
        out.append(0x5A) // 'Z'
        return out
    }
}
