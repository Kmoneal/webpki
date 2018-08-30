// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use ring;
pub use ring::der::{
    CONSTRUCTED,

    Tag,

    nested,
};
use Error;
use calendar;
use time;
use untrusted;

#[cfg(feature = "std")]
use std;

#[inline(always)]
pub fn expect_tag_and_get_value<'a>(input: &mut untrusted::Reader<'a>,
                                    tag: Tag) ->
                                    Result<untrusted::Input<'a>, Error> {
    ring::der::expect_tag_and_get_value(input, tag).map_err(|_| Error::BadDER)
}

#[inline(always)]
pub fn read_tag_and_get_value<'a>(input: &mut untrusted::Reader<'a>)
                                  -> Result<(u8, untrusted::Input<'a>), Error> {
    ring::der::read_tag_and_get_value(input).map_err(|_| Error::BadDER)
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
#[inline(always)]
pub fn nested_mut<'a, F, R, E: Copy>(input: &mut untrusted::Reader<'a>,
                                     tag: Tag, error: E, decoder: F)
                                     -> Result<R, E>
                                     where F : FnMut(&mut untrusted::Reader<'a>)
                                                     -> Result<R, E> {
    let inner = expect_tag_and_get_value(input, tag).map_err(|_| error)?;
    inner.read_all_mut(error, decoder).map_err(|_| error)
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
pub fn nested_of_mut<'a, F, E: Copy>(input: &mut untrusted::Reader<'a>,
                                     outer_tag: Tag, inner_tag: Tag, error: E,
                                     mut decoder: F) -> Result<(), E>
                                     where F : FnMut(&mut untrusted::Reader<'a>)
                                                     -> Result<(), E> {
    nested_mut(input, outer_tag, error, |outer| {
        loop {
            nested_mut(outer, inner_tag, error, |inner| decoder(inner))?;
            if outer.at_end() {
                break;
            }
        }
        Ok(())
    })
}

pub fn bit_string_with_no_unused_bits<'a>(input: &mut untrusted::Reader<'a>)
                                          -> Result<untrusted::Input<'a>,
                                                    Error> {
    nested(input, Tag::BitString, Error::BadDER, |value| {
        let unused_bits_at_end = value.read_byte().map_err(|_| Error::BadDER)?;
        if unused_bits_at_end != 0 {
            return Err(Error::BadDER);
        }
        Ok(value.skip_to_end())
    })
}

// Like mozilla::pkix, we accept the nonconformant explicit encoding of
// the default value (false) for compatibility with real-world certificates.
pub fn optional_boolean(input: &mut untrusted::Reader) -> Result<bool, Error> {
    if !input.peek(Tag::Boolean as u8) {
        return Ok(false);
    }
    nested(input, Tag::Boolean, Error::BadDER, |input| {
        match input.read_byte() {
            Ok(0xff) => Ok(true),
            Ok(0x00) => Ok(false),
            _ => Err(Error::BadDER)
        }
    })
}

pub fn positive_integer<'a>(input: &'a mut untrusted::Reader)
                            -> Result<untrusted::Input<'a>, Error> {
    ring::der::positive_integer(input).map_err(|_| Error::BadDER)
}

pub fn small_nonnegative_integer<'a>(input: &'a mut untrusted::Reader)
                                     -> Result<u8, Error> {
    ring::der::small_nonnegative_integer(input).map_err(|_| Error::BadDER)
}


pub fn time_choice<'a>(input: &mut untrusted::Reader<'a>)
                       -> Result<time::Time, Error> {
    let is_utc_time = input.peek(Tag::UTCTime as u8);
    let expected_tag = if is_utc_time { Tag::UTCTime }
                       else { Tag::GeneralizedTime };

    fn read_digit(inner: &mut untrusted::Reader) -> Result<u64, Error> {
        let b = inner.read_byte().map_err(|_| Error::BadDERTime)?;
        if b < b'0' || b > b'9' {
            return Err(Error::BadDERTime);
        }
        Ok((b - b'0') as u64)
    }

    fn read_two_digits(inner: &mut untrusted::Reader, min: u64, max: u64)
                       -> Result<u64, Error> {
        let hi = read_digit(inner)?;
        let lo = read_digit(inner)?;
        let value = (hi * 10) + lo;
        if value < min || value > max {
            return Err(Error::BadDERTime);
        }
        Ok(value)
    }

    nested(input, expected_tag, Error::BadDER, |value| {
        let (year_hi, year_lo) =
            if is_utc_time {
                let lo = read_two_digits(value, 0, 99)?;
                let hi = if lo >= 50 { 19 } else { 20 };
                (hi, lo)
            } else {
                let hi = read_two_digits(value, 0, 99)?;
                let lo = read_two_digits(value, 0, 99)?;
                (hi, lo)
            };

        let year = (year_hi * 100) + year_lo;
        let month = read_two_digits(value, 1, 12)?;
        let days_in_month = calendar::days_in_month(year, month);
        let day_of_month = read_two_digits(value, 1, days_in_month)?;
        let hours = read_two_digits(value, 0, 23)?;
        let minutes = read_two_digits(value, 0, 59)?;
        let seconds = read_two_digits(value, 0, 59)?;

        let time_zone = value.read_byte().map_err(|_| Error::BadDERTime)?;
        if time_zone != b'Z' {
            return Err(Error::BadDERTime);
        }

        calendar::time_from_ymdhms_utc(year, month, day_of_month, hours, minutes,
                                       seconds)
    })
}

///
#[cfg(feature = "std")]
pub fn parse_oid<'a>(input: &mut untrusted::Reader<'a>) -> Result<std::string::String, Error> {
    use std::string::ToString;
    let oid = expect_tag_and_get_value(input, Tag::OID)?;

    oid.read_all(Error::BadDER, |data| {
        let mut oid_string = std::string::String::new();
        let mut stack = std::collections::VecDeque::new();

        let first = data.read_byte().map_err(|_| Error::BadDER)?;
        oid_string.push_str(&(first/40).to_string());
        oid_string.push('.');
        oid_string.push_str(&(first%40).to_string());

        while let Ok(value) = data.read_byte() {
            if value >= 128 {
                stack.push_front(value);
            } else {
                oid_string.push('.');
                let mut subtotal = value as u64;
                let mut iteration = 0;
                while !stack.is_empty() {
                    iteration = iteration + 1;
                    let prev_value = stack.pop_front().ok_or_else(|| Error::BadDER)?;
                    subtotal = subtotal + ((prev_value - 128) as u64) * 128_u64.pow(iteration);
                }
                oid_string.push_str(&subtotal.to_string());
            }
        }
        Ok(oid_string)
    })
}

///
#[cfg(feature = "std")]
pub fn parse_directory_string<'a>(input: &mut untrusted::Reader<'a>) -> Result<std::string::String, Error> {
    use std::vec::Vec;
    use std::string::String;
    use core::iter::FromIterator;

    // Expect tag for PrintableString
    // TODO: check for string tag
    let (_, printable_string) =
        read_tag_and_get_value(input).map_err(|_| Error::BadDER)?;

    let value = Vec::from_iter(printable_string.iter().cloned());
    let value = String::from_utf8(value).map_err(|_| Error::BadDER);

    value
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct Name {
    common_name: Option<std::string::String>,
    country_name: Option<std::string::String>,
    locality_name: Option<std::string::String>,
    state_or_province_name: Option<std::string::String>,
    organization_name: Option<std::string::String>,
    organizational_unit_name: Option<std::string::String>,
    extra: Option<std::string::String>,
}

///
#[cfg(feature = "std")]
pub fn parse_name<'a>(input: &mut untrusted::Reader<'a>) -> Result<Name, Error> {
    use std::string::String;
    use std::string::ToString;

    // read one name component
    fn parse_one_name<'a>(input: &mut untrusted::Reader<'a>) -> Result<(String, String), Error> {
        // We expect a Set here
        if input.peek(0x31) {
            let (_, set_inner) =
                read_tag_and_get_value(input).map_err(|_| Error::BadDER)?;

            // read the sequence bytes
            let mut set_data = untrusted::Reader::new(set_inner);
            let seq = expect_tag_and_get_value(&mut set_data, Tag::Sequence)?;

            seq.read_all(Error::BadDER, |reader| {
                // Read attribute type and value
                let oid = parse_oid(reader)?;
                let name = parse_directory_string(reader)?;

                Ok((oid, name))
            })

        } else {
            Err(Error::BadDER)
        }
    }

    // Build up the Name by reading RDNs until there is nothing left
    let mut full_name = Name {
        common_name: None,
        country_name: None,
        locality_name: None,
        state_or_province_name: None,
        organization_name: None,
        organizational_unit_name: None,
        extra: None,
    };

    while let Ok((id, name)) = parse_one_name(input) {
        match id.as_str() {
            "2.5.4.3" => { full_name.common_name = Some(name); },
            "2.5.4.6" => { full_name.country_name = Some(name); },
            "2.5.4.7" => { full_name.locality_name = Some(name); },
            "2.5.4.8" => { full_name.state_or_province_name = Some(name); },
            "2.5.4.10" => { full_name.organization_name = Some(name); },
            "2.5.4.11" => { full_name.organizational_unit_name = Some(name); },
            other => { full_name.extra = Some(other.to_string()); }
        }
    }

    Ok(full_name)
}

///
#[cfg(feature = "std")]
pub fn parse_alt_name<'a>(input: &mut untrusted::Reader<'a>) -> Result<std::vec::Vec<std::string::String>, Error> {
    use std::string::String;
    use std::vec::Vec;
    use core::iter::FromIterator;

    let mut alt_names = Vec::new();
    while let Ok((_, name)) = read_tag_and_get_value(input).map_err(|_| Error::BadDER) {
        let value = Vec::from_iter(name.iter().cloned());
        let string_name = String::from_utf8(value).map_err(|_| Error::BadDER);
        let string_name = match string_name {
            Ok(name) => name,
            Err(e) => return Err(e)
        };

        alt_names.push(string_name);
    }

    Ok(alt_names)
}


macro_rules! oid {
    ( $first:expr, $second:expr, $( $tail:expr ),* ) =>
    (
        [(40 * $first) + $second, $( $tail ),*]
    )
}
