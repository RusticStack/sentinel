//! The few S3 XML responses the adapter reads, flattened: each element's
//! text by its name, grouped into records under a repeated element. Bounded
//! by the caller's body limit; entities are resolved, nothing is fetched.

use quick_xml::{
    Reader,
    events::{BytesRef, Event},
};

use crate::{Error, Result};

const MAX_DEPTH: usize = 16;

fn resolve(reference: &BytesRef<'_>) -> Option<String> {
    let name: &str = &reference[..];
    Some(match name {
        "amp" => "&".into(),
        "lt" => "<".into(),
        "gt" => ">".into(),
        "quot" => "\"".into(),
        "apos" => "'".into(),
        _ => {
            let code = if let Some(hex) = name.strip_prefix("#x") {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                name.strip_prefix('#')?.parse().ok()?
            };
            char::from_u32(code)?.to_string()
        }
    })
}

/// One element's text, by the name of the element that holds it.
pub type Fields = Vec<(String, String)>;

/// Every leaf element's text in document order, with the path of element
/// names above it (`ListPartsResult/Part/ETag`).
fn leaves(xml: &[u8]) -> Result<Vec<(String, String)>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = true;
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut out = Vec::new();
    loop {
        match reader
            .read_event()
            .map_err(|_| Error::Protocol("malformed XML response".into()))?
        {
            Event::Start(tag) => {
                if path.len() >= MAX_DEPTH {
                    return Err(Error::Protocol("XML response nested too deep".into()));
                }
                path.push(tag.local_name().into_inner().to_owned());
                text.clear();
            }
            Event::Text(t) => {
                text.push_str(&t[..]);
            }
            Event::CData(t) => text.push_str(&t[..]),
            Event::GeneralRef(r) => {
                text.push_str(
                    &resolve(&r).ok_or_else(|| Error::Protocol("unknown XML entity".into()))?,
                );
            }
            Event::End(_) => {
                if !text.is_empty() || path.last().is_some() {
                    out.push((path.join("/"), std::mem::take(&mut text)));
                }
                path.pop();
            }
            Event::Eof => return Ok(out),
            _ => {}
        }
    }
}

/// The text of the first element named `name`.
pub fn field(xml: &[u8], name: &str) -> Result<Option<String>> {
    Ok(leaves(xml)?
        .into_iter()
        .find(|(path, _)| path.rsplit('/').next() == Some(name))
        .map(|(_, v)| v))
}

/// The fields of every `record` element, each a list of (child, text).
pub fn records(xml: &[u8], record: &str) -> Result<Vec<Fields>> {
    let mut out: Vec<Fields> = Vec::new();
    let mut open: Option<(String, Fields)> = None;
    for (path, value) in leaves(xml)? {
        let parts: Vec<&str> = path.split('/').collect();
        let at = parts.iter().position(|p| *p == record);
        match at {
            Some(i) if i + 1 < parts.len() => {
                let prefix = parts[..=i].join("/");
                let fields = match &mut open {
                    Some((p, fields)) if *p == prefix => fields,
                    _ => {
                        if let Some((_, done)) = open.take() {
                            out.push(done);
                        }
                        open = Some((prefix, Vec::new()));
                        &mut open.as_mut().expect("just set").1
                    }
                };
                fields.push((parts[parts.len() - 1].to_owned(), value));
            }
            // The record element itself closing: flush it.
            Some(i) if i + 1 == parts.len() => {
                if let Some((_, done)) = open.take() {
                    out.push(done);
                }
            }
            _ => {}
        }
    }
    if let Some((_, done)) = open {
        out.push(done);
    }
    Ok(out)
}

/// The value of `name` in one record.
pub fn get<'a>(fields: &'a Fields, name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_fields_and_entities_read_like_s3_writes_them() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>b</Bucket><Key>a&amp;b/&#x41;</Key><UploadId>u-1</UploadId>
  <IsTruncated>false</IsTruncated>
  <Part><PartNumber>1</PartNumber><ETag>&quot;e1&quot;</ETag><Size>5242880</Size></Part>
  <Part><PartNumber>2</PartNumber><ETag>"e2"</ETag><Size>7</Size></Part>
</ListPartsResult>"#;
        assert_eq!(field(xml, "Key").unwrap().as_deref(), Some("a&b/A"));
        assert_eq!(field(xml, "UploadId").unwrap().as_deref(), Some("u-1"));
        let parts = records(xml, "Part").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(get(&parts[0], "ETag"), Some("\"e1\""));
        assert_eq!(get(&parts[1], "Size"), Some("7"));
        assert!(field(b"<a><b>1</a>", "b").is_err(), "mismatched end");
        assert!(field(b"<a>&bogus;</a>", "a").is_err());
        let deep = "<a>".repeat(20) + &"</a>".repeat(20);
        assert!(field(deep.as_bytes(), "a").is_err());
    }
}
