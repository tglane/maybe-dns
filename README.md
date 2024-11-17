# Maybe-DNS
`maybe-dns` is a simple, but (maybe) fully fledged DNS library for parsing and building domain name system packages.
The structs defined in this library stay close to the DNS standard and tries to mimic its data types as close as possible while maintaining an
ease of use by providing helper functions where they become helpful.

Note: This crate does **not** contain any DNS resolver or responder types and is purely for (de-)serializing and modifying DNS data.

## Structure
The top-level struct is the `maybe_dns::Packet` that first contains a `maybe_dns::Header` for the configuration of the packet. After that
each packet contains a (possibly empty) list of `maybe_dns::Questions` representing the questions for resources and a (possibly empty) list
of `maybe_dns::ResourceRecord` for the answer part, the authorities part and the additional part.

For more detailed information on the types check the documentation.

## Optional features:
* `mdns` - Activates optional struct members and methods used for mDNS queries and reponses defined in RFC 6762.
* `dnssec` - Adds more record types that are used for DNSSEC defined in RFC 4034. This might not be completely compliant to the defining RFC and unstable.

## Example:
The example code down below shows the programatical creation of a DNS packet as well as the serialization and deserialization process.
As a brief explanation, a DNS packet is created, that is configured as a query and contains two questions. The packet than gets serialized
into bytes and parsed back into a `maybe_dns::Packet`.

```rust
use maybe_dns::*;

fn main() {
    let mut query = Packet::default();
    query.add_question(Question::new(
        FQDN::new("_srv._udp.local"),
        QType::TXT,
        QClass::IN,
    ));
    query.add_question(Question::new(
        FQDN::from(&["_srv2", "_udp", "local"][..]),
        QType::TXT,
        QClass::IN,
    ));

    let binary = query.to_bytes();

    let parsed = Packet::try_from(&binary[..]);
    assert!(parsed.is_ok());

    let parsed = parsed.unwrap();
    assert_eq!(2, parsed.questions().len());
    assert_eq!("_srv._udp.local", parsed.questions()[0].q_name.to_string());
```
