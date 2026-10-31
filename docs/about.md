# About stix

The schema renders STIX 2.1 as five modules under one umbrella, so that a
schema which needs part of STIX can import that part alone:

| Module | Holds |
| --- | --- |
| `stix_vocabularies` | The open vocabularies and closed enumerations. |
| `stix_core` | The types, the shared slots, the abstract object bases, identity and the meta objects. |
| `stix_sco` | The cyber-observable objects, their predefined extensions and the types they embed. |
| `stix_sdo` | The domain objects other than identity. |
| `stix_sro` | Relationship and sighting. |

The umbrella `stix` holds only the bundle. Identity sits in `stix_core`
because every object's `created_by_ref` points at one.

## Names

- Classes and enums carry the `Stix` prefix: `StixAttackPattern`,
  `StixFile`, `StixIndustrySector`. Each enum names its STIX vocabulary in
  the `stix_vocabulary` annotation, such as `industry-sector-ov`.
- Slots are STIX's property names, each a top-level slot with a `stix:`
  slot URI. `type` holds the STIX type name, and each class pins its value.
  `id` is the identifier, and each class narrows its type prefix.
- A `*_ref` or `*_refs` slot ranges over the class STIX says it points at
  and carries the identifier's pattern for that class.

## Vocabularies

An open vocabulary (`-ov`) never rejects another string: its slot takes the
enum or any string, so the enum documents the list. A closed enumeration
(`-enum`) rejects other values. The vocabularies follow the OASIS Standard's
tables where the JSON schemas differ: the account types `windows-local` and
`windows-domain`, the region `south-eastern-asia`, the report type
`intrusion-set` and the four infrastructure types the JSON schema leaves
out.

## Where it departs from OASIS's JSON schemas

The schema follows the OASIS Standard where OASIS's JSON schemas say
otherwise:

- The IPv6 address pattern restores the backslashes the JSON schema lost,
  so it accepts an IPv4-mapped address such as `::ffff:192.0.2.128`.
- The "at least one property" rules name every property the object has,
  and only those. The JSON schemas also name `name`, `created` and
  `arguments` for a process, `modified` for a Windows registry key and
  `image_compression_algorithm` for a raster image, none of which STIX 2.1
  defines there. They leave out a process's `created_time` and the Windows
  process extension's `integrity_level`.
- A granular marking names exactly one of `marking_ref` and `lang`. The
  JSON schema requires `marking_ref`, which rejects a language marking.
- A marking definition's `created` is precise to the millisecond, like
  every other object's. The JSON schema takes any precision there.
- A sighting's `sighting_of_ref` points at a domain object, and a malware
  analysis's `analysis_sco_refs` and a file's `contains_refs` at
  observables. The JSON schemas take a wider set of identifiers.
- The vocabularies follow the standard's tables (see above).

`tests/test_upstream.py` lists each difference in the properties, the
required lists and the "at least one property" rules, so a new one fails.

## What the schema leaves out

- The STIX patterning language: an indicator's `pattern` is a string, and
  nothing checks its grammar.
- Custom properties and objects, until a schema that imports this one
  declares them ([Custom properties and objects](index.md#custom-properties-and-objects)).
- Custom marking definition types with free-form definitions: a marking's
  definition is a statement or a TLP level.
- The 2.0 style of custom extension, a `-ext` key without an
  `extension_type`.
- STIX 2.1 Errata 01, which is a Committee Specification Draft, not an
  approved standard.

## Reference

- [STIX Version 2.1, OASIS Standard, 10 June 2021](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
- [OASIS's STIX 2.1 JSON schemas](https://github.com/oasis-open/cti-stix2-json-schemas)
