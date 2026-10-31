# stix

This project is a LinkML model of Structured Threat Information Expression
(STIX) Version 2.1, the OASIS Standard of 10 June 2021 for exchanging cyber
threat intelligence. It covers the domain objects, the relationship
objects, the cyber-observable objects with their predefined extensions, the
meta objects (marking definitions, language content and extension
definitions), the vocabularies and enumerations, and the bundle. STIX's own
property names are the schema's keys, so STIX JSON validates unchanged.

- [Schema documentation](elements/index.md), generated from the schema
- [About](about.md): how the schema is built and what it leaves out
- [`stix.yaml`](schema/stix.yaml): the schema, with its modules merged

## Validating data

`linkml-validate -s src/stix/schema/stix.yaml -C StixBundle bundle.json`
checks a bundle against the JSON Schema generated from the schema, and
`-C StixIndicator` and so on checks a single object. `just gen-project`
writes the same JSON Schema to `project/jsonschema/stix.schema.json`, for a
validator of your own. `tests/test_data.py`
holds every example to it, and `tests/test_upstream.py` holds OASIS's own
examples to it.

Validate a file before loading it into either model in
`src/stix/datamodel/`. LinkML 1.12.1 generates models that check less:

- The dataclasses check required fields and enum values, but no pattern.
- The Pydantic models also check the patterns a field carries itself, such
  as a reference's identifier, but not those of the types, such as a
  timestamp's form.
- Neither applies the class-level rules below, and neither accepts the
  dictionaries: hashes, extensions, language content and the open
  dictionaries of the observable objects.
- Neither holds a bundle's objects. Both type the list as the abstract
  `StixObject`, and LinkML 1.12.1 cannot pick a subclass from STIX's `type`
  value, so load each object into its own class instead.

## What no generated validator checks

The JSON schemas state these rules, and LinkML cannot state them in a form
its generators carry:

- a malware family has a name (`is_family: true` needs `name`);
- an email's body matches `is_multipart`: `body` only when it is false,
  `body_multipart` only when it is true (that the two never appear together
  is checked);
- active network traffic has no end (`is_active: true` excludes `end`);
- an extension definition lists `extension_properties` only when its types
  include `toplevel-property-extension`;
- an external reference whose source is not `cve` or `capec` does not use a
  CVE or CAPEC identifier;
- the keys of a dictionary: the hash algorithms, and each hash's form for
  the eight that STIX names (an MD5 hash is 32 hexadecimal digits, and so
  on); that an extension's key ends in `-ext` or is an extension
  definition's identifier, and that a predefined extension sits under its
  own key; and that a dictionary has at least one key;
- the four Traffic Light Protocol marking definitions' fixed identifiers,
  names and creation time, and that a marking's definition matches its
  definition type;
- the forms the JSON schemas give as formats: a domain name's `value` as an
  internationalised host name, and an email address's `value` as an email
  address;
- that a registry key names its hive in full, never as an abbreviation such
  as `HKLM`;
- a type name's length, from 3 to 250 characters.

`tests/test_data.py` checks the first three over the examples, and
`tests/test_upstream.py` over OASIS's examples.

## Custom properties and objects

The classes are closed, so an object with a property its class does not
declare fails. To validate custom properties or custom objects, write a
schema that imports this one and declare them there, as a slot of a
subclass or as a class of its own; lmodel/attack does this for MITRE's
`x_mitre_` properties and `x-mitre-` objects.
