# Schema Directory

This folder holds the LinkML schema: the umbrella `stix.yaml`, which holds
only the bundle, and the modules it imports.

| Module | Holds |
| --- | --- |
| `stix_vocabularies.yaml` | The open vocabularies and closed enumerations. |
| `stix_core.yaml` | The types, the shared slots, the abstract object bases, identity and the meta objects. |
| `stix_sco.yaml` | The cyber-observable objects, their predefined extensions and the types they embed. |
| `stix_sdo.yaml` | The domain objects other than identity. |
| `stix_sro.yaml` | Relationship and sighting. |

Each module imports only the modules it uses, so a schema that needs part of
STIX can import that part alone.
