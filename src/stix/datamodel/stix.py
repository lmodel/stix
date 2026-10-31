# Auto generated from stix.yaml by pythongen.py version: 0.0.1
# Schema: stix
#
# id: https://w3id.org/lmodel/stix
# description: A LinkML model of Structured Threat Information Expression (STIX) Version 2.1, the OASIS Standard for exchanging cyber threat intelligence: its domain, relationship, cyber-observable and meta objects, their properties, vocabularies and enumerations, and the bundle that carries them. STIX's own property names are the schema's keys, so STIX JSON validates unchanged.
# license: Apache-2.0

import dataclasses
import re
from dataclasses import dataclass
from datetime import (
    date,
    datetime,
    time
)
from typing import (
    Any,
    ClassVar,
    Dict,
    List,
    Optional,
    Union
)

from jsonasobj2 import (
    JsonObj,
    as_dict
)
from linkml_runtime.linkml_model.meta import (
    EnumDefinition,
    PermissibleValue,
    PvFormulaOptions
)
from linkml_runtime.utils.curienamespace import CurieNamespace
from linkml_runtime.utils.enumerations import EnumDefinitionImpl
from linkml_runtime.utils.formatutils import (
    camelcase,
    sfx,
    underscore
)
from linkml_runtime.utils.metamodelcore import (
    bnode,
    empty_dict,
    empty_list
)
from linkml_runtime.utils.slot import Slot
from linkml_runtime.utils.yamlutils import (
    YAMLRoot,
    extended_float,
    extended_int,
    extended_str
)
from rdflib import (
    Namespace,
    URIRef
)

from linkml_runtime.linkml_model.types import Boolean, Float, Integer, String, Uri
from linkml_runtime.utils.metamodelcore import Bool, URI

metamodel_version = "1.12.0"
version = "2.1"

# Namespaces
LINKML = CurieNamespace('linkml', 'https://w3id.org/linkml/')
STIX = CurieNamespace('stix', 'https://w3id.org/lmodel/stix/')
UCO_CORE = CurieNamespace('uco-core', 'https://ontology.unifiedcyberontology.org/uco/core/')
UCO_IDENTITY = CurieNamespace('uco-identity', 'https://ontology.unifiedcyberontology.org/uco/identity/')
UCO_LOCATION = CurieNamespace('uco-location', 'https://ontology.unifiedcyberontology.org/uco/location/')
UCO_MARKING = CurieNamespace('uco-marking', 'https://ontology.unifiedcyberontology.org/uco/marking/')
UCO_OBSERVABLE = CurieNamespace('uco-observable', 'https://ontology.unifiedcyberontology.org/uco/observable/')
UCO_TOOL = CurieNamespace('uco-tool', 'https://ontology.unifiedcyberontology.org/uco/tool/')
XSD = CurieNamespace('xsd', 'http://www.w3.org/2001/XMLSchema#')
DEFAULT_ = STIX


# Types
class StixIdentifier(String):
    """ A STIX identifier: an object's type name, two hyphens and a UUID, such as indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f. """
    type_class_uri = XSD["string"]
    type_class_curie = "xsd:string"
    type_name = "stix_identifier"
    type_model_uri = STIX.StixIdentifier


class StixTimestamp(String):
    """ An RFC 3339 timestamp in UTC, ending in Z, with any precision of fractional seconds. """
    type_class_uri = XSD["dateTime"]
    type_class_curie = "xsd:dateTime"
    type_name = "stix_timestamp"
    type_model_uri = STIX.StixTimestamp


class StixTimestampMillis(String):
    """ A timestamp precise to the millisecond or finer: at least three digits of fractional seconds, as STIX requires of created and modified. """
    type_class_uri = XSD["dateTime"]
    type_class_curie = "xsd:dateTime"
    type_name = "stix_timestamp_millis"
    type_model_uri = STIX.StixTimestampMillis


class StixTimestampSeconds(String):
    """ A timestamp precise to the second, with no fractional seconds. """
    type_class_uri = XSD["dateTime"]
    type_class_curie = "xsd:dateTime"
    type_name = "stix_timestamp_seconds"
    type_model_uri = STIX.StixTimestampSeconds


class StixHex(String):
    """ Octets encoded as an even number of hexadecimal digits. """
    type_class_uri = XSD["hexBinary"]
    type_class_curie = "xsd:hexBinary"
    type_name = "stix_hex"
    type_model_uri = STIX.StixHex


class StixBinary(String):
    """ Bytes encoded in base64, as RFC 4648 specifies. """
    type_class_uri = XSD["base64Binary"]
    type_class_curie = "xsd:base64Binary"
    type_name = "stix_binary"
    type_model_uri = STIX.StixBinary


# Class references
class StixBundleId(StixIdentifier):
    pass


class StixObjectId(StixIdentifier):
    pass


class StixCommonObjectId(StixObjectId):
    pass


class StixDomainObjectId(StixCommonObjectId):
    pass


class StixRelationshipObjectId(StixCommonObjectId):
    pass


class StixCyberObservableObjectId(StixObjectId):
    pass


class StixIdentityId(StixDomainObjectId):
    pass


class StixMarkingDefinitionId(StixObjectId):
    pass


class StixLanguageContentId(StixCommonObjectId):
    pass


class StixExtensionDefinitionId(StixCommonObjectId):
    pass


class StixArtifactId(StixCyberObservableObjectId):
    pass


class StixAutonomousSystemId(StixCyberObservableObjectId):
    pass


class StixDirectoryId(StixCyberObservableObjectId):
    pass


class StixDomainNameId(StixCyberObservableObjectId):
    pass


class StixEmailAddressId(StixCyberObservableObjectId):
    pass


class StixEmailMessageId(StixCyberObservableObjectId):
    pass


class StixFileId(StixCyberObservableObjectId):
    pass


class StixIpv4AddressId(StixCyberObservableObjectId):
    pass


class StixIpv6AddressId(StixCyberObservableObjectId):
    pass


class StixMacAddressId(StixCyberObservableObjectId):
    pass


class StixMutexId(StixCyberObservableObjectId):
    pass


class StixNetworkTrafficId(StixCyberObservableObjectId):
    pass


class StixProcessId(StixCyberObservableObjectId):
    pass


class StixSoftwareId(StixCyberObservableObjectId):
    pass


class StixUrlId(StixCyberObservableObjectId):
    pass


class StixUserAccountId(StixCyberObservableObjectId):
    pass


class StixWindowsRegistryKeyId(StixCyberObservableObjectId):
    pass


class StixX509CertificateId(StixCyberObservableObjectId):
    pass


class StixAttackPatternId(StixDomainObjectId):
    pass


class StixCampaignId(StixDomainObjectId):
    pass


class StixCourseOfActionId(StixDomainObjectId):
    pass


class StixGroupingId(StixDomainObjectId):
    pass


class StixIncidentId(StixDomainObjectId):
    pass


class StixIndicatorId(StixDomainObjectId):
    pass


class StixInfrastructureId(StixDomainObjectId):
    pass


class StixIntrusionSetId(StixDomainObjectId):
    pass


class StixLocationId(StixDomainObjectId):
    pass


class StixMalwareId(StixDomainObjectId):
    pass


class StixMalwareAnalysisId(StixDomainObjectId):
    pass


class StixNoteId(StixDomainObjectId):
    pass


class StixObservedDataId(StixDomainObjectId):
    pass


class StixOpinionId(StixDomainObjectId):
    pass


class StixReportId(StixDomainObjectId):
    pass


class StixThreatActorId(StixDomainObjectId):
    pass


class StixToolId(StixDomainObjectId):
    pass


class StixVulnerabilityId(StixDomainObjectId):
    pass


class StixRelationshipId(StixRelationshipObjectId):
    pass


class StixSightingId(StixRelationshipObjectId):
    pass


@dataclass(repr=False)
class StixBundle(YAMLRoot):
    """
    A bundle: a collection of STIX objects grouped together in one container. A bundle is a container for transport,
    not a STIX object, so it carries no spec_version.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixBundle"]
    class_class_curie: ClassVar[str] = "stix:StixBundle"
    class_name: ClassVar[str] = "StixBundle"
    class_model_uri: ClassVar[URIRef] = STIX.StixBundle

    id: Union[str, StixBundleId] = None
    type: str = None
    objects: Optional[Union[dict[Union[str, StixObjectId], Union[dict, "StixObject"]], list[Union[dict, "StixObject"]]]] = empty_dict()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixBundleId):
            self.id = StixBundleId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        self._normalize_inlined_as_list(slot_name="objects", slot_type=StixObject, key_name="id", keyed=True)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixObject(YAMLRoot):
    """
    Any STIX object: the base of the domain, relationship and cyber-observable objects and of the meta objects.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixObject"]
    class_class_curie: ClassVar[str] = "stix:StixObject"
    class_name: ClassVar[str] = "StixObject"
    class_model_uri: ClassVar[URIRef] = STIX.StixObject

    id: Union[str, StixObjectId] = None
    type: str = None
    spec_version: Optional[Union[str, "StixSpecVersion"]] = None
    object_marking_refs: Optional[Union[Union[str, StixMarkingDefinitionId], list[Union[str, StixMarkingDefinitionId]]]] = empty_list()
    granular_markings: Optional[Union[Union[dict, "StixGranularMarking"], list[Union[dict, "StixGranularMarking"]]]] = empty_list()
    extensions: Optional[Union[dict, "StixExtensions"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixObjectId):
            self.id = StixObjectId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.spec_version is not None and not isinstance(self.spec_version, StixSpecVersion):
            self.spec_version = StixSpecVersion(self.spec_version)

        if not isinstance(self.object_marking_refs, list):
            self.object_marking_refs = [self.object_marking_refs] if self.object_marking_refs is not None else []
        self.object_marking_refs = [v if isinstance(v, StixMarkingDefinitionId) else StixMarkingDefinitionId(v) for v in self.object_marking_refs]

        self._normalize_inlined_as_list(slot_name="granular_markings", slot_type=StixGranularMarking, key_name="selectors", keyed=False)

        if self.extensions is not None and not isinstance(self.extensions, StixExtensions):
            self.extensions = StixExtensions()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixCommonObject(StixObject):
    """
    The base of the objects that carry STIX's common properties: the domain and relationship objects, language content
    and extension definitions.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixCommonObject"]
    class_class_curie: ClassVar[str] = "stix:StixCommonObject"
    class_name: ClassVar[str] = "StixCommonObject"
    class_model_uri: ClassVar[URIRef] = STIX.StixCommonObject

    id: Union[str, StixCommonObjectId] = None
    type: str = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    created_by_ref: Optional[Union[str, StixIdentityId]] = None
    revoked: Optional[Union[bool, Bool]] = None
    labels: Optional[Union[str, list[str]]] = empty_list()
    confidence: Optional[int] = None
    lang: Optional[str] = None
    external_references: Optional[Union[Union[dict, "StixExternalReference"], list[Union[dict, "StixExternalReference"]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.created):
            self.MissingRequiredField("created")
        if not isinstance(self.created, StixTimestampMillis):
            self.created = StixTimestampMillis(self.created)

        if self._is_empty(self.modified):
            self.MissingRequiredField("modified")
        if not isinstance(self.modified, StixTimestampMillis):
            self.modified = StixTimestampMillis(self.modified)

        if self._is_empty(self.spec_version):
            self.MissingRequiredField("spec_version")
        if not isinstance(self.spec_version, StixSpecVersion):
            self.spec_version = StixSpecVersion(self.spec_version)

        if self.created_by_ref is not None and not isinstance(self.created_by_ref, StixIdentityId):
            self.created_by_ref = StixIdentityId(self.created_by_ref)

        if self.revoked is not None and not isinstance(self.revoked, Bool):
            self.revoked = Bool(self.revoked)

        if not isinstance(self.labels, list):
            self.labels = [self.labels] if self.labels is not None else []
        self.labels = [v if isinstance(v, str) else str(v) for v in self.labels]

        if self.confidence is not None and not isinstance(self.confidence, int):
            self.confidence = int(self.confidence)

        if self.lang is not None and not isinstance(self.lang, str):
            self.lang = str(self.lang)

        self._normalize_inlined_as_list(slot_name="external_references", slot_type=StixExternalReference, key_name="source_name", keyed=False)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixDomainObject(StixCommonObject):
    """
    A STIX Domain Object (SDO): a higher-level concept of cyber threat intelligence, such as an attack pattern, a
    malware family or a threat actor.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixDomainObject"]
    class_class_curie: ClassVar[str] = "stix:StixDomainObject"
    class_name: ClassVar[str] = "StixDomainObject"
    class_model_uri: ClassVar[URIRef] = STIX.StixDomainObject

    id: Union[str, StixDomainObjectId] = None
    type: str = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None

@dataclass(repr=False)
class StixRelationshipObject(StixCommonObject):
    """
    A STIX Relationship Object (SRO): a relationship or a sighting that links other objects.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixRelationshipObject"]
    class_class_curie: ClassVar[str] = "stix:StixRelationshipObject"
    class_name: ClassVar[str] = "StixRelationshipObject"
    class_model_uri: ClassVar[URIRef] = STIX.StixRelationshipObject

    id: Union[str, StixRelationshipObjectId] = None
    type: str = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None

@dataclass(repr=False)
class StixCyberObservableObject(StixObject):
    """
    A STIX Cyber-observable Object (SCO): a fact observed on a network or host, such as a file, an address or a
    process.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixCyberObservableObject"]
    class_class_curie: ClassVar[str] = "stix:StixCyberObservableObject"
    class_name: ClassVar[str] = "StixCyberObservableObject"
    class_model_uri: ClassVar[URIRef] = STIX.StixCyberObservableObject

    id: Union[str, StixCyberObservableObjectId] = None
    type: str = None
    defanged: Optional[Union[bool, Bool]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.defanged is not None and not isinstance(self.defanged, Bool):
            self.defanged = Bool(self.defanged)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixIdentity(StixDomainObject):
    """
    Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of
    individuals, organizations, or groups.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixIdentity"]
    class_class_curie: ClassVar[str] = "stix:StixIdentity"
    class_name: ClassVar[str] = "StixIdentity"
    class_model_uri: ClassVar[URIRef] = STIX.StixIdentity

    id: Union[str, StixIdentityId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    roles: Optional[Union[str, list[str]]] = empty_list()
    description: Optional[str] = None
    identity_class: Optional[Union[str, "StixIdentityClass"]] = None
    sectors: Optional[Union[str, list[str]]] = empty_list()
    contact_information: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixIdentityId):
            self.id = StixIdentityId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.roles, list):
            self.roles = [self.roles] if self.roles is not None else []
        self.roles = [v if isinstance(v, str) else str(v) for v in self.roles]

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if self.identity_class is not None and not isinstance(self.identity_class, (StixIdentityClass, str)):
            value = self.identity_class
            for _coerce in (lambda: StixIdentityClass(value), lambda: str(value)):
                try:
                    self.identity_class = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixIdentityClass, str] could be constructed from {value!r} for slot identity_class")

        if not isinstance(self.sectors, list):
            self.sectors = [self.sectors] if self.sectors is not None else []
        self.sectors = [v if isinstance(v, str) else str(v) for v in self.sectors]

        if self.contact_information is not None and not isinstance(self.contact_information, str):
            self.contact_information = str(self.contact_information)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixMarkingDefinition(StixObject):
    """
    A marking definition: a statement, a Traffic Light Protocol (TLP) level or another marking that applies to the
    objects that reference it.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixMarkingDefinition"]
    class_class_curie: ClassVar[str] = "stix:StixMarkingDefinition"
    class_name: ClassVar[str] = "StixMarkingDefinition"
    class_model_uri: ClassVar[URIRef] = STIX.StixMarkingDefinition

    id: Union[str, StixMarkingDefinitionId] = None
    created: Union[str, StixTimestampMillis] = None
    type: str = None
    spec_version: Union[str, "StixSpecVersion"] = None
    created_by_ref: Optional[Union[str, StixIdentityId]] = None
    external_references: Optional[Union[Union[dict, "StixExternalReference"], list[Union[dict, "StixExternalReference"]]]] = empty_list()
    name: Optional[str] = None
    definition_type: Optional[Union[str, "StixMarkingDefinitionType"]] = None
    definition: Optional[Union[dict, "StixStatementMarking", "StixTlpMarking"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixMarkingDefinitionId):
            self.id = StixMarkingDefinitionId(self.id)

        if self._is_empty(self.created):
            self.MissingRequiredField("created")
        if not isinstance(self.created, StixTimestampMillis):
            self.created = StixTimestampMillis(self.created)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self._is_empty(self.spec_version):
            self.MissingRequiredField("spec_version")
        if not isinstance(self.spec_version, StixSpecVersion):
            self.spec_version = StixSpecVersion(self.spec_version)

        if self.created_by_ref is not None and not isinstance(self.created_by_ref, StixIdentityId):
            self.created_by_ref = StixIdentityId(self.created_by_ref)

        self._normalize_inlined_as_list(slot_name="external_references", slot_type=StixExternalReference, key_name="source_name", keyed=False)

        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.definition_type is not None and not isinstance(self.definition_type, (StixMarkingDefinitionType, str)):
            value = self.definition_type
            for _coerce in (lambda: StixMarkingDefinitionType(value), lambda: str(value)):
                try:
                    self.definition_type = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixMarkingDefinitionType, str] could be constructed from {value!r} for slot definition_type")

        if self.definition is not None and not isinstance(self.definition, (StixStatementMarking, StixTlpMarking)):
            value = self.definition
            for _coerce in (lambda: StixStatementMarking(**as_dict(value)), lambda: StixTlpMarking(**as_dict(value))):
                try:
                    self.definition = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixStatementMarking, StixTlpMarking] could be constructed from {value!r} for slot definition")

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixLanguageContent(StixCommonObject):
    """
    The language-content object represents text content for STIX Objects represented in languages other than that of
    the original object.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixLanguageContent"]
    class_class_curie: ClassVar[str] = "stix:StixLanguageContent"
    class_name: ClassVar[str] = "StixLanguageContent"
    class_model_uri: ClassVar[URIRef] = STIX.StixLanguageContent

    id: Union[str, StixLanguageContentId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    object_ref: Union[str, StixObjectId] = None
    contents: Union[dict, "StixLanguageContents"] = None
    type: str = None
    object_modified: Optional[Union[str, StixTimestamp]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixLanguageContentId):
            self.id = StixLanguageContentId(self.id)

        if self._is_empty(self.object_ref):
            self.MissingRequiredField("object_ref")
        if not isinstance(self.object_ref, StixObjectId):
            self.object_ref = StixObjectId(self.object_ref)

        if self._is_empty(self.contents):
            self.MissingRequiredField("contents")
        if not isinstance(self.contents, StixLanguageContents):
            self.contents = StixLanguageContents()

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.object_modified is not None and not isinstance(self.object_modified, StixTimestamp):
            self.object_modified = StixTimestamp(self.object_modified)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixExtensionDefinition(StixCommonObject):
    """
    The STIX Extension Definition object allows producers of threat intelligence to extend existing STIX objects or to
    create entirely new STIX objects in a standardized way.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixExtensionDefinition"]
    class_class_curie: ClassVar[str] = "stix:StixExtensionDefinition"
    class_name: ClassVar[str] = "StixExtensionDefinition"
    class_model_uri: ClassVar[URIRef] = STIX.StixExtensionDefinition

    id: Union[str, StixExtensionDefinitionId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    schema: str = None
    version: str = None
    extension_types: Union[Union[str, "StixExtensionType"], list[Union[str, "StixExtensionType"]]] = None
    type: str = None
    description: Optional[str] = None
    extension_properties: Optional[Union[str, list[str]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixExtensionDefinitionId):
            self.id = StixExtensionDefinitionId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.schema):
            self.MissingRequiredField("schema")
        if not isinstance(self.schema, str):
            self.schema = str(self.schema)

        if self._is_empty(self.version):
            self.MissingRequiredField("version")
        if not isinstance(self.version, str):
            self.version = str(self.version)

        if self._is_empty(self.extension_types):
            self.MissingRequiredField("extension_types")
        if not isinstance(self.extension_types, list):
            self.extension_types = [self.extension_types] if self.extension_types is not None else []
        self.extension_types = [v if isinstance(v, StixExtensionType) else StixExtensionType(v) for v in self.extension_types]

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if not isinstance(self.extension_properties, list):
            self.extension_properties = [self.extension_properties] if self.extension_properties is not None else []
        self.extension_properties = [v if isinstance(v, str) else str(v) for v in self.extension_properties]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixExternalReference(YAMLRoot):
    """
    External references are used to describe pointers to information represented outside of STIX.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixExternalReference"]
    class_class_curie: ClassVar[str] = "stix:StixExternalReference"
    class_name: ClassVar[str] = "StixExternalReference"
    class_model_uri: ClassVar[URIRef] = STIX.StixExternalReference

    source_name: str = None
    description: Optional[str] = None
    url: Optional[Union[str, URI]] = None
    hashes: Optional[Union[dict, "StixHashes"]] = None
    external_id: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.source_name):
            self.MissingRequiredField("source_name")
        if not isinstance(self.source_name, str):
            self.source_name = str(self.source_name)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if self.url is not None and not isinstance(self.url, URI):
            self.url = URI(self.url)

        if self.hashes is not None and not isinstance(self.hashes, StixHashes):
            self.hashes = StixHashes()

        if self.external_id is not None and not isinstance(self.external_id, str):
            self.external_id = str(self.external_id)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixKillChainPhase(YAMLRoot):
    """
    A phase in a kill chain, named by the chain and the phase.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixKillChainPhase"]
    class_class_curie: ClassVar[str] = "stix:StixKillChainPhase"
    class_name: ClassVar[str] = "StixKillChainPhase"
    class_model_uri: ClassVar[URIRef] = STIX.StixKillChainPhase

    kill_chain_name: str = None
    phase_name: str = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.kill_chain_name):
            self.MissingRequiredField("kill_chain_name")
        if not isinstance(self.kill_chain_name, str):
            self.kill_chain_name = str(self.kill_chain_name)

        if self._is_empty(self.phase_name):
            self.MissingRequiredField("phase_name")
        if not isinstance(self.phase_name, str):
            self.phase_name = str(self.phase_name)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixGranularMarking(YAMLRoot):
    """
    A marking of parts of an object: the properties its selectors name, marked either by a marking definition or with
    a language.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixGranularMarking"]
    class_class_curie: ClassVar[str] = "stix:StixGranularMarking"
    class_name: ClassVar[str] = "StixGranularMarking"
    class_model_uri: ClassVar[URIRef] = STIX.StixGranularMarking

    selectors: Union[str, list[str]] = None
    marking_ref: Optional[Union[str, StixMarkingDefinitionId]] = None
    lang: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.selectors):
            self.MissingRequiredField("selectors")
        if not isinstance(self.selectors, list):
            self.selectors = [self.selectors] if self.selectors is not None else []
        self.selectors = [v if isinstance(v, str) else str(v) for v in self.selectors]

        if self.marking_ref is not None and not isinstance(self.marking_ref, StixMarkingDefinitionId):
            self.marking_ref = StixMarkingDefinitionId(self.marking_ref)

        if self.lang is not None and not isinstance(self.lang, str):
            self.lang = str(self.lang)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixStatementMarking(YAMLRoot):
    """
    The definition of a statement marking: a statement, such as a copyright or terms of use.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixStatementMarking"]
    class_class_curie: ClassVar[str] = "stix:StixStatementMarking"
    class_name: ClassVar[str] = "StixStatementMarking"
    class_model_uri: ClassVar[URIRef] = STIX.StixStatementMarking

    statement: str = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.statement):
            self.MissingRequiredField("statement")
        if not isinstance(self.statement, str):
            self.statement = str(self.statement)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixTlpMarking(YAMLRoot):
    """
    The definition of a Traffic Light Protocol (TLP) marking: its level.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixTlpMarking"]
    class_class_curie: ClassVar[str] = "stix:StixTlpMarking"
    class_name: ClassVar[str] = "StixTlpMarking"
    class_model_uri: ClassVar[URIRef] = STIX.StixTlpMarking

    tlp: Union[str, "StixTlpLevel"] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.tlp):
            self.MissingRequiredField("tlp")
        if not isinstance(self.tlp, StixTlpLevel):
            self.tlp = StixTlpLevel(self.tlp)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixExtension(YAMLRoot):
    """
    An extension of an object that an extension definition defines. Besides its extension type it carries the
    properties that its definition's schema states.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixExtension"]
    class_class_curie: ClassVar[str] = "stix:StixExtension"
    class_name: ClassVar[str] = "StixExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixExtension

    extension_type: Union[str, "StixExtensionType"] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.extension_type):
            self.MissingRequiredField("extension_type")
        if not isinstance(self.extension_type, StixExtensionType):
            self.extension_type = StixExtensionType(self.extension_type)

        super().__post_init__(**kwargs)


class StixHashes(YAMLRoot):
    """
    A dictionary of hashes. Each key names a hash algorithm, from the hash-algorithm-ov vocabulary (StixHashAlgorithm)
    or a custom one, and each value is the hash as a string.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixHashes"]
    class_class_curie: ClassVar[str] = "stix:StixHashes"
    class_name: ClassVar[str] = "StixHashes"
    class_model_uri: ClassVar[URIRef] = STIX.StixHashes


class StixExtensions(YAMLRoot):
    """
    A dictionary of extensions, keyed by an extension definition's identifier.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixExtensions"]
    class_class_curie: ClassVar[str] = "stix:StixExtensions"
    class_name: ClassVar[str] = "StixExtensions"
    class_model_uri: ClassVar[URIRef] = STIX.StixExtensions


class StixDictionary(YAMLRoot):
    """
    A dictionary of key and value pairs that STIX leaves open.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixDictionary"]
    class_class_curie: ClassVar[str] = "stix:StixDictionary"
    class_name: ClassVar[str] = "StixDictionary"
    class_model_uri: ClassVar[URIRef] = STIX.StixDictionary


class StixLanguageContents(YAMLRoot):
    """
    The translations of a language content object, keyed by language code. Each value maps the translated properties
    to their translations.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixLanguageContents"]
    class_class_curie: ClassVar[str] = "stix:StixLanguageContents"
    class_name: ClassVar[str] = "StixLanguageContents"
    class_model_uri: ClassVar[URIRef] = STIX.StixLanguageContents


@dataclass(repr=False)
class StixArtifact(StixCyberObservableObject):
    """
    The Artifact Object permits capturing an array of bytes (8-bits), as a base64-encoded string string, or linking to
    a file-like payload.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixArtifact"]
    class_class_curie: ClassVar[str] = "stix:StixArtifact"
    class_name: ClassVar[str] = "StixArtifact"
    class_model_uri: ClassVar[URIRef] = STIX.StixArtifact

    id: Union[str, StixArtifactId] = None
    type: str = None
    mime_type: Optional[str] = None
    payload_bin: Optional[Union[str, StixBinary]] = None
    url: Optional[Union[str, URI]] = None
    hashes: Optional[Union[dict, StixHashes]] = None
    encryption_algorithm: Optional[Union[str, "StixEncryptionAlgorithm"]] = None
    decryption_key: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixArtifactId):
            self.id = StixArtifactId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.mime_type is not None and not isinstance(self.mime_type, str):
            self.mime_type = str(self.mime_type)

        if self.payload_bin is not None and not isinstance(self.payload_bin, StixBinary):
            self.payload_bin = StixBinary(self.payload_bin)

        if self.url is not None and not isinstance(self.url, URI):
            self.url = URI(self.url)

        if self.hashes is not None and not isinstance(self.hashes, StixHashes):
            self.hashes = StixHashes()

        if self.encryption_algorithm is not None and not isinstance(self.encryption_algorithm, StixEncryptionAlgorithm):
            self.encryption_algorithm = StixEncryptionAlgorithm(self.encryption_algorithm)

        if self.decryption_key is not None and not isinstance(self.decryption_key, str):
            self.decryption_key = str(self.decryption_key)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixAutonomousSystem(StixCyberObservableObject):
    """
    The AS object represents the properties of an Autonomous Systems (AS).
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixAutonomousSystem"]
    class_class_curie: ClassVar[str] = "stix:StixAutonomousSystem"
    class_name: ClassVar[str] = "StixAutonomousSystem"
    class_model_uri: ClassVar[URIRef] = STIX.StixAutonomousSystem

    id: Union[str, StixAutonomousSystemId] = None
    number: int = None
    type: str = None
    name: Optional[str] = None
    rir: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixAutonomousSystemId):
            self.id = StixAutonomousSystemId(self.id)

        if self._is_empty(self.number):
            self.MissingRequiredField("number")
        if not isinstance(self.number, int):
            self.number = int(self.number)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.rir is not None and not isinstance(self.rir, str):
            self.rir = str(self.rir)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixDirectory(StixCyberObservableObject):
    """
    The Directory Object represents the properties common to a file system directory.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixDirectory"]
    class_class_curie: ClassVar[str] = "stix:StixDirectory"
    class_name: ClassVar[str] = "StixDirectory"
    class_model_uri: ClassVar[URIRef] = STIX.StixDirectory

    id: Union[str, StixDirectoryId] = None
    path: str = None
    type: str = None
    path_enc: Optional[str] = None
    ctime: Optional[Union[str, StixTimestamp]] = None
    mtime: Optional[Union[str, StixTimestamp]] = None
    atime: Optional[Union[str, StixTimestamp]] = None
    contains_refs: Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixDirectoryId):
            self.id = StixDirectoryId(self.id)

        if self._is_empty(self.path):
            self.MissingRequiredField("path")
        if not isinstance(self.path, str):
            self.path = str(self.path)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.path_enc is not None and not isinstance(self.path_enc, str):
            self.path_enc = str(self.path_enc)

        if self.ctime is not None and not isinstance(self.ctime, StixTimestamp):
            self.ctime = StixTimestamp(self.ctime)

        if self.mtime is not None and not isinstance(self.mtime, StixTimestamp):
            self.mtime = StixTimestamp(self.mtime)

        if self.atime is not None and not isinstance(self.atime, StixTimestamp):
            self.atime = StixTimestamp(self.atime)

        if not isinstance(self.contains_refs, list):
            self.contains_refs = [self.contains_refs] if self.contains_refs is not None else []
        self.contains_refs = [v if isinstance(v, StixCyberObservableObjectId) else StixCyberObservableObjectId(v) for v in self.contains_refs]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixDomainName(StixCyberObservableObject):
    """
    The Domain Name represents the properties of a network domain name.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixDomainName"]
    class_class_curie: ClassVar[str] = "stix:StixDomainName"
    class_name: ClassVar[str] = "StixDomainName"
    class_model_uri: ClassVar[URIRef] = STIX.StixDomainName

    id: Union[str, StixDomainNameId] = None
    value: str = None
    type: str = None
    resolves_to_refs: Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixDomainNameId):
            self.id = StixDomainNameId(self.id)

        if self._is_empty(self.value):
            self.MissingRequiredField("value")
        if not isinstance(self.value, str):
            self.value = str(self.value)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.resolves_to_refs, list):
            self.resolves_to_refs = [self.resolves_to_refs] if self.resolves_to_refs is not None else []
        self.resolves_to_refs = [v if isinstance(v, StixCyberObservableObjectId) else StixCyberObservableObjectId(v) for v in self.resolves_to_refs]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixEmailAddress(StixCyberObservableObject):
    """
    The Email Address Object represents a single email address.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixEmailAddress"]
    class_class_curie: ClassVar[str] = "stix:StixEmailAddress"
    class_name: ClassVar[str] = "StixEmailAddress"
    class_model_uri: ClassVar[URIRef] = STIX.StixEmailAddress

    id: Union[str, StixEmailAddressId] = None
    value: str = None
    type: str = None
    display_name: Optional[str] = None
    belongs_to_ref: Optional[Union[str, StixUserAccountId]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixEmailAddressId):
            self.id = StixEmailAddressId(self.id)

        if self._is_empty(self.value):
            self.MissingRequiredField("value")
        if not isinstance(self.value, str):
            self.value = str(self.value)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.display_name is not None and not isinstance(self.display_name, str):
            self.display_name = str(self.display_name)

        if self.belongs_to_ref is not None and not isinstance(self.belongs_to_ref, StixUserAccountId):
            self.belongs_to_ref = StixUserAccountId(self.belongs_to_ref)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixEmailMessage(StixCyberObservableObject):
    """
    The Email Message Object represents an instance of an email message.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixEmailMessage"]
    class_class_curie: ClassVar[str] = "stix:StixEmailMessage"
    class_name: ClassVar[str] = "StixEmailMessage"
    class_model_uri: ClassVar[URIRef] = STIX.StixEmailMessage

    id: Union[str, StixEmailMessageId] = None
    is_multipart: Union[bool, Bool] = None
    type: str = None
    date: Optional[Union[str, StixTimestamp]] = None
    content_type: Optional[str] = None
    from_ref: Optional[Union[str, StixEmailAddressId]] = None
    sender_ref: Optional[Union[str, StixEmailAddressId]] = None
    to_refs: Optional[Union[Union[str, StixEmailAddressId], list[Union[str, StixEmailAddressId]]]] = empty_list()
    cc_refs: Optional[Union[Union[str, StixEmailAddressId], list[Union[str, StixEmailAddressId]]]] = empty_list()
    bcc_refs: Optional[Union[Union[str, StixEmailAddressId], list[Union[str, StixEmailAddressId]]]] = empty_list()
    message_id: Optional[str] = None
    subject: Optional[str] = None
    received_lines: Optional[Union[str, list[str]]] = empty_list()
    additional_header_fields: Optional[Union[dict, StixDictionary]] = None
    raw_email_ref: Optional[Union[str, StixArtifactId]] = None
    body: Optional[str] = None
    body_multipart: Optional[Union[Union[dict, "StixMimePart"], list[Union[dict, "StixMimePart"]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixEmailMessageId):
            self.id = StixEmailMessageId(self.id)

        if self._is_empty(self.is_multipart):
            self.MissingRequiredField("is_multipart")
        if not isinstance(self.is_multipart, Bool):
            self.is_multipart = Bool(self.is_multipart)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.date is not None and not isinstance(self.date, StixTimestamp):
            self.date = StixTimestamp(self.date)

        if self.content_type is not None and not isinstance(self.content_type, str):
            self.content_type = str(self.content_type)

        if self.from_ref is not None and not isinstance(self.from_ref, StixEmailAddressId):
            self.from_ref = StixEmailAddressId(self.from_ref)

        if self.sender_ref is not None and not isinstance(self.sender_ref, StixEmailAddressId):
            self.sender_ref = StixEmailAddressId(self.sender_ref)

        if not isinstance(self.to_refs, list):
            self.to_refs = [self.to_refs] if self.to_refs is not None else []
        self.to_refs = [v if isinstance(v, StixEmailAddressId) else StixEmailAddressId(v) for v in self.to_refs]

        if not isinstance(self.cc_refs, list):
            self.cc_refs = [self.cc_refs] if self.cc_refs is not None else []
        self.cc_refs = [v if isinstance(v, StixEmailAddressId) else StixEmailAddressId(v) for v in self.cc_refs]

        if not isinstance(self.bcc_refs, list):
            self.bcc_refs = [self.bcc_refs] if self.bcc_refs is not None else []
        self.bcc_refs = [v if isinstance(v, StixEmailAddressId) else StixEmailAddressId(v) for v in self.bcc_refs]

        if self.message_id is not None and not isinstance(self.message_id, str):
            self.message_id = str(self.message_id)

        if self.subject is not None and not isinstance(self.subject, str):
            self.subject = str(self.subject)

        if not isinstance(self.received_lines, list):
            self.received_lines = [self.received_lines] if self.received_lines is not None else []
        self.received_lines = [v if isinstance(v, str) else str(v) for v in self.received_lines]

        if self.additional_header_fields is not None and not isinstance(self.additional_header_fields, StixDictionary):
            self.additional_header_fields = StixDictionary()

        if self.raw_email_ref is not None and not isinstance(self.raw_email_ref, StixArtifactId):
            self.raw_email_ref = StixArtifactId(self.raw_email_ref)

        if self.body is not None and not isinstance(self.body, str):
            self.body = str(self.body)

        if not isinstance(self.body_multipart, list):
            self.body_multipart = [self.body_multipart] if self.body_multipart is not None else []
        self.body_multipart = [v if isinstance(v, StixMimePart) else StixMimePart(**as_dict(v)) for v in self.body_multipart]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixFile(StixCyberObservableObject):
    """
    The File Object represents the properties of a file.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixFile"]
    class_class_curie: ClassVar[str] = "stix:StixFile"
    class_name: ClassVar[str] = "StixFile"
    class_model_uri: ClassVar[URIRef] = STIX.StixFile

    id: Union[str, StixFileId] = None
    type: str = None
    hashes: Optional[Union[dict, StixHashes]] = None
    size: Optional[int] = None
    name: Optional[str] = None
    name_enc: Optional[str] = None
    magic_number_hex: Optional[Union[str, StixHex]] = None
    mime_type: Optional[str] = None
    ctime: Optional[Union[str, StixTimestamp]] = None
    mtime: Optional[Union[str, StixTimestamp]] = None
    atime: Optional[Union[str, StixTimestamp]] = None
    parent_directory_ref: Optional[Union[str, StixDirectoryId]] = None
    contains_refs: Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]] = empty_list()
    content_ref: Optional[Union[str, StixArtifactId]] = None
    extensions: Optional[Union[dict, "StixFileExtensions"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixFileId):
            self.id = StixFileId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.hashes is not None and not isinstance(self.hashes, StixHashes):
            self.hashes = StixHashes()

        if self.size is not None and not isinstance(self.size, int):
            self.size = int(self.size)

        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.name_enc is not None and not isinstance(self.name_enc, str):
            self.name_enc = str(self.name_enc)

        if self.magic_number_hex is not None and not isinstance(self.magic_number_hex, StixHex):
            self.magic_number_hex = StixHex(self.magic_number_hex)

        if self.mime_type is not None and not isinstance(self.mime_type, str):
            self.mime_type = str(self.mime_type)

        if self.ctime is not None and not isinstance(self.ctime, StixTimestamp):
            self.ctime = StixTimestamp(self.ctime)

        if self.mtime is not None and not isinstance(self.mtime, StixTimestamp):
            self.mtime = StixTimestamp(self.mtime)

        if self.atime is not None and not isinstance(self.atime, StixTimestamp):
            self.atime = StixTimestamp(self.atime)

        if self.parent_directory_ref is not None and not isinstance(self.parent_directory_ref, StixDirectoryId):
            self.parent_directory_ref = StixDirectoryId(self.parent_directory_ref)

        if not isinstance(self.contains_refs, list):
            self.contains_refs = [self.contains_refs] if self.contains_refs is not None else []
        self.contains_refs = [v if isinstance(v, StixCyberObservableObjectId) else StixCyberObservableObjectId(v) for v in self.contains_refs]

        if self.content_ref is not None and not isinstance(self.content_ref, StixArtifactId):
            self.content_ref = StixArtifactId(self.content_ref)

        if self.extensions is not None and not isinstance(self.extensions, StixFileExtensions):
            self.extensions = StixFileExtensions()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixIpv4Address(StixCyberObservableObject):
    """
    The IPv4 Address Object represents one or more IPv4 addresses expressed using CIDR notation.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixIpv4Address"]
    class_class_curie: ClassVar[str] = "stix:StixIpv4Address"
    class_name: ClassVar[str] = "StixIpv4Address"
    class_model_uri: ClassVar[URIRef] = STIX.StixIpv4Address

    id: Union[str, StixIpv4AddressId] = None
    value: str = None
    type: str = None
    resolves_to_refs: Optional[Union[Union[str, StixMacAddressId], list[Union[str, StixMacAddressId]]]] = empty_list()
    belongs_to_refs: Optional[Union[Union[str, StixAutonomousSystemId], list[Union[str, StixAutonomousSystemId]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixIpv4AddressId):
            self.id = StixIpv4AddressId(self.id)

        if self._is_empty(self.value):
            self.MissingRequiredField("value")
        if not isinstance(self.value, str):
            self.value = str(self.value)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.resolves_to_refs, list):
            self.resolves_to_refs = [self.resolves_to_refs] if self.resolves_to_refs is not None else []
        self.resolves_to_refs = [v if isinstance(v, StixMacAddressId) else StixMacAddressId(v) for v in self.resolves_to_refs]

        if not isinstance(self.belongs_to_refs, list):
            self.belongs_to_refs = [self.belongs_to_refs] if self.belongs_to_refs is not None else []
        self.belongs_to_refs = [v if isinstance(v, StixAutonomousSystemId) else StixAutonomousSystemId(v) for v in self.belongs_to_refs]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixIpv6Address(StixCyberObservableObject):
    """
    The IPv6 Address Object represents one or more IPv6 addresses expressed using CIDR notation.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixIpv6Address"]
    class_class_curie: ClassVar[str] = "stix:StixIpv6Address"
    class_name: ClassVar[str] = "StixIpv6Address"
    class_model_uri: ClassVar[URIRef] = STIX.StixIpv6Address

    id: Union[str, StixIpv6AddressId] = None
    value: str = None
    type: str = None
    resolves_to_refs: Optional[Union[Union[str, StixMacAddressId], list[Union[str, StixMacAddressId]]]] = empty_list()
    belongs_to_refs: Optional[Union[Union[str, StixAutonomousSystemId], list[Union[str, StixAutonomousSystemId]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixIpv6AddressId):
            self.id = StixIpv6AddressId(self.id)

        if self._is_empty(self.value):
            self.MissingRequiredField("value")
        if not isinstance(self.value, str):
            self.value = str(self.value)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.resolves_to_refs, list):
            self.resolves_to_refs = [self.resolves_to_refs] if self.resolves_to_refs is not None else []
        self.resolves_to_refs = [v if isinstance(v, StixMacAddressId) else StixMacAddressId(v) for v in self.resolves_to_refs]

        if not isinstance(self.belongs_to_refs, list):
            self.belongs_to_refs = [self.belongs_to_refs] if self.belongs_to_refs is not None else []
        self.belongs_to_refs = [v if isinstance(v, StixAutonomousSystemId) else StixAutonomousSystemId(v) for v in self.belongs_to_refs]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixMacAddress(StixCyberObservableObject):
    """
    The MAC Address Object represents a single Media Access Control (MAC) address.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixMacAddress"]
    class_class_curie: ClassVar[str] = "stix:StixMacAddress"
    class_name: ClassVar[str] = "StixMacAddress"
    class_model_uri: ClassVar[URIRef] = STIX.StixMacAddress

    id: Union[str, StixMacAddressId] = None
    value: str = None
    type: str = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixMacAddressId):
            self.id = StixMacAddressId(self.id)

        if self._is_empty(self.value):
            self.MissingRequiredField("value")
        if not isinstance(self.value, str):
            self.value = str(self.value)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixMutex(StixCyberObservableObject):
    """
    The Mutex Object represents the properties of a mutual exclusion (mutex) object.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixMutex"]
    class_class_curie: ClassVar[str] = "stix:StixMutex"
    class_name: ClassVar[str] = "StixMutex"
    class_model_uri: ClassVar[URIRef] = STIX.StixMutex

    id: Union[str, StixMutexId] = None
    name: str = None
    type: str = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixMutexId):
            self.id = StixMutexId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixNetworkTraffic(StixCyberObservableObject):
    """
    The Network Traffic Object represents arbitrary network traffic that originates from a source and is addressed to
    a destination.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixNetworkTraffic"]
    class_class_curie: ClassVar[str] = "stix:StixNetworkTraffic"
    class_name: ClassVar[str] = "StixNetworkTraffic"
    class_model_uri: ClassVar[URIRef] = STIX.StixNetworkTraffic

    id: Union[str, StixNetworkTrafficId] = None
    protocols: Union[str, list[str]] = None
    type: str = None
    start: Optional[Union[str, StixTimestamp]] = None
    end: Optional[Union[str, StixTimestamp]] = None
    src_ref: Optional[Union[str, StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId]] = None
    dst_ref: Optional[Union[str, StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId]] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_byte_count: Optional[int] = None
    dst_byte_count: Optional[int] = None
    src_packets: Optional[int] = None
    dst_packets: Optional[int] = None
    ipfix: Optional[Union[dict, StixDictionary]] = None
    src_payload_ref: Optional[Union[str, StixArtifactId]] = None
    dst_payload_ref: Optional[Union[str, StixArtifactId]] = None
    encapsulates_refs: Optional[Union[Union[str, StixNetworkTrafficId], list[Union[str, StixNetworkTrafficId]]]] = empty_list()
    encapsulated_by_ref: Optional[Union[str, StixNetworkTrafficId]] = None
    is_active: Optional[Union[bool, Bool]] = None
    extensions: Optional[Union[dict, "StixNetworkTrafficExtensions"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixNetworkTrafficId):
            self.id = StixNetworkTrafficId(self.id)

        if self._is_empty(self.protocols):
            self.MissingRequiredField("protocols")
        if not isinstance(self.protocols, list):
            self.protocols = [self.protocols] if self.protocols is not None else []
        self.protocols = [v if isinstance(v, str) else str(v) for v in self.protocols]

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.start is not None and not isinstance(self.start, StixTimestamp):
            self.start = StixTimestamp(self.start)

        if self.end is not None and not isinstance(self.end, StixTimestamp):
            self.end = StixTimestamp(self.end)

        if self.src_ref is not None and not isinstance(self.src_ref, (StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId)):
            value = self.src_ref
            for _coerce in (lambda: StixIpv4AddressId(value), lambda: StixIpv6AddressId(value), lambda: StixMacAddressId(value), lambda: StixDomainNameId(value)):
                try:
                    self.src_ref = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId] could be constructed from {value!r} for slot src_ref")

        if self.dst_ref is not None and not isinstance(self.dst_ref, (StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId)):
            value = self.dst_ref
            for _coerce in (lambda: StixIpv4AddressId(value), lambda: StixIpv6AddressId(value), lambda: StixMacAddressId(value), lambda: StixDomainNameId(value)):
                try:
                    self.dst_ref = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId] could be constructed from {value!r} for slot dst_ref")

        if self.src_port is not None and not isinstance(self.src_port, int):
            self.src_port = int(self.src_port)

        if self.dst_port is not None and not isinstance(self.dst_port, int):
            self.dst_port = int(self.dst_port)

        if self.src_byte_count is not None and not isinstance(self.src_byte_count, int):
            self.src_byte_count = int(self.src_byte_count)

        if self.dst_byte_count is not None and not isinstance(self.dst_byte_count, int):
            self.dst_byte_count = int(self.dst_byte_count)

        if self.src_packets is not None and not isinstance(self.src_packets, int):
            self.src_packets = int(self.src_packets)

        if self.dst_packets is not None and not isinstance(self.dst_packets, int):
            self.dst_packets = int(self.dst_packets)

        if self.ipfix is not None and not isinstance(self.ipfix, StixDictionary):
            self.ipfix = StixDictionary()

        if self.src_payload_ref is not None and not isinstance(self.src_payload_ref, StixArtifactId):
            self.src_payload_ref = StixArtifactId(self.src_payload_ref)

        if self.dst_payload_ref is not None and not isinstance(self.dst_payload_ref, StixArtifactId):
            self.dst_payload_ref = StixArtifactId(self.dst_payload_ref)

        if not isinstance(self.encapsulates_refs, list):
            self.encapsulates_refs = [self.encapsulates_refs] if self.encapsulates_refs is not None else []
        self.encapsulates_refs = [v if isinstance(v, StixNetworkTrafficId) else StixNetworkTrafficId(v) for v in self.encapsulates_refs]

        if self.encapsulated_by_ref is not None and not isinstance(self.encapsulated_by_ref, StixNetworkTrafficId):
            self.encapsulated_by_ref = StixNetworkTrafficId(self.encapsulated_by_ref)

        if self.is_active is not None and not isinstance(self.is_active, Bool):
            self.is_active = Bool(self.is_active)

        if self.extensions is not None and not isinstance(self.extensions, StixNetworkTrafficExtensions):
            self.extensions = StixNetworkTrafficExtensions()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixProcess(StixCyberObservableObject):
    """
    The Process Object represents common properties of an instance of a computer program as executed on an operating
    system.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixProcess"]
    class_class_curie: ClassVar[str] = "stix:StixProcess"
    class_name: ClassVar[str] = "StixProcess"
    class_model_uri: ClassVar[URIRef] = STIX.StixProcess

    id: Union[str, StixProcessId] = None
    type: str = None
    is_hidden: Optional[Union[bool, Bool]] = None
    pid: Optional[int] = None
    created_time: Optional[Union[str, StixTimestamp]] = None
    cwd: Optional[str] = None
    command_line: Optional[str] = None
    environment_variables: Optional[Union[dict, StixDictionary]] = None
    opened_connection_refs: Optional[Union[Union[str, StixNetworkTrafficId], list[Union[str, StixNetworkTrafficId]]]] = empty_list()
    creator_user_ref: Optional[Union[str, StixUserAccountId]] = None
    image_ref: Optional[Union[str, StixFileId]] = None
    parent_ref: Optional[Union[str, StixProcessId]] = None
    child_refs: Optional[Union[Union[str, StixProcessId], list[Union[str, StixProcessId]]]] = empty_list()
    extensions: Optional[Union[dict, "StixProcessExtensions"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixProcessId):
            self.id = StixProcessId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.is_hidden is not None and not isinstance(self.is_hidden, Bool):
            self.is_hidden = Bool(self.is_hidden)

        if self.pid is not None and not isinstance(self.pid, int):
            self.pid = int(self.pid)

        if self.created_time is not None and not isinstance(self.created_time, StixTimestamp):
            self.created_time = StixTimestamp(self.created_time)

        if self.cwd is not None and not isinstance(self.cwd, str):
            self.cwd = str(self.cwd)

        if self.command_line is not None and not isinstance(self.command_line, str):
            self.command_line = str(self.command_line)

        if self.environment_variables is not None and not isinstance(self.environment_variables, StixDictionary):
            self.environment_variables = StixDictionary()

        if not isinstance(self.opened_connection_refs, list):
            self.opened_connection_refs = [self.opened_connection_refs] if self.opened_connection_refs is not None else []
        self.opened_connection_refs = [v if isinstance(v, StixNetworkTrafficId) else StixNetworkTrafficId(v) for v in self.opened_connection_refs]

        if self.creator_user_ref is not None and not isinstance(self.creator_user_ref, StixUserAccountId):
            self.creator_user_ref = StixUserAccountId(self.creator_user_ref)

        if self.image_ref is not None and not isinstance(self.image_ref, StixFileId):
            self.image_ref = StixFileId(self.image_ref)

        if self.parent_ref is not None and not isinstance(self.parent_ref, StixProcessId):
            self.parent_ref = StixProcessId(self.parent_ref)

        if not isinstance(self.child_refs, list):
            self.child_refs = [self.child_refs] if self.child_refs is not None else []
        self.child_refs = [v if isinstance(v, StixProcessId) else StixProcessId(v) for v in self.child_refs]

        if self.extensions is not None and not isinstance(self.extensions, StixProcessExtensions):
            self.extensions = StixProcessExtensions()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixSoftware(StixCyberObservableObject):
    """
    The Software Object represents high-level properties associated with software, including software products.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixSoftware"]
    class_class_curie: ClassVar[str] = "stix:StixSoftware"
    class_name: ClassVar[str] = "StixSoftware"
    class_model_uri: ClassVar[URIRef] = STIX.StixSoftware

    id: Union[str, StixSoftwareId] = None
    name: str = None
    type: str = None
    cpe: Optional[str] = None
    swid: Optional[str] = None
    languages: Optional[Union[str, list[str]]] = empty_list()
    vendor: Optional[str] = None
    version: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixSoftwareId):
            self.id = StixSoftwareId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.cpe is not None and not isinstance(self.cpe, str):
            self.cpe = str(self.cpe)

        if self.swid is not None and not isinstance(self.swid, str):
            self.swid = str(self.swid)

        if not isinstance(self.languages, list):
            self.languages = [self.languages] if self.languages is not None else []
        self.languages = [v if isinstance(v, str) else str(v) for v in self.languages]

        if self.vendor is not None and not isinstance(self.vendor, str):
            self.vendor = str(self.vendor)

        if self.version is not None and not isinstance(self.version, str):
            self.version = str(self.version)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixUrl(StixCyberObservableObject):
    """
    The URL Object represents the properties of a uniform resource locator (URL).
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixUrl"]
    class_class_curie: ClassVar[str] = "stix:StixUrl"
    class_name: ClassVar[str] = "StixUrl"
    class_model_uri: ClassVar[URIRef] = STIX.StixUrl

    id: Union[str, StixUrlId] = None
    value: Union[str, URI] = None
    type: str = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixUrlId):
            self.id = StixUrlId(self.id)

        if self._is_empty(self.value):
            self.MissingRequiredField("value")
        if not isinstance(self.value, URI):
            self.value = URI(self.value)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixUserAccount(StixCyberObservableObject):
    """
    The User Account Object represents an instance of any type of user account, including but not limited to operating
    system, device, messaging service, and social media platform accounts.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixUserAccount"]
    class_class_curie: ClassVar[str] = "stix:StixUserAccount"
    class_name: ClassVar[str] = "StixUserAccount"
    class_model_uri: ClassVar[URIRef] = STIX.StixUserAccount

    id: Union[str, StixUserAccountId] = None
    type: str = None
    user_id: Optional[str] = None
    credential: Optional[str] = None
    account_login: Optional[str] = None
    account_type: Optional[Union[str, "StixAccountType"]] = None
    display_name: Optional[str] = None
    is_service_account: Optional[Union[bool, Bool]] = None
    is_privileged: Optional[Union[bool, Bool]] = None
    can_escalate_privs: Optional[Union[bool, Bool]] = None
    is_disabled: Optional[Union[bool, Bool]] = None
    account_created: Optional[Union[str, StixTimestamp]] = None
    account_expires: Optional[Union[str, StixTimestamp]] = None
    credential_last_changed: Optional[Union[str, StixTimestamp]] = None
    account_first_login: Optional[Union[str, StixTimestamp]] = None
    account_last_login: Optional[Union[str, StixTimestamp]] = None
    extensions: Optional[Union[dict, "StixUserAccountExtensions"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixUserAccountId):
            self.id = StixUserAccountId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.user_id is not None and not isinstance(self.user_id, str):
            self.user_id = str(self.user_id)

        if self.credential is not None and not isinstance(self.credential, str):
            self.credential = str(self.credential)

        if self.account_login is not None and not isinstance(self.account_login, str):
            self.account_login = str(self.account_login)

        if self.account_type is not None and not isinstance(self.account_type, (StixAccountType, str)):
            value = self.account_type
            for _coerce in (lambda: StixAccountType(value), lambda: str(value)):
                try:
                    self.account_type = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixAccountType, str] could be constructed from {value!r} for slot account_type")

        if self.display_name is not None and not isinstance(self.display_name, str):
            self.display_name = str(self.display_name)

        if self.is_service_account is not None and not isinstance(self.is_service_account, Bool):
            self.is_service_account = Bool(self.is_service_account)

        if self.is_privileged is not None and not isinstance(self.is_privileged, Bool):
            self.is_privileged = Bool(self.is_privileged)

        if self.can_escalate_privs is not None and not isinstance(self.can_escalate_privs, Bool):
            self.can_escalate_privs = Bool(self.can_escalate_privs)

        if self.is_disabled is not None and not isinstance(self.is_disabled, Bool):
            self.is_disabled = Bool(self.is_disabled)

        if self.account_created is not None and not isinstance(self.account_created, StixTimestamp):
            self.account_created = StixTimestamp(self.account_created)

        if self.account_expires is not None and not isinstance(self.account_expires, StixTimestamp):
            self.account_expires = StixTimestamp(self.account_expires)

        if self.credential_last_changed is not None and not isinstance(self.credential_last_changed, StixTimestamp):
            self.credential_last_changed = StixTimestamp(self.credential_last_changed)

        if self.account_first_login is not None and not isinstance(self.account_first_login, StixTimestamp):
            self.account_first_login = StixTimestamp(self.account_first_login)

        if self.account_last_login is not None and not isinstance(self.account_last_login, StixTimestamp):
            self.account_last_login = StixTimestamp(self.account_last_login)

        if self.extensions is not None and not isinstance(self.extensions, StixUserAccountExtensions):
            self.extensions = StixUserAccountExtensions()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixWindowsRegistryKey(StixCyberObservableObject):
    """
    The Registry Key Object represents the properties of a Windows registry key.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixWindowsRegistryKey"]
    class_class_curie: ClassVar[str] = "stix:StixWindowsRegistryKey"
    class_name: ClassVar[str] = "StixWindowsRegistryKey"
    class_model_uri: ClassVar[URIRef] = STIX.StixWindowsRegistryKey

    id: Union[str, StixWindowsRegistryKeyId] = None
    type: str = None
    key: Optional[str] = None
    values: Optional[Union[Union[dict, "StixWindowsRegistryValue"], list[Union[dict, "StixWindowsRegistryValue"]]]] = empty_list()
    modified_time: Optional[Union[str, StixTimestamp]] = None
    creator_user_ref: Optional[Union[str, StixUserAccountId]] = None
    number_of_subkeys: Optional[int] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixWindowsRegistryKeyId):
            self.id = StixWindowsRegistryKeyId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.key is not None and not isinstance(self.key, str):
            self.key = str(self.key)

        if not isinstance(self.values, list):
            self.values = [self.values] if self.values is not None else []
        self.values = [v if isinstance(v, StixWindowsRegistryValue) else StixWindowsRegistryValue(**as_dict(v)) for v in self.values]

        if self.modified_time is not None and not isinstance(self.modified_time, StixTimestamp):
            self.modified_time = StixTimestamp(self.modified_time)

        if self.creator_user_ref is not None and not isinstance(self.creator_user_ref, StixUserAccountId):
            self.creator_user_ref = StixUserAccountId(self.creator_user_ref)

        if self.number_of_subkeys is not None and not isinstance(self.number_of_subkeys, int):
            self.number_of_subkeys = int(self.number_of_subkeys)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixX509Certificate(StixCyberObservableObject):
    """
    The X509 Certificate Object represents the properties of an X.509 certificate.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixX509Certificate"]
    class_class_curie: ClassVar[str] = "stix:StixX509Certificate"
    class_name: ClassVar[str] = "StixX509Certificate"
    class_model_uri: ClassVar[URIRef] = STIX.StixX509Certificate

    id: Union[str, StixX509CertificateId] = None
    type: str = None
    is_self_signed: Optional[Union[bool, Bool]] = None
    hashes: Optional[Union[dict, StixHashes]] = None
    version: Optional[str] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    issuer: Optional[str] = None
    validity_not_before: Optional[Union[str, StixTimestamp]] = None
    validity_not_after: Optional[Union[str, StixTimestamp]] = None
    subject: Optional[str] = None
    subject_public_key_algorithm: Optional[str] = None
    subject_public_key_modulus: Optional[str] = None
    subject_public_key_exponent: Optional[int] = None
    x509_v3_extensions: Optional[Union[dict, "StixX509V3Extensions"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixX509CertificateId):
            self.id = StixX509CertificateId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.is_self_signed is not None and not isinstance(self.is_self_signed, Bool):
            self.is_self_signed = Bool(self.is_self_signed)

        if self.hashes is not None and not isinstance(self.hashes, StixHashes):
            self.hashes = StixHashes()

        if self.version is not None and not isinstance(self.version, str):
            self.version = str(self.version)

        if self.serial_number is not None and not isinstance(self.serial_number, str):
            self.serial_number = str(self.serial_number)

        if self.signature_algorithm is not None and not isinstance(self.signature_algorithm, str):
            self.signature_algorithm = str(self.signature_algorithm)

        if self.issuer is not None and not isinstance(self.issuer, str):
            self.issuer = str(self.issuer)

        if self.validity_not_before is not None and not isinstance(self.validity_not_before, StixTimestamp):
            self.validity_not_before = StixTimestamp(self.validity_not_before)

        if self.validity_not_after is not None and not isinstance(self.validity_not_after, StixTimestamp):
            self.validity_not_after = StixTimestamp(self.validity_not_after)

        if self.subject is not None and not isinstance(self.subject, str):
            self.subject = str(self.subject)

        if self.subject_public_key_algorithm is not None and not isinstance(self.subject_public_key_algorithm, str):
            self.subject_public_key_algorithm = str(self.subject_public_key_algorithm)

        if self.subject_public_key_modulus is not None and not isinstance(self.subject_public_key_modulus, str):
            self.subject_public_key_modulus = str(self.subject_public_key_modulus)

        if self.subject_public_key_exponent is not None and not isinstance(self.subject_public_key_exponent, int):
            self.subject_public_key_exponent = int(self.subject_public_key_exponent)

        if self.x509_v3_extensions is not None and not isinstance(self.x509_v3_extensions, StixX509V3Extensions):
            self.x509_v3_extensions = StixX509V3Extensions(**as_dict(self.x509_v3_extensions))

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixNtfsExtension(YAMLRoot):
    """
    The NTFS file extension specifies a default extension for capturing properties specific to the storage of the file
    on the NTFS file system.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixNtfsExtension"]
    class_class_curie: ClassVar[str] = "stix:StixNtfsExtension"
    class_name: ClassVar[str] = "StixNtfsExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixNtfsExtension

    sid: Optional[str] = None
    alternate_data_streams: Optional[Union[Union[dict, "StixAlternateDataStream"], list[Union[dict, "StixAlternateDataStream"]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.sid is not None and not isinstance(self.sid, str):
            self.sid = str(self.sid)

        self._normalize_inlined_as_list(slot_name="alternate_data_streams", slot_type=StixAlternateDataStream, key_name="name", keyed=False)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixRasterImageExtension(YAMLRoot):
    """
    The Raster Image file extension specifies a default extension for capturing properties specific to image files.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixRasterImageExtension"]
    class_class_curie: ClassVar[str] = "stix:StixRasterImageExtension"
    class_name: ClassVar[str] = "StixRasterImageExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixRasterImageExtension

    image_height: Optional[int] = None
    image_width: Optional[int] = None
    bits_per_pixel: Optional[int] = None
    exif_tags: Optional[Union[dict, "StixExifTags"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.image_height is not None and not isinstance(self.image_height, int):
            self.image_height = int(self.image_height)

        if self.image_width is not None and not isinstance(self.image_width, int):
            self.image_width = int(self.image_width)

        if self.bits_per_pixel is not None and not isinstance(self.bits_per_pixel, int):
            self.bits_per_pixel = int(self.bits_per_pixel)

        if self.exif_tags is not None and not isinstance(self.exif_tags, StixExifTags):
            self.exif_tags = StixExifTags()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixPdfExtension(YAMLRoot):
    """
    The PDF file extension specifies a default extension for capturing properties specific to PDF files.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixPdfExtension"]
    class_class_curie: ClassVar[str] = "stix:StixPdfExtension"
    class_name: ClassVar[str] = "StixPdfExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixPdfExtension

    version: Optional[str] = None
    is_optimized: Optional[Union[bool, Bool]] = None
    document_info_dict: Optional[Union[dict, "StixPdfDocumentInfo"]] = None
    pdfid0: Optional[str] = None
    pdfid1: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.version is not None and not isinstance(self.version, str):
            self.version = str(self.version)

        if self.is_optimized is not None and not isinstance(self.is_optimized, Bool):
            self.is_optimized = Bool(self.is_optimized)

        if self.document_info_dict is not None and not isinstance(self.document_info_dict, StixPdfDocumentInfo):
            self.document_info_dict = StixPdfDocumentInfo()

        if self.pdfid0 is not None and not isinstance(self.pdfid0, str):
            self.pdfid0 = str(self.pdfid0)

        if self.pdfid1 is not None and not isinstance(self.pdfid1, str):
            self.pdfid1 = str(self.pdfid1)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixArchiveExtension(YAMLRoot):
    """
    The Archive File extension specifies a default extension for capturing properties specific to archive files.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixArchiveExtension"]
    class_class_curie: ClassVar[str] = "stix:StixArchiveExtension"
    class_name: ClassVar[str] = "StixArchiveExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixArchiveExtension

    contains_refs: Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]] = None
    comment: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.contains_refs):
            self.MissingRequiredField("contains_refs")
        if not isinstance(self.contains_refs, list):
            self.contains_refs = [self.contains_refs] if self.contains_refs is not None else []
        self.contains_refs = [v if isinstance(v, StixCyberObservableObjectId) else StixCyberObservableObjectId(v) for v in self.contains_refs]

        if self.comment is not None and not isinstance(self.comment, str):
            self.comment = str(self.comment)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixWindowsPeBinaryExtension(YAMLRoot):
    """
    The Windows PE Binary File extension specifies a default extension for capturing properties specific to Windows
    portable executable (PE) files.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixWindowsPeBinaryExtension"]
    class_class_curie: ClassVar[str] = "stix:StixWindowsPeBinaryExtension"
    class_name: ClassVar[str] = "StixWindowsPeBinaryExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixWindowsPeBinaryExtension

    pe_type: Union[str, "StixWindowsPeBinaryType"] = None
    imphash: Optional[str] = None
    machine_hex: Optional[Union[str, StixHex]] = None
    number_of_sections: Optional[int] = None
    time_date_stamp: Optional[Union[str, StixTimestampSeconds]] = None
    pointer_to_symbol_table_hex: Optional[Union[str, StixHex]] = None
    number_of_symbols: Optional[int] = None
    size_of_optional_header: Optional[int] = None
    characteristics_hex: Optional[Union[str, StixHex]] = None
    file_header_hashes: Optional[Union[dict, StixHashes]] = None
    optional_header: Optional[Union[dict, "StixWindowsPeOptionalHeader"]] = None
    sections: Optional[Union[Union[dict, "StixWindowsPeSection"], list[Union[dict, "StixWindowsPeSection"]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.pe_type):
            self.MissingRequiredField("pe_type")
        if not isinstance(self.pe_type, (StixWindowsPeBinaryType, str)):
            value = self.pe_type
            for _coerce in (lambda: StixWindowsPeBinaryType(value), lambda: str(value)):
                try:
                    self.pe_type = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixWindowsPeBinaryType, str] could be constructed from {value!r} for slot pe_type")

        if self.imphash is not None and not isinstance(self.imphash, str):
            self.imphash = str(self.imphash)

        if self.machine_hex is not None and not isinstance(self.machine_hex, StixHex):
            self.machine_hex = StixHex(self.machine_hex)

        if self.number_of_sections is not None and not isinstance(self.number_of_sections, int):
            self.number_of_sections = int(self.number_of_sections)

        if self.time_date_stamp is not None and not isinstance(self.time_date_stamp, StixTimestampSeconds):
            self.time_date_stamp = StixTimestampSeconds(self.time_date_stamp)

        if self.pointer_to_symbol_table_hex is not None and not isinstance(self.pointer_to_symbol_table_hex, StixHex):
            self.pointer_to_symbol_table_hex = StixHex(self.pointer_to_symbol_table_hex)

        if self.number_of_symbols is not None and not isinstance(self.number_of_symbols, int):
            self.number_of_symbols = int(self.number_of_symbols)

        if self.size_of_optional_header is not None and not isinstance(self.size_of_optional_header, int):
            self.size_of_optional_header = int(self.size_of_optional_header)

        if self.characteristics_hex is not None and not isinstance(self.characteristics_hex, StixHex):
            self.characteristics_hex = StixHex(self.characteristics_hex)

        if self.file_header_hashes is not None and not isinstance(self.file_header_hashes, StixHashes):
            self.file_header_hashes = StixHashes()

        if self.optional_header is not None and not isinstance(self.optional_header, StixWindowsPeOptionalHeader):
            self.optional_header = StixWindowsPeOptionalHeader(**as_dict(self.optional_header))

        self._normalize_inlined_as_list(slot_name="sections", slot_type=StixWindowsPeSection, key_name="name", keyed=False)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixHttpRequestExtension(YAMLRoot):
    """
    The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP
    requests.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixHttpRequestExtension"]
    class_class_curie: ClassVar[str] = "stix:StixHttpRequestExtension"
    class_name: ClassVar[str] = "StixHttpRequestExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixHttpRequestExtension

    request_method: str = None
    request_value: str = None
    request_version: Optional[str] = None
    request_header: Optional[Union[dict, StixDictionary]] = None
    message_body_length: Optional[int] = None
    message_body_data_ref: Optional[Union[str, StixArtifactId]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.request_method):
            self.MissingRequiredField("request_method")
        if not isinstance(self.request_method, str):
            self.request_method = str(self.request_method)

        if self._is_empty(self.request_value):
            self.MissingRequiredField("request_value")
        if not isinstance(self.request_value, str):
            self.request_value = str(self.request_value)

        if self.request_version is not None and not isinstance(self.request_version, str):
            self.request_version = str(self.request_version)

        if self.request_header is not None and not isinstance(self.request_header, StixDictionary):
            self.request_header = StixDictionary()

        if self.message_body_length is not None and not isinstance(self.message_body_length, int):
            self.message_body_length = int(self.message_body_length)

        if self.message_body_data_ref is not None and not isinstance(self.message_body_data_ref, StixArtifactId):
            self.message_body_data_ref = StixArtifactId(self.message_body_data_ref)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixIcmpExtension(YAMLRoot):
    """
    The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixIcmpExtension"]
    class_class_curie: ClassVar[str] = "stix:StixIcmpExtension"
    class_name: ClassVar[str] = "StixIcmpExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixIcmpExtension

    icmp_type_hex: Union[str, StixHex] = None
    icmp_code_hex: Union[str, StixHex] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.icmp_type_hex):
            self.MissingRequiredField("icmp_type_hex")
        if not isinstance(self.icmp_type_hex, StixHex):
            self.icmp_type_hex = StixHex(self.icmp_type_hex)

        if self._is_empty(self.icmp_code_hex):
            self.MissingRequiredField("icmp_code_hex")
        if not isinstance(self.icmp_code_hex, StixHex):
            self.icmp_code_hex = StixHex(self.icmp_code_hex)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixSocketExtension(YAMLRoot):
    """
    The Network Socket extension specifies a default extension for capturing network traffic properties associated
    with network sockets.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixSocketExtension"]
    class_class_curie: ClassVar[str] = "stix:StixSocketExtension"
    class_name: ClassVar[str] = "StixSocketExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixSocketExtension

    address_family: Union[str, "StixNetworkSocketAddressFamily"] = None
    is_blocking: Optional[Union[bool, Bool]] = None
    is_listening: Optional[Union[bool, Bool]] = None
    options: Optional[Union[dict, "StixSocketOptions"]] = None
    socket_type: Optional[Union[str, "StixNetworkSocketType"]] = None
    socket_descriptor: Optional[int] = None
    socket_handle: Optional[int] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.address_family):
            self.MissingRequiredField("address_family")
        if not isinstance(self.address_family, StixNetworkSocketAddressFamily):
            self.address_family = StixNetworkSocketAddressFamily(self.address_family)

        if self.is_blocking is not None and not isinstance(self.is_blocking, Bool):
            self.is_blocking = Bool(self.is_blocking)

        if self.is_listening is not None and not isinstance(self.is_listening, Bool):
            self.is_listening = Bool(self.is_listening)

        if self.options is not None and not isinstance(self.options, StixSocketOptions):
            self.options = StixSocketOptions()

        if self.socket_type is not None and not isinstance(self.socket_type, StixNetworkSocketType):
            self.socket_type = StixNetworkSocketType(self.socket_type)

        if self.socket_descriptor is not None and not isinstance(self.socket_descriptor, int):
            self.socket_descriptor = int(self.socket_descriptor)

        if self.socket_handle is not None and not isinstance(self.socket_handle, int):
            self.socket_handle = int(self.socket_handle)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixTcpExtension(YAMLRoot):
    """
    The TCP extension specifies a default extension for capturing network traffic properties specific to TCP.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixTcpExtension"]
    class_class_curie: ClassVar[str] = "stix:StixTcpExtension"
    class_name: ClassVar[str] = "StixTcpExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixTcpExtension

    src_flags_hex: Optional[Union[str, StixHex]] = None
    dst_flags_hex: Optional[Union[str, StixHex]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.src_flags_hex is not None and not isinstance(self.src_flags_hex, StixHex):
            self.src_flags_hex = StixHex(self.src_flags_hex)

        if self.dst_flags_hex is not None and not isinstance(self.dst_flags_hex, StixHex):
            self.dst_flags_hex = StixHex(self.dst_flags_hex)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixWindowsProcessExtension(YAMLRoot):
    """
    The Windows Process extension specifies a default extension for capturing properties specific to Windows processes.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixWindowsProcessExtension"]
    class_class_curie: ClassVar[str] = "stix:StixWindowsProcessExtension"
    class_name: ClassVar[str] = "StixWindowsProcessExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixWindowsProcessExtension

    aslr_enabled: Optional[Union[bool, Bool]] = None
    dep_enabled: Optional[Union[bool, Bool]] = None
    priority: Optional[str] = None
    owner_sid: Optional[str] = None
    window_title: Optional[str] = None
    startup_info: Optional[Union[dict, StixDictionary]] = None
    integrity_level: Optional[Union[str, "StixWindowsIntegrityLevel"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.aslr_enabled is not None and not isinstance(self.aslr_enabled, Bool):
            self.aslr_enabled = Bool(self.aslr_enabled)

        if self.dep_enabled is not None and not isinstance(self.dep_enabled, Bool):
            self.dep_enabled = Bool(self.dep_enabled)

        if self.priority is not None and not isinstance(self.priority, str):
            self.priority = str(self.priority)

        if self.owner_sid is not None and not isinstance(self.owner_sid, str):
            self.owner_sid = str(self.owner_sid)

        if self.window_title is not None and not isinstance(self.window_title, str):
            self.window_title = str(self.window_title)

        if self.startup_info is not None and not isinstance(self.startup_info, StixDictionary):
            self.startup_info = StixDictionary()

        if self.integrity_level is not None and not isinstance(self.integrity_level, StixWindowsIntegrityLevel):
            self.integrity_level = StixWindowsIntegrityLevel(self.integrity_level)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixWindowsServiceExtension(YAMLRoot):
    """
    The Windows Service extension specifies a default extension for capturing properties specific to Windows services.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixWindowsServiceExtension"]
    class_class_curie: ClassVar[str] = "stix:StixWindowsServiceExtension"
    class_name: ClassVar[str] = "StixWindowsServiceExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixWindowsServiceExtension

    service_name: Optional[str] = None
    descriptions: Optional[Union[str, list[str]]] = empty_list()
    display_name: Optional[str] = None
    group_name: Optional[str] = None
    start_type: Optional[Union[str, "StixWindowsServiceStartType"]] = None
    service_dll_refs: Optional[Union[Union[str, StixFileId], list[Union[str, StixFileId]]]] = empty_list()
    service_type: Optional[Union[str, "StixWindowsServiceType"]] = None
    service_status: Optional[Union[str, "StixWindowsServiceStatus"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.service_name is not None and not isinstance(self.service_name, str):
            self.service_name = str(self.service_name)

        if not isinstance(self.descriptions, list):
            self.descriptions = [self.descriptions] if self.descriptions is not None else []
        self.descriptions = [v if isinstance(v, str) else str(v) for v in self.descriptions]

        if self.display_name is not None and not isinstance(self.display_name, str):
            self.display_name = str(self.display_name)

        if self.group_name is not None and not isinstance(self.group_name, str):
            self.group_name = str(self.group_name)

        if self.start_type is not None and not isinstance(self.start_type, StixWindowsServiceStartType):
            self.start_type = StixWindowsServiceStartType(self.start_type)

        if not isinstance(self.service_dll_refs, list):
            self.service_dll_refs = [self.service_dll_refs] if self.service_dll_refs is not None else []
        self.service_dll_refs = [v if isinstance(v, StixFileId) else StixFileId(v) for v in self.service_dll_refs]

        if self.service_type is not None and not isinstance(self.service_type, StixWindowsServiceType):
            self.service_type = StixWindowsServiceType(self.service_type)

        if self.service_status is not None and not isinstance(self.service_status, StixWindowsServiceStatus):
            self.service_status = StixWindowsServiceStatus(self.service_status)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixUnixAccountExtension(YAMLRoot):
    """
    The User Account Object defines the following extensions. In addition to these, producers MAY create their own.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixUnixAccountExtension"]
    class_class_curie: ClassVar[str] = "stix:StixUnixAccountExtension"
    class_name: ClassVar[str] = "StixUnixAccountExtension"
    class_model_uri: ClassVar[URIRef] = STIX.StixUnixAccountExtension

    gid: Optional[float] = None
    groups: Optional[Union[str, list[str]]] = empty_list()
    home_dir: Optional[str] = None
    shell: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.gid is not None and not isinstance(self.gid, float):
            self.gid = float(self.gid)

        if not isinstance(self.groups, list):
            self.groups = [self.groups] if self.groups is not None else []
        self.groups = [v if isinstance(v, str) else str(v) for v in self.groups]

        if self.home_dir is not None and not isinstance(self.home_dir, str):
            self.home_dir = str(self.home_dir)

        if self.shell is not None and not isinstance(self.shell, str):
            self.shell = str(self.shell)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixAlternateDataStream(YAMLRoot):
    """
    An NTFS alternate data stream of a file.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixAlternateDataStream"]
    class_class_curie: ClassVar[str] = "stix:StixAlternateDataStream"
    class_name: ClassVar[str] = "StixAlternateDataStream"
    class_model_uri: ClassVar[URIRef] = STIX.StixAlternateDataStream

    name: str = None
    hashes: Optional[Union[dict, StixHashes]] = None
    size: Optional[int] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self.hashes is not None and not isinstance(self.hashes, StixHashes):
            self.hashes = StixHashes()

        if self.size is not None and not isinstance(self.size, int):
            self.size = int(self.size)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixWindowsPeSection(YAMLRoot):
    """
    A section of a Windows PE binary.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixWindowsPeSection"]
    class_class_curie: ClassVar[str] = "stix:StixWindowsPeSection"
    class_name: ClassVar[str] = "StixWindowsPeSection"
    class_model_uri: ClassVar[URIRef] = STIX.StixWindowsPeSection

    name: str = None
    size: Optional[int] = None
    entropy: Optional[float] = None
    hashes: Optional[Union[dict, StixHashes]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self.size is not None and not isinstance(self.size, int):
            self.size = int(self.size)

        if self.entropy is not None and not isinstance(self.entropy, float):
            self.entropy = float(self.entropy)

        if self.hashes is not None and not isinstance(self.hashes, StixHashes):
            self.hashes = StixHashes()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixWindowsPeOptionalHeader(YAMLRoot):
    """
    The optional header of a Windows PE binary.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixWindowsPeOptionalHeader"]
    class_class_curie: ClassVar[str] = "stix:StixWindowsPeOptionalHeader"
    class_name: ClassVar[str] = "StixWindowsPeOptionalHeader"
    class_model_uri: ClassVar[URIRef] = STIX.StixWindowsPeOptionalHeader

    magic_hex: Optional[Union[str, StixHex]] = None
    major_linker_version: Optional[int] = None
    minor_linker_version: Optional[int] = None
    size_of_code: Optional[int] = None
    size_of_initialized_data: Optional[int] = None
    size_of_uninitialized_data: Optional[int] = None
    address_of_entry_point: Optional[int] = None
    base_of_code: Optional[int] = None
    base_of_data: Optional[int] = None
    image_base: Optional[int] = None
    section_alignment: Optional[int] = None
    file_alignment: Optional[int] = None
    major_os_version: Optional[int] = None
    minor_os_version: Optional[int] = None
    major_image_version: Optional[int] = None
    minor_image_version: Optional[int] = None
    major_subsystem_version: Optional[int] = None
    minor_subsystem_version: Optional[int] = None
    win32_version_value_hex: Optional[Union[str, StixHex]] = None
    size_of_image: Optional[int] = None
    size_of_headers: Optional[int] = None
    checksum_hex: Optional[Union[str, StixHex]] = None
    subsystem_hex: Optional[Union[str, StixHex]] = None
    dll_characteristics_hex: Optional[Union[str, StixHex]] = None
    size_of_stack_reserve: Optional[int] = None
    size_of_stack_commit: Optional[int] = None
    size_of_heap_reserve: Optional[int] = None
    size_of_heap_commit: Optional[int] = None
    loader_flags_hex: Optional[Union[str, StixHex]] = None
    number_of_rva_and_sizes: Optional[int] = None
    hashes: Optional[Union[dict, StixHashes]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.magic_hex is not None and not isinstance(self.magic_hex, StixHex):
            self.magic_hex = StixHex(self.magic_hex)

        if self.major_linker_version is not None and not isinstance(self.major_linker_version, int):
            self.major_linker_version = int(self.major_linker_version)

        if self.minor_linker_version is not None and not isinstance(self.minor_linker_version, int):
            self.minor_linker_version = int(self.minor_linker_version)

        if self.size_of_code is not None and not isinstance(self.size_of_code, int):
            self.size_of_code = int(self.size_of_code)

        if self.size_of_initialized_data is not None and not isinstance(self.size_of_initialized_data, int):
            self.size_of_initialized_data = int(self.size_of_initialized_data)

        if self.size_of_uninitialized_data is not None and not isinstance(self.size_of_uninitialized_data, int):
            self.size_of_uninitialized_data = int(self.size_of_uninitialized_data)

        if self.address_of_entry_point is not None and not isinstance(self.address_of_entry_point, int):
            self.address_of_entry_point = int(self.address_of_entry_point)

        if self.base_of_code is not None and not isinstance(self.base_of_code, int):
            self.base_of_code = int(self.base_of_code)

        if self.base_of_data is not None and not isinstance(self.base_of_data, int):
            self.base_of_data = int(self.base_of_data)

        if self.image_base is not None and not isinstance(self.image_base, int):
            self.image_base = int(self.image_base)

        if self.section_alignment is not None and not isinstance(self.section_alignment, int):
            self.section_alignment = int(self.section_alignment)

        if self.file_alignment is not None and not isinstance(self.file_alignment, int):
            self.file_alignment = int(self.file_alignment)

        if self.major_os_version is not None and not isinstance(self.major_os_version, int):
            self.major_os_version = int(self.major_os_version)

        if self.minor_os_version is not None and not isinstance(self.minor_os_version, int):
            self.minor_os_version = int(self.minor_os_version)

        if self.major_image_version is not None and not isinstance(self.major_image_version, int):
            self.major_image_version = int(self.major_image_version)

        if self.minor_image_version is not None and not isinstance(self.minor_image_version, int):
            self.minor_image_version = int(self.minor_image_version)

        if self.major_subsystem_version is not None and not isinstance(self.major_subsystem_version, int):
            self.major_subsystem_version = int(self.major_subsystem_version)

        if self.minor_subsystem_version is not None and not isinstance(self.minor_subsystem_version, int):
            self.minor_subsystem_version = int(self.minor_subsystem_version)

        if self.win32_version_value_hex is not None and not isinstance(self.win32_version_value_hex, StixHex):
            self.win32_version_value_hex = StixHex(self.win32_version_value_hex)

        if self.size_of_image is not None and not isinstance(self.size_of_image, int):
            self.size_of_image = int(self.size_of_image)

        if self.size_of_headers is not None and not isinstance(self.size_of_headers, int):
            self.size_of_headers = int(self.size_of_headers)

        if self.checksum_hex is not None and not isinstance(self.checksum_hex, StixHex):
            self.checksum_hex = StixHex(self.checksum_hex)

        if self.subsystem_hex is not None and not isinstance(self.subsystem_hex, StixHex):
            self.subsystem_hex = StixHex(self.subsystem_hex)

        if self.dll_characteristics_hex is not None and not isinstance(self.dll_characteristics_hex, StixHex):
            self.dll_characteristics_hex = StixHex(self.dll_characteristics_hex)

        if self.size_of_stack_reserve is not None and not isinstance(self.size_of_stack_reserve, int):
            self.size_of_stack_reserve = int(self.size_of_stack_reserve)

        if self.size_of_stack_commit is not None and not isinstance(self.size_of_stack_commit, int):
            self.size_of_stack_commit = int(self.size_of_stack_commit)

        if self.size_of_heap_reserve is not None and not isinstance(self.size_of_heap_reserve, int):
            self.size_of_heap_reserve = int(self.size_of_heap_reserve)

        if self.size_of_heap_commit is not None and not isinstance(self.size_of_heap_commit, int):
            self.size_of_heap_commit = int(self.size_of_heap_commit)

        if self.loader_flags_hex is not None and not isinstance(self.loader_flags_hex, StixHex):
            self.loader_flags_hex = StixHex(self.loader_flags_hex)

        if self.number_of_rva_and_sizes is not None and not isinstance(self.number_of_rva_and_sizes, int):
            self.number_of_rva_and_sizes = int(self.number_of_rva_and_sizes)

        if self.hashes is not None and not isinstance(self.hashes, StixHashes):
            self.hashes = StixHashes()

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixMimePart(YAMLRoot):
    """
    One MIME part of a multipart email body.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixMimePart"]
    class_class_curie: ClassVar[str] = "stix:StixMimePart"
    class_name: ClassVar[str] = "StixMimePart"
    class_model_uri: ClassVar[URIRef] = STIX.StixMimePart

    body: Optional[str] = None
    body_raw_ref: Optional[Union[str, StixArtifactId, StixFileId]] = None
    content_type: Optional[str] = None
    content_disposition: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.body is not None and not isinstance(self.body, str):
            self.body = str(self.body)

        if self.body_raw_ref is not None and not isinstance(self.body_raw_ref, (StixArtifactId, StixFileId)):
            value = self.body_raw_ref
            for _coerce in (lambda: StixArtifactId(value), lambda: StixFileId(value)):
                try:
                    self.body_raw_ref = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixArtifactId, StixFileId] could be constructed from {value!r} for slot body_raw_ref")

        if self.content_type is not None and not isinstance(self.content_type, str):
            self.content_type = str(self.content_type)

        if self.content_disposition is not None and not isinstance(self.content_disposition, str):
            self.content_disposition = str(self.content_disposition)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixWindowsRegistryValue(YAMLRoot):
    """
    A value found under a Windows registry key.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixWindowsRegistryValue"]
    class_class_curie: ClassVar[str] = "stix:StixWindowsRegistryValue"
    class_name: ClassVar[str] = "StixWindowsRegistryValue"
    class_model_uri: ClassVar[URIRef] = STIX.StixWindowsRegistryValue

    name: Optional[str] = None
    data: Optional[str] = None
    data_type: Optional[Union[str, "StixWindowsRegistryDatatype"]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.data is not None and not isinstance(self.data, str):
            self.data = str(self.data)

        if self.data_type is not None and not isinstance(self.data_type, StixWindowsRegistryDatatype):
            self.data_type = StixWindowsRegistryDatatype(self.data_type)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixX509V3Extensions(YAMLRoot):
    """
    The standard X.509 v3 extensions of a certificate.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixX509V3Extensions"]
    class_class_curie: ClassVar[str] = "stix:StixX509V3Extensions"
    class_name: ClassVar[str] = "StixX509V3Extensions"
    class_model_uri: ClassVar[URIRef] = STIX.StixX509V3Extensions

    basic_constraints: Optional[str] = None
    name_constraints: Optional[str] = None
    policy_constraints: Optional[str] = None
    key_usage: Optional[str] = None
    extended_key_usage: Optional[str] = None
    subject_key_identifier: Optional[str] = None
    authority_key_identifier: Optional[str] = None
    subject_alternative_name: Optional[str] = None
    issuer_alternative_name: Optional[str] = None
    subject_directory_attributes: Optional[str] = None
    crl_distribution_points: Optional[str] = None
    inhibit_any_policy: Optional[str] = None
    private_key_usage_period_not_before: Optional[Union[str, StixTimestamp]] = None
    private_key_usage_period_not_after: Optional[Union[str, StixTimestamp]] = None
    certificate_policies: Optional[str] = None
    policy_mappings: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self.basic_constraints is not None and not isinstance(self.basic_constraints, str):
            self.basic_constraints = str(self.basic_constraints)

        if self.name_constraints is not None and not isinstance(self.name_constraints, str):
            self.name_constraints = str(self.name_constraints)

        if self.policy_constraints is not None and not isinstance(self.policy_constraints, str):
            self.policy_constraints = str(self.policy_constraints)

        if self.key_usage is not None and not isinstance(self.key_usage, str):
            self.key_usage = str(self.key_usage)

        if self.extended_key_usage is not None and not isinstance(self.extended_key_usage, str):
            self.extended_key_usage = str(self.extended_key_usage)

        if self.subject_key_identifier is not None and not isinstance(self.subject_key_identifier, str):
            self.subject_key_identifier = str(self.subject_key_identifier)

        if self.authority_key_identifier is not None and not isinstance(self.authority_key_identifier, str):
            self.authority_key_identifier = str(self.authority_key_identifier)

        if self.subject_alternative_name is not None and not isinstance(self.subject_alternative_name, str):
            self.subject_alternative_name = str(self.subject_alternative_name)

        if self.issuer_alternative_name is not None and not isinstance(self.issuer_alternative_name, str):
            self.issuer_alternative_name = str(self.issuer_alternative_name)

        if self.subject_directory_attributes is not None and not isinstance(self.subject_directory_attributes, str):
            self.subject_directory_attributes = str(self.subject_directory_attributes)

        if self.crl_distribution_points is not None and not isinstance(self.crl_distribution_points, str):
            self.crl_distribution_points = str(self.crl_distribution_points)

        if self.inhibit_any_policy is not None and not isinstance(self.inhibit_any_policy, str):
            self.inhibit_any_policy = str(self.inhibit_any_policy)

        if self.private_key_usage_period_not_before is not None and not isinstance(self.private_key_usage_period_not_before, StixTimestamp):
            self.private_key_usage_period_not_before = StixTimestamp(self.private_key_usage_period_not_before)

        if self.private_key_usage_period_not_after is not None and not isinstance(self.private_key_usage_period_not_after, StixTimestamp):
            self.private_key_usage_period_not_after = StixTimestamp(self.private_key_usage_period_not_after)

        if self.certificate_policies is not None and not isinstance(self.certificate_policies, str):
            self.certificate_policies = str(self.certificate_policies)

        if self.policy_mappings is not None and not isinstance(self.policy_mappings, str):
            self.policy_mappings = str(self.policy_mappings)

        super().__post_init__(**kwargs)


class StixFileExtensions(YAMLRoot):
    """
    The extensions of a file: the predefined ntfs-ext, raster-image-ext, pdf-ext, archive-ext and
    windows-pebinary-ext, and extensions that an extension definition defines.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixFileExtensions"]
    class_class_curie: ClassVar[str] = "stix:StixFileExtensions"
    class_name: ClassVar[str] = "StixFileExtensions"
    class_model_uri: ClassVar[URIRef] = STIX.StixFileExtensions


class StixNetworkTrafficExtensions(YAMLRoot):
    """
    The extensions of network traffic: the predefined http-request-ext, icmp-ext, socket-ext and tcp-ext, and
    extensions that an extension definition defines.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixNetworkTrafficExtensions"]
    class_class_curie: ClassVar[str] = "stix:StixNetworkTrafficExtensions"
    class_name: ClassVar[str] = "StixNetworkTrafficExtensions"
    class_model_uri: ClassVar[URIRef] = STIX.StixNetworkTrafficExtensions


class StixProcessExtensions(YAMLRoot):
    """
    The extensions of a process: the predefined windows-process-ext and windows-service-ext, and extensions that an
    extension definition defines.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixProcessExtensions"]
    class_class_curie: ClassVar[str] = "stix:StixProcessExtensions"
    class_name: ClassVar[str] = "StixProcessExtensions"
    class_model_uri: ClassVar[URIRef] = STIX.StixProcessExtensions


class StixUserAccountExtensions(YAMLRoot):
    """
    The extensions of a user account: the predefined unix-account-ext, and extensions that an extension definition
    defines.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixUserAccountExtensions"]
    class_class_curie: ClassVar[str] = "stix:StixUserAccountExtensions"
    class_name: ClassVar[str] = "StixUserAccountExtensions"
    class_model_uri: ClassVar[URIRef] = STIX.StixUserAccountExtensions


class StixSocketOptions(YAMLRoot):
    """
    The options of a network socket, as a dictionary of option names, such as SO_RCVBUF, to integer values.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixSocketOptions"]
    class_class_curie: ClassVar[str] = "stix:StixSocketOptions"
    class_name: ClassVar[str] = "StixSocketOptions"
    class_model_uri: ClassVar[URIRef] = STIX.StixSocketOptions


class StixExifTags(YAMLRoot):
    """
    The EXIF tags of an image file, as a dictionary of tag names to string or integer values.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixExifTags"]
    class_class_curie: ClassVar[str] = "stix:StixExifTags"
    class_name: ClassVar[str] = "StixExifTags"
    class_model_uri: ClassVar[URIRef] = STIX.StixExifTags


class StixPdfDocumentInfo(YAMLRoot):
    """
    The document information dictionary of a PDF file, as a dictionary of string values.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixPdfDocumentInfo"]
    class_class_curie: ClassVar[str] = "stix:StixPdfDocumentInfo"
    class_name: ClassVar[str] = "StixPdfDocumentInfo"
    class_model_uri: ClassVar[URIRef] = STIX.StixPdfDocumentInfo


@dataclass(repr=False)
class StixAttackPattern(StixDomainObject):
    """
    Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixAttackPattern"]
    class_class_curie: ClassVar[str] = "stix:StixAttackPattern"
    class_name: ClassVar[str] = "StixAttackPattern"
    class_model_uri: ClassVar[URIRef] = STIX.StixAttackPattern

    id: Union[str, StixAttackPatternId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    aliases: Optional[Union[str, list[str]]] = empty_list()
    description: Optional[str] = None
    kill_chain_phases: Optional[Union[Union[dict, StixKillChainPhase], list[Union[dict, StixKillChainPhase]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixAttackPatternId):
            self.id = StixAttackPatternId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.aliases, list):
            self.aliases = [self.aliases] if self.aliases is not None else []
        self.aliases = [v if isinstance(v, str) else str(v) for v in self.aliases]

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        self._normalize_inlined_as_list(slot_name="kill_chain_phases", slot_type=StixKillChainPhase, key_name="kill_chain_name", keyed=False)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixCampaign(StixDomainObject):
    """
    A Campaign is a grouping of adversary behavior that describes a set of malicious activities or attacks that occur
    over a period of time against a specific set of targets.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixCampaign"]
    class_class_curie: ClassVar[str] = "stix:StixCampaign"
    class_name: ClassVar[str] = "StixCampaign"
    class_model_uri: ClassVar[URIRef] = STIX.StixCampaign

    id: Union[str, StixCampaignId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    description: Optional[str] = None
    aliases: Optional[Union[str, list[str]]] = empty_list()
    first_seen: Optional[Union[str, StixTimestamp]] = None
    last_seen: Optional[Union[str, StixTimestamp]] = None
    objective: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixCampaignId):
            self.id = StixCampaignId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if not isinstance(self.aliases, list):
            self.aliases = [self.aliases] if self.aliases is not None else []
        self.aliases = [v if isinstance(v, str) else str(v) for v in self.aliases]

        if self.first_seen is not None and not isinstance(self.first_seen, StixTimestamp):
            self.first_seen = StixTimestamp(self.first_seen)

        if self.last_seen is not None and not isinstance(self.last_seen, StixTimestamp):
            self.last_seen = StixTimestamp(self.last_seen)

        if self.objective is not None and not isinstance(self.objective, str):
            self.objective = str(self.objective)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixCourseOfAction(StixDomainObject):
    """
    A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixCourseOfAction"]
    class_class_curie: ClassVar[str] = "stix:StixCourseOfAction"
    class_name: ClassVar[str] = "StixCourseOfAction"
    class_model_uri: ClassVar[URIRef] = STIX.StixCourseOfAction

    id: Union[str, StixCourseOfActionId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    description: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixCourseOfActionId):
            self.id = StixCourseOfActionId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixGrouping(StixDomainObject):
    """
    A Grouping object explicitly asserts that the referenced STIX Objects have a shared content.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixGrouping"]
    class_class_curie: ClassVar[str] = "stix:StixGrouping"
    class_name: ClassVar[str] = "StixGrouping"
    class_model_uri: ClassVar[URIRef] = STIX.StixGrouping

    id: Union[str, StixGroupingId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    context: Union[str, "StixGroupingContext"] = None
    object_refs: Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]] = None
    type: str = None
    name: Optional[str] = None
    description: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixGroupingId):
            self.id = StixGroupingId(self.id)

        if self._is_empty(self.context):
            self.MissingRequiredField("context")
        if not isinstance(self.context, (StixGroupingContext, str)):
            value = self.context
            for _coerce in (lambda: StixGroupingContext(value), lambda: str(value)):
                try:
                    self.context = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixGroupingContext, str] could be constructed from {value!r} for slot context")

        if self._is_empty(self.object_refs):
            self.MissingRequiredField("object_refs")
        if not isinstance(self.object_refs, list):
            self.object_refs = [self.object_refs] if self.object_refs is not None else []
        self.object_refs = [v if isinstance(v, StixObjectId) else StixObjectId(v) for v in self.object_refs]

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixIncident(StixDomainObject):
    """
    The Incident object in STIX 2.1 is a stub, to be expanded in future STIX 2 releases.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixIncident"]
    class_class_curie: ClassVar[str] = "stix:StixIncident"
    class_name: ClassVar[str] = "StixIncident"
    class_model_uri: ClassVar[URIRef] = STIX.StixIncident

    id: Union[str, StixIncidentId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    description: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixIncidentId):
            self.id = StixIncidentId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixIndicator(StixDomainObject):
    """
    Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixIndicator"]
    class_class_curie: ClassVar[str] = "stix:StixIndicator"
    class_name: ClassVar[str] = "StixIndicator"
    class_model_uri: ClassVar[URIRef] = STIX.StixIndicator

    id: Union[str, StixIndicatorId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    pattern: str = None
    pattern_type: Union[str, "StixPatternType"] = None
    valid_from: Union[str, StixTimestamp] = None
    type: str = None
    indicator_types: Optional[Union[str, list[str]]] = empty_list()
    name: Optional[str] = None
    description: Optional[str] = None
    pattern_version: Optional[str] = None
    valid_until: Optional[Union[str, StixTimestamp]] = None
    kill_chain_phases: Optional[Union[Union[dict, StixKillChainPhase], list[Union[dict, StixKillChainPhase]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixIndicatorId):
            self.id = StixIndicatorId(self.id)

        if self._is_empty(self.pattern):
            self.MissingRequiredField("pattern")
        if not isinstance(self.pattern, str):
            self.pattern = str(self.pattern)

        if self._is_empty(self.pattern_type):
            self.MissingRequiredField("pattern_type")
        if not isinstance(self.pattern_type, (StixPatternType, str)):
            value = self.pattern_type
            for _coerce in (lambda: StixPatternType(value), lambda: str(value)):
                try:
                    self.pattern_type = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixPatternType, str] could be constructed from {value!r} for slot pattern_type")

        if self._is_empty(self.valid_from):
            self.MissingRequiredField("valid_from")
        if not isinstance(self.valid_from, StixTimestamp):
            self.valid_from = StixTimestamp(self.valid_from)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.indicator_types, list):
            self.indicator_types = [self.indicator_types] if self.indicator_types is not None else []
        self.indicator_types = [v if isinstance(v, str) else str(v) for v in self.indicator_types]

        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if self.pattern_version is not None and not isinstance(self.pattern_version, str):
            self.pattern_version = str(self.pattern_version)

        if self.valid_until is not None and not isinstance(self.valid_until, StixTimestamp):
            self.valid_until = StixTimestamp(self.valid_until)

        self._normalize_inlined_as_list(slot_name="kill_chain_phases", slot_type=StixKillChainPhase, key_name="kill_chain_name", keyed=False)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixInfrastructure(StixDomainObject):
    """
    Infrastructure objects describe systems, software services, and associated physical or virtual resources.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixInfrastructure"]
    class_class_curie: ClassVar[str] = "stix:StixInfrastructure"
    class_name: ClassVar[str] = "StixInfrastructure"
    class_model_uri: ClassVar[URIRef] = STIX.StixInfrastructure

    id: Union[str, StixInfrastructureId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    description: Optional[str] = None
    infrastructure_types: Optional[Union[str, list[str]]] = empty_list()
    aliases: Optional[Union[str, list[str]]] = empty_list()
    kill_chain_phases: Optional[Union[Union[dict, StixKillChainPhase], list[Union[dict, StixKillChainPhase]]]] = empty_list()
    first_seen: Optional[Union[str, StixTimestamp]] = None
    last_seen: Optional[Union[str, StixTimestamp]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixInfrastructureId):
            self.id = StixInfrastructureId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if not isinstance(self.infrastructure_types, list):
            self.infrastructure_types = [self.infrastructure_types] if self.infrastructure_types is not None else []
        self.infrastructure_types = [v if isinstance(v, str) else str(v) for v in self.infrastructure_types]

        if not isinstance(self.aliases, list):
            self.aliases = [self.aliases] if self.aliases is not None else []
        self.aliases = [v if isinstance(v, str) else str(v) for v in self.aliases]

        self._normalize_inlined_as_list(slot_name="kill_chain_phases", slot_type=StixKillChainPhase, key_name="kill_chain_name", keyed=False)

        if self.first_seen is not None and not isinstance(self.first_seen, StixTimestamp):
            self.first_seen = StixTimestamp(self.first_seen)

        if self.last_seen is not None and not isinstance(self.last_seen, StixTimestamp):
            self.last_seen = StixTimestamp(self.last_seen)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixIntrusionSet(StixDomainObject):
    """
    An Intrusion Set is a grouped set of adversary behavior and resources with common properties that is believed to
    be orchestrated by a single organization.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixIntrusionSet"]
    class_class_curie: ClassVar[str] = "stix:StixIntrusionSet"
    class_name: ClassVar[str] = "StixIntrusionSet"
    class_model_uri: ClassVar[URIRef] = STIX.StixIntrusionSet

    id: Union[str, StixIntrusionSetId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    description: Optional[str] = None
    aliases: Optional[Union[str, list[str]]] = empty_list()
    first_seen: Optional[Union[str, StixTimestamp]] = None
    last_seen: Optional[Union[str, StixTimestamp]] = None
    goals: Optional[Union[str, list[str]]] = empty_list()
    resource_level: Optional[Union[str, "StixAttackResourceLevel"]] = None
    primary_motivation: Optional[Union[str, "StixAttackMotivation"]] = None
    secondary_motivations: Optional[Union[str, list[str]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixIntrusionSetId):
            self.id = StixIntrusionSetId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if not isinstance(self.aliases, list):
            self.aliases = [self.aliases] if self.aliases is not None else []
        self.aliases = [v if isinstance(v, str) else str(v) for v in self.aliases]

        if self.first_seen is not None and not isinstance(self.first_seen, StixTimestamp):
            self.first_seen = StixTimestamp(self.first_seen)

        if self.last_seen is not None and not isinstance(self.last_seen, StixTimestamp):
            self.last_seen = StixTimestamp(self.last_seen)

        if not isinstance(self.goals, list):
            self.goals = [self.goals] if self.goals is not None else []
        self.goals = [v if isinstance(v, str) else str(v) for v in self.goals]

        if self.resource_level is not None and not isinstance(self.resource_level, (StixAttackResourceLevel, str)):
            value = self.resource_level
            for _coerce in (lambda: StixAttackResourceLevel(value), lambda: str(value)):
                try:
                    self.resource_level = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixAttackResourceLevel, str] could be constructed from {value!r} for slot resource_level")

        if self.primary_motivation is not None and not isinstance(self.primary_motivation, (StixAttackMotivation, str)):
            value = self.primary_motivation
            for _coerce in (lambda: StixAttackMotivation(value), lambda: str(value)):
                try:
                    self.primary_motivation = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixAttackMotivation, str] could be constructed from {value!r} for slot primary_motivation")

        if not isinstance(self.secondary_motivations, list):
            self.secondary_motivations = [self.secondary_motivations] if self.secondary_motivations is not None else []
        self.secondary_motivations = [v if isinstance(v, str) else str(v) for v in self.secondary_motivations]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixLocation(StixDomainObject):
    """
    A Location represents a geographic location. The location may be described as any, some or all of the following:
    region (e.g., North America), civic address (e.g. New York, US), latitude and longitude.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixLocation"]
    class_class_curie: ClassVar[str] = "stix:StixLocation"
    class_name: ClassVar[str] = "StixLocation"
    class_model_uri: ClassVar[URIRef] = STIX.StixLocation

    id: Union[str, StixLocationId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    type: str = None
    description: Optional[str] = None
    name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    precision: Optional[float] = None
    region: Optional[Union[str, "StixRegion"]] = None
    country: Optional[str] = None
    administrative_area: Optional[str] = None
    city: Optional[str] = None
    street_address: Optional[str] = None
    postal_code: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixLocationId):
            self.id = StixLocationId(self.id)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.latitude is not None and not isinstance(self.latitude, float):
            self.latitude = float(self.latitude)

        if self.longitude is not None and not isinstance(self.longitude, float):
            self.longitude = float(self.longitude)

        if self.precision is not None and not isinstance(self.precision, float):
            self.precision = float(self.precision)

        if self.region is not None and not isinstance(self.region, (StixRegion, str)):
            value = self.region
            for _coerce in (lambda: StixRegion(value), lambda: str(value)):
                try:
                    self.region = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixRegion, str] could be constructed from {value!r} for slot region")

        if self.country is not None and not isinstance(self.country, str):
            self.country = str(self.country)

        if self.administrative_area is not None and not isinstance(self.administrative_area, str):
            self.administrative_area = str(self.administrative_area)

        if self.city is not None and not isinstance(self.city, str):
            self.city = str(self.city)

        if self.street_address is not None and not isinstance(self.street_address, str):
            self.street_address = str(self.street_address)

        if self.postal_code is not None and not isinstance(self.postal_code, str):
            self.postal_code = str(self.postal_code)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixMalware(StixDomainObject):
    """
    Malware is a type of TTP that is also known as malicious code and malicious software, refers to a program that is
    inserted into a system, usually covertly, with the intent of compromising the confidentiality, integrity, or
    availability of the victim's data, applications, or operating system (OS) or of otherwise annoying or disrupting
    the victim.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixMalware"]
    class_class_curie: ClassVar[str] = "stix:StixMalware"
    class_name: ClassVar[str] = "StixMalware"
    class_model_uri: ClassVar[URIRef] = STIX.StixMalware

    id: Union[str, StixMalwareId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    is_family: Union[bool, Bool] = None
    type: str = None
    aliases: Optional[Union[str, list[str]]] = empty_list()
    first_seen: Optional[Union[str, StixTimestamp]] = None
    last_seen: Optional[Union[str, StixTimestamp]] = None
    operating_system_refs: Optional[Union[Union[str, StixSoftwareId], list[Union[str, StixSoftwareId]]]] = empty_list()
    architecture_execution_envs: Optional[Union[str, list[str]]] = empty_list()
    implementation_languages: Optional[Union[str, list[str]]] = empty_list()
    capabilities: Optional[Union[str, list[str]]] = empty_list()
    sample_refs: Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]] = empty_list()
    malware_types: Optional[Union[str, list[str]]] = empty_list()
    name: Optional[str] = None
    description: Optional[str] = None
    kill_chain_phases: Optional[Union[Union[dict, StixKillChainPhase], list[Union[dict, StixKillChainPhase]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixMalwareId):
            self.id = StixMalwareId(self.id)

        if self._is_empty(self.is_family):
            self.MissingRequiredField("is_family")
        if not isinstance(self.is_family, Bool):
            self.is_family = Bool(self.is_family)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.aliases, list):
            self.aliases = [self.aliases] if self.aliases is not None else []
        self.aliases = [v if isinstance(v, str) else str(v) for v in self.aliases]

        if self.first_seen is not None and not isinstance(self.first_seen, StixTimestamp):
            self.first_seen = StixTimestamp(self.first_seen)

        if self.last_seen is not None and not isinstance(self.last_seen, StixTimestamp):
            self.last_seen = StixTimestamp(self.last_seen)

        if not isinstance(self.operating_system_refs, list):
            self.operating_system_refs = [self.operating_system_refs] if self.operating_system_refs is not None else []
        self.operating_system_refs = [v if isinstance(v, StixSoftwareId) else StixSoftwareId(v) for v in self.operating_system_refs]

        if not isinstance(self.architecture_execution_envs, list):
            self.architecture_execution_envs = [self.architecture_execution_envs] if self.architecture_execution_envs is not None else []
        self.architecture_execution_envs = [v if isinstance(v, str) else str(v) for v in self.architecture_execution_envs]

        if not isinstance(self.implementation_languages, list):
            self.implementation_languages = [self.implementation_languages] if self.implementation_languages is not None else []
        self.implementation_languages = [v if isinstance(v, str) else str(v) for v in self.implementation_languages]

        if not isinstance(self.capabilities, list):
            self.capabilities = [self.capabilities] if self.capabilities is not None else []
        self.capabilities = [v if isinstance(v, str) else str(v) for v in self.capabilities]

        if not isinstance(self.sample_refs, list):
            self.sample_refs = [self.sample_refs] if self.sample_refs is not None else []
        self.sample_refs = [v if isinstance(v, StixCyberObservableObjectId) else StixCyberObservableObjectId(v) for v in self.sample_refs]

        if not isinstance(self.malware_types, list):
            self.malware_types = [self.malware_types] if self.malware_types is not None else []
        self.malware_types = [v if isinstance(v, str) else str(v) for v in self.malware_types]

        if self.name is not None and not isinstance(self.name, str):
            self.name = str(self.name)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        self._normalize_inlined_as_list(slot_name="kill_chain_phases", slot_type=StixKillChainPhase, key_name="kill_chain_name", keyed=False)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixMalwareAnalysis(StixDomainObject):
    """
    Malware Analysis captures the metadata and results of a particular analysis performed (static or dynamic) on the
    malware instance or family.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixMalwareAnalysis"]
    class_class_curie: ClassVar[str] = "stix:StixMalwareAnalysis"
    class_name: ClassVar[str] = "StixMalwareAnalysis"
    class_model_uri: ClassVar[URIRef] = STIX.StixMalwareAnalysis

    id: Union[str, StixMalwareAnalysisId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    product: str = None
    type: str = None
    version: Optional[str] = None
    configuration_version: Optional[str] = None
    modules: Optional[Union[str, list[str]]] = empty_list()
    analysis_engine_version: Optional[str] = None
    analysis_definition_version: Optional[str] = None
    submitted: Optional[Union[str, StixTimestamp]] = None
    analysis_started: Optional[Union[str, StixTimestamp]] = None
    analysis_ended: Optional[Union[str, StixTimestamp]] = None
    result_name: Optional[str] = None
    result: Optional[Union[str, "StixMalwareResult"]] = None
    host_vm_ref: Optional[Union[str, StixSoftwareId]] = None
    operating_system_ref: Optional[Union[str, StixSoftwareId]] = None
    installed_software_refs: Optional[Union[Union[str, StixSoftwareId], list[Union[str, StixSoftwareId]]]] = empty_list()
    analysis_sco_refs: Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]] = empty_list()
    sample_ref: Optional[Union[str, StixFileId, StixNetworkTrafficId, StixArtifactId]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixMalwareAnalysisId):
            self.id = StixMalwareAnalysisId(self.id)

        if self._is_empty(self.product):
            self.MissingRequiredField("product")
        if not isinstance(self.product, str):
            self.product = str(self.product)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.version is not None and not isinstance(self.version, str):
            self.version = str(self.version)

        if self.configuration_version is not None and not isinstance(self.configuration_version, str):
            self.configuration_version = str(self.configuration_version)

        if not isinstance(self.modules, list):
            self.modules = [self.modules] if self.modules is not None else []
        self.modules = [v if isinstance(v, str) else str(v) for v in self.modules]

        if self.analysis_engine_version is not None and not isinstance(self.analysis_engine_version, str):
            self.analysis_engine_version = str(self.analysis_engine_version)

        if self.analysis_definition_version is not None and not isinstance(self.analysis_definition_version, str):
            self.analysis_definition_version = str(self.analysis_definition_version)

        if self.submitted is not None and not isinstance(self.submitted, StixTimestamp):
            self.submitted = StixTimestamp(self.submitted)

        if self.analysis_started is not None and not isinstance(self.analysis_started, StixTimestamp):
            self.analysis_started = StixTimestamp(self.analysis_started)

        if self.analysis_ended is not None and not isinstance(self.analysis_ended, StixTimestamp):
            self.analysis_ended = StixTimestamp(self.analysis_ended)

        if self.result_name is not None and not isinstance(self.result_name, str):
            self.result_name = str(self.result_name)

        if self.result is not None and not isinstance(self.result, (StixMalwareResult, str)):
            value = self.result
            for _coerce in (lambda: StixMalwareResult(value), lambda: str(value)):
                try:
                    self.result = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixMalwareResult, str] could be constructed from {value!r} for slot result")

        if self.host_vm_ref is not None and not isinstance(self.host_vm_ref, StixSoftwareId):
            self.host_vm_ref = StixSoftwareId(self.host_vm_ref)

        if self.operating_system_ref is not None and not isinstance(self.operating_system_ref, StixSoftwareId):
            self.operating_system_ref = StixSoftwareId(self.operating_system_ref)

        if not isinstance(self.installed_software_refs, list):
            self.installed_software_refs = [self.installed_software_refs] if self.installed_software_refs is not None else []
        self.installed_software_refs = [v if isinstance(v, StixSoftwareId) else StixSoftwareId(v) for v in self.installed_software_refs]

        if not isinstance(self.analysis_sco_refs, list):
            self.analysis_sco_refs = [self.analysis_sco_refs] if self.analysis_sco_refs is not None else []
        self.analysis_sco_refs = [v if isinstance(v, StixCyberObservableObjectId) else StixCyberObservableObjectId(v) for v in self.analysis_sco_refs]

        if self.sample_ref is not None and not isinstance(self.sample_ref, (StixFileId, StixNetworkTrafficId, StixArtifactId)):
            value = self.sample_ref
            for _coerce in (lambda: StixFileId(value), lambda: StixNetworkTrafficId(value), lambda: StixArtifactId(value)):
                try:
                    self.sample_ref = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixFileId, StixNetworkTrafficId, StixArtifactId] could be constructed from {value!r} for slot sample_ref")

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixNote(StixDomainObject):
    """
    A Note is a comment or note containing informative text to help explain the context of one or more STIX Objects
    (SDOs or SROs) or to provide additional analysis that is not contained in the original object.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixNote"]
    class_class_curie: ClassVar[str] = "stix:StixNote"
    class_name: ClassVar[str] = "StixNote"
    class_model_uri: ClassVar[URIRef] = STIX.StixNote

    id: Union[str, StixNoteId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    content: str = None
    object_refs: Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]] = None
    type: str = None
    abstract: Optional[str] = None
    authors: Optional[Union[str, list[str]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixNoteId):
            self.id = StixNoteId(self.id)

        if self._is_empty(self.content):
            self.MissingRequiredField("content")
        if not isinstance(self.content, str):
            self.content = str(self.content)

        if self._is_empty(self.object_refs):
            self.MissingRequiredField("object_refs")
        if not isinstance(self.object_refs, list):
            self.object_refs = [self.object_refs] if self.object_refs is not None else []
        self.object_refs = [v if isinstance(v, StixObjectId) else StixObjectId(v) for v in self.object_refs]

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.abstract is not None and not isinstance(self.abstract, str):
            self.abstract = str(self.abstract)

        if not isinstance(self.authors, list):
            self.authors = [self.authors] if self.authors is not None else []
        self.authors = [v if isinstance(v, str) else str(v) for v in self.authors]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixObservedData(StixDomainObject):
    """
    Observed data conveys information that was observed on systems and networks, such as log data or network traffic,
    using the Cyber Observable specification.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixObservedData"]
    class_class_curie: ClassVar[str] = "stix:StixObservedData"
    class_name: ClassVar[str] = "StixObservedData"
    class_model_uri: ClassVar[URIRef] = STIX.StixObservedData

    id: Union[str, StixObservedDataId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    first_observed: Union[str, StixTimestamp] = None
    last_observed: Union[str, StixTimestamp] = None
    number_observed: int = None
    type: str = None
    objects: Optional[Union[dict, "StixObservedObjects"]] = None
    object_refs: Optional[Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixObservedDataId):
            self.id = StixObservedDataId(self.id)

        if self._is_empty(self.first_observed):
            self.MissingRequiredField("first_observed")
        if not isinstance(self.first_observed, StixTimestamp):
            self.first_observed = StixTimestamp(self.first_observed)

        if self._is_empty(self.last_observed):
            self.MissingRequiredField("last_observed")
        if not isinstance(self.last_observed, StixTimestamp):
            self.last_observed = StixTimestamp(self.last_observed)

        if self._is_empty(self.number_observed):
            self.MissingRequiredField("number_observed")
        if not isinstance(self.number_observed, int):
            self.number_observed = int(self.number_observed)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.objects is not None and not isinstance(self.objects, StixObservedObjects):
            self.objects = StixObservedObjects()

        if not isinstance(self.object_refs, list):
            self.object_refs = [self.object_refs] if self.object_refs is not None else []
        self.object_refs = [v if isinstance(v, StixObjectId) else StixObjectId(v) for v in self.object_refs]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixOpinion(StixDomainObject):
    """
    An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity
    and captures the level of agreement or disagreement using a fixed scale.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixOpinion"]
    class_class_curie: ClassVar[str] = "stix:StixOpinion"
    class_name: ClassVar[str] = "StixOpinion"
    class_model_uri: ClassVar[URIRef] = STIX.StixOpinion

    id: Union[str, StixOpinionId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    object_refs: Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]] = None
    opinion: Union[str, "StixAgreement"] = None
    type: str = None
    explanation: Optional[str] = None
    authors: Optional[Union[str, list[str]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixOpinionId):
            self.id = StixOpinionId(self.id)

        if self._is_empty(self.object_refs):
            self.MissingRequiredField("object_refs")
        if not isinstance(self.object_refs, list):
            self.object_refs = [self.object_refs] if self.object_refs is not None else []
        self.object_refs = [v if isinstance(v, StixObjectId) else StixObjectId(v) for v in self.object_refs]

        if self._is_empty(self.opinion):
            self.MissingRequiredField("opinion")
        if not isinstance(self.opinion, StixAgreement):
            self.opinion = StixAgreement(self.opinion)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.explanation is not None and not isinstance(self.explanation, str):
            self.explanation = str(self.explanation)

        if not isinstance(self.authors, list):
            self.authors = [self.authors] if self.authors is not None else []
        self.authors = [v if isinstance(v, str) else str(v) for v in self.authors]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixReport(StixDomainObject):
    """
    Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat
    actor, malware, or attack technique, including context and related details.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixReport"]
    class_class_curie: ClassVar[str] = "stix:StixReport"
    class_name: ClassVar[str] = "StixReport"
    class_model_uri: ClassVar[URIRef] = STIX.StixReport

    id: Union[str, StixReportId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    published: Union[str, StixTimestamp] = None
    object_refs: Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]] = None
    type: str = None
    report_types: Optional[Union[str, list[str]]] = empty_list()
    description: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixReportId):
            self.id = StixReportId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.published):
            self.MissingRequiredField("published")
        if not isinstance(self.published, StixTimestamp):
            self.published = StixTimestamp(self.published)

        if self._is_empty(self.object_refs):
            self.MissingRequiredField("object_refs")
        if not isinstance(self.object_refs, list):
            self.object_refs = [self.object_refs] if self.object_refs is not None else []
        self.object_refs = [v if isinstance(v, StixObjectId) else StixObjectId(v) for v in self.object_refs]

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.report_types, list):
            self.report_types = [self.report_types] if self.report_types is not None else []
        self.report_types = [v if isinstance(v, str) else str(v) for v in self.report_types]

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixThreatActor(StixDomainObject):
    """
    Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixThreatActor"]
    class_class_curie: ClassVar[str] = "stix:StixThreatActor"
    class_name: ClassVar[str] = "StixThreatActor"
    class_model_uri: ClassVar[URIRef] = STIX.StixThreatActor

    id: Union[str, StixThreatActorId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    threat_actor_types: Optional[Union[str, list[str]]] = empty_list()
    description: Optional[str] = None
    aliases: Optional[Union[str, list[str]]] = empty_list()
    roles: Optional[Union[str, list[str]]] = empty_list()
    goals: Optional[Union[str, list[str]]] = empty_list()
    first_seen: Optional[Union[str, StixTimestamp]] = None
    last_seen: Optional[Union[str, StixTimestamp]] = None
    sophistication: Optional[Union[str, "StixThreatActorSophistication"]] = None
    resource_level: Optional[Union[str, "StixAttackResourceLevel"]] = None
    primary_motivation: Optional[Union[str, "StixAttackMotivation"]] = None
    secondary_motivations: Optional[Union[str, list[str]]] = empty_list()
    personal_motivations: Optional[Union[str, list[str]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixThreatActorId):
            self.id = StixThreatActorId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.threat_actor_types, list):
            self.threat_actor_types = [self.threat_actor_types] if self.threat_actor_types is not None else []
        self.threat_actor_types = [v if isinstance(v, str) else str(v) for v in self.threat_actor_types]

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if not isinstance(self.aliases, list):
            self.aliases = [self.aliases] if self.aliases is not None else []
        self.aliases = [v if isinstance(v, str) else str(v) for v in self.aliases]

        if not isinstance(self.roles, list):
            self.roles = [self.roles] if self.roles is not None else []
        self.roles = [v if isinstance(v, str) else str(v) for v in self.roles]

        if not isinstance(self.goals, list):
            self.goals = [self.goals] if self.goals is not None else []
        self.goals = [v if isinstance(v, str) else str(v) for v in self.goals]

        if self.first_seen is not None and not isinstance(self.first_seen, StixTimestamp):
            self.first_seen = StixTimestamp(self.first_seen)

        if self.last_seen is not None and not isinstance(self.last_seen, StixTimestamp):
            self.last_seen = StixTimestamp(self.last_seen)

        if self.sophistication is not None and not isinstance(self.sophistication, (StixThreatActorSophistication, str)):
            value = self.sophistication
            for _coerce in (lambda: StixThreatActorSophistication(value), lambda: str(value)):
                try:
                    self.sophistication = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixThreatActorSophistication, str] could be constructed from {value!r} for slot sophistication")

        if self.resource_level is not None and not isinstance(self.resource_level, (StixAttackResourceLevel, str)):
            value = self.resource_level
            for _coerce in (lambda: StixAttackResourceLevel(value), lambda: str(value)):
                try:
                    self.resource_level = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixAttackResourceLevel, str] could be constructed from {value!r} for slot resource_level")

        if self.primary_motivation is not None and not isinstance(self.primary_motivation, (StixAttackMotivation, str)):
            value = self.primary_motivation
            for _coerce in (lambda: StixAttackMotivation(value), lambda: str(value)):
                try:
                    self.primary_motivation = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixAttackMotivation, str] could be constructed from {value!r} for slot primary_motivation")

        if not isinstance(self.secondary_motivations, list):
            self.secondary_motivations = [self.secondary_motivations] if self.secondary_motivations is not None else []
        self.secondary_motivations = [v if isinstance(v, str) else str(v) for v in self.secondary_motivations]

        if not isinstance(self.personal_motivations, list):
            self.personal_motivations = [self.personal_motivations] if self.personal_motivations is not None else []
        self.personal_motivations = [v if isinstance(v, str) else str(v) for v in self.personal_motivations]

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixTool(StixDomainObject):
    """
    Tools are legitimate software that can be used by threat actors to perform attacks.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixTool"]
    class_class_curie: ClassVar[str] = "stix:StixTool"
    class_name: ClassVar[str] = "StixTool"
    class_model_uri: ClassVar[URIRef] = STIX.StixTool

    id: Union[str, StixToolId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    aliases: Optional[Union[str, list[str]]] = empty_list()
    tool_types: Optional[Union[str, list[str]]] = empty_list()
    description: Optional[str] = None
    tool_version: Optional[str] = None
    kill_chain_phases: Optional[Union[Union[dict, StixKillChainPhase], list[Union[dict, StixKillChainPhase]]]] = empty_list()

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixToolId):
            self.id = StixToolId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if not isinstance(self.aliases, list):
            self.aliases = [self.aliases] if self.aliases is not None else []
        self.aliases = [v if isinstance(v, str) else str(v) for v in self.aliases]

        if not isinstance(self.tool_types, list):
            self.tool_types = [self.tool_types] if self.tool_types is not None else []
        self.tool_types = [v if isinstance(v, str) else str(v) for v in self.tool_types]

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if self.tool_version is not None and not isinstance(self.tool_version, str):
            self.tool_version = str(self.tool_version)

        self._normalize_inlined_as_list(slot_name="kill_chain_phases", slot_type=StixKillChainPhase, key_name="kill_chain_name", keyed=False)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixVulnerability(StixDomainObject):
    """
    A Vulnerability is a mistake in software that can be directly used by a hacker to gain access to a system or
    network.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixVulnerability"]
    class_class_curie: ClassVar[str] = "stix:StixVulnerability"
    class_name: ClassVar[str] = "StixVulnerability"
    class_model_uri: ClassVar[URIRef] = STIX.StixVulnerability

    id: Union[str, StixVulnerabilityId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    name: str = None
    type: str = None
    description: Optional[str] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixVulnerabilityId):
            self.id = StixVulnerabilityId(self.id)

        if self._is_empty(self.name):
            self.MissingRequiredField("name")
        if not isinstance(self.name, str):
            self.name = str(self.name)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        super().__post_init__(**kwargs)


class StixObservedObjects(YAMLRoot):
    """
    The cyber-observable objects of an observed data object, keyed by an index such as "0". STIX 2.1 deprecates this
    form in favour of object_refs.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixObservedObjects"]
    class_class_curie: ClassVar[str] = "stix:StixObservedObjects"
    class_name: ClassVar[str] = "StixObservedObjects"
    class_model_uri: ClassVar[URIRef] = STIX.StixObservedObjects


@dataclass(repr=False)
class StixRelationship(StixRelationshipObject):
    """
    The Relationship object is used to link together two SDOs in order to describe how they are related to each other.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixRelationship"]
    class_class_curie: ClassVar[str] = "stix:StixRelationship"
    class_name: ClassVar[str] = "StixRelationship"
    class_model_uri: ClassVar[URIRef] = STIX.StixRelationship

    id: Union[str, StixRelationshipId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    relationship_type: str = None
    source_ref: Union[str, StixDomainObjectId, StixCyberObservableObjectId] = None
    target_ref: Union[str, StixDomainObjectId, StixCyberObservableObjectId] = None
    type: str = None
    description: Optional[str] = None
    start_time: Optional[Union[str, StixTimestamp]] = None
    stop_time: Optional[Union[str, StixTimestamp]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixRelationshipId):
            self.id = StixRelationshipId(self.id)

        if self._is_empty(self.relationship_type):
            self.MissingRequiredField("relationship_type")
        if not isinstance(self.relationship_type, str):
            self.relationship_type = str(self.relationship_type)

        if self._is_empty(self.source_ref):
            self.MissingRequiredField("source_ref")
        if not isinstance(self.source_ref, (StixDomainObjectId, StixCyberObservableObjectId)):
            value = self.source_ref
            for _coerce in (lambda: StixDomainObjectId(value), lambda: StixCyberObservableObjectId(value)):
                try:
                    self.source_ref = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixDomainObjectId, StixCyberObservableObjectId] could be constructed from {value!r} for slot source_ref")

        if self._is_empty(self.target_ref):
            self.MissingRequiredField("target_ref")
        if not isinstance(self.target_ref, (StixDomainObjectId, StixCyberObservableObjectId)):
            value = self.target_ref
            for _coerce in (lambda: StixDomainObjectId(value), lambda: StixCyberObservableObjectId(value)):
                try:
                    self.target_ref = _coerce()
                    break
                except (ValueError, TypeError):
                    continue
            else:
                raise ValueError(f"None of the candidate types Union[StixDomainObjectId, StixCyberObservableObjectId] could be constructed from {value!r} for slot target_ref")

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if self.start_time is not None and not isinstance(self.start_time, StixTimestamp):
            self.start_time = StixTimestamp(self.start_time)

        if self.stop_time is not None and not isinstance(self.stop_time, StixTimestamp):
            self.stop_time = StixTimestamp(self.stop_time)

        super().__post_init__(**kwargs)


@dataclass(repr=False)
class StixSighting(StixRelationshipObject):
    """
    A Sighting denotes the belief that something in CTI (e.g., an indicator, malware, tool, threat actor, etc.) was
    seen.
    """
    _inherited_slots: ClassVar[list[str]] = []

    class_class_uri: ClassVar[URIRef] = STIX["StixSighting"]
    class_class_curie: ClassVar[str] = "stix:StixSighting"
    class_name: ClassVar[str] = "StixSighting"
    class_model_uri: ClassVar[URIRef] = STIX.StixSighting

    id: Union[str, StixSightingId] = None
    created: Union[str, StixTimestampMillis] = None
    modified: Union[str, StixTimestampMillis] = None
    spec_version: Union[str, "StixSpecVersion"] = None
    sighting_of_ref: Union[str, StixDomainObjectId] = None
    type: str = None
    description: Optional[str] = None
    first_seen: Optional[Union[str, StixTimestamp]] = None
    last_seen: Optional[Union[str, StixTimestamp]] = None
    count: Optional[int] = None
    observed_data_refs: Optional[Union[Union[str, StixObservedDataId], list[Union[str, StixObservedDataId]]]] = empty_list()
    where_sighted_refs: Optional[Union[Union[str, StixDomainObjectId], list[Union[str, StixDomainObjectId]]]] = empty_list()
    summary: Optional[Union[bool, Bool]] = None

    def __post_init__(self, *_: str, **kwargs: Any):
        if self._is_empty(self.id):
            self.MissingRequiredField("id")
        if not isinstance(self.id, StixSightingId):
            self.id = StixSightingId(self.id)

        if self._is_empty(self.sighting_of_ref):
            self.MissingRequiredField("sighting_of_ref")
        if not isinstance(self.sighting_of_ref, StixDomainObjectId):
            self.sighting_of_ref = StixDomainObjectId(self.sighting_of_ref)

        if self._is_empty(self.type):
            self.MissingRequiredField("type")
        if not isinstance(self.type, str):
            self.type = str(self.type)

        if self.description is not None and not isinstance(self.description, str):
            self.description = str(self.description)

        if self.first_seen is not None and not isinstance(self.first_seen, StixTimestamp):
            self.first_seen = StixTimestamp(self.first_seen)

        if self.last_seen is not None and not isinstance(self.last_seen, StixTimestamp):
            self.last_seen = StixTimestamp(self.last_seen)

        if self.count is not None and not isinstance(self.count, int):
            self.count = int(self.count)

        if not isinstance(self.observed_data_refs, list):
            self.observed_data_refs = [self.observed_data_refs] if self.observed_data_refs is not None else []
        self.observed_data_refs = [v if isinstance(v, StixObservedDataId) else StixObservedDataId(v) for v in self.observed_data_refs]

        if not isinstance(self.where_sighted_refs, list):
            self.where_sighted_refs = [self.where_sighted_refs] if self.where_sighted_refs is not None else []
        self.where_sighted_refs = [v if isinstance(v, StixDomainObjectId) else StixDomainObjectId(v) for v in self.where_sighted_refs]

        if self.summary is not None and not isinstance(self.summary, Bool):
            self.summary = Bool(self.summary)

        super().__post_init__(**kwargs)


# Enumerations
class StixAccountType(EnumDefinitionImpl):
    """
    Types of user account. An open vocabulary: a slot that names it also takes any other string.
    """
    facebook = PermissibleValue(text="facebook")
    ldap = PermissibleValue(text="ldap")
    nis = PermissibleValue(text="nis")
    openid = PermissibleValue(text="openid")
    radius = PermissibleValue(text="radius")
    skype = PermissibleValue(text="skype")
    tacacs = PermissibleValue(text="tacacs")
    twitter = PermissibleValue(text="twitter")
    unix = PermissibleValue(text="unix")

    _defn = EnumDefinition(
        name="StixAccountType",
        description="Types of user account. An open vocabulary: a slot that names it also takes any other string.",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "windows-local",
            PermissibleValue(text="windows-local"))
        setattr(cls, "windows-domain",
            PermissibleValue(text="windows-domain"))

class StixAttackMotivation(EnumDefinitionImpl):
    """
    Reasons, motivations or purposes behind an attack. An open vocabulary: a slot that names it also takes any other
    string.
    """
    accidental = PermissibleValue(text="accidental")
    coercion = PermissibleValue(text="coercion")
    dominance = PermissibleValue(text="dominance")
    ideology = PermissibleValue(text="ideology")
    notoriety = PermissibleValue(text="notoriety")
    revenge = PermissibleValue(text="revenge")
    unpredictable = PermissibleValue(text="unpredictable")

    _defn = EnumDefinition(
        name="StixAttackMotivation",
        description="""Reasons, motivations or purposes behind an attack. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "organizational-gain",
            PermissibleValue(text="organizational-gain"))
        setattr(cls, "personal-gain",
            PermissibleValue(text="personal-gain"))
        setattr(cls, "personal-satisfaction",
            PermissibleValue(text="personal-satisfaction"))

class StixAttackResourceLevel(EnumDefinitionImpl):
    """
    Levels of the resources that an actor may have, from an individual to a government. An open vocabulary: a slot
    that names it also takes any other string.
    """
    individual = PermissibleValue(text="individual")
    club = PermissibleValue(text="club")
    contest = PermissibleValue(text="contest")
    team = PermissibleValue(text="team")
    organization = PermissibleValue(text="organization")
    government = PermissibleValue(text="government")

    _defn = EnumDefinition(
        name="StixAttackResourceLevel",
        description="""Levels of the resources that an actor may have, from an individual to a government. An open vocabulary: a slot that names it also takes any other string.""",
    )

class StixEncryptionAlgorithm(EnumDefinitionImpl):
    """
    Encryption algorithms for sharing defanged or confidential artifacts. A closed enumeration: no other value is
    valid.
    """
    _defn = EnumDefinition(
        name="StixEncryptionAlgorithm",
        description="""Encryption algorithms for sharing defanged or confidential artifacts. A closed enumeration: no other value is valid.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "AES-256-GCM",
            PermissibleValue(text="AES-256-GCM"))
        setattr(cls, "ChaCha20-Poly1305",
            PermissibleValue(text="ChaCha20-Poly1305"))
        setattr(cls, "mime-type-indicated",
            PermissibleValue(text="mime-type-indicated"))

class StixExtensionType(EnumDefinitionImpl):
    """
    The kinds of extension that an extension definition can define. A closed enumeration: no other value is valid.
    """
    _defn = EnumDefinition(
        name="StixExtensionType",
        description="""The kinds of extension that an extension definition can define. A closed enumeration: no other value is valid.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "new-sdo",
            PermissibleValue(text="new-sdo"))
        setattr(cls, "new-sco",
            PermissibleValue(text="new-sco"))
        setattr(cls, "new-sro",
            PermissibleValue(text="new-sro"))
        setattr(cls, "property-extension",
            PermissibleValue(text="property-extension"))
        setattr(cls, "toplevel-property-extension",
            PermissibleValue(text="toplevel-property-extension"))

class StixGroupingContext(EnumDefinitionImpl):
    """
    Contexts of a grouping. An open vocabulary: a slot that names it also takes any other string.
    """
    unspecified = PermissibleValue(text="unspecified")

    _defn = EnumDefinition(
        name="StixGroupingContext",
        description="Contexts of a grouping. An open vocabulary: a slot that names it also takes any other string.",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "suspicious-activity",
            PermissibleValue(text="suspicious-activity"))
        setattr(cls, "malware-analysis",
            PermissibleValue(text="malware-analysis"))

class StixHashAlgorithm(EnumDefinitionImpl):
    """
    Hash algorithms, as the keys of a hashes dictionary name them. An open vocabulary: a slot that names it also takes
    any other string.
    """
    MD5 = PermissibleValue(text="MD5")
    SSDEEP = PermissibleValue(text="SSDEEP")
    TLSH = PermissibleValue(text="TLSH")

    _defn = EnumDefinition(
        name="StixHashAlgorithm",
        description="""Hash algorithms, as the keys of a hashes dictionary name them. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "SHA-1",
            PermissibleValue(text="SHA-1"))
        setattr(cls, "SHA-256",
            PermissibleValue(text="SHA-256"))
        setattr(cls, "SHA-512",
            PermissibleValue(text="SHA-512"))
        setattr(cls, "SHA3-256",
            PermissibleValue(text="SHA3-256"))
        setattr(cls, "SHA3-512",
            PermissibleValue(text="SHA3-512"))

class StixIdentityClass(EnumDefinitionImpl):
    """
    Kinds of entity that an identity describes. An open vocabulary: a slot that names it also takes any other string.
    """
    individual = PermissibleValue(text="individual")
    group = PermissibleValue(text="group")
    system = PermissibleValue(text="system")
    organization = PermissibleValue(text="organization")
    unknown = PermissibleValue(text="unknown")

    _defn = EnumDefinition(
        name="StixIdentityClass",
        description="""Kinds of entity that an identity describes. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "class",
            PermissibleValue(text="class"))

class StixImplementationLanguage(EnumDefinitionImpl):
    """
    Programming languages in which malware may be implemented. An open vocabulary: a slot that names it also takes any
    other string.
    """
    applescript = PermissibleValue(text="applescript")
    bash = PermissibleValue(text="bash")
    c = PermissibleValue(text="c")
    go = PermissibleValue(text="go")
    java = PermissibleValue(text="java")
    javascript = PermissibleValue(text="javascript")
    lua = PermissibleValue(text="lua")
    perl = PermissibleValue(text="perl")
    php = PermissibleValue(text="php")
    powershell = PermissibleValue(text="powershell")
    python = PermissibleValue(text="python")
    ruby = PermissibleValue(text="ruby")
    scala = PermissibleValue(text="scala")
    swift = PermissibleValue(text="swift")
    typescript = PermissibleValue(text="typescript")

    _defn = EnumDefinition(
        name="StixImplementationLanguage",
        description="""Programming languages in which malware may be implemented. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "c++",
            PermissibleValue(text="c++"))
        setattr(cls, "c#",
            PermissibleValue(text="c#"))
        setattr(cls, "objective-c",
            PermissibleValue(text="objective-c"))
        setattr(cls, "visual-basic",
            PermissibleValue(text="visual-basic"))
        setattr(cls, "x86-32",
            PermissibleValue(text="x86-32"))
        setattr(cls, "x86-64",
            PermissibleValue(text="x86-64"))

class StixIndicatorType(EnumDefinitionImpl):
    """
    High-level categories of indicator. An open vocabulary: a slot that names it also takes any other string.
    """
    anonymization = PermissibleValue(text="anonymization")
    benign = PermissibleValue(text="benign")
    compromised = PermissibleValue(text="compromised")
    attribution = PermissibleValue(text="attribution")
    unknown = PermissibleValue(text="unknown")

    _defn = EnumDefinition(
        name="StixIndicatorType",
        description="""High-level categories of indicator. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "anomalous-activity",
            PermissibleValue(text="anomalous-activity"))
        setattr(cls, "malicious-activity",
            PermissibleValue(text="malicious-activity"))

class StixIndustrySector(EnumDefinitionImpl):
    """
    Industrial and commercial sectors. An open vocabulary: a slot that names it also takes any other string.
    """
    agriculture = PermissibleValue(text="agriculture")
    aerospace = PermissibleValue(text="aerospace")
    automotive = PermissibleValue(text="automotive")
    chemical = PermissibleValue(text="chemical")
    commercial = PermissibleValue(text="commercial")
    communications = PermissibleValue(text="communications")
    construction = PermissibleValue(text="construction")
    defense = PermissibleValue(text="defense")
    education = PermissibleValue(text="education")
    energy = PermissibleValue(text="energy")
    entertainment = PermissibleValue(text="entertainment")
    government = PermissibleValue(text="government")
    healthcare = PermissibleValue(text="healthcare")
    infrastructure = PermissibleValue(text="infrastructure")
    dams = PermissibleValue(text="dams")
    nuclear = PermissibleValue(text="nuclear")
    water = PermissibleValue(text="water")
    insurance = PermissibleValue(text="insurance")
    manufacturing = PermissibleValue(text="manufacturing")
    mining = PermissibleValue(text="mining")
    pharmaceuticals = PermissibleValue(text="pharmaceuticals")
    retail = PermissibleValue(text="retail")
    technology = PermissibleValue(text="technology")
    telecommunications = PermissibleValue(text="telecommunications")
    transportation = PermissibleValue(text="transportation")
    utilities = PermissibleValue(text="utilities")

    _defn = EnumDefinition(
        name="StixIndustrySector",
        description="""Industrial and commercial sectors. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "financial-services",
            PermissibleValue(text="financial-services"))
        setattr(cls, "emergency-services",
            PermissibleValue(text="emergency-services"))
        setattr(cls, "government-local",
            PermissibleValue(text="government-local"))
        setattr(cls, "government-national",
            PermissibleValue(text="government-national"))
        setattr(cls, "government-public-services",
            PermissibleValue(text="government-public-services"))
        setattr(cls, "government-regional",
            PermissibleValue(text="government-regional"))
        setattr(cls, "hospitality-leisure",
            PermissibleValue(text="hospitality-leisure"))
        setattr(cls, "non-profit",
            PermissibleValue(text="non-profit"))

class StixInfrastructureType(EnumDefinitionImpl):
    """
    Types of infrastructure. An open vocabulary: a slot that names it also takes any other string.
    """
    amplification = PermissibleValue(text="amplification")
    anonymization = PermissibleValue(text="anonymization")
    botnet = PermissibleValue(text="botnet")
    exfiltration = PermissibleValue(text="exfiltration")
    firewall = PermissibleValue(text="firewall")
    phishing = PermissibleValue(text="phishing")
    reconnaissance = PermissibleValue(text="reconnaissance")
    staging = PermissibleValue(text="staging")
    workstation = PermissibleValue(text="workstation")
    unknown = PermissibleValue(text="unknown")

    _defn = EnumDefinition(
        name="StixInfrastructureType",
        description="Types of infrastructure. An open vocabulary: a slot that names it also takes any other string.",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "command-and-control",
            PermissibleValue(text="command-and-control"))
        setattr(cls, "control-system",
            PermissibleValue(text="control-system"))
        setattr(cls, "hosting-malware",
            PermissibleValue(text="hosting-malware"))
        setattr(cls, "hosting-target-lists",
            PermissibleValue(text="hosting-target-lists"))
        setattr(cls, "routers-switches",
            PermissibleValue(text="routers-switches"))

class StixMalwareResult(EnumDefinitionImpl):
    """
    Results of a scanner's or tool's analysis of malware. An open vocabulary: a slot that names it also takes any
    other string.
    """
    malicious = PermissibleValue(text="malicious")
    suspicious = PermissibleValue(text="suspicious")
    benign = PermissibleValue(text="benign")
    unknown = PermissibleValue(text="unknown")

    _defn = EnumDefinition(
        name="StixMalwareResult",
        description="""Results of a scanner's or tool's analysis of malware. An open vocabulary: a slot that names it also takes any other string.""",
    )

class StixMalwareCapability(EnumDefinitionImpl):
    """
    Capabilities that malware may have. An open vocabulary: a slot that names it also takes any other string.
    """
    _defn = EnumDefinition(
        name="StixMalwareCapability",
        description="""Capabilities that malware may have. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "accesses-remote-machines",
            PermissibleValue(text="accesses-remote-machines"))
        setattr(cls, "anti-debugging",
            PermissibleValue(text="anti-debugging"))
        setattr(cls, "anti-disassembly",
            PermissibleValue(text="anti-disassembly"))
        setattr(cls, "anti-emulation",
            PermissibleValue(text="anti-emulation"))
        setattr(cls, "anti-memory-forensics",
            PermissibleValue(text="anti-memory-forensics"))
        setattr(cls, "anti-sandbox",
            PermissibleValue(text="anti-sandbox"))
        setattr(cls, "anti-vm",
            PermissibleValue(text="anti-vm"))
        setattr(cls, "captures-input-peripherals",
            PermissibleValue(text="captures-input-peripherals"))
        setattr(cls, "captures-output-peripherals",
            PermissibleValue(text="captures-output-peripherals"))
        setattr(cls, "captures-system-state-data",
            PermissibleValue(text="captures-system-state-data"))
        setattr(cls, "cleans-traces-of-infection",
            PermissibleValue(text="cleans-traces-of-infection"))
        setattr(cls, "commits-fraud",
            PermissibleValue(text="commits-fraud"))
        setattr(cls, "communicates-with-c2",
            PermissibleValue(text="communicates-with-c2"))
        setattr(cls, "compromises-data-availability",
            PermissibleValue(text="compromises-data-availability"))
        setattr(cls, "compromises-data-integrity",
            PermissibleValue(text="compromises-data-integrity"))
        setattr(cls, "compromises-system-availability",
            PermissibleValue(text="compromises-system-availability"))
        setattr(cls, "controls-local-machine",
            PermissibleValue(text="controls-local-machine"))
        setattr(cls, "degrades-security-software",
            PermissibleValue(text="degrades-security-software"))
        setattr(cls, "degrades-system-updates",
            PermissibleValue(text="degrades-system-updates"))
        setattr(cls, "determines-c2-server",
            PermissibleValue(text="determines-c2-server"))
        setattr(cls, "emails-spam",
            PermissibleValue(text="emails-spam"))
        setattr(cls, "escalates-privileges",
            PermissibleValue(text="escalates-privileges"))
        setattr(cls, "evades-av",
            PermissibleValue(text="evades-av"))
        setattr(cls, "exfiltrates-data",
            PermissibleValue(text="exfiltrates-data"))
        setattr(cls, "fingerprints-host",
            PermissibleValue(text="fingerprints-host"))
        setattr(cls, "hides-artifacts",
            PermissibleValue(text="hides-artifacts"))
        setattr(cls, "hides-executing-code",
            PermissibleValue(text="hides-executing-code"))
        setattr(cls, "infects-files",
            PermissibleValue(text="infects-files"))
        setattr(cls, "infects-remote-machines",
            PermissibleValue(text="infects-remote-machines"))
        setattr(cls, "installs-other-components",
            PermissibleValue(text="installs-other-components"))
        setattr(cls, "persists-after-system-reboot",
            PermissibleValue(text="persists-after-system-reboot"))
        setattr(cls, "prevents-artifact-access",
            PermissibleValue(text="prevents-artifact-access"))
        setattr(cls, "prevents-artifact-deletion",
            PermissibleValue(text="prevents-artifact-deletion"))
        setattr(cls, "probes-network-environment",
            PermissibleValue(text="probes-network-environment"))
        setattr(cls, "self-modifies",
            PermissibleValue(text="self-modifies"))
        setattr(cls, "steals-authentication-credentials",
            PermissibleValue(text="steals-authentication-credentials"))
        setattr(cls, "violates-system-operational-integrity",
            PermissibleValue(text="violates-system-operational-integrity"))

class StixMalwareType(EnumDefinitionImpl):
    """
    Types of malware. An open vocabulary: a slot that names it also takes any other string.
    """
    adware = PermissibleValue(text="adware")
    backdoor = PermissibleValue(text="backdoor")
    bot = PermissibleValue(text="bot")
    bootkit = PermissibleValue(text="bootkit")
    ddos = PermissibleValue(text="ddos")
    downloader = PermissibleValue(text="downloader")
    dropper = PermissibleValue(text="dropper")
    keylogger = PermissibleValue(text="keylogger")
    ransomware = PermissibleValue(text="ransomware")
    rootkit = PermissibleValue(text="rootkit")
    spyware = PermissibleValue(text="spyware")
    trojan = PermissibleValue(text="trojan")
    unknown = PermissibleValue(text="unknown")
    virus = PermissibleValue(text="virus")
    webshell = PermissibleValue(text="webshell")
    wiper = PermissibleValue(text="wiper")
    worm = PermissibleValue(text="worm")

    _defn = EnumDefinition(
        name="StixMalwareType",
        description="Types of malware. An open vocabulary: a slot that names it also takes any other string.",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "exploit-kit",
            PermissibleValue(text="exploit-kit"))
        setattr(cls, "remote-access-trojan",
            PermissibleValue(text="remote-access-trojan"))
        setattr(cls, "resource-exploitation",
            PermissibleValue(text="resource-exploitation"))
        setattr(cls, "rogue-security-software",
            PermissibleValue(text="rogue-security-software"))
        setattr(cls, "screen-capture",
            PermissibleValue(text="screen-capture"))

class StixNetworkSocketAddressFamily(EnumDefinitionImpl):
    """
    Address families of a network socket. A closed enumeration: no other value is valid.
    """
    AF_UNSPEC = PermissibleValue(text="AF_UNSPEC")
    AF_INET = PermissibleValue(text="AF_INET")
    AF_IPX = PermissibleValue(text="AF_IPX")
    AF_APPLETALK = PermissibleValue(text="AF_APPLETALK")
    AF_NETBIOS = PermissibleValue(text="AF_NETBIOS")
    AF_INET6 = PermissibleValue(text="AF_INET6")
    AF_IRDA = PermissibleValue(text="AF_IRDA")
    AF_BTH = PermissibleValue(text="AF_BTH")

    _defn = EnumDefinition(
        name="StixNetworkSocketAddressFamily",
        description="Address families of a network socket. A closed enumeration: no other value is valid.",
    )

class StixNetworkSocketType(EnumDefinitionImpl):
    """
    Types of network socket. A closed enumeration: no other value is valid.
    """
    SOCK_STREAM = PermissibleValue(text="SOCK_STREAM")
    SOCK_DGRAM = PermissibleValue(text="SOCK_DGRAM")
    SOCK_RAW = PermissibleValue(text="SOCK_RAW")
    SOCK_RDM = PermissibleValue(text="SOCK_RDM")
    SOCK_SEQPACKET = PermissibleValue(text="SOCK_SEQPACKET")

    _defn = EnumDefinition(
        name="StixNetworkSocketType",
        description="Types of network socket. A closed enumeration: no other value is valid.",
    )

class StixAgreement(EnumDefinitionImpl):
    """
    Degrees of agreement with the information in a STIX object, from disagreement to agreement. A closed enumeration:
    no other value is valid.
    """
    disagree = PermissibleValue(text="disagree")
    neutral = PermissibleValue(text="neutral")
    agree = PermissibleValue(text="agree")

    _defn = EnumDefinition(
        name="StixAgreement",
        description="""Degrees of agreement with the information in a STIX object, from disagreement to agreement. A closed enumeration: no other value is valid.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "strongly-disagree",
            PermissibleValue(text="strongly-disagree"))
        setattr(cls, "strongly-agree",
            PermissibleValue(text="strongly-agree"))

class StixPatternType(EnumDefinitionImpl):
    """
    Pattern languages in which an indicator's pattern may be written. An open vocabulary: a slot that names it also
    takes any other string.
    """
    stix = PermissibleValue(text="stix")
    pcre = PermissibleValue(text="pcre")
    sigma = PermissibleValue(text="sigma")
    snort = PermissibleValue(text="snort")
    suricata = PermissibleValue(text="suricata")
    yara = PermissibleValue(text="yara")

    _defn = EnumDefinition(
        name="StixPatternType",
        description="""Pattern languages in which an indicator's pattern may be written. An open vocabulary: a slot that names it also takes any other string.""",
    )

class StixProcessorArchitecture(EnumDefinitionImpl):
    """
    Processor architectures. An open vocabulary: a slot that names it also takes any other string.
    """
    alpha = PermissibleValue(text="alpha")
    arm = PermissibleValue(text="arm")
    mips = PermissibleValue(text="mips")
    powerpc = PermissibleValue(text="powerpc")
    sparc = PermissibleValue(text="sparc")
    x86 = PermissibleValue(text="x86")

    _defn = EnumDefinition(
        name="StixProcessorArchitecture",
        description="Processor architectures. An open vocabulary: a slot that names it also takes any other string.",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "ia-64",
            PermissibleValue(text="ia-64"))
        setattr(cls, "x86-64",
            PermissibleValue(text="x86-64"))

class StixRegion(EnumDefinitionImpl):
    """
    World regions, after the United Nations geoscheme (UNSD M49). An open vocabulary: a slot that names it also takes
    any other string.
    """
    africa = PermissibleValue(text="africa")
    americas = PermissibleValue(text="americas")
    caribbean = PermissibleValue(text="caribbean")
    asia = PermissibleValue(text="asia")
    europe = PermissibleValue(text="europe")
    oceania = PermissibleValue(text="oceania")
    antarctica = PermissibleValue(text="antarctica")
    melanesia = PermissibleValue(text="melanesia")
    micronesia = PermissibleValue(text="micronesia")
    polynesia = PermissibleValue(text="polynesia")

    _defn = EnumDefinition(
        name="StixRegion",
        description="""World regions, after the United Nations geoscheme (UNSD M49). An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "eastern-africa",
            PermissibleValue(text="eastern-africa"))
        setattr(cls, "middle-africa",
            PermissibleValue(text="middle-africa"))
        setattr(cls, "northern-africa",
            PermissibleValue(text="northern-africa"))
        setattr(cls, "southern-africa",
            PermissibleValue(text="southern-africa"))
        setattr(cls, "western-africa",
            PermissibleValue(text="western-africa"))
        setattr(cls, "central-america",
            PermissibleValue(text="central-america"))
        setattr(cls, "latin-america-caribbean",
            PermissibleValue(text="latin-america-caribbean"))
        setattr(cls, "northern-america",
            PermissibleValue(text="northern-america"))
        setattr(cls, "south-america",
            PermissibleValue(text="south-america"))
        setattr(cls, "central-asia",
            PermissibleValue(text="central-asia"))
        setattr(cls, "eastern-asia",
            PermissibleValue(text="eastern-asia"))
        setattr(cls, "southern-asia",
            PermissibleValue(text="southern-asia"))
        setattr(cls, "south-eastern-asia",
            PermissibleValue(text="south-eastern-asia"))
        setattr(cls, "western-asia",
            PermissibleValue(text="western-asia"))
        setattr(cls, "eastern-europe",
            PermissibleValue(text="eastern-europe"))
        setattr(cls, "northern-europe",
            PermissibleValue(text="northern-europe"))
        setattr(cls, "southern-europe",
            PermissibleValue(text="southern-europe"))
        setattr(cls, "western-europe",
            PermissibleValue(text="western-europe"))
        setattr(cls, "australia-new-zealand",
            PermissibleValue(text="australia-new-zealand"))

class StixReportType(EnumDefinitionImpl):
    """
    Primary subjects of a report. An open vocabulary: a slot that names it also takes any other string.
    """
    campaign = PermissibleValue(text="campaign")
    identity = PermissibleValue(text="identity")
    indicator = PermissibleValue(text="indicator")
    malware = PermissibleValue(text="malware")
    tool = PermissibleValue(text="tool")
    vulnerability = PermissibleValue(text="vulnerability")

    _defn = EnumDefinition(
        name="StixReportType",
        description="Primary subjects of a report. An open vocabulary: a slot that names it also takes any other string.",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "attack-pattern",
            PermissibleValue(text="attack-pattern"))
        setattr(cls, "intrusion-set",
            PermissibleValue(text="intrusion-set"))
        setattr(cls, "observed-data",
            PermissibleValue(text="observed-data"))
        setattr(cls, "threat-actor",
            PermissibleValue(text="threat-actor"))
        setattr(cls, "threat-report",
            PermissibleValue(text="threat-report"))

class StixThreatActorType(EnumDefinitionImpl):
    """
    Types of threat actor. An open vocabulary: a slot that names it also takes any other string.
    """
    activist = PermissibleValue(text="activist")
    competitor = PermissibleValue(text="competitor")
    criminal = PermissibleValue(text="criminal")
    hacker = PermissibleValue(text="hacker")
    sensationalist = PermissibleValue(text="sensationalist")
    spy = PermissibleValue(text="spy")
    terrorist = PermissibleValue(text="terrorist")
    unknown = PermissibleValue(text="unknown")

    _defn = EnumDefinition(
        name="StixThreatActorType",
        description="Types of threat actor. An open vocabulary: a slot that names it also takes any other string.",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "crime-syndicate",
            PermissibleValue(text="crime-syndicate"))
        setattr(cls, "insider-accidental",
            PermissibleValue(text="insider-accidental"))
        setattr(cls, "insider-disgruntled",
            PermissibleValue(text="insider-disgruntled"))
        setattr(cls, "nation-state",
            PermissibleValue(text="nation-state"))

class StixThreatActorRole(EnumDefinitionImpl):
    """
    Roles that a threat actor may play. An open vocabulary: a slot that names it also takes any other string.
    """
    agent = PermissibleValue(text="agent")
    director = PermissibleValue(text="director")
    independent = PermissibleValue(text="independent")
    sponsor = PermissibleValue(text="sponsor")

    _defn = EnumDefinition(
        name="StixThreatActorRole",
        description="""Roles that a threat actor may play. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "infrastructure-architect",
            PermissibleValue(text="infrastructure-architect"))
        setattr(cls, "infrastructure-operator",
            PermissibleValue(text="infrastructure-operator"))
        setattr(cls, "malware-author",
            PermissibleValue(text="malware-author"))

class StixThreatActorSophistication(EnumDefinitionImpl):
    """
    Skill levels of a threat actor. An open vocabulary: a slot that names it also takes any other string.
    """
    none = PermissibleValue(text="none")
    minimal = PermissibleValue(text="minimal")
    intermediate = PermissibleValue(text="intermediate")
    advanced = PermissibleValue(text="advanced")
    expert = PermissibleValue(text="expert")
    innovator = PermissibleValue(text="innovator")
    strategic = PermissibleValue(text="strategic")

    _defn = EnumDefinition(
        name="StixThreatActorSophistication",
        description="""Skill levels of a threat actor. An open vocabulary: a slot that names it also takes any other string.""",
    )

class StixToolType(EnumDefinitionImpl):
    """
    Categories of tool that may be used to perform attacks. An open vocabulary: a slot that names it also takes any
    other string.
    """
    exploitation = PermissibleValue(text="exploitation")
    unknown = PermissibleValue(text="unknown")

    _defn = EnumDefinition(
        name="StixToolType",
        description="""Categories of tool that may be used to perform attacks. An open vocabulary: a slot that names it also takes any other string.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "denial-of-service",
            PermissibleValue(text="denial-of-service"))
        setattr(cls, "information-gathering",
            PermissibleValue(text="information-gathering"))
        setattr(cls, "network-capture",
            PermissibleValue(text="network-capture"))
        setattr(cls, "credential-exploitation",
            PermissibleValue(text="credential-exploitation"))
        setattr(cls, "remote-access",
            PermissibleValue(text="remote-access"))
        setattr(cls, "vulnerability-scanning",
            PermissibleValue(text="vulnerability-scanning"))

class StixWindowsIntegrityLevel(EnumDefinitionImpl):
    """
    Windows integrity levels. A closed enumeration: no other value is valid.
    """
    low = PermissibleValue(text="low")
    medium = PermissibleValue(text="medium")
    high = PermissibleValue(text="high")
    system = PermissibleValue(text="system")

    _defn = EnumDefinition(
        name="StixWindowsIntegrityLevel",
        description="Windows integrity levels. A closed enumeration: no other value is valid.",
    )

class StixWindowsPeBinaryType(EnumDefinitionImpl):
    """
    Types of Windows PE binary. An open vocabulary: a slot that names it also takes any other string.
    """
    dll = PermissibleValue(text="dll")
    exe = PermissibleValue(text="exe")
    sys = PermissibleValue(text="sys")

    _defn = EnumDefinition(
        name="StixWindowsPeBinaryType",
        description="Types of Windows PE binary. An open vocabulary: a slot that names it also takes any other string.",
    )

class StixWindowsRegistryDatatype(EnumDefinitionImpl):
    """
    Data types of a Windows registry value. A closed enumeration: no other value is valid.
    """
    REG_NONE = PermissibleValue(text="REG_NONE")
    REG_SZ = PermissibleValue(text="REG_SZ")
    REG_EXPAND_SZ = PermissibleValue(text="REG_EXPAND_SZ")
    REG_BINARY = PermissibleValue(text="REG_BINARY")
    REG_DWORD = PermissibleValue(text="REG_DWORD")
    REG_DWORD_BIG_ENDIAN = PermissibleValue(text="REG_DWORD_BIG_ENDIAN")
    REG_DWORD_LITTLE_ENDIAN = PermissibleValue(text="REG_DWORD_LITTLE_ENDIAN")
    REG_LINK = PermissibleValue(text="REG_LINK")
    REG_MULTI_SZ = PermissibleValue(text="REG_MULTI_SZ")
    REG_RESOURCE_LIST = PermissibleValue(text="REG_RESOURCE_LIST")
    REG_FULL_RESOURCE_DESCRIPTION = PermissibleValue(text="REG_FULL_RESOURCE_DESCRIPTION")
    REG_RESOURCE_REQUIREMENTS_LIST = PermissibleValue(text="REG_RESOURCE_REQUIREMENTS_LIST")
    REG_QWORD = PermissibleValue(text="REG_QWORD")
    REG_INVALID_TYPE = PermissibleValue(text="REG_INVALID_TYPE")

    _defn = EnumDefinition(
        name="StixWindowsRegistryDatatype",
        description="Data types of a Windows registry value. A closed enumeration: no other value is valid.",
    )

class StixWindowsServiceStartType(EnumDefinitionImpl):
    """
    Start types of a Windows service. A closed enumeration: no other value is valid.
    """
    SERVICE_AUTO_START = PermissibleValue(text="SERVICE_AUTO_START")
    SERVICE_BOOT_START = PermissibleValue(text="SERVICE_BOOT_START")
    SERVICE_DEMAND_START = PermissibleValue(text="SERVICE_DEMAND_START")
    SERVICE_DISABLED = PermissibleValue(text="SERVICE_DISABLED")
    SERVICE_SYSTEM_ALERT = PermissibleValue(text="SERVICE_SYSTEM_ALERT")

    _defn = EnumDefinition(
        name="StixWindowsServiceStartType",
        description="Start types of a Windows service. A closed enumeration: no other value is valid.",
    )

class StixWindowsServiceType(EnumDefinitionImpl):
    """
    Types of Windows service. A closed enumeration: no other value is valid.
    """
    SERVICE_KERNEL_DRIVER = PermissibleValue(text="SERVICE_KERNEL_DRIVER")
    SERVICE_FILE_SYSTEM_DRIVER = PermissibleValue(text="SERVICE_FILE_SYSTEM_DRIVER")
    SERVICE_WIN32_OWN_PROCESS = PermissibleValue(text="SERVICE_WIN32_OWN_PROCESS")
    SERVICE_WIN32_SHARE_PROCESS = PermissibleValue(text="SERVICE_WIN32_SHARE_PROCESS")

    _defn = EnumDefinition(
        name="StixWindowsServiceType",
        description="Types of Windows service. A closed enumeration: no other value is valid.",
    )

class StixWindowsServiceStatus(EnumDefinitionImpl):
    """
    Statuses of a Windows service. A closed enumeration: no other value is valid.
    """
    SERVICE_CONTINUE_PENDING = PermissibleValue(text="SERVICE_CONTINUE_PENDING")
    SERVICE_PAUSE_PENDING = PermissibleValue(text="SERVICE_PAUSE_PENDING")
    SERVICE_PAUSED = PermissibleValue(text="SERVICE_PAUSED")
    SERVICE_RUNNING = PermissibleValue(text="SERVICE_RUNNING")
    SERVICE_START_PENDING = PermissibleValue(text="SERVICE_START_PENDING")
    SERVICE_STOP_PENDING = PermissibleValue(text="SERVICE_STOP_PENDING")
    SERVICE_STOPPED = PermissibleValue(text="SERVICE_STOPPED")

    _defn = EnumDefinition(
        name="StixWindowsServiceStatus",
        description="Statuses of a Windows service. A closed enumeration: no other value is valid.",
    )

class StixSpecVersion(EnumDefinitionImpl):
    """
    The STIX versions that an object may declare. The JSON schemas accept 2.0 beside 2.1. A closed enumeration.
    """
    _defn = EnumDefinition(
        name="StixSpecVersion",
        description="""The STIX versions that an object may declare. The JSON schemas accept 2.0 beside 2.1. A closed enumeration.""",
    )

    @classmethod
    def _addvals(cls):
        setattr(cls, "2.0",
            PermissibleValue(text="2.0"))
        setattr(cls, "2.1",
            PermissibleValue(text="2.1"))

class StixTlpLevel(EnumDefinitionImpl):
    """
    The four levels of the Traffic Light Protocol (TLP) that STIX 2.1 defines marking definitions for. A closed
    enumeration.
    """
    white = PermissibleValue(text="white")
    green = PermissibleValue(text="green")
    amber = PermissibleValue(text="amber")
    red = PermissibleValue(text="red")

    _defn = EnumDefinition(
        name="StixTlpLevel",
        description="""The four levels of the Traffic Light Protocol (TLP) that STIX 2.1 defines marking definitions for. A closed enumeration.""",
    )

class StixMarkingDefinitionType(EnumDefinitionImpl):
    """
    The marking definition types that STIX 2.1 defines, statement and tlp. A slot that names it also takes any other
    string, as the JSON schemas do.
    """
    statement = PermissibleValue(text="statement")
    tlp = PermissibleValue(text="tlp")

    _defn = EnumDefinition(
        name="StixMarkingDefinitionType",
        description="""The marking definition types that STIX 2.1 defines, statement and tlp. A slot that names it also takes any other string, as the JSON schemas do.""",
    )

# Slots
class slots:
    pass

slots.id = Slot(uri=STIX.id, name="id", curie=STIX.curie('id'),
                   model_uri=STIX.id, domain=None, range=URIRef)

slots.type = Slot(uri=STIX.type, name="type", curie=STIX.curie('type'),
                   model_uri=STIX.type, domain=None, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.spec_version = Slot(uri=STIX.spec_version, name="spec_version", curie=STIX.curie('spec_version'),
                   model_uri=STIX.spec_version, domain=None, range=Optional[Union[str, "StixSpecVersion"]])

slots.object_marking_refs = Slot(uri=STIX.object_marking_refs, name="object_marking_refs", curie=STIX.curie('object_marking_refs'),
                   model_uri=STIX.object_marking_refs, domain=None, range=Optional[Union[Union[str, StixMarkingDefinitionId], list[Union[str, StixMarkingDefinitionId]]]],
                   pattern=re.compile(r'^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.granular_markings = Slot(uri=STIX.granular_markings, name="granular_markings", curie=STIX.curie('granular_markings'),
                   model_uri=STIX.granular_markings, domain=None, range=Optional[Union[Union[dict, StixGranularMarking], list[Union[dict, StixGranularMarking]]]])

slots.extensions = Slot(uri=STIX.extensions, name="extensions", curie=STIX.curie('extensions'),
                   model_uri=STIX.extensions, domain=None, range=Optional[Union[dict, StixExtensions]])

slots.created_by_ref = Slot(uri=STIX.created_by_ref, name="created_by_ref", curie=STIX.curie('created_by_ref'),
                   model_uri=STIX.created_by_ref, domain=None, range=Optional[Union[str, StixIdentityId]],
                   pattern=re.compile(r'^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.created = Slot(uri=STIX.created, name="created", curie=STIX.curie('created'),
                   model_uri=STIX.created, domain=None, range=Optional[Union[str, StixTimestampMillis]])

slots.modified = Slot(uri=STIX.modified, name="modified", curie=STIX.curie('modified'),
                   model_uri=STIX.modified, domain=None, range=Optional[Union[str, StixTimestampMillis]])

slots.revoked = Slot(uri=STIX.revoked, name="revoked", curie=STIX.curie('revoked'),
                   model_uri=STIX.revoked, domain=None, range=Optional[Union[bool, Bool]])

slots.labels = Slot(uri=STIX.labels, name="labels", curie=STIX.curie('labels'),
                   model_uri=STIX.labels, domain=None, range=Optional[Union[str, list[str]]])

slots.confidence = Slot(uri=STIX.confidence, name="confidence", curie=STIX.curie('confidence'),
                   model_uri=STIX.confidence, domain=None, range=Optional[int])

slots.lang = Slot(uri=STIX.lang, name="lang", curie=STIX.curie('lang'),
                   model_uri=STIX.lang, domain=None, range=Optional[str])

slots.external_references = Slot(uri=STIX.external_references, name="external_references", curie=STIX.curie('external_references'),
                   model_uri=STIX.external_references, domain=None, range=Optional[Union[Union[dict, StixExternalReference], list[Union[dict, StixExternalReference]]]])

slots.defanged = Slot(uri=STIX.defanged, name="defanged", curie=STIX.curie('defanged'),
                   model_uri=STIX.defanged, domain=None, range=Optional[Union[bool, Bool]])

slots.roles = Slot(uri=STIX.roles, name="roles", curie=STIX.curie('roles'),
                   model_uri=STIX.roles, domain=None, range=Optional[Union[str, list[str]]])

slots.name = Slot(uri=STIX.name, name="name", curie=STIX.curie('name'),
                   model_uri=STIX.name, domain=None, range=Optional[str])

slots.description = Slot(uri=STIX.description, name="description", curie=STIX.curie('description'),
                   model_uri=STIX.description, domain=None, range=Optional[str])

slots.identity_class = Slot(uri=STIX.identity_class, name="identity_class", curie=STIX.curie('identity_class'),
                   model_uri=STIX.identity_class, domain=None, range=Optional[Union[str, "StixIdentityClass"]])

slots.sectors = Slot(uri=STIX.sectors, name="sectors", curie=STIX.curie('sectors'),
                   model_uri=STIX.sectors, domain=None, range=Optional[Union[str, list[str]]])

slots.contact_information = Slot(uri=STIX.contact_information, name="contact_information", curie=STIX.curie('contact_information'),
                   model_uri=STIX.contact_information, domain=None, range=Optional[str])

slots.definition_type = Slot(uri=STIX.definition_type, name="definition_type", curie=STIX.curie('definition_type'),
                   model_uri=STIX.definition_type, domain=None, range=Optional[Union[str, "StixMarkingDefinitionType"]])

slots.definition = Slot(uri=STIX.definition, name="definition", curie=STIX.curie('definition'),
                   model_uri=STIX.definition, domain=None, range=Optional[Union[dict, StixStatementMarking, StixTlpMarking]])

slots.object_ref = Slot(uri=STIX.object_ref, name="object_ref", curie=STIX.curie('object_ref'),
                   model_uri=STIX.object_ref, domain=None, range=Optional[Union[str, StixObjectId]],
                   pattern=re.compile(r'^(?!(bundle|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.object_modified = Slot(uri=STIX.object_modified, name="object_modified", curie=STIX.curie('object_modified'),
                   model_uri=STIX.object_modified, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.contents = Slot(uri=STIX.contents, name="contents", curie=STIX.curie('contents'),
                   model_uri=STIX.contents, domain=None, range=Optional[Union[dict, StixLanguageContents]])

slots.schema = Slot(uri=STIX.schema, name="schema", curie=STIX.curie('schema'),
                   model_uri=STIX.schema, domain=None, range=Optional[str])

slots.version = Slot(uri=STIX.version, name="version", curie=STIX.curie('version'),
                   model_uri=STIX.version, domain=None, range=Optional[str])

slots.extension_types = Slot(uri=STIX.extension_types, name="extension_types", curie=STIX.curie('extension_types'),
                   model_uri=STIX.extension_types, domain=None, range=Optional[Union[Union[str, "StixExtensionType"], list[Union[str, "StixExtensionType"]]]])

slots.extension_properties = Slot(uri=STIX.extension_properties, name="extension_properties", curie=STIX.curie('extension_properties'),
                   model_uri=STIX.extension_properties, domain=None, range=Optional[Union[str, list[str]]])

slots.source_name = Slot(uri=STIX.source_name, name="source_name", curie=STIX.curie('source_name'),
                   model_uri=STIX.source_name, domain=None, range=Optional[str])

slots.url = Slot(uri=STIX.url, name="url", curie=STIX.curie('url'),
                   model_uri=STIX.url, domain=None, range=Optional[Union[str, URI]])

slots.hashes = Slot(uri=STIX.hashes, name="hashes", curie=STIX.curie('hashes'),
                   model_uri=STIX.hashes, domain=None, range=Optional[Union[dict, StixHashes]])

slots.external_id = Slot(uri=STIX.external_id, name="external_id", curie=STIX.curie('external_id'),
                   model_uri=STIX.external_id, domain=None, range=Optional[str])

slots.kill_chain_name = Slot(uri=STIX.kill_chain_name, name="kill_chain_name", curie=STIX.curie('kill_chain_name'),
                   model_uri=STIX.kill_chain_name, domain=None, range=Optional[str])

slots.phase_name = Slot(uri=STIX.phase_name, name="phase_name", curie=STIX.curie('phase_name'),
                   model_uri=STIX.phase_name, domain=None, range=Optional[str])

slots.marking_ref = Slot(uri=STIX.marking_ref, name="marking_ref", curie=STIX.curie('marking_ref'),
                   model_uri=STIX.marking_ref, domain=None, range=Optional[Union[str, StixMarkingDefinitionId]],
                   pattern=re.compile(r'^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.selectors = Slot(uri=STIX.selectors, name="selectors", curie=STIX.curie('selectors'),
                   model_uri=STIX.selectors, domain=None, range=Optional[Union[str, list[str]]],
                   pattern=re.compile(r'^([a-z0-9_-]{3,249}(\.(\[\d+\]|[a-z0-9_-]{1,250}))*|id)$'))

slots.statement = Slot(uri=STIX.statement, name="statement", curie=STIX.curie('statement'),
                   model_uri=STIX.statement, domain=None, range=Optional[str])

slots.tlp = Slot(uri=STIX.tlp, name="tlp", curie=STIX.curie('tlp'),
                   model_uri=STIX.tlp, domain=None, range=Optional[Union[str, "StixTlpLevel"]])

slots.extension_type = Slot(uri=STIX.extension_type, name="extension_type", curie=STIX.curie('extension_type'),
                   model_uri=STIX.extension_type, domain=None, range=Optional[Union[str, "StixExtensionType"]])

slots.objects = Slot(uri=STIX.objects, name="objects", curie=STIX.curie('objects'),
                   model_uri=STIX.objects, domain=None, range=Optional[str])

slots.mime_type = Slot(uri=STIX.mime_type, name="mime_type", curie=STIX.curie('mime_type'),
                   model_uri=STIX.mime_type, domain=None, range=Optional[str])

slots.payload_bin = Slot(uri=STIX.payload_bin, name="payload_bin", curie=STIX.curie('payload_bin'),
                   model_uri=STIX.payload_bin, domain=None, range=Optional[Union[str, StixBinary]])

slots.encryption_algorithm = Slot(uri=STIX.encryption_algorithm, name="encryption_algorithm", curie=STIX.curie('encryption_algorithm'),
                   model_uri=STIX.encryption_algorithm, domain=None, range=Optional[Union[str, "StixEncryptionAlgorithm"]])

slots.decryption_key = Slot(uri=STIX.decryption_key, name="decryption_key", curie=STIX.curie('decryption_key'),
                   model_uri=STIX.decryption_key, domain=None, range=Optional[str])

slots.number = Slot(uri=STIX.number, name="number", curie=STIX.curie('number'),
                   model_uri=STIX.number, domain=None, range=Optional[int])

slots.rir = Slot(uri=STIX.rir, name="rir", curie=STIX.curie('rir'),
                   model_uri=STIX.rir, domain=None, range=Optional[str])

slots.path = Slot(uri=STIX.path, name="path", curie=STIX.curie('path'),
                   model_uri=STIX.path, domain=None, range=Optional[str])

slots.path_enc = Slot(uri=STIX.path_enc, name="path_enc", curie=STIX.curie('path_enc'),
                   model_uri=STIX.path_enc, domain=None, range=Optional[str],
                   pattern=re.compile(r'^[a-zA-Z0-9/\.+_:-]{2,250}$'))

slots.ctime = Slot(uri=STIX.ctime, name="ctime", curie=STIX.curie('ctime'),
                   model_uri=STIX.ctime, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.mtime = Slot(uri=STIX.mtime, name="mtime", curie=STIX.curie('mtime'),
                   model_uri=STIX.mtime, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.atime = Slot(uri=STIX.atime, name="atime", curie=STIX.curie('atime'),
                   model_uri=STIX.atime, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.contains_refs = Slot(uri=STIX.contains_refs, name="contains_refs", curie=STIX.curie('contains_refs'),
                   model_uri=STIX.contains_refs, domain=None, range=Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]],
                   pattern=re.compile(r'^(?!(attack-pattern|campaign|course-of-action|grouping|identity|incident|indicator|infrastructure|intrusion-set|location|malware|malware-analysis|note|observed-data|opinion|report|threat-actor|tool|vulnerability|relationship|sighting|bundle|marking-definition|language-content|extension-definition)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.value = Slot(uri=STIX.value, name="value", curie=STIX.curie('value'),
                   model_uri=STIX.value, domain=None, range=Optional[str])

slots.resolves_to_refs = Slot(uri=STIX.resolves_to_refs, name="resolves_to_refs", curie=STIX.curie('resolves_to_refs'),
                   model_uri=STIX.resolves_to_refs, domain=None, range=Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]],
                   pattern=re.compile(r'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.display_name = Slot(uri=STIX.display_name, name="display_name", curie=STIX.curie('display_name'),
                   model_uri=STIX.display_name, domain=None, range=Optional[str])

slots.belongs_to_ref = Slot(uri=STIX.belongs_to_ref, name="belongs_to_ref", curie=STIX.curie('belongs_to_ref'),
                   model_uri=STIX.belongs_to_ref, domain=None, range=Optional[Union[str, StixUserAccountId]],
                   pattern=re.compile(r'^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.email_date = Slot(uri=STIX.date, name="email_date", curie=STIX.curie('date'),
                   model_uri=STIX.email_date, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.content_type = Slot(uri=STIX.content_type, name="content_type", curie=STIX.curie('content_type'),
                   model_uri=STIX.content_type, domain=None, range=Optional[str])

slots.from_ref = Slot(uri=STIX.from_ref, name="from_ref", curie=STIX.curie('from_ref'),
                   model_uri=STIX.from_ref, domain=None, range=Optional[Union[str, StixEmailAddressId]],
                   pattern=re.compile(r'^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.sender_ref = Slot(uri=STIX.sender_ref, name="sender_ref", curie=STIX.curie('sender_ref'),
                   model_uri=STIX.sender_ref, domain=None, range=Optional[Union[str, StixEmailAddressId]],
                   pattern=re.compile(r'^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.to_refs = Slot(uri=STIX.to_refs, name="to_refs", curie=STIX.curie('to_refs'),
                   model_uri=STIX.to_refs, domain=None, range=Optional[Union[Union[str, StixEmailAddressId], list[Union[str, StixEmailAddressId]]]],
                   pattern=re.compile(r'^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.cc_refs = Slot(uri=STIX.cc_refs, name="cc_refs", curie=STIX.curie('cc_refs'),
                   model_uri=STIX.cc_refs, domain=None, range=Optional[Union[Union[str, StixEmailAddressId], list[Union[str, StixEmailAddressId]]]],
                   pattern=re.compile(r'^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.bcc_refs = Slot(uri=STIX.bcc_refs, name="bcc_refs", curie=STIX.curie('bcc_refs'),
                   model_uri=STIX.bcc_refs, domain=None, range=Optional[Union[Union[str, StixEmailAddressId], list[Union[str, StixEmailAddressId]]]],
                   pattern=re.compile(r'^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.message_id = Slot(uri=STIX.message_id, name="message_id", curie=STIX.curie('message_id'),
                   model_uri=STIX.message_id, domain=None, range=Optional[str])

slots.subject = Slot(uri=STIX.subject, name="subject", curie=STIX.curie('subject'),
                   model_uri=STIX.subject, domain=None, range=Optional[str])

slots.received_lines = Slot(uri=STIX.received_lines, name="received_lines", curie=STIX.curie('received_lines'),
                   model_uri=STIX.received_lines, domain=None, range=Optional[Union[str, list[str]]])

slots.additional_header_fields = Slot(uri=STIX.additional_header_fields, name="additional_header_fields", curie=STIX.curie('additional_header_fields'),
                   model_uri=STIX.additional_header_fields, domain=None, range=Optional[Union[dict, StixDictionary]])

slots.raw_email_ref = Slot(uri=STIX.raw_email_ref, name="raw_email_ref", curie=STIX.curie('raw_email_ref'),
                   model_uri=STIX.raw_email_ref, domain=None, range=Optional[Union[str, StixArtifactId]],
                   pattern=re.compile(r'^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.is_multipart = Slot(uri=STIX.is_multipart, name="is_multipart", curie=STIX.curie('is_multipart'),
                   model_uri=STIX.is_multipart, domain=None, range=Optional[Union[bool, Bool]])

slots.body = Slot(uri=STIX.body, name="body", curie=STIX.curie('body'),
                   model_uri=STIX.body, domain=None, range=Optional[str])

slots.body_multipart = Slot(uri=STIX.body_multipart, name="body_multipart", curie=STIX.curie('body_multipart'),
                   model_uri=STIX.body_multipart, domain=None, range=Optional[Union[Union[dict, StixMimePart], list[Union[dict, StixMimePart]]]])

slots.size = Slot(uri=STIX.size, name="size", curie=STIX.curie('size'),
                   model_uri=STIX.size, domain=None, range=Optional[int])

slots.name_enc = Slot(uri=STIX.name_enc, name="name_enc", curie=STIX.curie('name_enc'),
                   model_uri=STIX.name_enc, domain=None, range=Optional[str],
                   pattern=re.compile(r'^[a-zA-Z0-9/\.+_:-]{2,250}$'))

slots.magic_number_hex = Slot(uri=STIX.magic_number_hex, name="magic_number_hex", curie=STIX.curie('magic_number_hex'),
                   model_uri=STIX.magic_number_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.parent_directory_ref = Slot(uri=STIX.parent_directory_ref, name="parent_directory_ref", curie=STIX.curie('parent_directory_ref'),
                   model_uri=STIX.parent_directory_ref, domain=None, range=Optional[Union[str, StixDirectoryId]],
                   pattern=re.compile(r'^directory--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.content_ref = Slot(uri=STIX.content_ref, name="content_ref", curie=STIX.curie('content_ref'),
                   model_uri=STIX.content_ref, domain=None, range=Optional[Union[str, StixArtifactId]],
                   pattern=re.compile(r'^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.belongs_to_refs = Slot(uri=STIX.belongs_to_refs, name="belongs_to_refs", curie=STIX.curie('belongs_to_refs'),
                   model_uri=STIX.belongs_to_refs, domain=None, range=Optional[Union[Union[str, StixAutonomousSystemId], list[Union[str, StixAutonomousSystemId]]]],
                   pattern=re.compile(r'^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.start = Slot(uri=STIX.start, name="start", curie=STIX.curie('start'),
                   model_uri=STIX.start, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.end = Slot(uri=STIX.end, name="end", curie=STIX.curie('end'),
                   model_uri=STIX.end, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.src_ref = Slot(uri=STIX.src_ref, name="src_ref", curie=STIX.curie('src_ref'),
                   model_uri=STIX.src_ref, domain=None, range=Optional[Union[str, StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId]],
                   pattern=re.compile(r'^(ipv4-addr|ipv6-addr|mac-addr|domain-name)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.dst_ref = Slot(uri=STIX.dst_ref, name="dst_ref", curie=STIX.curie('dst_ref'),
                   model_uri=STIX.dst_ref, domain=None, range=Optional[Union[str, StixIpv4AddressId, StixIpv6AddressId, StixMacAddressId, StixDomainNameId]],
                   pattern=re.compile(r'^(ipv4-addr|ipv6-addr|mac-addr|domain-name)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.src_port = Slot(uri=STIX.src_port, name="src_port", curie=STIX.curie('src_port'),
                   model_uri=STIX.src_port, domain=None, range=Optional[int])

slots.dst_port = Slot(uri=STIX.dst_port, name="dst_port", curie=STIX.curie('dst_port'),
                   model_uri=STIX.dst_port, domain=None, range=Optional[int])

slots.protocols = Slot(uri=STIX.protocols, name="protocols", curie=STIX.curie('protocols'),
                   model_uri=STIX.protocols, domain=None, range=Optional[Union[str, list[str]]])

slots.src_byte_count = Slot(uri=STIX.src_byte_count, name="src_byte_count", curie=STIX.curie('src_byte_count'),
                   model_uri=STIX.src_byte_count, domain=None, range=Optional[int])

slots.dst_byte_count = Slot(uri=STIX.dst_byte_count, name="dst_byte_count", curie=STIX.curie('dst_byte_count'),
                   model_uri=STIX.dst_byte_count, domain=None, range=Optional[int])

slots.src_packets = Slot(uri=STIX.src_packets, name="src_packets", curie=STIX.curie('src_packets'),
                   model_uri=STIX.src_packets, domain=None, range=Optional[int])

slots.dst_packets = Slot(uri=STIX.dst_packets, name="dst_packets", curie=STIX.curie('dst_packets'),
                   model_uri=STIX.dst_packets, domain=None, range=Optional[int])

slots.ipfix = Slot(uri=STIX.ipfix, name="ipfix", curie=STIX.curie('ipfix'),
                   model_uri=STIX.ipfix, domain=None, range=Optional[Union[dict, StixDictionary]])

slots.src_payload_ref = Slot(uri=STIX.src_payload_ref, name="src_payload_ref", curie=STIX.curie('src_payload_ref'),
                   model_uri=STIX.src_payload_ref, domain=None, range=Optional[Union[str, StixArtifactId]],
                   pattern=re.compile(r'^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.dst_payload_ref = Slot(uri=STIX.dst_payload_ref, name="dst_payload_ref", curie=STIX.curie('dst_payload_ref'),
                   model_uri=STIX.dst_payload_ref, domain=None, range=Optional[Union[str, StixArtifactId]],
                   pattern=re.compile(r'^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.encapsulates_refs = Slot(uri=STIX.encapsulates_refs, name="encapsulates_refs", curie=STIX.curie('encapsulates_refs'),
                   model_uri=STIX.encapsulates_refs, domain=None, range=Optional[Union[Union[str, StixNetworkTrafficId], list[Union[str, StixNetworkTrafficId]]]],
                   pattern=re.compile(r'^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.encapsulated_by_ref = Slot(uri=STIX.encapsulated_by_ref, name="encapsulated_by_ref", curie=STIX.curie('encapsulated_by_ref'),
                   model_uri=STIX.encapsulated_by_ref, domain=None, range=Optional[Union[str, StixNetworkTrafficId]],
                   pattern=re.compile(r'^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.is_active = Slot(uri=STIX.is_active, name="is_active", curie=STIX.curie('is_active'),
                   model_uri=STIX.is_active, domain=None, range=Optional[Union[bool, Bool]])

slots.is_hidden = Slot(uri=STIX.is_hidden, name="is_hidden", curie=STIX.curie('is_hidden'),
                   model_uri=STIX.is_hidden, domain=None, range=Optional[Union[bool, Bool]])

slots.pid = Slot(uri=STIX.pid, name="pid", curie=STIX.curie('pid'),
                   model_uri=STIX.pid, domain=None, range=Optional[int])

slots.created_time = Slot(uri=STIX.created_time, name="created_time", curie=STIX.curie('created_time'),
                   model_uri=STIX.created_time, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.cwd = Slot(uri=STIX.cwd, name="cwd", curie=STIX.curie('cwd'),
                   model_uri=STIX.cwd, domain=None, range=Optional[str])

slots.command_line = Slot(uri=STIX.command_line, name="command_line", curie=STIX.curie('command_line'),
                   model_uri=STIX.command_line, domain=None, range=Optional[str])

slots.environment_variables = Slot(uri=STIX.environment_variables, name="environment_variables", curie=STIX.curie('environment_variables'),
                   model_uri=STIX.environment_variables, domain=None, range=Optional[Union[dict, StixDictionary]])

slots.opened_connection_refs = Slot(uri=STIX.opened_connection_refs, name="opened_connection_refs", curie=STIX.curie('opened_connection_refs'),
                   model_uri=STIX.opened_connection_refs, domain=None, range=Optional[Union[Union[str, StixNetworkTrafficId], list[Union[str, StixNetworkTrafficId]]]],
                   pattern=re.compile(r'^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.creator_user_ref = Slot(uri=STIX.creator_user_ref, name="creator_user_ref", curie=STIX.curie('creator_user_ref'),
                   model_uri=STIX.creator_user_ref, domain=None, range=Optional[Union[str, StixUserAccountId]],
                   pattern=re.compile(r'^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.image_ref = Slot(uri=STIX.image_ref, name="image_ref", curie=STIX.curie('image_ref'),
                   model_uri=STIX.image_ref, domain=None, range=Optional[Union[str, StixFileId]],
                   pattern=re.compile(r'^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.parent_ref = Slot(uri=STIX.parent_ref, name="parent_ref", curie=STIX.curie('parent_ref'),
                   model_uri=STIX.parent_ref, domain=None, range=Optional[Union[str, StixProcessId]],
                   pattern=re.compile(r'^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.child_refs = Slot(uri=STIX.child_refs, name="child_refs", curie=STIX.curie('child_refs'),
                   model_uri=STIX.child_refs, domain=None, range=Optional[Union[Union[str, StixProcessId], list[Union[str, StixProcessId]]]],
                   pattern=re.compile(r'^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.cpe = Slot(uri=STIX.cpe, name="cpe", curie=STIX.curie('cpe'),
                   model_uri=STIX.cpe, domain=None, range=Optional[str],
                   pattern=re.compile(r'cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\x22#$$%&\x27\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\x22#$$%&\x27\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}'))

slots.swid = Slot(uri=STIX.swid, name="swid", curie=STIX.curie('swid'),
                   model_uri=STIX.swid, domain=None, range=Optional[str])

slots.languages = Slot(uri=STIX.languages, name="languages", curie=STIX.curie('languages'),
                   model_uri=STIX.languages, domain=None, range=Optional[Union[str, list[str]]],
                   pattern=re.compile(r'^([a-z]{2}(-[A-Z]{2})?(-[a-z]{4})?(-[A-Z]{2}|[0-9]{3})?(-[a-z0-9]{5,8}|[0-9][a-z0-9]{3})*(-[a-z0-9]{1,8})*|[a-z]{3})$'))

slots.vendor = Slot(uri=STIX.vendor, name="vendor", curie=STIX.curie('vendor'),
                   model_uri=STIX.vendor, domain=None, range=Optional[str])

slots.user_id = Slot(uri=STIX.user_id, name="user_id", curie=STIX.curie('user_id'),
                   model_uri=STIX.user_id, domain=None, range=Optional[str])

slots.credential = Slot(uri=STIX.credential, name="credential", curie=STIX.curie('credential'),
                   model_uri=STIX.credential, domain=None, range=Optional[str])

slots.account_login = Slot(uri=STIX.account_login, name="account_login", curie=STIX.curie('account_login'),
                   model_uri=STIX.account_login, domain=None, range=Optional[str])

slots.account_type = Slot(uri=STIX.account_type, name="account_type", curie=STIX.curie('account_type'),
                   model_uri=STIX.account_type, domain=None, range=Optional[Union[str, "StixAccountType"]])

slots.is_service_account = Slot(uri=STIX.is_service_account, name="is_service_account", curie=STIX.curie('is_service_account'),
                   model_uri=STIX.is_service_account, domain=None, range=Optional[Union[bool, Bool]])

slots.is_privileged = Slot(uri=STIX.is_privileged, name="is_privileged", curie=STIX.curie('is_privileged'),
                   model_uri=STIX.is_privileged, domain=None, range=Optional[Union[bool, Bool]])

slots.can_escalate_privs = Slot(uri=STIX.can_escalate_privs, name="can_escalate_privs", curie=STIX.curie('can_escalate_privs'),
                   model_uri=STIX.can_escalate_privs, domain=None, range=Optional[Union[bool, Bool]])

slots.is_disabled = Slot(uri=STIX.is_disabled, name="is_disabled", curie=STIX.curie('is_disabled'),
                   model_uri=STIX.is_disabled, domain=None, range=Optional[Union[bool, Bool]])

slots.account_created = Slot(uri=STIX.account_created, name="account_created", curie=STIX.curie('account_created'),
                   model_uri=STIX.account_created, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.account_expires = Slot(uri=STIX.account_expires, name="account_expires", curie=STIX.curie('account_expires'),
                   model_uri=STIX.account_expires, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.credential_last_changed = Slot(uri=STIX.credential_last_changed, name="credential_last_changed", curie=STIX.curie('credential_last_changed'),
                   model_uri=STIX.credential_last_changed, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.account_first_login = Slot(uri=STIX.account_first_login, name="account_first_login", curie=STIX.curie('account_first_login'),
                   model_uri=STIX.account_first_login, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.account_last_login = Slot(uri=STIX.account_last_login, name="account_last_login", curie=STIX.curie('account_last_login'),
                   model_uri=STIX.account_last_login, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.key = Slot(uri=STIX.key, name="key", curie=STIX.curie('key'),
                   model_uri=STIX.key, domain=None, range=Optional[str])

slots.values = Slot(uri=STIX.values, name="values", curie=STIX.curie('values'),
                   model_uri=STIX.values, domain=None, range=Optional[Union[Union[dict, StixWindowsRegistryValue], list[Union[dict, StixWindowsRegistryValue]]]])

slots.modified_time = Slot(uri=STIX.modified_time, name="modified_time", curie=STIX.curie('modified_time'),
                   model_uri=STIX.modified_time, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.number_of_subkeys = Slot(uri=STIX.number_of_subkeys, name="number_of_subkeys", curie=STIX.curie('number_of_subkeys'),
                   model_uri=STIX.number_of_subkeys, domain=None, range=Optional[int])

slots.is_self_signed = Slot(uri=STIX.is_self_signed, name="is_self_signed", curie=STIX.curie('is_self_signed'),
                   model_uri=STIX.is_self_signed, domain=None, range=Optional[Union[bool, Bool]])

slots.serial_number = Slot(uri=STIX.serial_number, name="serial_number", curie=STIX.curie('serial_number'),
                   model_uri=STIX.serial_number, domain=None, range=Optional[str])

slots.signature_algorithm = Slot(uri=STIX.signature_algorithm, name="signature_algorithm", curie=STIX.curie('signature_algorithm'),
                   model_uri=STIX.signature_algorithm, domain=None, range=Optional[str])

slots.issuer = Slot(uri=STIX.issuer, name="issuer", curie=STIX.curie('issuer'),
                   model_uri=STIX.issuer, domain=None, range=Optional[str])

slots.validity_not_before = Slot(uri=STIX.validity_not_before, name="validity_not_before", curie=STIX.curie('validity_not_before'),
                   model_uri=STIX.validity_not_before, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.validity_not_after = Slot(uri=STIX.validity_not_after, name="validity_not_after", curie=STIX.curie('validity_not_after'),
                   model_uri=STIX.validity_not_after, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.subject_public_key_algorithm = Slot(uri=STIX.subject_public_key_algorithm, name="subject_public_key_algorithm", curie=STIX.curie('subject_public_key_algorithm'),
                   model_uri=STIX.subject_public_key_algorithm, domain=None, range=Optional[str])

slots.subject_public_key_modulus = Slot(uri=STIX.subject_public_key_modulus, name="subject_public_key_modulus", curie=STIX.curie('subject_public_key_modulus'),
                   model_uri=STIX.subject_public_key_modulus, domain=None, range=Optional[str])

slots.subject_public_key_exponent = Slot(uri=STIX.subject_public_key_exponent, name="subject_public_key_exponent", curie=STIX.curie('subject_public_key_exponent'),
                   model_uri=STIX.subject_public_key_exponent, domain=None, range=Optional[int])

slots.x509_v3_extensions = Slot(uri=STIX.x509_v3_extensions, name="x509_v3_extensions", curie=STIX.curie('x509_v3_extensions'),
                   model_uri=STIX.x509_v3_extensions, domain=None, range=Optional[Union[dict, StixX509V3Extensions]])

slots.sid = Slot(uri=STIX.sid, name="sid", curie=STIX.curie('sid'),
                   model_uri=STIX.sid, domain=None, range=Optional[str])

slots.alternate_data_streams = Slot(uri=STIX.alternate_data_streams, name="alternate_data_streams", curie=STIX.curie('alternate_data_streams'),
                   model_uri=STIX.alternate_data_streams, domain=None, range=Optional[Union[Union[dict, StixAlternateDataStream], list[Union[dict, StixAlternateDataStream]]]])

slots.image_height = Slot(uri=STIX.image_height, name="image_height", curie=STIX.curie('image_height'),
                   model_uri=STIX.image_height, domain=None, range=Optional[int])

slots.image_width = Slot(uri=STIX.image_width, name="image_width", curie=STIX.curie('image_width'),
                   model_uri=STIX.image_width, domain=None, range=Optional[int])

slots.bits_per_pixel = Slot(uri=STIX.bits_per_pixel, name="bits_per_pixel", curie=STIX.curie('bits_per_pixel'),
                   model_uri=STIX.bits_per_pixel, domain=None, range=Optional[int])

slots.exif_tags = Slot(uri=STIX.exif_tags, name="exif_tags", curie=STIX.curie('exif_tags'),
                   model_uri=STIX.exif_tags, domain=None, range=Optional[Union[dict, StixExifTags]])

slots.is_optimized = Slot(uri=STIX.is_optimized, name="is_optimized", curie=STIX.curie('is_optimized'),
                   model_uri=STIX.is_optimized, domain=None, range=Optional[Union[bool, Bool]])

slots.document_info_dict = Slot(uri=STIX.document_info_dict, name="document_info_dict", curie=STIX.curie('document_info_dict'),
                   model_uri=STIX.document_info_dict, domain=None, range=Optional[Union[dict, StixPdfDocumentInfo]])

slots.pdfid0 = Slot(uri=STIX.pdfid0, name="pdfid0", curie=STIX.curie('pdfid0'),
                   model_uri=STIX.pdfid0, domain=None, range=Optional[str])

slots.pdfid1 = Slot(uri=STIX.pdfid1, name="pdfid1", curie=STIX.curie('pdfid1'),
                   model_uri=STIX.pdfid1, domain=None, range=Optional[str])

slots.comment = Slot(uri=STIX.comment, name="comment", curie=STIX.curie('comment'),
                   model_uri=STIX.comment, domain=None, range=Optional[str])

slots.pe_type = Slot(uri=STIX.pe_type, name="pe_type", curie=STIX.curie('pe_type'),
                   model_uri=STIX.pe_type, domain=None, range=Optional[Union[str, "StixWindowsPeBinaryType"]])

slots.imphash = Slot(uri=STIX.imphash, name="imphash", curie=STIX.curie('imphash'),
                   model_uri=STIX.imphash, domain=None, range=Optional[str])

slots.machine_hex = Slot(uri=STIX.machine_hex, name="machine_hex", curie=STIX.curie('machine_hex'),
                   model_uri=STIX.machine_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.number_of_sections = Slot(uri=STIX.number_of_sections, name="number_of_sections", curie=STIX.curie('number_of_sections'),
                   model_uri=STIX.number_of_sections, domain=None, range=Optional[int])

slots.time_date_stamp = Slot(uri=STIX.time_date_stamp, name="time_date_stamp", curie=STIX.curie('time_date_stamp'),
                   model_uri=STIX.time_date_stamp, domain=None, range=Optional[Union[str, StixTimestampSeconds]])

slots.pointer_to_symbol_table_hex = Slot(uri=STIX.pointer_to_symbol_table_hex, name="pointer_to_symbol_table_hex", curie=STIX.curie('pointer_to_symbol_table_hex'),
                   model_uri=STIX.pointer_to_symbol_table_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.number_of_symbols = Slot(uri=STIX.number_of_symbols, name="number_of_symbols", curie=STIX.curie('number_of_symbols'),
                   model_uri=STIX.number_of_symbols, domain=None, range=Optional[int])

slots.size_of_optional_header = Slot(uri=STIX.size_of_optional_header, name="size_of_optional_header", curie=STIX.curie('size_of_optional_header'),
                   model_uri=STIX.size_of_optional_header, domain=None, range=Optional[int])

slots.characteristics_hex = Slot(uri=STIX.characteristics_hex, name="characteristics_hex", curie=STIX.curie('characteristics_hex'),
                   model_uri=STIX.characteristics_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.file_header_hashes = Slot(uri=STIX.file_header_hashes, name="file_header_hashes", curie=STIX.curie('file_header_hashes'),
                   model_uri=STIX.file_header_hashes, domain=None, range=Optional[Union[dict, StixHashes]])

slots.optional_header = Slot(uri=STIX.optional_header, name="optional_header", curie=STIX.curie('optional_header'),
                   model_uri=STIX.optional_header, domain=None, range=Optional[Union[dict, StixWindowsPeOptionalHeader]])

slots.sections = Slot(uri=STIX.sections, name="sections", curie=STIX.curie('sections'),
                   model_uri=STIX.sections, domain=None, range=Optional[Union[Union[dict, StixWindowsPeSection], list[Union[dict, StixWindowsPeSection]]]])

slots.request_method = Slot(uri=STIX.request_method, name="request_method", curie=STIX.curie('request_method'),
                   model_uri=STIX.request_method, domain=None, range=Optional[str])

slots.request_value = Slot(uri=STIX.request_value, name="request_value", curie=STIX.curie('request_value'),
                   model_uri=STIX.request_value, domain=None, range=Optional[str])

slots.request_version = Slot(uri=STIX.request_version, name="request_version", curie=STIX.curie('request_version'),
                   model_uri=STIX.request_version, domain=None, range=Optional[str])

slots.request_header = Slot(uri=STIX.request_header, name="request_header", curie=STIX.curie('request_header'),
                   model_uri=STIX.request_header, domain=None, range=Optional[Union[dict, StixDictionary]])

slots.message_body_length = Slot(uri=STIX.message_body_length, name="message_body_length", curie=STIX.curie('message_body_length'),
                   model_uri=STIX.message_body_length, domain=None, range=Optional[int])

slots.message_body_data_ref = Slot(uri=STIX.message_body_data_ref, name="message_body_data_ref", curie=STIX.curie('message_body_data_ref'),
                   model_uri=STIX.message_body_data_ref, domain=None, range=Optional[Union[str, StixArtifactId]],
                   pattern=re.compile(r'^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.icmp_type_hex = Slot(uri=STIX.icmp_type_hex, name="icmp_type_hex", curie=STIX.curie('icmp_type_hex'),
                   model_uri=STIX.icmp_type_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.icmp_code_hex = Slot(uri=STIX.icmp_code_hex, name="icmp_code_hex", curie=STIX.curie('icmp_code_hex'),
                   model_uri=STIX.icmp_code_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.address_family = Slot(uri=STIX.address_family, name="address_family", curie=STIX.curie('address_family'),
                   model_uri=STIX.address_family, domain=None, range=Optional[Union[str, "StixNetworkSocketAddressFamily"]])

slots.is_blocking = Slot(uri=STIX.is_blocking, name="is_blocking", curie=STIX.curie('is_blocking'),
                   model_uri=STIX.is_blocking, domain=None, range=Optional[Union[bool, Bool]])

slots.is_listening = Slot(uri=STIX.is_listening, name="is_listening", curie=STIX.curie('is_listening'),
                   model_uri=STIX.is_listening, domain=None, range=Optional[Union[bool, Bool]])

slots.options = Slot(uri=STIX.options, name="options", curie=STIX.curie('options'),
                   model_uri=STIX.options, domain=None, range=Optional[Union[dict, StixSocketOptions]])

slots.socket_type = Slot(uri=STIX.socket_type, name="socket_type", curie=STIX.curie('socket_type'),
                   model_uri=STIX.socket_type, domain=None, range=Optional[Union[str, "StixNetworkSocketType"]])

slots.socket_descriptor = Slot(uri=STIX.socket_descriptor, name="socket_descriptor", curie=STIX.curie('socket_descriptor'),
                   model_uri=STIX.socket_descriptor, domain=None, range=Optional[int])

slots.socket_handle = Slot(uri=STIX.socket_handle, name="socket_handle", curie=STIX.curie('socket_handle'),
                   model_uri=STIX.socket_handle, domain=None, range=Optional[int])

slots.src_flags_hex = Slot(uri=STIX.src_flags_hex, name="src_flags_hex", curie=STIX.curie('src_flags_hex'),
                   model_uri=STIX.src_flags_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.dst_flags_hex = Slot(uri=STIX.dst_flags_hex, name="dst_flags_hex", curie=STIX.curie('dst_flags_hex'),
                   model_uri=STIX.dst_flags_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.aslr_enabled = Slot(uri=STIX.aslr_enabled, name="aslr_enabled", curie=STIX.curie('aslr_enabled'),
                   model_uri=STIX.aslr_enabled, domain=None, range=Optional[Union[bool, Bool]])

slots.dep_enabled = Slot(uri=STIX.dep_enabled, name="dep_enabled", curie=STIX.curie('dep_enabled'),
                   model_uri=STIX.dep_enabled, domain=None, range=Optional[Union[bool, Bool]])

slots.priority = Slot(uri=STIX.priority, name="priority", curie=STIX.curie('priority'),
                   model_uri=STIX.priority, domain=None, range=Optional[str])

slots.owner_sid = Slot(uri=STIX.owner_sid, name="owner_sid", curie=STIX.curie('owner_sid'),
                   model_uri=STIX.owner_sid, domain=None, range=Optional[str])

slots.window_title = Slot(uri=STIX.window_title, name="window_title", curie=STIX.curie('window_title'),
                   model_uri=STIX.window_title, domain=None, range=Optional[str])

slots.startup_info = Slot(uri=STIX.startup_info, name="startup_info", curie=STIX.curie('startup_info'),
                   model_uri=STIX.startup_info, domain=None, range=Optional[Union[dict, StixDictionary]])

slots.integrity_level = Slot(uri=STIX.integrity_level, name="integrity_level", curie=STIX.curie('integrity_level'),
                   model_uri=STIX.integrity_level, domain=None, range=Optional[Union[str, "StixWindowsIntegrityLevel"]])

slots.service_name = Slot(uri=STIX.service_name, name="service_name", curie=STIX.curie('service_name'),
                   model_uri=STIX.service_name, domain=None, range=Optional[str])

slots.descriptions = Slot(uri=STIX.descriptions, name="descriptions", curie=STIX.curie('descriptions'),
                   model_uri=STIX.descriptions, domain=None, range=Optional[Union[str, list[str]]])

slots.group_name = Slot(uri=STIX.group_name, name="group_name", curie=STIX.curie('group_name'),
                   model_uri=STIX.group_name, domain=None, range=Optional[str])

slots.start_type = Slot(uri=STIX.start_type, name="start_type", curie=STIX.curie('start_type'),
                   model_uri=STIX.start_type, domain=None, range=Optional[Union[str, "StixWindowsServiceStartType"]])

slots.service_dll_refs = Slot(uri=STIX.service_dll_refs, name="service_dll_refs", curie=STIX.curie('service_dll_refs'),
                   model_uri=STIX.service_dll_refs, domain=None, range=Optional[Union[Union[str, StixFileId], list[Union[str, StixFileId]]]],
                   pattern=re.compile(r'^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.service_type = Slot(uri=STIX.service_type, name="service_type", curie=STIX.curie('service_type'),
                   model_uri=STIX.service_type, domain=None, range=Optional[Union[str, "StixWindowsServiceType"]])

slots.service_status = Slot(uri=STIX.service_status, name="service_status", curie=STIX.curie('service_status'),
                   model_uri=STIX.service_status, domain=None, range=Optional[Union[str, "StixWindowsServiceStatus"]])

slots.gid = Slot(uri=STIX.gid, name="gid", curie=STIX.curie('gid'),
                   model_uri=STIX.gid, domain=None, range=Optional[float])

slots.groups = Slot(uri=STIX.groups, name="groups", curie=STIX.curie('groups'),
                   model_uri=STIX.groups, domain=None, range=Optional[Union[str, list[str]]])

slots.home_dir = Slot(uri=STIX.home_dir, name="home_dir", curie=STIX.curie('home_dir'),
                   model_uri=STIX.home_dir, domain=None, range=Optional[str])

slots.shell = Slot(uri=STIX.shell, name="shell", curie=STIX.curie('shell'),
                   model_uri=STIX.shell, domain=None, range=Optional[str])

slots.entropy = Slot(uri=STIX.entropy, name="entropy", curie=STIX.curie('entropy'),
                   model_uri=STIX.entropy, domain=None, range=Optional[float])

slots.magic_hex = Slot(uri=STIX.magic_hex, name="magic_hex", curie=STIX.curie('magic_hex'),
                   model_uri=STIX.magic_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.major_linker_version = Slot(uri=STIX.major_linker_version, name="major_linker_version", curie=STIX.curie('major_linker_version'),
                   model_uri=STIX.major_linker_version, domain=None, range=Optional[int])

slots.minor_linker_version = Slot(uri=STIX.minor_linker_version, name="minor_linker_version", curie=STIX.curie('minor_linker_version'),
                   model_uri=STIX.minor_linker_version, domain=None, range=Optional[int])

slots.size_of_code = Slot(uri=STIX.size_of_code, name="size_of_code", curie=STIX.curie('size_of_code'),
                   model_uri=STIX.size_of_code, domain=None, range=Optional[int])

slots.size_of_initialized_data = Slot(uri=STIX.size_of_initialized_data, name="size_of_initialized_data", curie=STIX.curie('size_of_initialized_data'),
                   model_uri=STIX.size_of_initialized_data, domain=None, range=Optional[int])

slots.size_of_uninitialized_data = Slot(uri=STIX.size_of_uninitialized_data, name="size_of_uninitialized_data", curie=STIX.curie('size_of_uninitialized_data'),
                   model_uri=STIX.size_of_uninitialized_data, domain=None, range=Optional[int])

slots.address_of_entry_point = Slot(uri=STIX.address_of_entry_point, name="address_of_entry_point", curie=STIX.curie('address_of_entry_point'),
                   model_uri=STIX.address_of_entry_point, domain=None, range=Optional[int])

slots.base_of_code = Slot(uri=STIX.base_of_code, name="base_of_code", curie=STIX.curie('base_of_code'),
                   model_uri=STIX.base_of_code, domain=None, range=Optional[int])

slots.base_of_data = Slot(uri=STIX.base_of_data, name="base_of_data", curie=STIX.curie('base_of_data'),
                   model_uri=STIX.base_of_data, domain=None, range=Optional[int])

slots.image_base = Slot(uri=STIX.image_base, name="image_base", curie=STIX.curie('image_base'),
                   model_uri=STIX.image_base, domain=None, range=Optional[int])

slots.section_alignment = Slot(uri=STIX.section_alignment, name="section_alignment", curie=STIX.curie('section_alignment'),
                   model_uri=STIX.section_alignment, domain=None, range=Optional[int])

slots.file_alignment = Slot(uri=STIX.file_alignment, name="file_alignment", curie=STIX.curie('file_alignment'),
                   model_uri=STIX.file_alignment, domain=None, range=Optional[int])

slots.major_os_version = Slot(uri=STIX.major_os_version, name="major_os_version", curie=STIX.curie('major_os_version'),
                   model_uri=STIX.major_os_version, domain=None, range=Optional[int])

slots.minor_os_version = Slot(uri=STIX.minor_os_version, name="minor_os_version", curie=STIX.curie('minor_os_version'),
                   model_uri=STIX.minor_os_version, domain=None, range=Optional[int])

slots.major_image_version = Slot(uri=STIX.major_image_version, name="major_image_version", curie=STIX.curie('major_image_version'),
                   model_uri=STIX.major_image_version, domain=None, range=Optional[int])

slots.minor_image_version = Slot(uri=STIX.minor_image_version, name="minor_image_version", curie=STIX.curie('minor_image_version'),
                   model_uri=STIX.minor_image_version, domain=None, range=Optional[int])

slots.major_subsystem_version = Slot(uri=STIX.major_subsystem_version, name="major_subsystem_version", curie=STIX.curie('major_subsystem_version'),
                   model_uri=STIX.major_subsystem_version, domain=None, range=Optional[int])

slots.minor_subsystem_version = Slot(uri=STIX.minor_subsystem_version, name="minor_subsystem_version", curie=STIX.curie('minor_subsystem_version'),
                   model_uri=STIX.minor_subsystem_version, domain=None, range=Optional[int])

slots.win32_version_value_hex = Slot(uri=STIX.win32_version_value_hex, name="win32_version_value_hex", curie=STIX.curie('win32_version_value_hex'),
                   model_uri=STIX.win32_version_value_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.size_of_image = Slot(uri=STIX.size_of_image, name="size_of_image", curie=STIX.curie('size_of_image'),
                   model_uri=STIX.size_of_image, domain=None, range=Optional[int])

slots.size_of_headers = Slot(uri=STIX.size_of_headers, name="size_of_headers", curie=STIX.curie('size_of_headers'),
                   model_uri=STIX.size_of_headers, domain=None, range=Optional[int])

slots.checksum_hex = Slot(uri=STIX.checksum_hex, name="checksum_hex", curie=STIX.curie('checksum_hex'),
                   model_uri=STIX.checksum_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.subsystem_hex = Slot(uri=STIX.subsystem_hex, name="subsystem_hex", curie=STIX.curie('subsystem_hex'),
                   model_uri=STIX.subsystem_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.dll_characteristics_hex = Slot(uri=STIX.dll_characteristics_hex, name="dll_characteristics_hex", curie=STIX.curie('dll_characteristics_hex'),
                   model_uri=STIX.dll_characteristics_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.size_of_stack_reserve = Slot(uri=STIX.size_of_stack_reserve, name="size_of_stack_reserve", curie=STIX.curie('size_of_stack_reserve'),
                   model_uri=STIX.size_of_stack_reserve, domain=None, range=Optional[int])

slots.size_of_stack_commit = Slot(uri=STIX.size_of_stack_commit, name="size_of_stack_commit", curie=STIX.curie('size_of_stack_commit'),
                   model_uri=STIX.size_of_stack_commit, domain=None, range=Optional[int])

slots.size_of_heap_reserve = Slot(uri=STIX.size_of_heap_reserve, name="size_of_heap_reserve", curie=STIX.curie('size_of_heap_reserve'),
                   model_uri=STIX.size_of_heap_reserve, domain=None, range=Optional[int])

slots.size_of_heap_commit = Slot(uri=STIX.size_of_heap_commit, name="size_of_heap_commit", curie=STIX.curie('size_of_heap_commit'),
                   model_uri=STIX.size_of_heap_commit, domain=None, range=Optional[int])

slots.loader_flags_hex = Slot(uri=STIX.loader_flags_hex, name="loader_flags_hex", curie=STIX.curie('loader_flags_hex'),
                   model_uri=STIX.loader_flags_hex, domain=None, range=Optional[Union[str, StixHex]])

slots.number_of_rva_and_sizes = Slot(uri=STIX.number_of_rva_and_sizes, name="number_of_rva_and_sizes", curie=STIX.curie('number_of_rva_and_sizes'),
                   model_uri=STIX.number_of_rva_and_sizes, domain=None, range=Optional[int])

slots.body_raw_ref = Slot(uri=STIX.body_raw_ref, name="body_raw_ref", curie=STIX.curie('body_raw_ref'),
                   model_uri=STIX.body_raw_ref, domain=None, range=Optional[Union[str, StixArtifactId, StixFileId]],
                   pattern=re.compile(r'^(artifact|file)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.content_disposition = Slot(uri=STIX.content_disposition, name="content_disposition", curie=STIX.curie('content_disposition'),
                   model_uri=STIX.content_disposition, domain=None, range=Optional[str])

slots.data = Slot(uri=STIX.data, name="data", curie=STIX.curie('data'),
                   model_uri=STIX.data, domain=None, range=Optional[str])

slots.data_type = Slot(uri=STIX.data_type, name="data_type", curie=STIX.curie('data_type'),
                   model_uri=STIX.data_type, domain=None, range=Optional[Union[str, "StixWindowsRegistryDatatype"]])

slots.basic_constraints = Slot(uri=STIX.basic_constraints, name="basic_constraints", curie=STIX.curie('basic_constraints'),
                   model_uri=STIX.basic_constraints, domain=None, range=Optional[str])

slots.name_constraints = Slot(uri=STIX.name_constraints, name="name_constraints", curie=STIX.curie('name_constraints'),
                   model_uri=STIX.name_constraints, domain=None, range=Optional[str])

slots.policy_constraints = Slot(uri=STIX.policy_constraints, name="policy_constraints", curie=STIX.curie('policy_constraints'),
                   model_uri=STIX.policy_constraints, domain=None, range=Optional[str])

slots.key_usage = Slot(uri=STIX.key_usage, name="key_usage", curie=STIX.curie('key_usage'),
                   model_uri=STIX.key_usage, domain=None, range=Optional[str])

slots.extended_key_usage = Slot(uri=STIX.extended_key_usage, name="extended_key_usage", curie=STIX.curie('extended_key_usage'),
                   model_uri=STIX.extended_key_usage, domain=None, range=Optional[str])

slots.subject_key_identifier = Slot(uri=STIX.subject_key_identifier, name="subject_key_identifier", curie=STIX.curie('subject_key_identifier'),
                   model_uri=STIX.subject_key_identifier, domain=None, range=Optional[str])

slots.authority_key_identifier = Slot(uri=STIX.authority_key_identifier, name="authority_key_identifier", curie=STIX.curie('authority_key_identifier'),
                   model_uri=STIX.authority_key_identifier, domain=None, range=Optional[str])

slots.subject_alternative_name = Slot(uri=STIX.subject_alternative_name, name="subject_alternative_name", curie=STIX.curie('subject_alternative_name'),
                   model_uri=STIX.subject_alternative_name, domain=None, range=Optional[str])

slots.issuer_alternative_name = Slot(uri=STIX.issuer_alternative_name, name="issuer_alternative_name", curie=STIX.curie('issuer_alternative_name'),
                   model_uri=STIX.issuer_alternative_name, domain=None, range=Optional[str])

slots.subject_directory_attributes = Slot(uri=STIX.subject_directory_attributes, name="subject_directory_attributes", curie=STIX.curie('subject_directory_attributes'),
                   model_uri=STIX.subject_directory_attributes, domain=None, range=Optional[str])

slots.crl_distribution_points = Slot(uri=STIX.crl_distribution_points, name="crl_distribution_points", curie=STIX.curie('crl_distribution_points'),
                   model_uri=STIX.crl_distribution_points, domain=None, range=Optional[str])

slots.inhibit_any_policy = Slot(uri=STIX.inhibit_any_policy, name="inhibit_any_policy", curie=STIX.curie('inhibit_any_policy'),
                   model_uri=STIX.inhibit_any_policy, domain=None, range=Optional[str])

slots.private_key_usage_period_not_before = Slot(uri=STIX.private_key_usage_period_not_before, name="private_key_usage_period_not_before", curie=STIX.curie('private_key_usage_period_not_before'),
                   model_uri=STIX.private_key_usage_period_not_before, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.private_key_usage_period_not_after = Slot(uri=STIX.private_key_usage_period_not_after, name="private_key_usage_period_not_after", curie=STIX.curie('private_key_usage_period_not_after'),
                   model_uri=STIX.private_key_usage_period_not_after, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.certificate_policies = Slot(uri=STIX.certificate_policies, name="certificate_policies", curie=STIX.curie('certificate_policies'),
                   model_uri=STIX.certificate_policies, domain=None, range=Optional[str])

slots.policy_mappings = Slot(uri=STIX.policy_mappings, name="policy_mappings", curie=STIX.curie('policy_mappings'),
                   model_uri=STIX.policy_mappings, domain=None, range=Optional[str])

slots.aliases = Slot(uri=STIX.aliases, name="aliases", curie=STIX.curie('aliases'),
                   model_uri=STIX.aliases, domain=None, range=Optional[Union[str, list[str]]])

slots.kill_chain_phases = Slot(uri=STIX.kill_chain_phases, name="kill_chain_phases", curie=STIX.curie('kill_chain_phases'),
                   model_uri=STIX.kill_chain_phases, domain=None, range=Optional[Union[Union[dict, StixKillChainPhase], list[Union[dict, StixKillChainPhase]]]])

slots.first_seen = Slot(uri=STIX.first_seen, name="first_seen", curie=STIX.curie('first_seen'),
                   model_uri=STIX.first_seen, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.last_seen = Slot(uri=STIX.last_seen, name="last_seen", curie=STIX.curie('last_seen'),
                   model_uri=STIX.last_seen, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.objective = Slot(uri=STIX.objective, name="objective", curie=STIX.curie('objective'),
                   model_uri=STIX.objective, domain=None, range=Optional[str])

slots.context = Slot(uri=STIX.context, name="context", curie=STIX.curie('context'),
                   model_uri=STIX.context, domain=None, range=Optional[Union[str, "StixGroupingContext"]])

slots.object_refs = Slot(uri=STIX.object_refs, name="object_refs", curie=STIX.curie('object_refs'),
                   model_uri=STIX.object_refs, domain=None, range=Optional[Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]]],
                   pattern=re.compile(r'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.indicator_types = Slot(uri=STIX.indicator_types, name="indicator_types", curie=STIX.curie('indicator_types'),
                   model_uri=STIX.indicator_types, domain=None, range=Optional[Union[str, list[str]]])

slots.pattern = Slot(uri=STIX.pattern, name="pattern", curie=STIX.curie('pattern'),
                   model_uri=STIX.pattern, domain=None, range=Optional[str])

slots.pattern_type = Slot(uri=STIX.pattern_type, name="pattern_type", curie=STIX.curie('pattern_type'),
                   model_uri=STIX.pattern_type, domain=None, range=Optional[Union[str, "StixPatternType"]])

slots.pattern_version = Slot(uri=STIX.pattern_version, name="pattern_version", curie=STIX.curie('pattern_version'),
                   model_uri=STIX.pattern_version, domain=None, range=Optional[str])

slots.valid_from = Slot(uri=STIX.valid_from, name="valid_from", curie=STIX.curie('valid_from'),
                   model_uri=STIX.valid_from, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.valid_until = Slot(uri=STIX.valid_until, name="valid_until", curie=STIX.curie('valid_until'),
                   model_uri=STIX.valid_until, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.infrastructure_types = Slot(uri=STIX.infrastructure_types, name="infrastructure_types", curie=STIX.curie('infrastructure_types'),
                   model_uri=STIX.infrastructure_types, domain=None, range=Optional[Union[str, list[str]]])

slots.goals = Slot(uri=STIX.goals, name="goals", curie=STIX.curie('goals'),
                   model_uri=STIX.goals, domain=None, range=Optional[Union[str, list[str]]])

slots.resource_level = Slot(uri=STIX.resource_level, name="resource_level", curie=STIX.curie('resource_level'),
                   model_uri=STIX.resource_level, domain=None, range=Optional[Union[str, "StixAttackResourceLevel"]])

slots.primary_motivation = Slot(uri=STIX.primary_motivation, name="primary_motivation", curie=STIX.curie('primary_motivation'),
                   model_uri=STIX.primary_motivation, domain=None, range=Optional[Union[str, "StixAttackMotivation"]])

slots.secondary_motivations = Slot(uri=STIX.secondary_motivations, name="secondary_motivations", curie=STIX.curie('secondary_motivations'),
                   model_uri=STIX.secondary_motivations, domain=None, range=Optional[Union[str, list[str]]])

slots.latitude = Slot(uri=STIX.latitude, name="latitude", curie=STIX.curie('latitude'),
                   model_uri=STIX.latitude, domain=None, range=Optional[float])

slots.longitude = Slot(uri=STIX.longitude, name="longitude", curie=STIX.curie('longitude'),
                   model_uri=STIX.longitude, domain=None, range=Optional[float])

slots.precision = Slot(uri=STIX.precision, name="precision", curie=STIX.curie('precision'),
                   model_uri=STIX.precision, domain=None, range=Optional[float])

slots.region = Slot(uri=STIX.region, name="region", curie=STIX.curie('region'),
                   model_uri=STIX.region, domain=None, range=Optional[Union[str, "StixRegion"]])

slots.country = Slot(uri=STIX.country, name="country", curie=STIX.curie('country'),
                   model_uri=STIX.country, domain=None, range=Optional[str])

slots.administrative_area = Slot(uri=STIX.administrative_area, name="administrative_area", curie=STIX.curie('administrative_area'),
                   model_uri=STIX.administrative_area, domain=None, range=Optional[str])

slots.city = Slot(uri=STIX.city, name="city", curie=STIX.curie('city'),
                   model_uri=STIX.city, domain=None, range=Optional[str])

slots.street_address = Slot(uri=STIX.street_address, name="street_address", curie=STIX.curie('street_address'),
                   model_uri=STIX.street_address, domain=None, range=Optional[str])

slots.postal_code = Slot(uri=STIX.postal_code, name="postal_code", curie=STIX.curie('postal_code'),
                   model_uri=STIX.postal_code, domain=None, range=Optional[str])

slots.operating_system_refs = Slot(uri=STIX.operating_system_refs, name="operating_system_refs", curie=STIX.curie('operating_system_refs'),
                   model_uri=STIX.operating_system_refs, domain=None, range=Optional[Union[Union[str, StixSoftwareId], list[Union[str, StixSoftwareId]]]],
                   pattern=re.compile(r'^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.architecture_execution_envs = Slot(uri=STIX.architecture_execution_envs, name="architecture_execution_envs", curie=STIX.curie('architecture_execution_envs'),
                   model_uri=STIX.architecture_execution_envs, domain=None, range=Optional[Union[str, list[str]]])

slots.implementation_languages = Slot(uri=STIX.implementation_languages, name="implementation_languages", curie=STIX.curie('implementation_languages'),
                   model_uri=STIX.implementation_languages, domain=None, range=Optional[Union[str, list[str]]])

slots.capabilities = Slot(uri=STIX.capabilities, name="capabilities", curie=STIX.curie('capabilities'),
                   model_uri=STIX.capabilities, domain=None, range=Optional[Union[str, list[str]]])

slots.sample_refs = Slot(uri=STIX.sample_refs, name="sample_refs", curie=STIX.curie('sample_refs'),
                   model_uri=STIX.sample_refs, domain=None, range=Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]],
                   pattern=re.compile(r'^(file|artifact)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.malware_types = Slot(uri=STIX.malware_types, name="malware_types", curie=STIX.curie('malware_types'),
                   model_uri=STIX.malware_types, domain=None, range=Optional[Union[str, list[str]]])

slots.is_family = Slot(uri=STIX.is_family, name="is_family", curie=STIX.curie('is_family'),
                   model_uri=STIX.is_family, domain=None, range=Optional[Union[bool, Bool]])

slots.product = Slot(uri=STIX.product, name="product", curie=STIX.curie('product'),
                   model_uri=STIX.product, domain=None, range=Optional[str])

slots.configuration_version = Slot(uri=STIX.configuration_version, name="configuration_version", curie=STIX.curie('configuration_version'),
                   model_uri=STIX.configuration_version, domain=None, range=Optional[str])

slots.modules = Slot(uri=STIX.modules, name="modules", curie=STIX.curie('modules'),
                   model_uri=STIX.modules, domain=None, range=Optional[Union[str, list[str]]])

slots.analysis_engine_version = Slot(uri=STIX.analysis_engine_version, name="analysis_engine_version", curie=STIX.curie('analysis_engine_version'),
                   model_uri=STIX.analysis_engine_version, domain=None, range=Optional[str])

slots.analysis_definition_version = Slot(uri=STIX.analysis_definition_version, name="analysis_definition_version", curie=STIX.curie('analysis_definition_version'),
                   model_uri=STIX.analysis_definition_version, domain=None, range=Optional[str])

slots.submitted = Slot(uri=STIX.submitted, name="submitted", curie=STIX.curie('submitted'),
                   model_uri=STIX.submitted, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.analysis_started = Slot(uri=STIX.analysis_started, name="analysis_started", curie=STIX.curie('analysis_started'),
                   model_uri=STIX.analysis_started, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.analysis_ended = Slot(uri=STIX.analysis_ended, name="analysis_ended", curie=STIX.curie('analysis_ended'),
                   model_uri=STIX.analysis_ended, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.result_name = Slot(uri=STIX.result_name, name="result_name", curie=STIX.curie('result_name'),
                   model_uri=STIX.result_name, domain=None, range=Optional[str])

slots.result = Slot(uri=STIX.result, name="result", curie=STIX.curie('result'),
                   model_uri=STIX.result, domain=None, range=Optional[Union[str, "StixMalwareResult"]])

slots.host_vm_ref = Slot(uri=STIX.host_vm_ref, name="host_vm_ref", curie=STIX.curie('host_vm_ref'),
                   model_uri=STIX.host_vm_ref, domain=None, range=Optional[Union[str, StixSoftwareId]],
                   pattern=re.compile(r'^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.operating_system_ref = Slot(uri=STIX.operating_system_ref, name="operating_system_ref", curie=STIX.curie('operating_system_ref'),
                   model_uri=STIX.operating_system_ref, domain=None, range=Optional[Union[str, StixSoftwareId]],
                   pattern=re.compile(r'^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.installed_software_refs = Slot(uri=STIX.installed_software_refs, name="installed_software_refs", curie=STIX.curie('installed_software_refs'),
                   model_uri=STIX.installed_software_refs, domain=None, range=Optional[Union[Union[str, StixSoftwareId], list[Union[str, StixSoftwareId]]]],
                   pattern=re.compile(r'^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.analysis_sco_refs = Slot(uri=STIX.analysis_sco_refs, name="analysis_sco_refs", curie=STIX.curie('analysis_sco_refs'),
                   model_uri=STIX.analysis_sco_refs, domain=None, range=Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]],
                   pattern=re.compile(r'^(?!(attack-pattern|campaign|course-of-action|grouping|identity|incident|indicator|infrastructure|intrusion-set|location|malware|malware-analysis|note|observed-data|opinion|report|threat-actor|tool|vulnerability|relationship|sighting|bundle|marking-definition|language-content|extension-definition)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.sample_ref = Slot(uri=STIX.sample_ref, name="sample_ref", curie=STIX.curie('sample_ref'),
                   model_uri=STIX.sample_ref, domain=None, range=Optional[Union[str, StixFileId, StixNetworkTrafficId, StixArtifactId]],
                   pattern=re.compile(r'^(file|network-traffic|artifact)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.abstract = Slot(uri=STIX.abstract, name="abstract", curie=STIX.curie('abstract'),
                   model_uri=STIX.abstract, domain=None, range=Optional[str])

slots.content = Slot(uri=STIX.content, name="content", curie=STIX.curie('content'),
                   model_uri=STIX.content, domain=None, range=Optional[str])

slots.authors = Slot(uri=STIX.authors, name="authors", curie=STIX.curie('authors'),
                   model_uri=STIX.authors, domain=None, range=Optional[Union[str, list[str]]])

slots.first_observed = Slot(uri=STIX.first_observed, name="first_observed", curie=STIX.curie('first_observed'),
                   model_uri=STIX.first_observed, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.last_observed = Slot(uri=STIX.last_observed, name="last_observed", curie=STIX.curie('last_observed'),
                   model_uri=STIX.last_observed, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.number_observed = Slot(uri=STIX.number_observed, name="number_observed", curie=STIX.curie('number_observed'),
                   model_uri=STIX.number_observed, domain=None, range=Optional[int])

slots.explanation = Slot(uri=STIX.explanation, name="explanation", curie=STIX.curie('explanation'),
                   model_uri=STIX.explanation, domain=None, range=Optional[str])

slots.opinion = Slot(uri=STIX.opinion, name="opinion", curie=STIX.curie('opinion'),
                   model_uri=STIX.opinion, domain=None, range=Optional[Union[str, "StixAgreement"]])

slots.report_types = Slot(uri=STIX.report_types, name="report_types", curie=STIX.curie('report_types'),
                   model_uri=STIX.report_types, domain=None, range=Optional[Union[str, list[str]]])

slots.published = Slot(uri=STIX.published, name="published", curie=STIX.curie('published'),
                   model_uri=STIX.published, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.threat_actor_types = Slot(uri=STIX.threat_actor_types, name="threat_actor_types", curie=STIX.curie('threat_actor_types'),
                   model_uri=STIX.threat_actor_types, domain=None, range=Optional[Union[str, list[str]]])

slots.sophistication = Slot(uri=STIX.sophistication, name="sophistication", curie=STIX.curie('sophistication'),
                   model_uri=STIX.sophistication, domain=None, range=Optional[Union[str, "StixThreatActorSophistication"]])

slots.personal_motivations = Slot(uri=STIX.personal_motivations, name="personal_motivations", curie=STIX.curie('personal_motivations'),
                   model_uri=STIX.personal_motivations, domain=None, range=Optional[Union[str, list[str]]])

slots.tool_types = Slot(uri=STIX.tool_types, name="tool_types", curie=STIX.curie('tool_types'),
                   model_uri=STIX.tool_types, domain=None, range=Optional[Union[str, list[str]]])

slots.tool_version = Slot(uri=STIX.tool_version, name="tool_version", curie=STIX.curie('tool_version'),
                   model_uri=STIX.tool_version, domain=None, range=Optional[str])

slots.relationship_type = Slot(uri=STIX.relationship_type, name="relationship_type", curie=STIX.curie('relationship_type'),
                   model_uri=STIX.relationship_type, domain=None, range=Optional[str],
                   pattern=re.compile(r'^[a-z0-9\-]+$'))

slots.source_ref = Slot(uri=STIX.source_ref, name="source_ref", curie=STIX.curie('source_ref'),
                   model_uri=STIX.source_ref, domain=None, range=Optional[Union[str, StixDomainObjectId, StixCyberObservableObjectId]],
                   pattern=re.compile(r'^(?!(relationship|sighting|bundle|marking-definition|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.target_ref = Slot(uri=STIX.target_ref, name="target_ref", curie=STIX.curie('target_ref'),
                   model_uri=STIX.target_ref, domain=None, range=Optional[Union[str, StixDomainObjectId, StixCyberObservableObjectId]],
                   pattern=re.compile(r'^(?!(relationship|sighting|bundle|marking-definition|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.start_time = Slot(uri=STIX.start_time, name="start_time", curie=STIX.curie('start_time'),
                   model_uri=STIX.start_time, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.stop_time = Slot(uri=STIX.stop_time, name="stop_time", curie=STIX.curie('stop_time'),
                   model_uri=STIX.stop_time, domain=None, range=Optional[Union[str, StixTimestamp]])

slots.count = Slot(uri=STIX.count, name="count", curie=STIX.curie('count'),
                   model_uri=STIX.count, domain=None, range=Optional[int])

slots.sighting_of_ref = Slot(uri=STIX.sighting_of_ref, name="sighting_of_ref", curie=STIX.curie('sighting_of_ref'),
                   model_uri=STIX.sighting_of_ref, domain=None, range=Optional[Union[str, StixDomainObjectId]],
                   pattern=re.compile(r'^(?!(artifact|autonomous-system|directory|domain-name|email-addr|email-message|file|ipv4-addr|ipv6-addr|mac-addr|mutex|network-traffic|process|software|url|user-account|windows-registry-key|x509-certificate|relationship|sighting|bundle|marking-definition|language-content|extension-definition)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.observed_data_refs = Slot(uri=STIX.observed_data_refs, name="observed_data_refs", curie=STIX.curie('observed_data_refs'),
                   model_uri=STIX.observed_data_refs, domain=None, range=Optional[Union[Union[str, StixObservedDataId], list[Union[str, StixObservedDataId]]]],
                   pattern=re.compile(r'^observed-data--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.where_sighted_refs = Slot(uri=STIX.where_sighted_refs, name="where_sighted_refs", curie=STIX.curie('where_sighted_refs'),
                   model_uri=STIX.where_sighted_refs, domain=None, range=Optional[Union[Union[str, StixDomainObjectId], list[Union[str, StixDomainObjectId]]]],
                   pattern=re.compile(r'^(identity|location)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.summary = Slot(uri=STIX.summary, name="summary", curie=STIX.curie('summary'),
                   model_uri=STIX.summary, domain=None, range=Optional[Union[bool, Bool]])

slots.StixBundle_id = Slot(uri=STIX.id, name="StixBundle_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixBundle_id, domain=StixBundle, range=Union[str, StixBundleId],
                   pattern=re.compile(r'^bundle--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixBundle_type = Slot(uri=STIX.type, name="StixBundle_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixBundle_type, domain=StixBundle, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixBundle_objects = Slot(uri=STIX.objects, name="StixBundle_objects", curie=STIX.curie('objects'),
                   model_uri=STIX.StixBundle_objects, domain=StixBundle, range=Optional[Union[dict[Union[str, StixObjectId], Union[dict, "StixObject"]], list[Union[dict, "StixObject"]]]])

slots.StixCommonObject_spec_version = Slot(uri=STIX.spec_version, name="StixCommonObject_spec_version", curie=STIX.curie('spec_version'),
                   model_uri=STIX.StixCommonObject_spec_version, domain=StixCommonObject, range=Union[str, "StixSpecVersion"])

slots.StixCommonObject_created = Slot(uri=STIX.created, name="StixCommonObject_created", curie=STIX.curie('created'),
                   model_uri=STIX.StixCommonObject_created, domain=StixCommonObject, range=Union[str, StixTimestampMillis])

slots.StixCommonObject_modified = Slot(uri=STIX.modified, name="StixCommonObject_modified", curie=STIX.curie('modified'),
                   model_uri=STIX.StixCommonObject_modified, domain=StixCommonObject, range=Union[str, StixTimestampMillis])

slots.StixIdentity_id = Slot(uri=STIX.id, name="StixIdentity_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixIdentity_id, domain=StixIdentity, range=Union[str, StixIdentityId],
                   pattern=re.compile(r'^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIdentity_type = Slot(uri=STIX.type, name="StixIdentity_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixIdentity_type, domain=StixIdentity, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixIdentity_name = Slot(uri=STIX.name, name="StixIdentity_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixIdentity_name, domain=StixIdentity, range=str)

slots.StixMarkingDefinition_id = Slot(uri=STIX.id, name="StixMarkingDefinition_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixMarkingDefinition_id, domain=StixMarkingDefinition, range=Union[str, StixMarkingDefinitionId],
                   pattern=re.compile(r'^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixMarkingDefinition_type = Slot(uri=STIX.type, name="StixMarkingDefinition_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixMarkingDefinition_type, domain=StixMarkingDefinition, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixMarkingDefinition_spec_version = Slot(uri=STIX.spec_version, name="StixMarkingDefinition_spec_version", curie=STIX.curie('spec_version'),
                   model_uri=STIX.StixMarkingDefinition_spec_version, domain=StixMarkingDefinition, range=Union[str, "StixSpecVersion"])

slots.StixMarkingDefinition_created = Slot(uri=STIX.created, name="StixMarkingDefinition_created", curie=STIX.curie('created'),
                   model_uri=STIX.StixMarkingDefinition_created, domain=StixMarkingDefinition, range=Union[str, StixTimestampMillis])

slots.StixLanguageContent_id = Slot(uri=STIX.id, name="StixLanguageContent_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixLanguageContent_id, domain=StixLanguageContent, range=Union[str, StixLanguageContentId],
                   pattern=re.compile(r'^language-content--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixLanguageContent_type = Slot(uri=STIX.type, name="StixLanguageContent_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixLanguageContent_type, domain=StixLanguageContent, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixLanguageContent_object_ref = Slot(uri=STIX.object_ref, name="StixLanguageContent_object_ref", curie=STIX.curie('object_ref'),
                   model_uri=STIX.StixLanguageContent_object_ref, domain=StixLanguageContent, range=Union[str, StixObjectId],
                   pattern=re.compile(r'^(?!(bundle|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixLanguageContent_contents = Slot(uri=STIX.contents, name="StixLanguageContent_contents", curie=STIX.curie('contents'),
                   model_uri=STIX.StixLanguageContent_contents, domain=StixLanguageContent, range=Union[dict, "StixLanguageContents"])

slots.StixExtensionDefinition_id = Slot(uri=STIX.id, name="StixExtensionDefinition_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixExtensionDefinition_id, domain=StixExtensionDefinition, range=Union[str, StixExtensionDefinitionId],
                   pattern=re.compile(r'^extension-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixExtensionDefinition_type = Slot(uri=STIX.type, name="StixExtensionDefinition_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixExtensionDefinition_type, domain=StixExtensionDefinition, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixExtensionDefinition_name = Slot(uri=STIX.name, name="StixExtensionDefinition_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixExtensionDefinition_name, domain=StixExtensionDefinition, range=str)

slots.StixExtensionDefinition_schema = Slot(uri=STIX.schema, name="StixExtensionDefinition_schema", curie=STIX.curie('schema'),
                   model_uri=STIX.StixExtensionDefinition_schema, domain=StixExtensionDefinition, range=str)

slots.StixExtensionDefinition_version = Slot(uri=STIX.version, name="StixExtensionDefinition_version", curie=STIX.curie('version'),
                   model_uri=STIX.StixExtensionDefinition_version, domain=StixExtensionDefinition, range=str)

slots.StixExtensionDefinition_extension_types = Slot(uri=STIX.extension_types, name="StixExtensionDefinition_extension_types", curie=STIX.curie('extension_types'),
                   model_uri=STIX.StixExtensionDefinition_extension_types, domain=StixExtensionDefinition, range=Union[Union[str, "StixExtensionType"], list[Union[str, "StixExtensionType"]]])

slots.StixExternalReference_source_name = Slot(uri=STIX.source_name, name="StixExternalReference_source_name", curie=STIX.curie('source_name'),
                   model_uri=STIX.StixExternalReference_source_name, domain=StixExternalReference, range=str)

slots.StixKillChainPhase_kill_chain_name = Slot(uri=STIX.kill_chain_name, name="StixKillChainPhase_kill_chain_name", curie=STIX.curie('kill_chain_name'),
                   model_uri=STIX.StixKillChainPhase_kill_chain_name, domain=StixKillChainPhase, range=str)

slots.StixKillChainPhase_phase_name = Slot(uri=STIX.phase_name, name="StixKillChainPhase_phase_name", curie=STIX.curie('phase_name'),
                   model_uri=STIX.StixKillChainPhase_phase_name, domain=StixKillChainPhase, range=str)

slots.StixGranularMarking_selectors = Slot(uri=STIX.selectors, name="StixGranularMarking_selectors", curie=STIX.curie('selectors'),
                   model_uri=STIX.StixGranularMarking_selectors, domain=StixGranularMarking, range=Union[str, list[str]],
                   pattern=re.compile(r'^([a-z0-9_-]{3,249}(\.(\[\d+\]|[a-z0-9_-]{1,250}))*|id)$'))

slots.StixStatementMarking_statement = Slot(uri=STIX.statement, name="StixStatementMarking_statement", curie=STIX.curie('statement'),
                   model_uri=STIX.StixStatementMarking_statement, domain=StixStatementMarking, range=str)

slots.StixTlpMarking_tlp = Slot(uri=STIX.tlp, name="StixTlpMarking_tlp", curie=STIX.curie('tlp'),
                   model_uri=STIX.StixTlpMarking_tlp, domain=StixTlpMarking, range=Union[str, "StixTlpLevel"])

slots.StixExtension_extension_type = Slot(uri=STIX.extension_type, name="StixExtension_extension_type", curie=STIX.curie('extension_type'),
                   model_uri=STIX.StixExtension_extension_type, domain=StixExtension, range=Union[str, "StixExtensionType"])

slots.StixArtifact_id = Slot(uri=STIX.id, name="StixArtifact_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixArtifact_id, domain=StixArtifact, range=Union[str, StixArtifactId],
                   pattern=re.compile(r'^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixArtifact_type = Slot(uri=STIX.type, name="StixArtifact_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixArtifact_type, domain=StixArtifact, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixArtifact_mime_type = Slot(uri=STIX.mime_type, name="StixArtifact_mime_type", curie=STIX.curie('mime_type'),
                   model_uri=STIX.StixArtifact_mime_type, domain=StixArtifact, range=Optional[str],
                   pattern=re.compile(r'^(application|audio|font|image|message|model|multipart|text|video)/[a-zA-Z0-9.+_-]+'))

slots.StixAutonomousSystem_id = Slot(uri=STIX.id, name="StixAutonomousSystem_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixAutonomousSystem_id, domain=StixAutonomousSystem, range=Union[str, StixAutonomousSystemId],
                   pattern=re.compile(r'^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixAutonomousSystem_type = Slot(uri=STIX.type, name="StixAutonomousSystem_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixAutonomousSystem_type, domain=StixAutonomousSystem, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixAutonomousSystem_number = Slot(uri=STIX.number, name="StixAutonomousSystem_number", curie=STIX.curie('number'),
                   model_uri=STIX.StixAutonomousSystem_number, domain=StixAutonomousSystem, range=int)

slots.StixDirectory_id = Slot(uri=STIX.id, name="StixDirectory_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixDirectory_id, domain=StixDirectory, range=Union[str, StixDirectoryId],
                   pattern=re.compile(r'^directory--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixDirectory_type = Slot(uri=STIX.type, name="StixDirectory_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixDirectory_type, domain=StixDirectory, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixDirectory_path = Slot(uri=STIX.path, name="StixDirectory_path", curie=STIX.curie('path'),
                   model_uri=STIX.StixDirectory_path, domain=StixDirectory, range=str)

slots.StixDirectory_contains_refs = Slot(uri=STIX.contains_refs, name="StixDirectory_contains_refs", curie=STIX.curie('contains_refs'),
                   model_uri=STIX.StixDirectory_contains_refs, domain=StixDirectory, range=Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]],
                   pattern=re.compile(r'^(file|directory)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixDomainName_id = Slot(uri=STIX.id, name="StixDomainName_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixDomainName_id, domain=StixDomainName, range=Union[str, StixDomainNameId],
                   pattern=re.compile(r'^domain-name--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixDomainName_type = Slot(uri=STIX.type, name="StixDomainName_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixDomainName_type, domain=StixDomainName, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixDomainName_value = Slot(uri=STIX.value, name="StixDomainName_value", curie=STIX.curie('value'),
                   model_uri=STIX.StixDomainName_value, domain=StixDomainName, range=str)

slots.StixDomainName_resolves_to_refs = Slot(uri=STIX.resolves_to_refs, name="StixDomainName_resolves_to_refs", curie=STIX.curie('resolves_to_refs'),
                   model_uri=STIX.StixDomainName_resolves_to_refs, domain=StixDomainName, range=Optional[Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]]],
                   pattern=re.compile(r'^(ipv4-addr|ipv6-addr|domain-name)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixEmailAddress_id = Slot(uri=STIX.id, name="StixEmailAddress_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixEmailAddress_id, domain=StixEmailAddress, range=Union[str, StixEmailAddressId],
                   pattern=re.compile(r'^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixEmailAddress_type = Slot(uri=STIX.type, name="StixEmailAddress_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixEmailAddress_type, domain=StixEmailAddress, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixEmailAddress_value = Slot(uri=STIX.value, name="StixEmailAddress_value", curie=STIX.curie('value'),
                   model_uri=STIX.StixEmailAddress_value, domain=StixEmailAddress, range=str)

slots.StixEmailMessage_id = Slot(uri=STIX.id, name="StixEmailMessage_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixEmailMessage_id, domain=StixEmailMessage, range=Union[str, StixEmailMessageId],
                   pattern=re.compile(r'^email-message--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixEmailMessage_type = Slot(uri=STIX.type, name="StixEmailMessage_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixEmailMessage_type, domain=StixEmailMessage, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixEmailMessage_is_multipart = Slot(uri=STIX.is_multipart, name="StixEmailMessage_is_multipart", curie=STIX.curie('is_multipart'),
                   model_uri=STIX.StixEmailMessage_is_multipart, domain=StixEmailMessage, range=Union[bool, Bool])

slots.StixFile_id = Slot(uri=STIX.id, name="StixFile_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixFile_id, domain=StixFile, range=Union[str, StixFileId],
                   pattern=re.compile(r'^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixFile_type = Slot(uri=STIX.type, name="StixFile_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixFile_type, domain=StixFile, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixFile_extensions = Slot(uri=STIX.extensions, name="StixFile_extensions", curie=STIX.curie('extensions'),
                   model_uri=STIX.StixFile_extensions, domain=StixFile, range=Optional[Union[dict, "StixFileExtensions"]])

slots.StixIpv4Address_id = Slot(uri=STIX.id, name="StixIpv4Address_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixIpv4Address_id, domain=StixIpv4Address, range=Union[str, StixIpv4AddressId],
                   pattern=re.compile(r'^ipv4-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIpv4Address_type = Slot(uri=STIX.type, name="StixIpv4Address_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixIpv4Address_type, domain=StixIpv4Address, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixIpv4Address_value = Slot(uri=STIX.value, name="StixIpv4Address_value", curie=STIX.curie('value'),
                   model_uri=STIX.StixIpv4Address_value, domain=StixIpv4Address, range=str,
                   pattern=re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))?$'))

slots.StixIpv4Address_resolves_to_refs = Slot(uri=STIX.resolves_to_refs, name="StixIpv4Address_resolves_to_refs", curie=STIX.curie('resolves_to_refs'),
                   model_uri=STIX.StixIpv4Address_resolves_to_refs, domain=StixIpv4Address, range=Optional[Union[Union[str, StixMacAddressId], list[Union[str, StixMacAddressId]]]],
                   pattern=re.compile(r'^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIpv6Address_id = Slot(uri=STIX.id, name="StixIpv6Address_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixIpv6Address_id, domain=StixIpv6Address, range=Union[str, StixIpv6AddressId],
                   pattern=re.compile(r'^ipv6-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIpv6Address_type = Slot(uri=STIX.type, name="StixIpv6Address_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixIpv6Address_type, domain=StixIpv6Address, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixIpv6Address_value = Slot(uri=STIX.value, name="StixIpv6Address_value", curie=STIX.curie('value'),
                   model_uri=STIX.StixIpv6Address_value, domain=StixIpv6Address, range=str,
                   pattern=re.compile(r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?$'))

slots.StixIpv6Address_resolves_to_refs = Slot(uri=STIX.resolves_to_refs, name="StixIpv6Address_resolves_to_refs", curie=STIX.curie('resolves_to_refs'),
                   model_uri=STIX.StixIpv6Address_resolves_to_refs, domain=StixIpv6Address, range=Optional[Union[Union[str, StixMacAddressId], list[Union[str, StixMacAddressId]]]],
                   pattern=re.compile(r'^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixMacAddress_id = Slot(uri=STIX.id, name="StixMacAddress_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixMacAddress_id, domain=StixMacAddress, range=Union[str, StixMacAddressId],
                   pattern=re.compile(r'^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixMacAddress_type = Slot(uri=STIX.type, name="StixMacAddress_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixMacAddress_type, domain=StixMacAddress, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixMacAddress_value = Slot(uri=STIX.value, name="StixMacAddress_value", curie=STIX.curie('value'),
                   model_uri=STIX.StixMacAddress_value, domain=StixMacAddress, range=str,
                   pattern=re.compile(r'^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$'))

slots.StixMutex_id = Slot(uri=STIX.id, name="StixMutex_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixMutex_id, domain=StixMutex, range=Union[str, StixMutexId],
                   pattern=re.compile(r'^mutex--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixMutex_type = Slot(uri=STIX.type, name="StixMutex_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixMutex_type, domain=StixMutex, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixMutex_name = Slot(uri=STIX.name, name="StixMutex_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixMutex_name, domain=StixMutex, range=str)

slots.StixNetworkTraffic_id = Slot(uri=STIX.id, name="StixNetworkTraffic_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixNetworkTraffic_id, domain=StixNetworkTraffic, range=Union[str, StixNetworkTrafficId],
                   pattern=re.compile(r'^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixNetworkTraffic_type = Slot(uri=STIX.type, name="StixNetworkTraffic_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixNetworkTraffic_type, domain=StixNetworkTraffic, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixNetworkTraffic_protocols = Slot(uri=STIX.protocols, name="StixNetworkTraffic_protocols", curie=STIX.curie('protocols'),
                   model_uri=STIX.StixNetworkTraffic_protocols, domain=StixNetworkTraffic, range=Union[str, list[str]])

slots.StixNetworkTraffic_extensions = Slot(uri=STIX.extensions, name="StixNetworkTraffic_extensions", curie=STIX.curie('extensions'),
                   model_uri=STIX.StixNetworkTraffic_extensions, domain=StixNetworkTraffic, range=Optional[Union[dict, "StixNetworkTrafficExtensions"]])

slots.StixProcess_id = Slot(uri=STIX.id, name="StixProcess_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixProcess_id, domain=StixProcess, range=Union[str, StixProcessId],
                   pattern=re.compile(r'^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixProcess_type = Slot(uri=STIX.type, name="StixProcess_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixProcess_type, domain=StixProcess, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixProcess_extensions = Slot(uri=STIX.extensions, name="StixProcess_extensions", curie=STIX.curie('extensions'),
                   model_uri=STIX.StixProcess_extensions, domain=StixProcess, range=Optional[Union[dict, "StixProcessExtensions"]])

slots.StixSoftware_id = Slot(uri=STIX.id, name="StixSoftware_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixSoftware_id, domain=StixSoftware, range=Union[str, StixSoftwareId],
                   pattern=re.compile(r'^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixSoftware_type = Slot(uri=STIX.type, name="StixSoftware_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixSoftware_type, domain=StixSoftware, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixSoftware_name = Slot(uri=STIX.name, name="StixSoftware_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixSoftware_name, domain=StixSoftware, range=str)

slots.StixUrl_id = Slot(uri=STIX.id, name="StixUrl_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixUrl_id, domain=StixUrl, range=Union[str, StixUrlId],
                   pattern=re.compile(r'^url--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixUrl_type = Slot(uri=STIX.type, name="StixUrl_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixUrl_type, domain=StixUrl, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixUrl_value = Slot(uri=STIX.value, name="StixUrl_value", curie=STIX.curie('value'),
                   model_uri=STIX.StixUrl_value, domain=StixUrl, range=Union[str, URI])

slots.StixUserAccount_id = Slot(uri=STIX.id, name="StixUserAccount_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixUserAccount_id, domain=StixUserAccount, range=Union[str, StixUserAccountId],
                   pattern=re.compile(r'^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixUserAccount_type = Slot(uri=STIX.type, name="StixUserAccount_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixUserAccount_type, domain=StixUserAccount, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixUserAccount_extensions = Slot(uri=STIX.extensions, name="StixUserAccount_extensions", curie=STIX.curie('extensions'),
                   model_uri=STIX.StixUserAccount_extensions, domain=StixUserAccount, range=Optional[Union[dict, "StixUserAccountExtensions"]])

slots.StixWindowsRegistryKey_id = Slot(uri=STIX.id, name="StixWindowsRegistryKey_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixWindowsRegistryKey_id, domain=StixWindowsRegistryKey, range=Union[str, StixWindowsRegistryKeyId],
                   pattern=re.compile(r'^windows-registry-key--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixWindowsRegistryKey_type = Slot(uri=STIX.type, name="StixWindowsRegistryKey_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixWindowsRegistryKey_type, domain=StixWindowsRegistryKey, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixX509Certificate_id = Slot(uri=STIX.id, name="StixX509Certificate_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixX509Certificate_id, domain=StixX509Certificate, range=Union[str, StixX509CertificateId],
                   pattern=re.compile(r'^x509-certificate--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixX509Certificate_type = Slot(uri=STIX.type, name="StixX509Certificate_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixX509Certificate_type, domain=StixX509Certificate, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixArchiveExtension_contains_refs = Slot(uri=STIX.contains_refs, name="StixArchiveExtension_contains_refs", curie=STIX.curie('contains_refs'),
                   model_uri=STIX.StixArchiveExtension_contains_refs, domain=StixArchiveExtension, range=Union[Union[str, StixCyberObservableObjectId], list[Union[str, StixCyberObservableObjectId]]],
                   pattern=re.compile(r'^(file|directory)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixWindowsPeBinaryExtension_pe_type = Slot(uri=STIX.pe_type, name="StixWindowsPeBinaryExtension_pe_type", curie=STIX.curie('pe_type'),
                   model_uri=STIX.StixWindowsPeBinaryExtension_pe_type, domain=StixWindowsPeBinaryExtension, range=Union[str, "StixWindowsPeBinaryType"])

slots.StixHttpRequestExtension_request_method = Slot(uri=STIX.request_method, name="StixHttpRequestExtension_request_method", curie=STIX.curie('request_method'),
                   model_uri=STIX.StixHttpRequestExtension_request_method, domain=StixHttpRequestExtension, range=str)

slots.StixHttpRequestExtension_request_value = Slot(uri=STIX.request_value, name="StixHttpRequestExtension_request_value", curie=STIX.curie('request_value'),
                   model_uri=STIX.StixHttpRequestExtension_request_value, domain=StixHttpRequestExtension, range=str)

slots.StixIcmpExtension_icmp_type_hex = Slot(uri=STIX.icmp_type_hex, name="StixIcmpExtension_icmp_type_hex", curie=STIX.curie('icmp_type_hex'),
                   model_uri=STIX.StixIcmpExtension_icmp_type_hex, domain=StixIcmpExtension, range=Union[str, StixHex])

slots.StixIcmpExtension_icmp_code_hex = Slot(uri=STIX.icmp_code_hex, name="StixIcmpExtension_icmp_code_hex", curie=STIX.curie('icmp_code_hex'),
                   model_uri=STIX.StixIcmpExtension_icmp_code_hex, domain=StixIcmpExtension, range=Union[str, StixHex])

slots.StixSocketExtension_address_family = Slot(uri=STIX.address_family, name="StixSocketExtension_address_family", curie=STIX.curie('address_family'),
                   model_uri=STIX.StixSocketExtension_address_family, domain=StixSocketExtension, range=Union[str, "StixNetworkSocketAddressFamily"])

slots.StixAlternateDataStream_name = Slot(uri=STIX.name, name="StixAlternateDataStream_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixAlternateDataStream_name, domain=StixAlternateDataStream, range=str)

slots.StixWindowsPeSection_name = Slot(uri=STIX.name, name="StixWindowsPeSection_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixWindowsPeSection_name, domain=StixWindowsPeSection, range=str)

slots.StixAttackPattern_id = Slot(uri=STIX.id, name="StixAttackPattern_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixAttackPattern_id, domain=StixAttackPattern, range=Union[str, StixAttackPatternId],
                   pattern=re.compile(r'^attack-pattern--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixAttackPattern_type = Slot(uri=STIX.type, name="StixAttackPattern_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixAttackPattern_type, domain=StixAttackPattern, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixAttackPattern_name = Slot(uri=STIX.name, name="StixAttackPattern_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixAttackPattern_name, domain=StixAttackPattern, range=str)

slots.StixCampaign_id = Slot(uri=STIX.id, name="StixCampaign_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixCampaign_id, domain=StixCampaign, range=Union[str, StixCampaignId],
                   pattern=re.compile(r'^campaign--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixCampaign_type = Slot(uri=STIX.type, name="StixCampaign_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixCampaign_type, domain=StixCampaign, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixCampaign_name = Slot(uri=STIX.name, name="StixCampaign_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixCampaign_name, domain=StixCampaign, range=str)

slots.StixCourseOfAction_id = Slot(uri=STIX.id, name="StixCourseOfAction_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixCourseOfAction_id, domain=StixCourseOfAction, range=Union[str, StixCourseOfActionId],
                   pattern=re.compile(r'^course-of-action--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixCourseOfAction_type = Slot(uri=STIX.type, name="StixCourseOfAction_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixCourseOfAction_type, domain=StixCourseOfAction, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixCourseOfAction_name = Slot(uri=STIX.name, name="StixCourseOfAction_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixCourseOfAction_name, domain=StixCourseOfAction, range=str)

slots.StixGrouping_id = Slot(uri=STIX.id, name="StixGrouping_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixGrouping_id, domain=StixGrouping, range=Union[str, StixGroupingId],
                   pattern=re.compile(r'^grouping--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixGrouping_type = Slot(uri=STIX.type, name="StixGrouping_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixGrouping_type, domain=StixGrouping, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixGrouping_context = Slot(uri=STIX.context, name="StixGrouping_context", curie=STIX.curie('context'),
                   model_uri=STIX.StixGrouping_context, domain=StixGrouping, range=Union[str, "StixGroupingContext"])

slots.StixGrouping_object_refs = Slot(uri=STIX.object_refs, name="StixGrouping_object_refs", curie=STIX.curie('object_refs'),
                   model_uri=STIX.StixGrouping_object_refs, domain=StixGrouping, range=Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]],
                   pattern=re.compile(r'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIncident_id = Slot(uri=STIX.id, name="StixIncident_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixIncident_id, domain=StixIncident, range=Union[str, StixIncidentId],
                   pattern=re.compile(r'^incident--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIncident_type = Slot(uri=STIX.type, name="StixIncident_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixIncident_type, domain=StixIncident, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixIncident_name = Slot(uri=STIX.name, name="StixIncident_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixIncident_name, domain=StixIncident, range=str)

slots.StixIndicator_id = Slot(uri=STIX.id, name="StixIndicator_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixIndicator_id, domain=StixIndicator, range=Union[str, StixIndicatorId],
                   pattern=re.compile(r'^indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIndicator_type = Slot(uri=STIX.type, name="StixIndicator_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixIndicator_type, domain=StixIndicator, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixIndicator_pattern = Slot(uri=STIX.pattern, name="StixIndicator_pattern", curie=STIX.curie('pattern'),
                   model_uri=STIX.StixIndicator_pattern, domain=StixIndicator, range=str)

slots.StixIndicator_pattern_type = Slot(uri=STIX.pattern_type, name="StixIndicator_pattern_type", curie=STIX.curie('pattern_type'),
                   model_uri=STIX.StixIndicator_pattern_type, domain=StixIndicator, range=Union[str, "StixPatternType"])

slots.StixIndicator_valid_from = Slot(uri=STIX.valid_from, name="StixIndicator_valid_from", curie=STIX.curie('valid_from'),
                   model_uri=STIX.StixIndicator_valid_from, domain=StixIndicator, range=Union[str, StixTimestamp])

slots.StixInfrastructure_id = Slot(uri=STIX.id, name="StixInfrastructure_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixInfrastructure_id, domain=StixInfrastructure, range=Union[str, StixInfrastructureId],
                   pattern=re.compile(r'^infrastructure--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixInfrastructure_type = Slot(uri=STIX.type, name="StixInfrastructure_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixInfrastructure_type, domain=StixInfrastructure, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixInfrastructure_name = Slot(uri=STIX.name, name="StixInfrastructure_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixInfrastructure_name, domain=StixInfrastructure, range=str)

slots.StixIntrusionSet_id = Slot(uri=STIX.id, name="StixIntrusionSet_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixIntrusionSet_id, domain=StixIntrusionSet, range=Union[str, StixIntrusionSetId],
                   pattern=re.compile(r'^intrusion-set--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixIntrusionSet_type = Slot(uri=STIX.type, name="StixIntrusionSet_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixIntrusionSet_type, domain=StixIntrusionSet, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixIntrusionSet_name = Slot(uri=STIX.name, name="StixIntrusionSet_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixIntrusionSet_name, domain=StixIntrusionSet, range=str)

slots.StixLocation_id = Slot(uri=STIX.id, name="StixLocation_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixLocation_id, domain=StixLocation, range=Union[str, StixLocationId],
                   pattern=re.compile(r'^location--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixLocation_type = Slot(uri=STIX.type, name="StixLocation_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixLocation_type, domain=StixLocation, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixMalware_id = Slot(uri=STIX.id, name="StixMalware_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixMalware_id, domain=StixMalware, range=Union[str, StixMalwareId],
                   pattern=re.compile(r'^malware--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixMalware_type = Slot(uri=STIX.type, name="StixMalware_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixMalware_type, domain=StixMalware, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixMalware_is_family = Slot(uri=STIX.is_family, name="StixMalware_is_family", curie=STIX.curie('is_family'),
                   model_uri=STIX.StixMalware_is_family, domain=StixMalware, range=Union[bool, Bool])

slots.StixMalwareAnalysis_id = Slot(uri=STIX.id, name="StixMalwareAnalysis_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixMalwareAnalysis_id, domain=StixMalwareAnalysis, range=Union[str, StixMalwareAnalysisId],
                   pattern=re.compile(r'^malware-analysis--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixMalwareAnalysis_type = Slot(uri=STIX.type, name="StixMalwareAnalysis_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixMalwareAnalysis_type, domain=StixMalwareAnalysis, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixMalwareAnalysis_product = Slot(uri=STIX.product, name="StixMalwareAnalysis_product", curie=STIX.curie('product'),
                   model_uri=STIX.StixMalwareAnalysis_product, domain=StixMalwareAnalysis, range=str)

slots.StixNote_id = Slot(uri=STIX.id, name="StixNote_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixNote_id, domain=StixNote, range=Union[str, StixNoteId],
                   pattern=re.compile(r'^note--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixNote_type = Slot(uri=STIX.type, name="StixNote_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixNote_type, domain=StixNote, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixNote_content = Slot(uri=STIX.content, name="StixNote_content", curie=STIX.curie('content'),
                   model_uri=STIX.StixNote_content, domain=StixNote, range=str)

slots.StixNote_object_refs = Slot(uri=STIX.object_refs, name="StixNote_object_refs", curie=STIX.curie('object_refs'),
                   model_uri=STIX.StixNote_object_refs, domain=StixNote, range=Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]],
                   pattern=re.compile(r'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixObservedData_id = Slot(uri=STIX.id, name="StixObservedData_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixObservedData_id, domain=StixObservedData, range=Union[str, StixObservedDataId],
                   pattern=re.compile(r'^observed-data--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixObservedData_type = Slot(uri=STIX.type, name="StixObservedData_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixObservedData_type, domain=StixObservedData, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixObservedData_first_observed = Slot(uri=STIX.first_observed, name="StixObservedData_first_observed", curie=STIX.curie('first_observed'),
                   model_uri=STIX.StixObservedData_first_observed, domain=StixObservedData, range=Union[str, StixTimestamp])

slots.StixObservedData_last_observed = Slot(uri=STIX.last_observed, name="StixObservedData_last_observed", curie=STIX.curie('last_observed'),
                   model_uri=STIX.StixObservedData_last_observed, domain=StixObservedData, range=Union[str, StixTimestamp])

slots.StixObservedData_number_observed = Slot(uri=STIX.number_observed, name="StixObservedData_number_observed", curie=STIX.curie('number_observed'),
                   model_uri=STIX.StixObservedData_number_observed, domain=StixObservedData, range=int)

slots.StixObservedData_object_refs = Slot(uri=STIX.object_refs, name="StixObservedData_object_refs", curie=STIX.curie('object_refs'),
                   model_uri=STIX.StixObservedData_object_refs, domain=StixObservedData, range=Optional[Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]]],
                   pattern=re.compile(r'^(?!(attack-pattern|campaign|course-of-action|grouping|identity|incident|indicator|infrastructure|intrusion-set|location|malware|malware-analysis|note|observed-data|opinion|report|threat-actor|tool|vulnerability)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixObservedData_objects = Slot(uri=STIX.objects, name="StixObservedData_objects", curie=STIX.curie('objects'),
                   model_uri=STIX.StixObservedData_objects, domain=StixObservedData, range=Optional[Union[dict, "StixObservedObjects"]])

slots.StixOpinion_id = Slot(uri=STIX.id, name="StixOpinion_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixOpinion_id, domain=StixOpinion, range=Union[str, StixOpinionId],
                   pattern=re.compile(r'^opinion--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixOpinion_type = Slot(uri=STIX.type, name="StixOpinion_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixOpinion_type, domain=StixOpinion, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixOpinion_object_refs = Slot(uri=STIX.object_refs, name="StixOpinion_object_refs", curie=STIX.curie('object_refs'),
                   model_uri=STIX.StixOpinion_object_refs, domain=StixOpinion, range=Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]],
                   pattern=re.compile(r'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixOpinion_opinion = Slot(uri=STIX.opinion, name="StixOpinion_opinion", curie=STIX.curie('opinion'),
                   model_uri=STIX.StixOpinion_opinion, domain=StixOpinion, range=Union[str, "StixAgreement"])

slots.StixReport_id = Slot(uri=STIX.id, name="StixReport_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixReport_id, domain=StixReport, range=Union[str, StixReportId],
                   pattern=re.compile(r'^report--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixReport_type = Slot(uri=STIX.type, name="StixReport_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixReport_type, domain=StixReport, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixReport_name = Slot(uri=STIX.name, name="StixReport_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixReport_name, domain=StixReport, range=str)

slots.StixReport_object_refs = Slot(uri=STIX.object_refs, name="StixReport_object_refs", curie=STIX.curie('object_refs'),
                   model_uri=STIX.StixReport_object_refs, domain=StixReport, range=Union[Union[str, StixObjectId], list[Union[str, StixObjectId]]],
                   pattern=re.compile(r'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixReport_published = Slot(uri=STIX.published, name="StixReport_published", curie=STIX.curie('published'),
                   model_uri=STIX.StixReport_published, domain=StixReport, range=Union[str, StixTimestamp])

slots.StixThreatActor_id = Slot(uri=STIX.id, name="StixThreatActor_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixThreatActor_id, domain=StixThreatActor, range=Union[str, StixThreatActorId],
                   pattern=re.compile(r'^threat-actor--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixThreatActor_type = Slot(uri=STIX.type, name="StixThreatActor_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixThreatActor_type, domain=StixThreatActor, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixThreatActor_name = Slot(uri=STIX.name, name="StixThreatActor_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixThreatActor_name, domain=StixThreatActor, range=str)

slots.StixThreatActor_roles = Slot(uri=STIX.roles, name="StixThreatActor_roles", curie=STIX.curie('roles'),
                   model_uri=STIX.StixThreatActor_roles, domain=StixThreatActor, range=Optional[Union[str, list[str]]])

slots.StixTool_id = Slot(uri=STIX.id, name="StixTool_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixTool_id, domain=StixTool, range=Union[str, StixToolId],
                   pattern=re.compile(r'^tool--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixTool_type = Slot(uri=STIX.type, name="StixTool_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixTool_type, domain=StixTool, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixTool_name = Slot(uri=STIX.name, name="StixTool_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixTool_name, domain=StixTool, range=str)

slots.StixVulnerability_id = Slot(uri=STIX.id, name="StixVulnerability_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixVulnerability_id, domain=StixVulnerability, range=Union[str, StixVulnerabilityId],
                   pattern=re.compile(r'^vulnerability--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixVulnerability_type = Slot(uri=STIX.type, name="StixVulnerability_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixVulnerability_type, domain=StixVulnerability, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixVulnerability_name = Slot(uri=STIX.name, name="StixVulnerability_name", curie=STIX.curie('name'),
                   model_uri=STIX.StixVulnerability_name, domain=StixVulnerability, range=str)

slots.StixRelationship_id = Slot(uri=STIX.id, name="StixRelationship_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixRelationship_id, domain=StixRelationship, range=Union[str, StixRelationshipId],
                   pattern=re.compile(r'^relationship--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixRelationship_type = Slot(uri=STIX.type, name="StixRelationship_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixRelationship_type, domain=StixRelationship, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixRelationship_relationship_type = Slot(uri=STIX.relationship_type, name="StixRelationship_relationship_type", curie=STIX.curie('relationship_type'),
                   model_uri=STIX.StixRelationship_relationship_type, domain=StixRelationship, range=str,
                   pattern=re.compile(r'^[a-z0-9\-]+$'))

slots.StixRelationship_source_ref = Slot(uri=STIX.source_ref, name="StixRelationship_source_ref", curie=STIX.curie('source_ref'),
                   model_uri=STIX.StixRelationship_source_ref, domain=StixRelationship, range=Union[str, StixDomainObjectId, StixCyberObservableObjectId],
                   pattern=re.compile(r'^(?!(relationship|sighting|bundle|marking-definition|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixRelationship_target_ref = Slot(uri=STIX.target_ref, name="StixRelationship_target_ref", curie=STIX.curie('target_ref'),
                   model_uri=STIX.StixRelationship_target_ref, domain=StixRelationship, range=Union[str, StixDomainObjectId, StixCyberObservableObjectId],
                   pattern=re.compile(r'^(?!(relationship|sighting|bundle|marking-definition|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixSighting_id = Slot(uri=STIX.id, name="StixSighting_id", curie=STIX.curie('id'),
                   model_uri=STIX.StixSighting_id, domain=StixSighting, range=Union[str, StixSightingId],
                   pattern=re.compile(r'^sighting--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))

slots.StixSighting_type = Slot(uri=STIX.type, name="StixSighting_type", curie=STIX.curie('type'),
                   model_uri=STIX.StixSighting_type, domain=StixSighting, range=str,
                   pattern=re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$'))

slots.StixSighting_sighting_of_ref = Slot(uri=STIX.sighting_of_ref, name="StixSighting_sighting_of_ref", curie=STIX.curie('sighting_of_ref'),
                   model_uri=STIX.StixSighting_sighting_of_ref, domain=StixSighting, range=Union[str, StixDomainObjectId],
                   pattern=re.compile(r'^(?!(artifact|autonomous-system|directory|domain-name|email-addr|email-message|file|ipv4-addr|ipv6-addr|mac-addr|mutex|network-traffic|process|software|url|user-account|windows-registry-key|x509-certificate|relationship|sighting|bundle|marking-definition|language-content|extension-definition)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'))
