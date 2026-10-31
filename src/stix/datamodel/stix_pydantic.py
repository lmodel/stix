from __future__ import annotations

import re
import sys
from datetime import (
    date,
    datetime,
    time
)
from decimal import Decimal
from enum import Enum
from typing import (
    Any,
    ClassVar,
    Literal,
    Optional,
    Union
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer
)


metamodel_version = "1.12.0"
version = "2.1"


class ConfiguredBaseModel(BaseModel):
    model_config = ConfigDict(
        serialize_by_alias = True,
        validate_by_name = True,
        validate_assignment = True,
        validate_default = True,
        extra = "forbid",
        arbitrary_types_allowed = True,
        use_enum_values = True,
        strict = False,
    )





class LinkMLMeta(RootModel):
    root: dict[str, Any] = {}
    model_config = ConfigDict(frozen=True)

    def __getattr__(self, key:str):
        return getattr(self.root, key)

    def __getitem__(self, key:str):
        return self.root[key]

    def __setitem__(self, key:str, value):
        self.root[key] = value

    def __contains__(self, key:str) -> bool:
        return key in self.root


linkml_meta = LinkMLMeta({'annotations': {'json_schemas_commit': {'tag': 'json_schemas_commit',
                                             'value': '9af1db41b7b86c06324f899649ae83480134f66e'},
                     'json_schemas_repository': {'tag': 'json_schemas_repository',
                                                 'value': 'https://github.com/oasis-open/cti-stix2-json-schemas'},
                     'stix_publication_date': {'tag': 'stix_publication_date',
                                               'value': '2021-06-10'}},
     'comments': ['The version is the edition of STIX that the schema renders, and '
                  'source is the OASIS Standard of 10 June 2021. OASIS publishes '
                  'no release of its JSON schemas, so upstream/ copies them, their '
                  'examples and their licence at the commit in the annotations, '
                  'and scripts/check_upstream_release.py reports when that '
                  'repository moves. STIX 2.1 Errata 01 exists only as a Committee '
                  'Specification Draft (2 April 2025); the schema follows the '
                  'approved standard, and the values the draft adds to four open '
                  'vocabularies validate anyway.',
                  'The specification is copyright OASIS Open, and nothing here '
                  "copies its text. Descriptions come from OASIS's JSON schemas, "
                  'which are under the BSD-3-Clause licence that NOTICE carries, '
                  "or are this project's own.",
                  'The classes are closed: an object validates only with the '
                  'properties its class declares. STIX allows custom properties '
                  'and custom objects; they validate once a schema that imports '
                  'this one declares them, as a slot of a subclass or a class of '
                  "its own, as lmodel/attack does for MITRE's x_mitre_ properties "
                  'and x-mitre- objects. Opening the object bases with extra_slots '
                  "would accept every misspelled key as well, and LinkML 1.12.1's "
                  'Pydantic generator ignores extra_slots.',
                  'The JSON keys that contain a hyphen are dictionary keys, never '
                  'property names: hash algorithms (SHA-256), extension names '
                  '(ntfs-ext) and extension definition identifiers. The '
                  'dictionaries that hold them are classes with extra_slots, which '
                  'the generated JSON Schema checks; the generated Python models '
                  'do not, and docs/index.md lists what goes unchecked.',
                  'Classes and slots map to terms of the Unified Cyber Ontology '
                  "(UCO) 1.5.0 where the meaning matches, under UCO's own "
                  'namespaces: close_mappings for the cyber-observable objects, '
                  'their extensions and the shared objects, and broad_mappings for '
                  'Tool, which UCO defines more widely. The domain objects that '
                  'UCO has no term for are left unmapped. tests/test_mappings.py '
                  "checks each against UCO's term list."],
     'default_prefix': 'stix',
     'default_range': 'string',
     'description': 'A LinkML model of Structured Threat Information Expression '
                    '(STIX) Version 2.1, the OASIS Standard for exchanging cyber '
                    'threat intelligence: its domain, relationship, '
                    'cyber-observable and meta objects, their properties, '
                    'vocabularies and enumerations, and the bundle that carries '
                    "them. STIX's own property names are the schema's keys, so "
                    'STIX JSON validates unchanged.',
     'id': 'https://w3id.org/lmodel/stix',
     'imports': ['linkml:types',
                 './stix_vocabularies',
                 './stix_core',
                 './stix_sco',
                 './stix_sdo',
                 './stix_sro'],
     'license': 'Apache-2.0',
     'name': 'stix',
     'prefixes': {'linkml': {'prefix_prefix': 'linkml',
                             'prefix_reference': 'https://w3id.org/linkml/'},
                  'stix': {'prefix_prefix': 'stix',
                           'prefix_reference': 'https://w3id.org/lmodel/stix/'},
                  'uco-core': {'prefix_prefix': 'uco-core',
                               'prefix_reference': 'https://ontology.unifiedcyberontology.org/uco/core/'}},
     'see_also': ['https://lmodel.github.io/stix',
                  'https://github.com/oasis-open/cti-stix2-json-schemas/tree/9af1db41b7b86c06324f899649ae83480134f66e'],
     'source': 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html',
     'source_file': 'src/stix/schema/stix.yaml',
     'title': 'Structured Threat Information Expression (STIX)'} )

class StixAccountType(str, Enum):
    """
    Types of user account. An open vocabulary: a slot that names it also takes any other string.
    """
    facebook = "facebook"
    ldap = "ldap"
    nis = "nis"
    openid = "openid"
    radius = "radius"
    skype = "skype"
    tacacs = "tacacs"
    twitter = "twitter"
    unix = "unix"
    windows_local = "windows-local"
    windows_domain = "windows-domain"


class StixAttackMotivation(str, Enum):
    """
    Reasons, motivations or purposes behind an attack. An open vocabulary: a slot that names it also takes any other string.
    """
    accidental = "accidental"
    coercion = "coercion"
    dominance = "dominance"
    ideology = "ideology"
    notoriety = "notoriety"
    organizational_gain = "organizational-gain"
    personal_gain = "personal-gain"
    personal_satisfaction = "personal-satisfaction"
    revenge = "revenge"
    unpredictable = "unpredictable"


class StixAttackResourceLevel(str, Enum):
    """
    Levels of the resources that an actor may have, from an individual to a government. An open vocabulary: a slot that names it also takes any other string.
    """
    individual = "individual"
    club = "club"
    contest = "contest"
    team = "team"
    organization = "organization"
    government = "government"


class StixEncryptionAlgorithm(str, Enum):
    """
    Encryption algorithms for sharing defanged or confidential artifacts. A closed enumeration: no other value is valid.
    """
    AES_256_GCM = "AES-256-GCM"
    ChaCha20_Poly1305 = "ChaCha20-Poly1305"
    mime_type_indicated = "mime-type-indicated"


class StixExtensionType(str, Enum):
    """
    The kinds of extension that an extension definition can define. A closed enumeration: no other value is valid.
    """
    new_sdo = "new-sdo"
    new_sco = "new-sco"
    new_sro = "new-sro"
    property_extension = "property-extension"
    toplevel_property_extension = "toplevel-property-extension"


class StixGroupingContext(str, Enum):
    """
    Contexts of a grouping. An open vocabulary: a slot that names it also takes any other string.
    """
    suspicious_activity = "suspicious-activity"
    malware_analysis = "malware-analysis"
    unspecified = "unspecified"


class StixHashAlgorithm(str, Enum):
    """
    Hash algorithms, as the keys of a hashes dictionary name them. An open vocabulary: a slot that names it also takes any other string.
    """
    MD5 = "MD5"
    SHA_1 = "SHA-1"
    SHA_256 = "SHA-256"
    SHA_512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"
    SSDEEP = "SSDEEP"
    TLSH = "TLSH"


class StixIdentityClass(str, Enum):
    """
    Kinds of entity that an identity describes. An open vocabulary: a slot that names it also takes any other string.
    """
    individual = "individual"
    group = "group"
    system = "system"
    organization = "organization"
    class_ = "class"
    unknown = "unknown"


class StixImplementationLanguage(str, Enum):
    """
    Programming languages in which malware may be implemented. An open vocabulary: a slot that names it also takes any other string.
    """
    applescript = "applescript"
    bash = "bash"
    c = "c"
    cPLUS_SIGNPLUS_SIGN = "c++"
    cNUMBER_SIGN = "c#"
    go = "go"
    java = "java"
    javascript = "javascript"
    lua = "lua"
    objective_c = "objective-c"
    perl = "perl"
    php = "php"
    powershell = "powershell"
    python = "python"
    ruby = "ruby"
    scala = "scala"
    swift = "swift"
    typescript = "typescript"
    visual_basic = "visual-basic"
    x86_32 = "x86-32"
    x86_64 = "x86-64"


class StixIndicatorType(str, Enum):
    """
    High-level categories of indicator. An open vocabulary: a slot that names it also takes any other string.
    """
    anomalous_activity = "anomalous-activity"
    anonymization = "anonymization"
    benign = "benign"
    compromised = "compromised"
    malicious_activity = "malicious-activity"
    attribution = "attribution"
    unknown = "unknown"


class StixIndustrySector(str, Enum):
    """
    Industrial and commercial sectors. An open vocabulary: a slot that names it also takes any other string.
    """
    agriculture = "agriculture"
    aerospace = "aerospace"
    automotive = "automotive"
    chemical = "chemical"
    commercial = "commercial"
    communications = "communications"
    construction = "construction"
    defense = "defense"
    education = "education"
    energy = "energy"
    entertainment = "entertainment"
    financial_services = "financial-services"
    government = "government"
    emergency_services = "emergency-services"
    government_local = "government-local"
    government_national = "government-national"
    government_public_services = "government-public-services"
    government_regional = "government-regional"
    healthcare = "healthcare"
    hospitality_leisure = "hospitality-leisure"
    infrastructure = "infrastructure"
    dams = "dams"
    nuclear = "nuclear"
    water = "water"
    insurance = "insurance"
    manufacturing = "manufacturing"
    mining = "mining"
    non_profit = "non-profit"
    pharmaceuticals = "pharmaceuticals"
    retail = "retail"
    technology = "technology"
    telecommunications = "telecommunications"
    transportation = "transportation"
    utilities = "utilities"


class StixInfrastructureType(str, Enum):
    """
    Types of infrastructure. An open vocabulary: a slot that names it also takes any other string.
    """
    amplification = "amplification"
    anonymization = "anonymization"
    botnet = "botnet"
    command_and_control = "command-and-control"
    control_system = "control-system"
    exfiltration = "exfiltration"
    firewall = "firewall"
    hosting_malware = "hosting-malware"
    hosting_target_lists = "hosting-target-lists"
    phishing = "phishing"
    reconnaissance = "reconnaissance"
    routers_switches = "routers-switches"
    staging = "staging"
    workstation = "workstation"
    unknown = "unknown"


class StixMalwareResult(str, Enum):
    """
    Results of a scanner's or tool's analysis of malware. An open vocabulary: a slot that names it also takes any other string.
    """
    malicious = "malicious"
    suspicious = "suspicious"
    benign = "benign"
    unknown = "unknown"


class StixMalwareCapability(str, Enum):
    """
    Capabilities that malware may have. An open vocabulary: a slot that names it also takes any other string.
    """
    accesses_remote_machines = "accesses-remote-machines"
    anti_debugging = "anti-debugging"
    anti_disassembly = "anti-disassembly"
    anti_emulation = "anti-emulation"
    anti_memory_forensics = "anti-memory-forensics"
    anti_sandbox = "anti-sandbox"
    anti_vm = "anti-vm"
    captures_input_peripherals = "captures-input-peripherals"
    captures_output_peripherals = "captures-output-peripherals"
    captures_system_state_data = "captures-system-state-data"
    cleans_traces_of_infection = "cleans-traces-of-infection"
    commits_fraud = "commits-fraud"
    communicates_with_c2 = "communicates-with-c2"
    compromises_data_availability = "compromises-data-availability"
    compromises_data_integrity = "compromises-data-integrity"
    compromises_system_availability = "compromises-system-availability"
    controls_local_machine = "controls-local-machine"
    degrades_security_software = "degrades-security-software"
    degrades_system_updates = "degrades-system-updates"
    determines_c2_server = "determines-c2-server"
    emails_spam = "emails-spam"
    escalates_privileges = "escalates-privileges"
    evades_av = "evades-av"
    exfiltrates_data = "exfiltrates-data"
    fingerprints_host = "fingerprints-host"
    hides_artifacts = "hides-artifacts"
    hides_executing_code = "hides-executing-code"
    infects_files = "infects-files"
    infects_remote_machines = "infects-remote-machines"
    installs_other_components = "installs-other-components"
    persists_after_system_reboot = "persists-after-system-reboot"
    prevents_artifact_access = "prevents-artifact-access"
    prevents_artifact_deletion = "prevents-artifact-deletion"
    probes_network_environment = "probes-network-environment"
    self_modifies = "self-modifies"
    steals_authentication_credentials = "steals-authentication-credentials"
    violates_system_operational_integrity = "violates-system-operational-integrity"


class StixMalwareType(str, Enum):
    """
    Types of malware. An open vocabulary: a slot that names it also takes any other string.
    """
    adware = "adware"
    backdoor = "backdoor"
    bot = "bot"
    bootkit = "bootkit"
    ddos = "ddos"
    downloader = "downloader"
    dropper = "dropper"
    exploit_kit = "exploit-kit"
    keylogger = "keylogger"
    ransomware = "ransomware"
    remote_access_trojan = "remote-access-trojan"
    resource_exploitation = "resource-exploitation"
    rogue_security_software = "rogue-security-software"
    rootkit = "rootkit"
    screen_capture = "screen-capture"
    spyware = "spyware"
    trojan = "trojan"
    unknown = "unknown"
    virus = "virus"
    webshell = "webshell"
    wiper = "wiper"
    worm = "worm"


class StixNetworkSocketAddressFamily(str, Enum):
    """
    Address families of a network socket. A closed enumeration: no other value is valid.
    """
    AF_UNSPEC = "AF_UNSPEC"
    AF_INET = "AF_INET"
    AF_IPX = "AF_IPX"
    AF_APPLETALK = "AF_APPLETALK"
    AF_NETBIOS = "AF_NETBIOS"
    AF_INET6 = "AF_INET6"
    AF_IRDA = "AF_IRDA"
    AF_BTH = "AF_BTH"


class StixNetworkSocketType(str, Enum):
    """
    Types of network socket. A closed enumeration: no other value is valid.
    """
    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"
    SOCK_RAW = "SOCK_RAW"
    SOCK_RDM = "SOCK_RDM"
    SOCK_SEQPACKET = "SOCK_SEQPACKET"


class StixAgreement(str, Enum):
    """
    Degrees of agreement with the information in a STIX object, from disagreement to agreement. A closed enumeration: no other value is valid.
    """
    strongly_disagree = "strongly-disagree"
    disagree = "disagree"
    neutral = "neutral"
    agree = "agree"
    strongly_agree = "strongly-agree"


class StixPatternType(str, Enum):
    """
    Pattern languages in which an indicator's pattern may be written. An open vocabulary: a slot that names it also takes any other string.
    """
    stix = "stix"
    pcre = "pcre"
    sigma = "sigma"
    snort = "snort"
    suricata = "suricata"
    yara = "yara"


class StixProcessorArchitecture(str, Enum):
    """
    Processor architectures. An open vocabulary: a slot that names it also takes any other string.
    """
    alpha = "alpha"
    arm = "arm"
    ia_64 = "ia-64"
    mips = "mips"
    powerpc = "powerpc"
    sparc = "sparc"
    x86 = "x86"
    x86_64 = "x86-64"


class StixRegion(str, Enum):
    """
    World regions, after the United Nations geoscheme (UNSD M49). An open vocabulary: a slot that names it also takes any other string.
    """
    africa = "africa"
    eastern_africa = "eastern-africa"
    middle_africa = "middle-africa"
    northern_africa = "northern-africa"
    southern_africa = "southern-africa"
    western_africa = "western-africa"
    americas = "americas"
    caribbean = "caribbean"
    central_america = "central-america"
    latin_america_caribbean = "latin-america-caribbean"
    northern_america = "northern-america"
    south_america = "south-america"
    asia = "asia"
    central_asia = "central-asia"
    eastern_asia = "eastern-asia"
    southern_asia = "southern-asia"
    south_eastern_asia = "south-eastern-asia"
    western_asia = "western-asia"
    europe = "europe"
    eastern_europe = "eastern-europe"
    northern_europe = "northern-europe"
    southern_europe = "southern-europe"
    western_europe = "western-europe"
    oceania = "oceania"
    antarctica = "antarctica"
    australia_new_zealand = "australia-new-zealand"
    melanesia = "melanesia"
    micronesia = "micronesia"
    polynesia = "polynesia"


class StixReportType(str, Enum):
    """
    Primary subjects of a report. An open vocabulary: a slot that names it also takes any other string.
    """
    attack_pattern = "attack-pattern"
    campaign = "campaign"
    identity = "identity"
    indicator = "indicator"
    intrusion_set = "intrusion-set"
    malware = "malware"
    observed_data = "observed-data"
    threat_actor = "threat-actor"
    threat_report = "threat-report"
    tool = "tool"
    vulnerability = "vulnerability"


class StixThreatActorType(str, Enum):
    """
    Types of threat actor. An open vocabulary: a slot that names it also takes any other string.
    """
    activist = "activist"
    competitor = "competitor"
    crime_syndicate = "crime-syndicate"
    criminal = "criminal"
    hacker = "hacker"
    insider_accidental = "insider-accidental"
    insider_disgruntled = "insider-disgruntled"
    nation_state = "nation-state"
    sensationalist = "sensationalist"
    spy = "spy"
    terrorist = "terrorist"
    unknown = "unknown"


class StixThreatActorRole(str, Enum):
    """
    Roles that a threat actor may play. An open vocabulary: a slot that names it also takes any other string.
    """
    agent = "agent"
    director = "director"
    independent = "independent"
    infrastructure_architect = "infrastructure-architect"
    infrastructure_operator = "infrastructure-operator"
    malware_author = "malware-author"
    sponsor = "sponsor"


class StixThreatActorSophistication(str, Enum):
    """
    Skill levels of a threat actor. An open vocabulary: a slot that names it also takes any other string.
    """
    none = "none"
    minimal = "minimal"
    intermediate = "intermediate"
    advanced = "advanced"
    expert = "expert"
    innovator = "innovator"
    strategic = "strategic"


class StixToolType(str, Enum):
    """
    Categories of tool that may be used to perform attacks. An open vocabulary: a slot that names it also takes any other string.
    """
    denial_of_service = "denial-of-service"
    exploitation = "exploitation"
    information_gathering = "information-gathering"
    network_capture = "network-capture"
    credential_exploitation = "credential-exploitation"
    remote_access = "remote-access"
    vulnerability_scanning = "vulnerability-scanning"
    unknown = "unknown"


class StixWindowsIntegrityLevel(str, Enum):
    """
    Windows integrity levels. A closed enumeration: no other value is valid.
    """
    low = "low"
    medium = "medium"
    high = "high"
    system = "system"


class StixWindowsPeBinaryType(str, Enum):
    """
    Types of Windows PE binary. An open vocabulary: a slot that names it also takes any other string.
    """
    dll = "dll"
    exe = "exe"
    sys = "sys"


class StixWindowsRegistryDatatype(str, Enum):
    """
    Data types of a Windows registry value. A closed enumeration: no other value is valid.
    """
    REG_NONE = "REG_NONE"
    REG_SZ = "REG_SZ"
    REG_EXPAND_SZ = "REG_EXPAND_SZ"
    REG_BINARY = "REG_BINARY"
    REG_DWORD = "REG_DWORD"
    REG_DWORD_BIG_ENDIAN = "REG_DWORD_BIG_ENDIAN"
    REG_DWORD_LITTLE_ENDIAN = "REG_DWORD_LITTLE_ENDIAN"
    REG_LINK = "REG_LINK"
    REG_MULTI_SZ = "REG_MULTI_SZ"
    REG_RESOURCE_LIST = "REG_RESOURCE_LIST"
    REG_FULL_RESOURCE_DESCRIPTION = "REG_FULL_RESOURCE_DESCRIPTION"
    REG_RESOURCE_REQUIREMENTS_LIST = "REG_RESOURCE_REQUIREMENTS_LIST"
    REG_QWORD = "REG_QWORD"
    REG_INVALID_TYPE = "REG_INVALID_TYPE"


class StixWindowsServiceStartType(str, Enum):
    """
    Start types of a Windows service. A closed enumeration: no other value is valid.
    """
    SERVICE_AUTO_START = "SERVICE_AUTO_START"
    SERVICE_BOOT_START = "SERVICE_BOOT_START"
    SERVICE_DEMAND_START = "SERVICE_DEMAND_START"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    SERVICE_SYSTEM_ALERT = "SERVICE_SYSTEM_ALERT"


class StixWindowsServiceType(str, Enum):
    """
    Types of Windows service. A closed enumeration: no other value is valid.
    """
    SERVICE_KERNEL_DRIVER = "SERVICE_KERNEL_DRIVER"
    SERVICE_FILE_SYSTEM_DRIVER = "SERVICE_FILE_SYSTEM_DRIVER"
    SERVICE_WIN32_OWN_PROCESS = "SERVICE_WIN32_OWN_PROCESS"
    SERVICE_WIN32_SHARE_PROCESS = "SERVICE_WIN32_SHARE_PROCESS"


class StixWindowsServiceStatus(str, Enum):
    """
    Statuses of a Windows service. A closed enumeration: no other value is valid.
    """
    SERVICE_CONTINUE_PENDING = "SERVICE_CONTINUE_PENDING"
    SERVICE_PAUSE_PENDING = "SERVICE_PAUSE_PENDING"
    SERVICE_PAUSED = "SERVICE_PAUSED"
    SERVICE_RUNNING = "SERVICE_RUNNING"
    SERVICE_START_PENDING = "SERVICE_START_PENDING"
    SERVICE_STOP_PENDING = "SERVICE_STOP_PENDING"
    SERVICE_STOPPED = "SERVICE_STOPPED"


class StixSpecVersion(str, Enum):
    """
    The STIX versions that an object may declare. The JSON schemas accept 2.0 beside 2.1. A closed enumeration.
    """
    number_2FULL_STOP0 = "2.0"
    number_2FULL_STOP1 = "2.1"


class StixTlpLevel(str, Enum):
    """
    The four levels of the Traffic Light Protocol (TLP) that STIX 2.1 defines marking definitions for. A closed enumeration.
    """
    white = "white"
    green = "green"
    amber = "amber"
    red = "red"


class StixMarkingDefinitionType(str, Enum):
    """
    The marking definition types that STIX 2.1 defines, statement and tlp. A slot that names it also takes any other string, as the JSON schemas do.
    """
    statement = "statement"
    tlp = "tlp"



class StixObject(ConfiguredBaseModel):
    """
    Any STIX object: the base of the domain, relationship and cyber-observable objects and of the meta objects.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: str = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixCommonObject(StixObject):
    """
    The base of the objects that carry STIX's common properties: the domain and relationship objects, language content and extension definitions.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True,
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'created': {'name': 'created', 'required': True},
                        'modified': {'name': 'modified', 'required': True},
                        'spec_version': {'name': 'spec_version', 'required': True}}})

    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: str = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixDomainObject(StixCommonObject):
    """
    A STIX Domain Object (SDO): a higher-level concept of cyber threat intelligence, such as an attack pattern, a malware family or a threat actor.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: str = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixRelationshipObject(StixCommonObject):
    """
    A STIX Relationship Object (SRO): a relationship or a sighting that links other objects.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: str = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixCyberObservableObject(StixObject):
    """
    A STIX Cyber-observable Object (SCO): a fact observed on a network or host, such as a file, an address or a process.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: str = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixIdentity(StixDomainObject):
    """
    Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, or groups.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'identity'}},
         'close_mappings': ['uco-identity:Identity'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'identity', 'name': 'type'}}})

    roles: Optional[list[str]] = Field(default=None, description="""The roles that the identity or threat actor plays.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixIdentity', 'StixThreatActor'], 'slot_uri': 'stix:roles'} })
    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    identity_class: Optional[Union[StixIdentityClass, str]] = Field(default=None, description="""The type of entity that this Identity describes, e.g., an individual or organization. Open Vocab - identity-class-ov.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixIdentityClass'}, {'range': 'string'}],
         'domain_of': ['StixIdentity'],
         'slot_uri': 'stix:identity_class'} })
    sectors: Optional[list[Union[StixIndustrySector, str]]] = Field(default=None, description="""The list of sectors that this Identity belongs to. Open Vocab - industry-sector-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixIndustrySector'}, {'range': 'string'}],
         'domain_of': ['StixIdentity'],
         'slot_uri': 'stix:sectors'} })
    contact_information: Optional[str] = Field(default=None, description="""The contact information (e-mail, phone number, etc.) for this Identity.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixIdentity'], 'slot_uri': 'stix:contact_information'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["identity"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'identity',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixMarkingDefinition(StixObject):
    """
    A marking definition: a statement, a Traffic Light Protocol (TLP) level or another marking that applies to the objects that reference it.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'marking-definition'}},
         'close_mappings': ['uco-marking:MarkingDefinition'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'rules': [{'description': 'Without extensions, a marking definition states '
                                   'its definition and definition type.',
                    'postconditions': {'slot_conditions': {'definition': {'name': 'definition',
                                                                          'required': True},
                                                           'definition_type': {'name': 'definition_type',
                                                                               'required': True}}},
                    'preconditions': {'slot_conditions': {'extensions': {'name': 'extensions',
                                                                         'value_presence': 'ABSENT'}}}}],
         'slot_usage': {'created': {'name': 'created',
                                    'range': 'stix_timestamp',
                                    'required': True},
                        'id': {'name': 'id',
                               'pattern': '^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'spec_version': {'name': 'spec_version', 'required': True},
                        'type': {'equals_string': 'marking-definition',
                                 'name': 'type'}}})

    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    definition_type: Optional[Union[StixMarkingDefinitionType, str]] = Field(default=None, description="""The type of the marking definition, such as statement or tlp.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixMarkingDefinitionType'}, {'range': 'string'}],
         'close_mappings': ['uco-marking:definitionType'],
         'domain_of': ['StixMarkingDefinition'],
         'slot_uri': 'stix:definition_type'} })
    definition: Optional[Union[StixStatementMarking, StixTlpMarking]] = Field(default=None, description="""The marking itself: a statement, or a Traffic Light Protocol (TLP) level.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixStatementMarking'}, {'range': 'StixTlpMarking'}],
         'close_mappings': ['uco-marking:definition'],
         'domain_of': ['StixMarkingDefinition'],
         'slot_uri': 'stix:definition'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["marking-definition"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'marking-definition',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixLanguageContent(StixCommonObject):
    """
    The language-content object represents text content for STIX Objects represented in languages other than that of the original object.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'language-content'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'contents': {'name': 'contents', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^language-content--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_ref': {'name': 'object_ref', 'required': True},
                        'type': {'equals_string': 'language-content', 'name': 'type'}}})

    object_ref: str = Field(default=..., description="""Identifies the object that this Language Content applies to.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLanguageContent'], 'slot_uri': 'stix:object_ref'} })
    object_modified: Optional[str] = Field(default=None, description="""Identifies the modified time of the object that this Language Content applies to.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLanguageContent'], 'slot_uri': 'stix:object_modified'} })
    contents: StixLanguageContents = Field(default=..., description="""Contains the actual Language Content (translation).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLanguageContent'], 'slot_uri': 'stix:contents'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["language-content"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'language-content',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('object_ref')
    def pattern_object_ref(cls, v):
        pattern=re.compile(r"^(?!(bundle|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^language-content--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixExtensionDefinition(StixCommonObject):
    """
    The STIX Extension Definition object allows producers of threat intelligence to extend existing STIX objects or to create entirely new STIX objects in a standardized way.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'extension-definition'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'extension_types': {'name': 'extension_types',
                                            'required': True},
                        'id': {'name': 'id',
                               'pattern': '^extension-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'schema': {'name': 'schema', 'required': True},
                        'type': {'equals_string': 'extension-definition',
                                 'name': 'type'},
                        'version': {'name': 'version', 'required': True}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    schema: str = Field(default=..., description="""The normative definition of the extension, either as a URL or as plain text explaining the definition.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition'], 'slot_uri': 'stix:schema'} })
    version: str = Field(default=..., description="""A version, as a string; each class says of what.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition',
                       'StixSoftware',
                       'StixX509Certificate',
                       'StixPdfExtension',
                       'StixMalwareAnalysis'],
         'slot_uri': 'stix:version'} })
    extension_types: list[StixExtensionType] = Field(default=..., description="""Which extension types are contained within this extension.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition'], 'slot_uri': 'stix:extension_types'} })
    extension_properties: Optional[list[str]] = Field(default=None, description="""The list of new property names that are added to an object by this extension.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition'],
         'slot_uri': 'stix:extension_properties'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["extension-definition"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'extension-definition',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^extension-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixExternalReference(ConfiguredBaseModel):
    """
    External references are used to describe pointers to information represented outside of STIX.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'any_of': [{'slot_conditions': {'external_id': {'name': 'external_id',
                                                         'required': True}}},
                    {'slot_conditions': {'description': {'name': 'description',
                                                         'required': True}}},
                    {'slot_conditions': {'url': {'name': 'url', 'required': True}}}],
         'close_mappings': ['uco-core:ExternalReference'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'rules': [{'description': 'A reference to the CVE list names a CVE '
                                   'identifier.',
                    'postconditions': {'slot_conditions': {'external_id': {'name': 'external_id',
                                                                           'pattern': '^CVE-\\d{4}-(0\\d{3}|[1-9]\\d{3,})$',
                                                                           'required': True}}},
                    'preconditions': {'slot_conditions': {'source_name': {'equals_string': 'cve',
                                                                          'name': 'source_name'}}}},
                   {'description': 'A reference to CAPEC names a CAPEC identifier.',
                    'postconditions': {'slot_conditions': {'external_id': {'name': 'external_id',
                                                                           'pattern': '^CAPEC-\\d+$',
                                                                           'required': True}}},
                    'preconditions': {'slot_conditions': {'source_name': {'equals_string': 'capec',
                                                                          'name': 'source_name'}}}}],
         'slot_usage': {'source_name': {'name': 'source_name', 'required': True}}})

    source_name: str = Field(default=..., description="""The source, such as a system, registry or organization, that defines the reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference'], 'slot_uri': 'stix:source_name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    url: Optional[str] = Field(default=None, description="""A URL.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference', 'StixArtifact'], 'slot_uri': 'stix:url'} })
    hashes: Optional[StixHashes] = Field(default=None, description="""A dictionary of hashes of the content, keyed by hash algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference',
                       'StixArtifact',
                       'StixFile',
                       'StixX509Certificate',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:hashes'} })
    external_id: Optional[str] = Field(default=None, description="""An identifier of the external content in its source, such as CVE-2016-1234.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalIdentifier'],
         'domain_of': ['StixExternalReference'],
         'slot_uri': 'stix:external_id'} })


class StixKillChainPhase(ConfiguredBaseModel):
    """
    A phase in a kill chain, named by the chain and the phase.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'kill_chain_name': {'name': 'kill_chain_name',
                                            'required': True},
                        'phase_name': {'name': 'phase_name', 'required': True}}})

    kill_chain_name: str = Field(default=..., description="""The name of the kill chain.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixKillChainPhase'], 'slot_uri': 'stix:kill_chain_name'} })
    phase_name: str = Field(default=..., description="""The name of the phase in the kill chain.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixKillChainPhase'], 'slot_uri': 'stix:phase_name'} })


class StixGranularMarking(ConfiguredBaseModel):
    """
    A marking of parts of an object: the properties its selectors name, marked either by a marking definition or with a language.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['uco-marking:GranularMarking'],
         'comments': ["STIX 2.1 requires exactly one of marking_ref and lang. OASIS's "
                      'JSON schema requires marking_ref, which rejects a language '
                      'marking; the schema follows the standard.'],
         'exactly_one_of': [{'slot_conditions': {'marking_ref': {'name': 'marking_ref',
                                                                 'required': True}}},
                            {'slot_conditions': {'lang': {'name': 'lang',
                                                          'required': True}}}],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'selectors': {'name': 'selectors', 'required': True}}})

    marking_ref: Optional[str] = Field(default=None, description="""The marking_ref property specifies the ID of the marking-definition object that describes the marking.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-marking:marking'],
         'domain_of': ['StixGranularMarking'],
         'slot_uri': 'stix:marking_ref'} })
    selectors: list[str] = Field(default=..., description="""A list of selectors for content contained within the STIX object in which this property appears.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-marking:contentSelectors'],
         'domain_of': ['StixGranularMarking'],
         'slot_uri': 'stix:selectors'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })

    @field_validator('marking_ref')
    def pattern_marking_ref(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid marking_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid marking_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('selectors')
    def pattern_selectors(cls, v):
        pattern=re.compile(r"^([a-z0-9_-]{3,249}(\.(\[\d+\]|[a-z0-9_-]{1,250}))*|id)$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid selectors format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid selectors format: {v}"
            raise ValueError(err_msg)
        return v


class StixStatementMarking(ConfiguredBaseModel):
    """
    The definition of a statement marking: a statement, such as a copyright or terms of use.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['uco-marking:StatementMarking'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'statement': {'name': 'statement', 'required': True}}})

    statement: str = Field(default=..., description="""A statement, such as a copyright or terms of use, that applies to the marked content.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-marking:statement'],
         'domain_of': ['StixStatementMarking'],
         'slot_uri': 'stix:statement'} })


class StixTlpMarking(ConfiguredBaseModel):
    """
    The definition of a Traffic Light Protocol (TLP) marking: its level.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'tlp': {'name': 'tlp', 'required': True}}})

    tlp: StixTlpLevel = Field(default=..., description="""The Traffic Light Protocol level.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixTlpMarking'], 'slot_uri': 'stix:tlp'} })


class StixExtension(ConfiguredBaseModel):
    """
    An extension of an object that an extension definition defines. Besides its extension type it carries the properties that its definition's schema states.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'allowed': True},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core',
         'slot_usage': {'extension_type': {'name': 'extension_type', 'required': True}}})

    extension_type: StixExtensionType = Field(default=..., description="""The kind of extension, as the extension's definition declares it.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtension'], 'slot_uri': 'stix:extension_type'} })


class StixHashes(ConfiguredBaseModel):
    """
    A dictionary of hashes. Each key names a hash algorithm, from the hash-algorithm-ov vocabulary (StixHashAlgorithm) or a custom one, and each value is the hash as a string.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'range': 'string'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    pass


class StixExtensions(ConfiguredBaseModel):
    """
    A dictionary of extensions, keyed by an extension definition's identifier.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'range': 'StixExtension'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    pass


class StixDictionary(ConfiguredBaseModel):
    """
    A dictionary of key and value pairs that STIX leaves open.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'allowed': True},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    pass


class StixLanguageContents(ConfiguredBaseModel):
    """
    The translations of a language content object, keyed by language code. Each value maps the translated properties to their translations.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'range': 'StixDictionary'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_core'})

    pass


class StixArtifact(StixCyberObservableObject):
    """
    The Artifact Object permits capturing an array of bytes (8-bits), as a base64-encoded string string, or linking to a file-like payload.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'artifact'}},
         'any_of': [{'slot_conditions': {'payload_bin': {'name': 'payload_bin',
                                                         'required': True}}},
                    {'slot_conditions': {'url': {'name': 'url', 'required': True}}}],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'rules': [{'description': 'payload_bin and url exclude each other.',
                    'postconditions': {'slot_conditions': {'url': {'name': 'url',
                                                                   'value_presence': 'ABSENT'}}},
                    'preconditions': {'slot_conditions': {'payload_bin': {'name': 'payload_bin',
                                                                          'value_presence': 'PRESENT'}}}},
                   {'description': 'An artifact given by url carries its hashes.',
                    'postconditions': {'slot_conditions': {'hashes': {'name': 'hashes',
                                                                      'required': True}}},
                    'preconditions': {'slot_conditions': {'url': {'name': 'url',
                                                                  'value_presence': 'PRESENT'}}}},
                   {'description': 'A decryption key needs an encryption algorithm.',
                    'postconditions': {'slot_conditions': {'encryption_algorithm': {'name': 'encryption_algorithm',
                                                                                    'required': True}}},
                    'preconditions': {'slot_conditions': {'decryption_key': {'name': 'decryption_key',
                                                                             'value_presence': 'PRESENT'}}}}],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'mime_type': {'name': 'mime_type',
                                      'pattern': '^(application|audio|font|image|message|model|multipart|text|video)/[a-zA-Z0-9.+_-]+'},
                        'type': {'equals_string': 'artifact', 'name': 'type'}}})

    mime_type: Optional[str] = Field(default=None, description="""The value of this property MUST be a valid MIME type as specified in the IANA Media Types registry.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixArtifact', 'StixFile'], 'slot_uri': 'stix:mime_type'} })
    payload_bin: Optional[str] = Field(default=None, description="""Specifies the binary data contained in the artifact as a base64-encoded string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixArtifact'], 'slot_uri': 'stix:payload_bin'} })
    url: Optional[str] = Field(default=None, description="""A URL.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference', 'StixArtifact'], 'slot_uri': 'stix:url'} })
    hashes: Optional[StixHashes] = Field(default=None, description="""A dictionary of hashes of the content, keyed by hash algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference',
                       'StixArtifact',
                       'StixFile',
                       'StixX509Certificate',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:hashes'} })
    encryption_algorithm: Optional[StixEncryptionAlgorithm] = Field(default=None, description="""If the artifact is encrypted, specifies the type of encryption algorithm the binary data (either via payload_bin or url) is encoded in.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixArtifact'], 'slot_uri': 'stix:encryption_algorithm'} })
    decryption_key: Optional[str] = Field(default=None, description="""Specifies the decryption key for the encrypted binary data (either via payload_bin or url).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixArtifact'], 'slot_uri': 'stix:decryption_key'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["artifact"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'artifact',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('mime_type')
    def pattern_mime_type(cls, v):
        pattern=re.compile(r"^(application|audio|font|image|message|model|multipart|text|video)/[a-zA-Z0-9.+_-]+")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid mime_type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid mime_type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixAutonomousSystem(StixCyberObservableObject):
    """
    The AS object represents the properties of an Autonomous Systems (AS).
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'autonomous-system'}},
         'close_mappings': ['uco-observable:AutonomousSystem'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'number': {'name': 'number', 'required': True},
                        'type': {'equals_string': 'autonomous-system', 'name': 'type'}}})

    number: int = Field(default=..., description="""Specifies the number assigned to the AS. Such assignments are typically performed by a Regional Internet Registries (RIR).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixAutonomousSystem'], 'slot_uri': 'stix:number'} })
    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    rir: Optional[str] = Field(default=None, description="""Specifies the name of the Regional Internet Registry (RIR) that assigned the number to the AS.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixAutonomousSystem'], 'slot_uri': 'stix:rir'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["autonomous-system"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'autonomous-system',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixDirectory(StixCyberObservableObject):
    """
    The Directory Object represents the properties common to a file system directory.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'directory'}},
         'close_mappings': ['uco-observable:Directory'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'contains_refs': {'any_of': [{'range': 'StixFile'},
                                                     {'range': 'StixDirectory'}],
                                          'name': 'contains_refs',
                                          'pattern': '^(file|directory)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                          'range': 'StixCyberObservableObject'},
                        'id': {'name': 'id',
                               'pattern': '^directory--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'path': {'name': 'path', 'required': True},
                        'type': {'equals_string': 'directory', 'name': 'type'}}})

    path: str = Field(default=..., description="""A path, as it was observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory'], 'slot_uri': 'stix:path'} })
    path_enc: Optional[str] = Field(default=None, description="""Specifies the observed encoding for the path.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory'], 'slot_uri': 'stix:path_enc'} })
    ctime: Optional[str] = Field(default=None, description="""The time at which the object was created.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory', 'StixFile'], 'slot_uri': 'stix:ctime'} })
    mtime: Optional[str] = Field(default=None, description="""The time at which the object was last written to.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory', 'StixFile'], 'slot_uri': 'stix:mtime'} })
    atime: Optional[str] = Field(default=None, description="""The time at which the object was last accessed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory', 'StixFile'], 'slot_uri': 'stix:atime'} })
    contains_refs: Optional[list[str]] = Field(default=None, description="""References to other cyber-observable objects that this one contains.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixFile'}, {'range': 'StixDirectory'}],
         'domain_of': ['StixDirectory', 'StixFile', 'StixArchiveExtension'],
         'slot_uri': 'stix:contains_refs'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["directory"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'directory',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('path_enc')
    def pattern_path_enc(cls, v):
        pattern=re.compile(r"^[a-zA-Z0-9/\.+_:-]{2,250}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid path_enc format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid path_enc format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('contains_refs')
    def pattern_contains_refs(cls, v):
        pattern=re.compile(r"^(file|directory)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid contains_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid contains_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^directory--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixDomainName(StixCyberObservableObject):
    """
    The Domain Name represents the properties of a network domain name.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'domain-name'}},
         'close_mappings': ['uco-observable:DomainName'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^domain-name--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'resolves_to_refs': {'any_of': [{'range': 'StixIpv4Address'},
                                                        {'range': 'StixIpv6Address'},
                                                        {'range': 'StixDomainName'}],
                                             'name': 'resolves_to_refs',
                                             'pattern': '^(ipv4-addr|ipv6-addr|domain-name)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                             'range': 'StixCyberObservableObject'},
                        'type': {'equals_string': 'domain-name', 'name': 'type'},
                        'value': {'name': 'value', 'required': True}}})

    value: str = Field(default=..., description="""The value of the observable, in the form each class states.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName',
                       'StixEmailAddress',
                       'StixIpv4Address',
                       'StixIpv6Address',
                       'StixMacAddress',
                       'StixUrl'],
         'slot_uri': 'stix:value'} })
    resolves_to_refs: Optional[list[str]] = Field(default=None, description="""References to the cyber-observable objects that this one resolves to.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixIpv4Address'},
                    {'range': 'StixIpv6Address'},
                    {'range': 'StixDomainName'}],
         'domain_of': ['StixDomainName', 'StixIpv4Address', 'StixIpv6Address'],
         'slot_uri': 'stix:resolves_to_refs'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["domain-name"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'domain-name',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('resolves_to_refs')
    def pattern_resolves_to_refs(cls, v):
        pattern=re.compile(r"^(ipv4-addr|ipv6-addr|domain-name)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid resolves_to_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid resolves_to_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^domain-name--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixEmailAddress(StixCyberObservableObject):
    """
    The Email Address Object represents a single email address.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'email-addr'}},
         'close_mappings': ['uco-observable:EmailAddress'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'email-addr', 'name': 'type'},
                        'value': {'name': 'value', 'required': True}}})

    value: str = Field(default=..., description="""The value of the observable, in the form each class states.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName',
                       'StixEmailAddress',
                       'StixIpv4Address',
                       'StixIpv6Address',
                       'StixMacAddress',
                       'StixUrl'],
         'slot_uri': 'stix:value'} })
    display_name: Optional[str] = Field(default=None, description="""A name for display.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailAddress',
                       'StixUserAccount',
                       'StixWindowsServiceExtension'],
         'slot_uri': 'stix:display_name'} })
    belongs_to_ref: Optional[str] = Field(default=None, description="""Specifies the user account that the email address belongs to, as a reference to a User Account Object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailAddress'], 'slot_uri': 'stix:belongs_to_ref'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["email-addr"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'email-addr',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('belongs_to_ref')
    def pattern_belongs_to_ref(cls, v):
        pattern=re.compile(r"^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid belongs_to_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid belongs_to_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixEmailMessage(StixCyberObservableObject):
    """
    The Email Message Object represents an instance of an email message.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'email-message'}},
         'close_mappings': ['uco-observable:EmailMessage'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'rules': [{'description': 'body and body_multipart exclude each other.',
                    'postconditions': {'slot_conditions': {'body_multipart': {'name': 'body_multipart',
                                                                              'value_presence': 'ABSENT'}}},
                    'preconditions': {'slot_conditions': {'body': {'name': 'body',
                                                                   'value_presence': 'PRESENT'}}}}],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^email-message--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'is_multipart': {'name': 'is_multipart', 'required': True},
                        'type': {'equals_string': 'email-message', 'name': 'type'}}})

    date: Optional[str] = Field(default=None, description="""Specifies the date/time that the email message was sent.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:date'} })
    content_type: Optional[str] = Field(default=None, description="""The value of a Content-Type header field.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage', 'StixMimePart'],
         'slot_uri': 'stix:content_type'} })
    from_ref: Optional[str] = Field(default=None, description="""Specifies the value of the 'From:' header of the email message.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:from_ref'} })
    sender_ref: Optional[str] = Field(default=None, description="""Specifies the value of the 'From' field of the email message.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:sender_ref'} })
    to_refs: Optional[list[str]] = Field(default=None, description="""Specifies the mailboxes that are 'To:' recipients of the email message.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:to_refs'} })
    cc_refs: Optional[list[str]] = Field(default=None, description="""Specifies the mailboxes that are 'CC:' recipients of the email message.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:cc_refs'} })
    bcc_refs: Optional[list[str]] = Field(default=None, description="""Specifies the mailboxes that are 'BCC:' recipients of the email message.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:bcc_refs'} })
    message_id: Optional[str] = Field(default=None, description="""Specifies the Message-ID field of the email message.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:message_id'} })
    subject: Optional[str] = Field(default=None, description="""A subject, as a string; each class says of what.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage', 'StixX509Certificate'],
         'slot_uri': 'stix:subject'} })
    received_lines: Optional[list[str]] = Field(default=None, description="""Specifies one or more Received header fields that may be included in the email headers.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:received_lines'} })
    additional_header_fields: Optional[StixDictionary] = Field(default=None, description="""Specifies any other header fields found in the email message, as a dictionary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:additional_header_fields'} })
    raw_email_ref: Optional[str] = Field(default=None, description="""Specifies the raw binary contents of the email message, including both the headers and body, as a reference to an Artifact Object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:raw_email_ref'} })
    is_multipart: bool = Field(default=..., description="""Indicates whether the email body contains multiple MIME parts.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:is_multipart'} })
    body: Optional[str] = Field(default=None, description="""A body of text.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage', 'StixMimePart'], 'slot_uri': 'stix:body'} })
    body_multipart: Optional[list[StixMimePart]] = Field(default=None, description="""Specifies a list of the MIME parts that make up the email body. This property MAY only be used if is_multipart is true.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage'], 'slot_uri': 'stix:body_multipart'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["email-message"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'email-message',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('from_ref')
    def pattern_from_ref(cls, v):
        pattern=re.compile(r"^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid from_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid from_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('sender_ref')
    def pattern_sender_ref(cls, v):
        pattern=re.compile(r"^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid sender_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid sender_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('to_refs')
    def pattern_to_refs(cls, v):
        pattern=re.compile(r"^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid to_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid to_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('cc_refs')
    def pattern_cc_refs(cls, v):
        pattern=re.compile(r"^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid cc_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid cc_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('bcc_refs')
    def pattern_bcc_refs(cls, v):
        pattern=re.compile(r"^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid bcc_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid bcc_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('raw_email_ref')
    def pattern_raw_email_ref(cls, v):
        pattern=re.compile(r"^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid raw_email_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid raw_email_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^email-message--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixFile(StixCyberObservableObject):
    """
    The File Object represents the properties of a file.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'file'}},
         'any_of': [{'slot_conditions': {'hashes': {'name': 'hashes',
                                                    'required': True}}},
                    {'slot_conditions': {'name': {'name': 'name', 'required': True}}}],
         'close_mappings': ['uco-observable:File'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'extensions': {'name': 'extensions',
                                       'range': 'StixFileExtensions'},
                        'id': {'name': 'id',
                               'pattern': '^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'file', 'name': 'type'}}})

    hashes: Optional[StixHashes] = Field(default=None, description="""A dictionary of hashes of the content, keyed by hash algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference',
                       'StixArtifact',
                       'StixFile',
                       'StixX509Certificate',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:hashes'} })
    size: Optional[int] = Field(default=None, description="""A size in bytes, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixFile', 'StixAlternateDataStream', 'StixWindowsPeSection'],
         'slot_uri': 'stix:size'} })
    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    name_enc: Optional[str] = Field(default=None, description="""Specifies the observed encoding for the name of the file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixFile'], 'slot_uri': 'stix:name_enc'} })
    magic_number_hex: Optional[str] = Field(default=None, description="""Specifies the hexadecimal constant ('magic number') associated with a specific file format that corresponds to the file, if applicable.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixFile'], 'slot_uri': 'stix:magic_number_hex'} })
    mime_type: Optional[str] = Field(default=None, description="""The value of this property MUST be a valid MIME type as specified in the IANA Media Types registry.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixArtifact', 'StixFile'], 'slot_uri': 'stix:mime_type'} })
    ctime: Optional[str] = Field(default=None, description="""The time at which the object was created.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory', 'StixFile'], 'slot_uri': 'stix:ctime'} })
    mtime: Optional[str] = Field(default=None, description="""The time at which the object was last written to.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory', 'StixFile'], 'slot_uri': 'stix:mtime'} })
    atime: Optional[str] = Field(default=None, description="""The time at which the object was last accessed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory', 'StixFile'], 'slot_uri': 'stix:atime'} })
    parent_directory_ref: Optional[str] = Field(default=None, description="""Specifies the parent directory of the file, as a reference to a Directory Object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixFile'], 'slot_uri': 'stix:parent_directory_ref'} })
    contains_refs: Optional[list[str]] = Field(default=None, description="""References to other cyber-observable objects that this one contains.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixDirectory', 'StixFile', 'StixArchiveExtension'],
         'slot_uri': 'stix:contains_refs'} })
    content_ref: Optional[str] = Field(default=None, description="""Specifies the content of the file, represented as an Artifact Object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixFile'], 'slot_uri': 'stix:content_ref'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["file"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'file',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixFileExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('name_enc')
    def pattern_name_enc(cls, v):
        pattern=re.compile(r"^[a-zA-Z0-9/\.+_:-]{2,250}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid name_enc format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid name_enc format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('parent_directory_ref')
    def pattern_parent_directory_ref(cls, v):
        pattern=re.compile(r"^directory--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid parent_directory_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid parent_directory_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('contains_refs')
    def pattern_contains_refs(cls, v):
        pattern=re.compile(r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid contains_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid contains_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('content_ref')
    def pattern_content_ref(cls, v):
        pattern=re.compile(r"^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid content_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid content_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixIpv4Address(StixCyberObservableObject):
    """
    The IPv4 Address Object represents one or more IPv4 addresses expressed using CIDR notation.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'ipv4-addr'}},
         'close_mappings': ['uco-observable:IPv4Address'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^ipv4-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'resolves_to_refs': {'name': 'resolves_to_refs',
                                             'pattern': '^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                             'range': 'StixMacAddress'},
                        'type': {'equals_string': 'ipv4-addr', 'name': 'type'},
                        'value': {'name': 'value',
                                  'pattern': '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(3[0-2]|[1-2][0-9]|[0-9]))?$',
                                  'required': True}}})

    value: str = Field(default=..., description="""The value of the observable, in the form each class states.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName',
                       'StixEmailAddress',
                       'StixIpv4Address',
                       'StixIpv6Address',
                       'StixMacAddress',
                       'StixUrl'],
         'slot_uri': 'stix:value'} })
    resolves_to_refs: Optional[list[str]] = Field(default=None, description="""References to the cyber-observable objects that this one resolves to.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName', 'StixIpv4Address', 'StixIpv6Address'],
         'slot_uri': 'stix:resolves_to_refs'} })
    belongs_to_refs: Optional[list[str]] = Field(default=None, description="""References to the autonomous systems that this address belongs to.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixIpv4Address', 'StixIpv6Address'],
         'slot_uri': 'stix:belongs_to_refs'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["ipv4-addr"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'ipv4-addr',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('value')
    def pattern_value(cls, v):
        pattern=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid value format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid value format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('resolves_to_refs')
    def pattern_resolves_to_refs(cls, v):
        pattern=re.compile(r"^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid resolves_to_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid resolves_to_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('belongs_to_refs')
    def pattern_belongs_to_refs(cls, v):
        pattern=re.compile(r"^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid belongs_to_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid belongs_to_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^ipv4-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixIpv6Address(StixCyberObservableObject):
    """
    The IPv6 Address Object represents one or more IPv6 addresses expressed using CIDR notation.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'ipv6-addr'}},
         'close_mappings': ['uco-observable:IPv6Address'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^ipv6-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'resolves_to_refs': {'name': 'resolves_to_refs',
                                             'pattern': '^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                             'range': 'StixMacAddress'},
                        'type': {'equals_string': 'ipv6-addr', 'name': 'type'},
                        'value': {'name': 'value',
                                  'pattern': '^\\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))(%.+)?\\s*(\\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?$',
                                  'required': True}}})

    value: str = Field(default=..., description="""The value of the observable, in the form each class states.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName',
                       'StixEmailAddress',
                       'StixIpv4Address',
                       'StixIpv6Address',
                       'StixMacAddress',
                       'StixUrl'],
         'slot_uri': 'stix:value'} })
    resolves_to_refs: Optional[list[str]] = Field(default=None, description="""References to the cyber-observable objects that this one resolves to.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName', 'StixIpv4Address', 'StixIpv6Address'],
         'slot_uri': 'stix:resolves_to_refs'} })
    belongs_to_refs: Optional[list[str]] = Field(default=None, description="""References to the autonomous systems that this address belongs to.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixIpv4Address', 'StixIpv6Address'],
         'slot_uri': 'stix:belongs_to_refs'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["ipv6-addr"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'ipv6-addr',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('value')
    def pattern_value(cls, v):
        pattern=re.compile(r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid value format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid value format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('resolves_to_refs')
    def pattern_resolves_to_refs(cls, v):
        pattern=re.compile(r"^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid resolves_to_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid resolves_to_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('belongs_to_refs')
    def pattern_belongs_to_refs(cls, v):
        pattern=re.compile(r"^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid belongs_to_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid belongs_to_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^ipv6-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixMacAddress(StixCyberObservableObject):
    """
    The MAC Address Object represents a single Media Access Control (MAC) address.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'mac-addr'}},
         'close_mappings': ['uco-observable:MACAddress'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'mac-addr', 'name': 'type'},
                        'value': {'name': 'value',
                                  'pattern': '^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$',
                                  'required': True}}})

    value: str = Field(default=..., description="""The value of the observable, in the form each class states.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName',
                       'StixEmailAddress',
                       'StixIpv4Address',
                       'StixIpv6Address',
                       'StixMacAddress',
                       'StixUrl'],
         'slot_uri': 'stix:value'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["mac-addr"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'mac-addr',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('value')
    def pattern_value(cls, v):
        pattern=re.compile(r"^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid value format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid value format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixMutex(StixCyberObservableObject):
    """
    The Mutex Object represents the properties of a mutual exclusion (mutex) object.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'mutex'}},
         'close_mappings': ['uco-observable:Mutex'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^mutex--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'mutex', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["mutex"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'mutex',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^mutex--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixNetworkTraffic(StixCyberObservableObject):
    """
    The Network Traffic Object represents arbitrary network traffic that originates from a source and is addressed to a destination.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'network-traffic'}},
         'any_of': [{'slot_conditions': {'src_ref': {'name': 'src_ref',
                                                     'required': True}}},
                    {'slot_conditions': {'dst_ref': {'name': 'dst_ref',
                                                     'required': True}}}],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'extensions': {'name': 'extensions',
                                       'range': 'StixNetworkTrafficExtensions'},
                        'id': {'name': 'id',
                               'pattern': '^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'protocols': {'name': 'protocols', 'required': True},
                        'type': {'equals_string': 'network-traffic', 'name': 'type'}}})

    start: Optional[str] = Field(default=None, description="""Specifies the date/time the network traffic was initiated, if known.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:start'} })
    end: Optional[str] = Field(default=None, description="""Specifies the date/time the network traffic ended, if known.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:end'} })
    src_ref: Optional[str] = Field(default=None, description="""Specifies the source of the network traffic, as a reference to an Observable Object.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixIpv4Address'},
                    {'range': 'StixIpv6Address'},
                    {'range': 'StixMacAddress'},
                    {'range': 'StixDomainName'}],
         'domain_of': ['StixNetworkTraffic'],
         'slot_uri': 'stix:src_ref'} })
    dst_ref: Optional[str] = Field(default=None, description="""Specifies the destination of the network traffic, as a reference to an Observable Object.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixIpv4Address'},
                    {'range': 'StixIpv6Address'},
                    {'range': 'StixMacAddress'},
                    {'range': 'StixDomainName'}],
         'domain_of': ['StixNetworkTraffic'],
         'slot_uri': 'stix:dst_ref'} })
    src_port: Optional[int] = Field(default=None, description="""Specifies the source port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535.""", ge=0, le=65535, json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:src_port'} })
    dst_port: Optional[int] = Field(default=None, description="""Specifies the destination port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535.""", ge=0, le=65535, json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:dst_port'} })
    protocols: list[str] = Field(default=..., description="""Specifies the protocols observed in the network traffic, along with their corresponding state.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:protocols'} })
    src_byte_count: Optional[int] = Field(default=None, description="""Specifies the number of bytes sent from the source to the destination.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:src_byte_count'} })
    dst_byte_count: Optional[int] = Field(default=None, description="""Specifies the number of bytes sent from the destination to the source.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:dst_byte_count'} })
    src_packets: Optional[int] = Field(default=None, description="""Specifies the number of packets sent from the source to the destination.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:src_packets'} })
    dst_packets: Optional[int] = Field(default=None, description="""Specifies the number of packets sent destination to the source.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:dst_packets'} })
    ipfix: Optional[StixDictionary] = Field(default=None, description="""Specifies any IP Flow Information Export (IPFIX) data for the traffic.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:ipfix'} })
    src_payload_ref: Optional[str] = Field(default=None, description="""Specifies the bytes sent from the source to the destination.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:src_payload_ref'} })
    dst_payload_ref: Optional[str] = Field(default=None, description="""Specifies the bytes sent from the source to the destination.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:dst_payload_ref'} })
    encapsulates_refs: Optional[list[str]] = Field(default=None, description="""Links to other network-traffic objects encapsulated by a network-traffic.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:encapsulates_refs'} })
    encapsulated_by_ref: Optional[str] = Field(default=None, description="""Links to another network-traffic object which encapsulates this object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:encapsulated_by_ref'} })
    is_active: Optional[bool] = Field(default=None, description="""Indicates whether the network traffic is still ongoing.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNetworkTraffic'], 'slot_uri': 'stix:is_active'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["network-traffic"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'network-traffic',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixNetworkTrafficExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('src_ref')
    def pattern_src_ref(cls, v):
        pattern=re.compile(r"^(ipv4-addr|ipv6-addr|mac-addr|domain-name)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid src_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid src_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('dst_ref')
    def pattern_dst_ref(cls, v):
        pattern=re.compile(r"^(ipv4-addr|ipv6-addr|mac-addr|domain-name)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid dst_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid dst_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('src_payload_ref')
    def pattern_src_payload_ref(cls, v):
        pattern=re.compile(r"^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid src_payload_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid src_payload_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('dst_payload_ref')
    def pattern_dst_payload_ref(cls, v):
        pattern=re.compile(r"^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid dst_payload_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid dst_payload_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('encapsulates_refs')
    def pattern_encapsulates_refs(cls, v):
        pattern=re.compile(r"^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid encapsulates_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid encapsulates_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('encapsulated_by_ref')
    def pattern_encapsulated_by_ref(cls, v):
        pattern=re.compile(r"^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid encapsulated_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid encapsulated_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixProcess(StixCyberObservableObject):
    """
    The Process Object represents common properties of an instance of a computer program as executed on an operating system.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'process'}},
         'any_of': [{'slot_conditions': {'extensions': {'name': 'extensions',
                                                        'required': True}}},
                    {'slot_conditions': {'is_hidden': {'name': 'is_hidden',
                                                       'required': True}}},
                    {'slot_conditions': {'pid': {'name': 'pid', 'required': True}}},
                    {'slot_conditions': {'cwd': {'name': 'cwd', 'required': True}}},
                    {'slot_conditions': {'command_line': {'name': 'command_line',
                                                          'required': True}}},
                    {'slot_conditions': {'environment_variables': {'name': 'environment_variables',
                                                                   'required': True}}},
                    {'slot_conditions': {'opened_connection_refs': {'name': 'opened_connection_refs',
                                                                    'required': True}}},
                    {'slot_conditions': {'creator_user_ref': {'name': 'creator_user_ref',
                                                              'required': True}}},
                    {'slot_conditions': {'image_ref': {'name': 'image_ref',
                                                       'required': True}}},
                    {'slot_conditions': {'parent_ref': {'name': 'parent_ref',
                                                        'required': True}}},
                    {'slot_conditions': {'child_refs': {'name': 'child_refs',
                                                        'required': True}}}],
         'close_mappings': ['uco-observable:Process'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'extensions': {'name': 'extensions',
                                       'range': 'StixProcessExtensions'},
                        'id': {'name': 'id',
                               'pattern': '^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'process', 'name': 'type'}}})

    is_hidden: Optional[bool] = Field(default=None, description="""Specifies whether the process is hidden.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:is_hidden'} })
    pid: Optional[int] = Field(default=None, description="""Specifies the Process ID, or PID, of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:pid'} })
    created_time: Optional[str] = Field(default=None, description="""Specifies the date/time at which the process was created.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:created_time'} })
    cwd: Optional[str] = Field(default=None, description="""Specifies the current working directory of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:cwd'} })
    command_line: Optional[str] = Field(default=None, description="""Specifies the full command line used in executing the process, including the process name (which may be specified individually via the binary_ref.name property) and any arguments.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:command_line'} })
    environment_variables: Optional[StixDictionary] = Field(default=None, description="""Specifies the list of environment variables associated with the process as a dictionary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:environment_variables'} })
    opened_connection_refs: Optional[list[str]] = Field(default=None, description="""Specifies the list of network connections opened by the process, as a reference to one or more Network Traffic Objects.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:opened_connection_refs'} })
    creator_user_ref: Optional[str] = Field(default=None, description="""A reference to the user account that created the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess', 'StixWindowsRegistryKey'],
         'slot_uri': 'stix:creator_user_ref'} })
    image_ref: Optional[str] = Field(default=None, description="""Specifies the executable binary that was executed as the process image, as a reference to a File Object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:image_ref'} })
    parent_ref: Optional[str] = Field(default=None, description="""Specifies the other process that spawned (i.e. is the parent of) this one, as represented by a Process Object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:parent_ref'} })
    child_refs: Optional[list[str]] = Field(default=None, description="""Specifies the other processes that were spawned by (i.e. children of) this process, as a reference to one or more other Process Objects.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess'], 'slot_uri': 'stix:child_refs'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["process"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'process',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixProcessExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('opened_connection_refs')
    def pattern_opened_connection_refs(cls, v):
        pattern=re.compile(r"^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid opened_connection_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid opened_connection_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('creator_user_ref')
    def pattern_creator_user_ref(cls, v):
        pattern=re.compile(r"^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid creator_user_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid creator_user_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('image_ref')
    def pattern_image_ref(cls, v):
        pattern=re.compile(r"^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid image_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid image_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('parent_ref')
    def pattern_parent_ref(cls, v):
        pattern=re.compile(r"^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid parent_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid parent_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('child_refs')
    def pattern_child_refs(cls, v):
        pattern=re.compile(r"^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid child_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid child_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixSoftware(StixCyberObservableObject):
    """
    The Software Object represents high-level properties associated with software, including software products.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'software'}},
         'close_mappings': ['uco-observable:Software'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'software', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    cpe: Optional[str] = Field(default=None, description="""Specifies the Common Platform Enumeration (CPE) entry for the software, if available. The value for this property MUST be a CPE v2.3 entry from the official NVD CPE Dictionary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSoftware'], 'slot_uri': 'stix:cpe'} })
    swid: Optional[str] = Field(default=None, description="""Specifies the Software Identification (SWID) Tags entry for the software, if available.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSoftware'], 'slot_uri': 'stix:swid'} })
    languages: Optional[list[str]] = Field(default=None, description="""Specifies the languages supported by the software. The value of each list member MUST be an RFC 5646 language code. ISO 639-2 codes are accepted for backward compatibility.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixSoftware'], 'slot_uri': 'stix:languages'} })
    vendor: Optional[str] = Field(default=None, description="""Specifies the name of the vendor of the software.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSoftware'], 'slot_uri': 'stix:vendor'} })
    version: Optional[str] = Field(default=None, description="""A version, as a string; each class says of what.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition',
                       'StixSoftware',
                       'StixX509Certificate',
                       'StixPdfExtension',
                       'StixMalwareAnalysis'],
         'slot_uri': 'stix:version'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["software"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'software',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('cpe')
    def pattern_cpe(cls, v):
        pattern=re.compile(r"cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\x22#$$%&\x27\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\x22#$$%&\x27\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid cpe format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid cpe format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('languages')
    def pattern_languages(cls, v):
        pattern=re.compile(r"^([a-z]{2}(-[A-Z]{2})?(-[a-z]{4})?(-[A-Z]{2}|[0-9]{3})?(-[a-z0-9]{5,8}|[0-9][a-z0-9]{3})*(-[a-z0-9]{1,8})*|[a-z]{3})$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid languages format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid languages format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixUrl(StixCyberObservableObject):
    """
    The URL Object represents the properties of a uniform resource locator (URL).
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'url'}},
         'close_mappings': ['uco-observable:URL'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^url--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'url', 'name': 'type'},
                        'value': {'name': 'value', 'range': 'uri', 'required': True}}})

    value: str = Field(default=..., description="""The value of the observable, in the form each class states.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixDomainName',
                       'StixEmailAddress',
                       'StixIpv4Address',
                       'StixIpv6Address',
                       'StixMacAddress',
                       'StixUrl'],
         'slot_uri': 'stix:value'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["url"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'url',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^url--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixUserAccount(StixCyberObservableObject):
    """
    The User Account Object represents an instance of any type of user account, including but not limited to operating system, device, messaging service, and social media platform accounts.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'user-account'}},
         'any_of': [{'slot_conditions': {'extensions': {'name': 'extensions',
                                                        'required': True}}},
                    {'slot_conditions': {'user_id': {'name': 'user_id',
                                                     'required': True}}},
                    {'slot_conditions': {'credential': {'name': 'credential',
                                                        'required': True}}},
                    {'slot_conditions': {'account_login': {'name': 'account_login',
                                                           'required': True}}},
                    {'slot_conditions': {'account_type': {'name': 'account_type',
                                                          'required': True}}},
                    {'slot_conditions': {'display_name': {'name': 'display_name',
                                                          'required': True}}},
                    {'slot_conditions': {'is_service_account': {'name': 'is_service_account',
                                                                'required': True}}},
                    {'slot_conditions': {'is_privileged': {'name': 'is_privileged',
                                                           'required': True}}},
                    {'slot_conditions': {'can_escalate_privs': {'name': 'can_escalate_privs',
                                                                'required': True}}},
                    {'slot_conditions': {'is_disabled': {'name': 'is_disabled',
                                                         'required': True}}},
                    {'slot_conditions': {'account_created': {'name': 'account_created',
                                                             'required': True}}},
                    {'slot_conditions': {'account_expires': {'name': 'account_expires',
                                                             'required': True}}},
                    {'slot_conditions': {'credential_last_changed': {'name': 'credential_last_changed',
                                                                     'required': True}}},
                    {'slot_conditions': {'account_first_login': {'name': 'account_first_login',
                                                                 'required': True}}},
                    {'slot_conditions': {'account_last_login': {'name': 'account_last_login',
                                                                'required': True}}}],
         'close_mappings': ['uco-observable:UserAccount'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'extensions': {'name': 'extensions',
                                       'range': 'StixUserAccountExtensions'},
                        'id': {'name': 'id',
                               'pattern': '^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'user-account', 'name': 'type'}}})

    user_id: Optional[str] = Field(default=None, description="""Specifies the identifier of the account.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:user_id'} })
    credential: Optional[str] = Field(default=None, description="""Specifies a cleartext credential. This is only intended to be used in capturing metadata from malware analysis (e.g., a hard-coded domain administrator password that the malware attempts to use for lateral movement) and SHOULD NOT be used for sharing of PII.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:credential'} })
    account_login: Optional[str] = Field(default=None, description="""Specifies the account login string, used in cases where the user_id property specifies something other than what a user would type when they login.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:account_login'} })
    account_type: Optional[Union[StixAccountType, str]] = Field(default=None, description="""Specifies the type of the account. This is an open vocabulary and values SHOULD come from the account-type-ov vocabulary.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAccountType'}, {'range': 'string'}],
         'domain_of': ['StixUserAccount'],
         'slot_uri': 'stix:account_type'} })
    display_name: Optional[str] = Field(default=None, description="""A name for display.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailAddress',
                       'StixUserAccount',
                       'StixWindowsServiceExtension'],
         'slot_uri': 'stix:display_name'} })
    is_service_account: Optional[bool] = Field(default=None, description="""Indicates that the account is associated with a network service or system process (daemon), not a specific individual.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:is_service_account'} })
    is_privileged: Optional[bool] = Field(default=None, description="""Specifies that the account has elevated privileges (i.e., in the case of root on Unix or the Windows Administrator account).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:is_privileged'} })
    can_escalate_privs: Optional[bool] = Field(default=None, description="""Specifies that the account has the ability to escalate privileges (i.e., in the case of sudo on Unix or a Windows Domain Admin account).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:can_escalate_privs'} })
    is_disabled: Optional[bool] = Field(default=None, description="""Specifies if the account is disabled.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:is_disabled'} })
    account_created: Optional[str] = Field(default=None, description="""Specifies when the account was created.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:account_created'} })
    account_expires: Optional[str] = Field(default=None, description="""Specifies the expiration date of the account.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:account_expires'} })
    credential_last_changed: Optional[str] = Field(default=None, description="""Specifies when the account credential was last changed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:credential_last_changed'} })
    account_first_login: Optional[str] = Field(default=None, description="""Specifies when the account was first accessed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:account_first_login'} })
    account_last_login: Optional[str] = Field(default=None, description="""Specifies when the account was last accessed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUserAccount'], 'slot_uri': 'stix:account_last_login'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["user-account"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'user-account',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixUserAccountExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixWindowsRegistryKey(StixCyberObservableObject):
    """
    The Registry Key Object represents the properties of a Windows registry key.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'windows-registry-key'}},
         'any_of': [{'slot_conditions': {'key': {'name': 'key', 'required': True}}},
                    {'slot_conditions': {'values': {'name': 'values',
                                                    'required': True}}},
                    {'slot_conditions': {'modified_time': {'name': 'modified_time',
                                                           'required': True}}},
                    {'slot_conditions': {'creator_user_ref': {'name': 'creator_user_ref',
                                                              'required': True}}},
                    {'slot_conditions': {'number_of_subkeys': {'name': 'number_of_subkeys',
                                                               'required': True}}}],
         'close_mappings': ['uco-observable:WindowsRegistryKey'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^windows-registry-key--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'windows-registry-key',
                                 'name': 'type'}}})

    key: Optional[str] = Field(default=None, description="""Specifies the full registry key including the hive.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsRegistryKey'], 'slot_uri': 'stix:key'} })
    values: Optional[list[StixWindowsRegistryValue]] = Field(default=None, description="""Specifies the values found under the registry key.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsRegistryKey'], 'slot_uri': 'stix:values'} })
    modified_time: Optional[str] = Field(default=None, description="""Specifies the last date/time that the registry key was modified.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsRegistryKey'], 'slot_uri': 'stix:modified_time'} })
    creator_user_ref: Optional[str] = Field(default=None, description="""A reference to the user account that created the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixProcess', 'StixWindowsRegistryKey'],
         'slot_uri': 'stix:creator_user_ref'} })
    number_of_subkeys: Optional[int] = Field(default=None, description="""Specifies the number of subkeys contained under the registry key.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsRegistryKey'], 'slot_uri': 'stix:number_of_subkeys'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["windows-registry-key"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'windows-registry-key',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('creator_user_ref')
    def pattern_creator_user_ref(cls, v):
        pattern=re.compile(r"^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid creator_user_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid creator_user_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^windows-registry-key--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixX509Certificate(StixCyberObservableObject):
    """
    The X509 Certificate Object represents the properties of an X.509 certificate.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'x509-certificate'}},
         'any_of': [{'slot_conditions': {'is_self_signed': {'name': 'is_self_signed',
                                                            'required': True}}},
                    {'slot_conditions': {'hashes': {'name': 'hashes',
                                                    'required': True}}},
                    {'slot_conditions': {'version': {'name': 'version',
                                                     'required': True}}},
                    {'slot_conditions': {'serial_number': {'name': 'serial_number',
                                                           'required': True}}},
                    {'slot_conditions': {'signature_algorithm': {'name': 'signature_algorithm',
                                                                 'required': True}}},
                    {'slot_conditions': {'issuer': {'name': 'issuer',
                                                    'required': True}}},
                    {'slot_conditions': {'validity_not_before': {'name': 'validity_not_before',
                                                                 'required': True}}},
                    {'slot_conditions': {'validity_not_after': {'name': 'validity_not_after',
                                                                'required': True}}},
                    {'slot_conditions': {'subject': {'name': 'subject',
                                                     'required': True}}},
                    {'slot_conditions': {'subject_public_key_algorithm': {'name': 'subject_public_key_algorithm',
                                                                          'required': True}}},
                    {'slot_conditions': {'subject_public_key_modulus': {'name': 'subject_public_key_modulus',
                                                                        'required': True}}},
                    {'slot_conditions': {'subject_public_key_exponent': {'name': 'subject_public_key_exponent',
                                                                         'required': True}}},
                    {'slot_conditions': {'x509_v3_extensions': {'name': 'x509_v3_extensions',
                                                                'required': True}}}],
         'close_mappings': ['uco-observable:X509Certificate'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^x509-certificate--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'x509-certificate', 'name': 'type'}}})

    is_self_signed: Optional[bool] = Field(default=None, description="""Specifies whether the certificate is self-signed, i.e., whether it is signed by the same entity whose identity it certifies.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'], 'slot_uri': 'stix:is_self_signed'} })
    hashes: Optional[StixHashes] = Field(default=None, description="""A dictionary of hashes of the content, keyed by hash algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference',
                       'StixArtifact',
                       'StixFile',
                       'StixX509Certificate',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:hashes'} })
    version: Optional[str] = Field(default=None, description="""A version, as a string; each class says of what.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition',
                       'StixSoftware',
                       'StixX509Certificate',
                       'StixPdfExtension',
                       'StixMalwareAnalysis'],
         'slot_uri': 'stix:version'} })
    serial_number: Optional[str] = Field(default=None, description="""Specifies the unique identifier for the certificate, as issued by a specific Certificate Authority.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'], 'slot_uri': 'stix:serial_number'} })
    signature_algorithm: Optional[str] = Field(default=None, description="""Specifies the name of the algorithm used to sign the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'], 'slot_uri': 'stix:signature_algorithm'} })
    issuer: Optional[str] = Field(default=None, description="""Specifies the name of the Certificate Authority that issued the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'], 'slot_uri': 'stix:issuer'} })
    validity_not_before: Optional[str] = Field(default=None, description="""Specifies the date on which the certificate validity period begins.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'], 'slot_uri': 'stix:validity_not_before'} })
    validity_not_after: Optional[str] = Field(default=None, description="""Specifies the date on which the certificate validity period ends.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'], 'slot_uri': 'stix:validity_not_after'} })
    subject: Optional[str] = Field(default=None, description="""A subject, as a string; each class says of what.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage', 'StixX509Certificate'],
         'slot_uri': 'stix:subject'} })
    subject_public_key_algorithm: Optional[str] = Field(default=None, description="""Specifies the name of the algorithm with which to encrypt data being sent to the subject.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'],
         'slot_uri': 'stix:subject_public_key_algorithm'} })
    subject_public_key_modulus: Optional[str] = Field(default=None, description="""Specifies the modulus portion of the subject's public RSA key.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'],
         'slot_uri': 'stix:subject_public_key_modulus'} })
    subject_public_key_exponent: Optional[int] = Field(default=None, description="""Specifies the exponent portion of the subject's public RSA key, as an integer.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'],
         'slot_uri': 'stix:subject_public_key_exponent'} })
    x509_v3_extensions: Optional[StixX509V3Extensions] = Field(default=None, description="""Specifies any standard X.509 v3 extensions that may be used in the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509Certificate'], 'slot_uri': 'stix:x509_v3_extensions'} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCyberObservableObject'], 'slot_uri': 'stix:defanged'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["x509-certificate"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'x509-certificate',
         'slot_uri': 'stix:type'} })
    spec_version: Optional[StixSpecVersion] = Field(default=None, description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^x509-certificate--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixNtfsExtension(ConfiguredBaseModel):
    """
    The NTFS file extension specifies a default extension for capturing properties specific to the storage of the file on the NTFS file system.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'ntfs-ext'}},
         'any_of': [{'slot_conditions': {'sid': {'name': 'sid', 'required': True}}},
                    {'slot_conditions': {'alternate_data_streams': {'name': 'alternate_data_streams',
                                                                    'required': True}}}],
         'close_mappings': ['uco-observable:NTFSFileFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    sid: Optional[str] = Field(default=None, description="""Specifies the security ID (SID) value assigned to the file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNtfsExtension'], 'slot_uri': 'stix:sid'} })
    alternate_data_streams: Optional[list[StixAlternateDataStream]] = Field(default=None, description="""Specifies a list of NTFS alternate data streams that exist for the file.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixNtfsExtension'], 'slot_uri': 'stix:alternate_data_streams'} })


class StixRasterImageExtension(ConfiguredBaseModel):
    """
    The Raster Image file extension specifies a default extension for capturing properties specific to image files.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'raster-image-ext'}},
         'any_of': [{'slot_conditions': {'image_height': {'name': 'image_height',
                                                          'required': True}}},
                    {'slot_conditions': {'image_width': {'name': 'image_width',
                                                         'required': True}}},
                    {'slot_conditions': {'bits_per_pixel': {'name': 'bits_per_pixel',
                                                            'required': True}}},
                    {'slot_conditions': {'exif_tags': {'name': 'exif_tags',
                                                       'required': True}}}],
         'close_mappings': ['uco-observable:RasterPictureFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    image_height: Optional[int] = Field(default=None, description="""Specifies the height of the image in the image file, in pixels.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixRasterImageExtension'], 'slot_uri': 'stix:image_height'} })
    image_width: Optional[int] = Field(default=None, description="""Specifies the width of the image in the image file, in pixels.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixRasterImageExtension'], 'slot_uri': 'stix:image_width'} })
    bits_per_pixel: Optional[int] = Field(default=None, description="""Specifies the sum of bits used for each color channel in the image in the image file, and thus the total number of pixels used for expressing the color depth of the image.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixRasterImageExtension'], 'slot_uri': 'stix:bits_per_pixel'} })
    exif_tags: Optional[StixExifTags] = Field(default=None, description="""Specifies the set of EXIF tags found in the image file, as a dictionary. Each key/value pair in the dictionary represents the name/value of a single EXIF tag.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixRasterImageExtension'], 'slot_uri': 'stix:exif_tags'} })


class StixPdfExtension(ConfiguredBaseModel):
    """
    The PDF file extension specifies a default extension for capturing properties specific to PDF files.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'pdf-ext'}},
         'any_of': [{'slot_conditions': {'version': {'name': 'version',
                                                     'required': True}}},
                    {'slot_conditions': {'is_optimized': {'name': 'is_optimized',
                                                          'required': True}}},
                    {'slot_conditions': {'document_info_dict': {'name': 'document_info_dict',
                                                                'required': True}}},
                    {'slot_conditions': {'pdfid0': {'name': 'pdfid0',
                                                    'required': True}}},
                    {'slot_conditions': {'pdfid1': {'name': 'pdfid1',
                                                    'required': True}}}],
         'close_mappings': ['uco-observable:PDFFileFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    version: Optional[str] = Field(default=None, description="""A version, as a string; each class says of what.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition',
                       'StixSoftware',
                       'StixX509Certificate',
                       'StixPdfExtension',
                       'StixMalwareAnalysis'],
         'slot_uri': 'stix:version'} })
    is_optimized: Optional[bool] = Field(default=None, description="""Specifies whether the PDF file has been optimized.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixPdfExtension'], 'slot_uri': 'stix:is_optimized'} })
    document_info_dict: Optional[StixPdfDocumentInfo] = Field(default=None, description="""Specifies details of the PDF document information dictionary (DID), which includes properties like the document creation data and producer, as a dictionary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixPdfExtension'], 'slot_uri': 'stix:document_info_dict'} })
    pdfid0: Optional[str] = Field(default=None, description="""Specifies the first file identifier found for the PDF file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixPdfExtension'], 'slot_uri': 'stix:pdfid0'} })
    pdfid1: Optional[str] = Field(default=None, description="""Specifies the second file identifier found for the PDF file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixPdfExtension'], 'slot_uri': 'stix:pdfid1'} })


class StixArchiveExtension(ConfiguredBaseModel):
    """
    The Archive File extension specifies a default extension for capturing properties specific to archive files.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'archive-ext'}},
         'close_mappings': ['uco-observable:ArchiveFileFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'contains_refs': {'any_of': [{'range': 'StixFile'},
                                                     {'range': 'StixDirectory'}],
                                          'name': 'contains_refs',
                                          'pattern': '^(file|directory)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                          'range': 'StixCyberObservableObject',
                                          'required': True}}})

    contains_refs: list[str] = Field(default=..., description="""References to other cyber-observable objects that this one contains.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixFile'}, {'range': 'StixDirectory'}],
         'domain_of': ['StixDirectory', 'StixFile', 'StixArchiveExtension'],
         'slot_uri': 'stix:contains_refs'} })
    comment: Optional[str] = Field(default=None, description="""Specifies a comment included as part of the archive file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixArchiveExtension'], 'slot_uri': 'stix:comment'} })

    @field_validator('contains_refs')
    def pattern_contains_refs(cls, v):
        pattern=re.compile(r"^(file|directory)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid contains_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid contains_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixWindowsPeBinaryExtension(ConfiguredBaseModel):
    """
    The Windows PE Binary File extension specifies a default extension for capturing properties specific to Windows portable executable (PE) files.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'windows-pebinary-ext'}},
         'any_of': [{'slot_conditions': {'imphash': {'name': 'imphash',
                                                     'required': True}}},
                    {'slot_conditions': {'machine_hex': {'name': 'machine_hex',
                                                         'required': True}}},
                    {'slot_conditions': {'number_of_sections': {'name': 'number_of_sections',
                                                                'required': True}}},
                    {'slot_conditions': {'time_date_stamp': {'name': 'time_date_stamp',
                                                             'required': True}}},
                    {'slot_conditions': {'pointer_to_symbol_table_hex': {'name': 'pointer_to_symbol_table_hex',
                                                                         'required': True}}},
                    {'slot_conditions': {'number_of_symbols': {'name': 'number_of_symbols',
                                                               'required': True}}},
                    {'slot_conditions': {'size_of_optional_header': {'name': 'size_of_optional_header',
                                                                     'required': True}}},
                    {'slot_conditions': {'characteristics_hex': {'name': 'characteristics_hex',
                                                                 'required': True}}},
                    {'slot_conditions': {'file_header_hashes': {'name': 'file_header_hashes',
                                                                'required': True}}},
                    {'slot_conditions': {'optional_header': {'name': 'optional_header',
                                                             'required': True}}},
                    {'slot_conditions': {'sections': {'name': 'sections',
                                                      'required': True}}}],
         'close_mappings': ['uco-observable:WindowsPEBinaryFileFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'pe_type': {'name': 'pe_type', 'required': True}}})

    pe_type: Union[StixWindowsPeBinaryType, str] = Field(default=..., description="""Specifies the type of the PE binary. Open Vocabulary - windows-pebinary-type-ov.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixWindowsPeBinaryType'}, {'range': 'string'}],
         'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:pe_type'} })
    imphash: Optional[str] = Field(default=None, description="""Specifies the special import hash, or 'imphash', calculated for the PE Binary based on its imported libraries and functions.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'], 'slot_uri': 'stix:imphash'} })
    machine_hex: Optional[str] = Field(default=None, description="""Specifies the type of target machine.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'], 'slot_uri': 'stix:machine_hex'} })
    number_of_sections: Optional[int] = Field(default=None, description="""Specifies the number of sections in the PE binary, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:number_of_sections'} })
    time_date_stamp: Optional[str] = Field(default=None, description="""Specifies the time when the PE binary was created. The timestamp value MUST BE precise to the second.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:time_date_stamp'} })
    pointer_to_symbol_table_hex: Optional[str] = Field(default=None, description="""Specifies the file offset of the COFF symbol table.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:pointer_to_symbol_table_hex'} })
    number_of_symbols: Optional[int] = Field(default=None, description="""Specifies the number of entries in the symbol table of the PE binary, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:number_of_symbols'} })
    size_of_optional_header: Optional[int] = Field(default=None, description="""Specifies the size of the optional header of the PE binary.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:size_of_optional_header'} })
    characteristics_hex: Optional[str] = Field(default=None, description="""Specifies the flags that indicate the file's characteristics.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:characteristics_hex'} })
    file_header_hashes: Optional[StixHashes] = Field(default=None, description="""Specifies any hashes that were computed for the file header.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:file_header_hashes'} })
    optional_header: Optional[StixWindowsPeOptionalHeader] = Field(default=None, description="""Specifies the PE optional header of the PE binary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'],
         'slot_uri': 'stix:optional_header'} })
    sections: Optional[list[StixWindowsPeSection]] = Field(default=None, description="""Specifies metadata about the sections in the PE file.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeBinaryExtension'], 'slot_uri': 'stix:sections'} })


class StixHttpRequestExtension(ConfiguredBaseModel):
    """
    The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP requests.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'http-request-ext'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'request_method': {'name': 'request_method', 'required': True},
                        'request_value': {'name': 'request_value', 'required': True}}})

    request_method: str = Field(default=..., description="""Specifies the HTTP method portion of the HTTP request line, as a lowercase string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixHttpRequestExtension'], 'slot_uri': 'stix:request_method'} })
    request_value: str = Field(default=..., description="""Specifies the value (typically a resource path) portion of the HTTP request line.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixHttpRequestExtension'], 'slot_uri': 'stix:request_value'} })
    request_version: Optional[str] = Field(default=None, description="""Specifies the HTTP version portion of the HTTP request line, as a lowercase string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixHttpRequestExtension'], 'slot_uri': 'stix:request_version'} })
    request_header: Optional[StixDictionary] = Field(default=None, description="""Specifies all of the HTTP header fields that may be found in the HTTP client request, as a dictionary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixHttpRequestExtension'], 'slot_uri': 'stix:request_header'} })
    message_body_length: Optional[int] = Field(default=None, description="""Specifies the length of the HTTP message body, if included, in bytes.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixHttpRequestExtension'],
         'slot_uri': 'stix:message_body_length'} })
    message_body_data_ref: Optional[str] = Field(default=None, description="""Specifies the data contained in the HTTP message body, if included.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixHttpRequestExtension'],
         'slot_uri': 'stix:message_body_data_ref'} })

    @field_validator('message_body_data_ref')
    def pattern_message_body_data_ref(cls, v):
        pattern=re.compile(r"^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid message_body_data_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid message_body_data_ref format: {v}"
            raise ValueError(err_msg)
        return v


class StixIcmpExtension(ConfiguredBaseModel):
    """
    The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'icmp-ext'}},
         'close_mappings': ['uco-observable:ICMPConnectionFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'icmp_code_hex': {'name': 'icmp_code_hex', 'required': True},
                        'icmp_type_hex': {'name': 'icmp_type_hex', 'required': True}}})

    icmp_type_hex: str = Field(default=..., description="""Specifies the ICMP type byte.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixIcmpExtension'], 'slot_uri': 'stix:icmp_type_hex'} })
    icmp_code_hex: str = Field(default=..., description="""Specifies the ICMP code byte.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixIcmpExtension'], 'slot_uri': 'stix:icmp_code_hex'} })


class StixSocketExtension(ConfiguredBaseModel):
    """
    The Network Socket extension specifies a default extension for capturing network traffic properties associated with network sockets.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'socket-ext'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'address_family': {'name': 'address_family', 'required': True}}})

    address_family: StixNetworkSocketAddressFamily = Field(default=..., description="""Specifies the address family (AF_*) that the socket is configured for.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSocketExtension'], 'slot_uri': 'stix:address_family'} })
    is_blocking: Optional[bool] = Field(default=None, description="""Specifies whether the socket is in blocking mode.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSocketExtension'], 'slot_uri': 'stix:is_blocking'} })
    is_listening: Optional[bool] = Field(default=None, description="""Specifies whether the socket is in listening mode.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSocketExtension'], 'slot_uri': 'stix:is_listening'} })
    options: Optional[StixSocketOptions] = Field(default=None, description="""Specifies any options (SO_*) that may be used by the socket, as a dictionary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSocketExtension'], 'slot_uri': 'stix:options'} })
    socket_type: Optional[StixNetworkSocketType] = Field(default=None, description="""Specifies the type of the socket.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSocketExtension'], 'slot_uri': 'stix:socket_type'} })
    socket_descriptor: Optional[int] = Field(default=None, description="""Specifies the socket file descriptor value associated with the socket, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixSocketExtension'], 'slot_uri': 'stix:socket_descriptor'} })
    socket_handle: Optional[int] = Field(default=None, description="""Specifies the handle or inode value associated with the socket.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSocketExtension'], 'slot_uri': 'stix:socket_handle'} })


class StixTcpExtension(ConfiguredBaseModel):
    """
    The TCP extension specifies a default extension for capturing network traffic properties specific to TCP.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'tcp-ext'}},
         'any_of': [{'slot_conditions': {'src_flags_hex': {'name': 'src_flags_hex',
                                                           'required': True}}},
                    {'slot_conditions': {'dst_flags_hex': {'name': 'dst_flags_hex',
                                                           'required': True}}}],
         'close_mappings': ['uco-observable:TCPConnectionFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    src_flags_hex: Optional[str] = Field(default=None, description="""Specifies the source TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixTcpExtension'], 'slot_uri': 'stix:src_flags_hex'} })
    dst_flags_hex: Optional[str] = Field(default=None, description="""Specifies the destination TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixTcpExtension'], 'slot_uri': 'stix:dst_flags_hex'} })


class StixWindowsProcessExtension(ConfiguredBaseModel):
    """
    The Windows Process extension specifies a default extension for capturing properties specific to Windows processes.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'windows-process-ext'}},
         'any_of': [{'slot_conditions': {'aslr_enabled': {'name': 'aslr_enabled',
                                                          'required': True}}},
                    {'slot_conditions': {'dep_enabled': {'name': 'dep_enabled',
                                                         'required': True}}},
                    {'slot_conditions': {'priority': {'name': 'priority',
                                                      'required': True}}},
                    {'slot_conditions': {'owner_sid': {'name': 'owner_sid',
                                                       'required': True}}},
                    {'slot_conditions': {'window_title': {'name': 'window_title',
                                                          'required': True}}},
                    {'slot_conditions': {'startup_info': {'name': 'startup_info',
                                                          'required': True}}}],
         'close_mappings': ['uco-observable:WindowsProcessFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    aslr_enabled: Optional[bool] = Field(default=None, description="""Specifies whether Address Space Layout Randomization (ASLR) is enabled for the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsProcessExtension'], 'slot_uri': 'stix:aslr_enabled'} })
    dep_enabled: Optional[bool] = Field(default=None, description="""Specifies whether Data Execution Prevention (DEP) is enabled for the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsProcessExtension'], 'slot_uri': 'stix:dep_enabled'} })
    priority: Optional[str] = Field(default=None, description="""Specifies the current priority class of the process in Windows.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsProcessExtension'], 'slot_uri': 'stix:priority'} })
    owner_sid: Optional[str] = Field(default=None, description="""Specifies the Security ID (SID) value of the owner of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsProcessExtension'], 'slot_uri': 'stix:owner_sid'} })
    window_title: Optional[str] = Field(default=None, description="""Specifies the title of the main window of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsProcessExtension'], 'slot_uri': 'stix:window_title'} })
    startup_info: Optional[StixDictionary] = Field(default=None, description="""Specifies the STARTUP_INFO struct used by the process, as a dictionary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsProcessExtension'], 'slot_uri': 'stix:startup_info'} })
    integrity_level: Optional[StixWindowsIntegrityLevel] = Field(default=None, description="""Specifies the Windows integrity level, or trustworthiness, of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsProcessExtension'],
         'slot_uri': 'stix:integrity_level'} })


class StixWindowsServiceExtension(ConfiguredBaseModel):
    """
    The Windows Service extension specifies a default extension for capturing properties specific to Windows services.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'windows-service-ext'}},
         'any_of': [{'slot_conditions': {'service_name': {'name': 'service_name',
                                                          'required': True}}},
                    {'slot_conditions': {'descriptions': {'name': 'descriptions',
                                                          'required': True}}},
                    {'slot_conditions': {'display_name': {'name': 'display_name',
                                                          'required': True}}},
                    {'slot_conditions': {'group_name': {'name': 'group_name',
                                                        'required': True}}},
                    {'slot_conditions': {'start_type': {'name': 'start_type',
                                                        'required': True}}},
                    {'slot_conditions': {'service_dll_refs': {'name': 'service_dll_refs',
                                                              'required': True}}},
                    {'slot_conditions': {'service_type': {'name': 'service_type',
                                                          'required': True}}},
                    {'slot_conditions': {'service_status': {'name': 'service_status',
                                                            'required': True}}}],
         'close_mappings': ['uco-observable:WindowsServiceFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    service_name: Optional[str] = Field(default=None, description="""Specifies the name of the service.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsServiceExtension'], 'slot_uri': 'stix:service_name'} })
    descriptions: Optional[list[str]] = Field(default=None, description="""Specifies the descriptions defined for the service.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsServiceExtension'], 'slot_uri': 'stix:descriptions'} })
    display_name: Optional[str] = Field(default=None, description="""A name for display.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailAddress',
                       'StixUserAccount',
                       'StixWindowsServiceExtension'],
         'slot_uri': 'stix:display_name'} })
    group_name: Optional[str] = Field(default=None, description="""Specifies the name of the load ordering group of which the service is a member.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsServiceExtension'], 'slot_uri': 'stix:group_name'} })
    start_type: Optional[StixWindowsServiceStartType] = Field(default=None, description="""Specifies the start options defined for the service. windows-service-start-enum.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsServiceExtension'], 'slot_uri': 'stix:start_type'} })
    service_dll_refs: Optional[list[str]] = Field(default=None, description="""Specifies the DLLs loaded by the service, as a reference to one or more File Objects.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsServiceExtension'],
         'slot_uri': 'stix:service_dll_refs'} })
    service_type: Optional[StixWindowsServiceType] = Field(default=None, description="""Specifies the type of the service. windows-service-enum.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsServiceExtension'], 'slot_uri': 'stix:service_type'} })
    service_status: Optional[StixWindowsServiceStatus] = Field(default=None, description="""Specifies the current status of the service. windows-service-status-enum.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsServiceExtension'],
         'slot_uri': 'stix:service_status'} })

    @field_validator('service_dll_refs')
    def pattern_service_dll_refs(cls, v):
        pattern=re.compile(r"^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid service_dll_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid service_dll_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixUnixAccountExtension(ConfiguredBaseModel):
    """
    The User Account Object defines the following extensions. In addition to these, producers MAY create their own.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_extension_name': {'tag': 'stix_extension_name',
                                                 'value': 'unix-account-ext'}},
         'any_of': [{'slot_conditions': {'gid': {'name': 'gid', 'required': True}}},
                    {'slot_conditions': {'groups': {'name': 'groups',
                                                    'required': True}}},
                    {'slot_conditions': {'home_dir': {'name': 'home_dir',
                                                      'required': True}}},
                    {'slot_conditions': {'shell': {'name': 'shell',
                                                   'required': True}}}],
         'close_mappings': ['uco-observable:UNIXAccountFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    gid: Optional[float] = Field(default=None, description="""Specifies the primary group ID of the account.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUnixAccountExtension'], 'slot_uri': 'stix:gid'} })
    groups: Optional[list[str]] = Field(default=None, description="""Specifies a list of names of groups that the account is a member of.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixUnixAccountExtension'], 'slot_uri': 'stix:groups'} })
    home_dir: Optional[str] = Field(default=None, description="""Specifies the home directory of the account.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUnixAccountExtension'], 'slot_uri': 'stix:home_dir'} })
    shell: Optional[str] = Field(default=None, description="""Specifies the account's command shell.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixUnixAccountExtension'], 'slot_uri': 'stix:shell'} })


class StixAlternateDataStream(ConfiguredBaseModel):
    """
    An NTFS alternate data stream of a file.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['uco-observable:AlternateDataStream'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'name': {'name': 'name', 'required': True}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    hashes: Optional[StixHashes] = Field(default=None, description="""A dictionary of hashes of the content, keyed by hash algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference',
                       'StixArtifact',
                       'StixFile',
                       'StixX509Certificate',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:hashes'} })
    size: Optional[int] = Field(default=None, description="""A size in bytes, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixFile', 'StixAlternateDataStream', 'StixWindowsPeSection'],
         'slot_uri': 'stix:size'} })


class StixWindowsPeSection(ConfiguredBaseModel):
    """
    A section of a Windows PE binary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['uco-observable:WindowsPESection'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'slot_usage': {'name': {'name': 'name', 'required': True}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    size: Optional[int] = Field(default=None, description="""A size in bytes, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixFile', 'StixAlternateDataStream', 'StixWindowsPeSection'],
         'slot_uri': 'stix:size'} })
    entropy: Optional[float] = Field(default=None, description="""Specifies the calculated entropy for the section, as calculated using the Shannon algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeSection'], 'slot_uri': 'stix:entropy'} })
    hashes: Optional[StixHashes] = Field(default=None, description="""A dictionary of hashes of the content, keyed by hash algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference',
                       'StixArtifact',
                       'StixFile',
                       'StixX509Certificate',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:hashes'} })


class StixWindowsPeOptionalHeader(ConfiguredBaseModel):
    """
    The optional header of a Windows PE binary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['uco-observable:WindowsPEOptionalHeader'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    magic_hex: Optional[str] = Field(default=None, description="""Specifies the unsigned integer that indicates the type of the PE binary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:magic_hex'} })
    major_linker_version: Optional[int] = Field(default=None, description="""Specifies the linker major version number.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:major_linker_version'} })
    minor_linker_version: Optional[int] = Field(default=None, description="""Specifies the linker minor version number.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:minor_linker_version'} })
    size_of_code: Optional[int] = Field(default=None, description="""Specifies the size of the code (text) section. If there are multiple such sections, this refers to the sum of the sizes of each section.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:size_of_code'} })
    size_of_initialized_data: Optional[int] = Field(default=None, description="""Specifies the size of the initialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:size_of_initialized_data'} })
    size_of_uninitialized_data: Optional[int] = Field(default=None, description="""Specifies the size of the uninitialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:size_of_uninitialized_data'} })
    address_of_entry_point: Optional[int] = Field(default=None, description="""Specifies the address of the entry point relative to the image base when the executable is loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:address_of_entry_point'} })
    base_of_code: Optional[int] = Field(default=None, description="""Specifies the address that is relative to the image base of the beginning-of-code section when it is loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:base_of_code'} })
    base_of_data: Optional[int] = Field(default=None, description="""Specifies the address that is relative to the image base of the beginning-of-data section when it is loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:base_of_data'} })
    image_base: Optional[int] = Field(default=None, description="""Specifies the preferred address of the first byte of the image when loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:image_base'} })
    section_alignment: Optional[int] = Field(default=None, description="""Specifies the alignment (in bytes) of PE sections when they are loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:section_alignment'} })
    file_alignment: Optional[int] = Field(default=None, description="""Specifies the factor (in bytes) that is used to align the raw data of sections in the image file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:file_alignment'} })
    major_os_version: Optional[int] = Field(default=None, description="""Specifies the major version number of the required operating system.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:major_os_version'} })
    minor_os_version: Optional[int] = Field(default=None, description="""Specifies the minor version number of the required operating system.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:minor_os_version'} })
    major_image_version: Optional[int] = Field(default=None, description="""Specifies the major version number of the image.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:major_image_version'} })
    minor_image_version: Optional[int] = Field(default=None, description="""Specifies the minor version number of the image.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:minor_image_version'} })
    major_subsystem_version: Optional[int] = Field(default=None, description="""Specifies the major version number of the subsystem.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:major_subsystem_version'} })
    minor_subsystem_version: Optional[int] = Field(default=None, description="""Specifies the minor version number of the subsystem.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:minor_subsystem_version'} })
    win32_version_value_hex: Optional[str] = Field(default=None, description="""Specifies the reserved win32 version value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:win32_version_value_hex'} })
    size_of_image: Optional[int] = Field(default=None, description="""Specifies the size, in bytes, of the image, including all headers, as the image is loaded in memory.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:size_of_image'} })
    size_of_headers: Optional[int] = Field(default=None, description="""Specifies the combined size of the MS-DOS, PE header, and section headers, rounded up a multiple of the value specified in the file_alignment header.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:size_of_headers'} })
    checksum_hex: Optional[str] = Field(default=None, description="""Specifies the checksum of the PE binary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:checksum_hex'} })
    subsystem_hex: Optional[str] = Field(default=None, description="""Specifies the subsystem (e.g., GUI, device driver, etc.) that is required to run this image.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'], 'slot_uri': 'stix:subsystem_hex'} })
    dll_characteristics_hex: Optional[str] = Field(default=None, description="""Specifies the flags that characterize the PE binary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:dll_characteristics_hex'} })
    size_of_stack_reserve: Optional[int] = Field(default=None, description="""Specifies the size of the stack to reserve.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:size_of_stack_reserve'} })
    size_of_stack_commit: Optional[int] = Field(default=None, description="""Specifies the size of the stack to commit.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:size_of_stack_commit'} })
    size_of_heap_reserve: Optional[int] = Field(default=None, description="""Specifies the size of the local heap space to reserve.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:size_of_heap_reserve'} })
    size_of_heap_commit: Optional[int] = Field(default=None, description="""Specifies the size of the local heap space to commit.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:size_of_heap_commit'} })
    loader_flags_hex: Optional[str] = Field(default=None, description="""Specifies the reserved loader flags.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:loader_flags_hex'} })
    number_of_rva_and_sizes: Optional[int] = Field(default=None, description="""Specifies the number of data-directory entries in the remainder of the optional header.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:number_of_rva_and_sizes'} })
    hashes: Optional[StixHashes] = Field(default=None, description="""A dictionary of hashes of the content, keyed by hash algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExternalReference',
                       'StixArtifact',
                       'StixFile',
                       'StixX509Certificate',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsPeOptionalHeader'],
         'slot_uri': 'stix:hashes'} })


class StixMimePart(ConfiguredBaseModel):
    """
    One MIME part of a multipart email body.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'any_of': [{'slot_conditions': {'body': {'name': 'body', 'required': True}}},
                    {'slot_conditions': {'body_raw_ref': {'name': 'body_raw_ref',
                                                          'required': True}}}],
         'close_mappings': ['uco-observable:MimePartType'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco',
         'rules': [{'description': 'body and body_raw_ref exclude each other.',
                    'postconditions': {'slot_conditions': {'body_raw_ref': {'name': 'body_raw_ref',
                                                                            'value_presence': 'ABSENT'}}},
                    'preconditions': {'slot_conditions': {'body': {'name': 'body',
                                                                   'value_presence': 'PRESENT'}}}}]})

    body: Optional[str] = Field(default=None, description="""A body of text.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage', 'StixMimePart'], 'slot_uri': 'stix:body'} })
    body_raw_ref: Optional[str] = Field(default=None, description="""Specifies the contents of non-textual MIME parts, that is those whose content_type does not start with text/, as a reference to an Artifact Object or File Object.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixArtifact'}, {'range': 'StixFile'}],
         'domain_of': ['StixMimePart'],
         'slot_uri': 'stix:body_raw_ref'} })
    content_type: Optional[str] = Field(default=None, description="""The value of a Content-Type header field.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEmailMessage', 'StixMimePart'],
         'slot_uri': 'stix:content_type'} })
    content_disposition: Optional[str] = Field(default=None, description="""Specifies the value of the 'Content-Disposition' header field of the MIME part.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMimePart'], 'slot_uri': 'stix:content_disposition'} })

    @field_validator('body_raw_ref')
    def pattern_body_raw_ref(cls, v):
        pattern=re.compile(r"^(artifact|file)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid body_raw_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid body_raw_ref format: {v}"
            raise ValueError(err_msg)
        return v


class StixWindowsRegistryValue(ConfiguredBaseModel):
    """
    A value found under a Windows registry key.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'any_of': [{'slot_conditions': {'name': {'name': 'name', 'required': True}}},
                    {'slot_conditions': {'data': {'name': 'data', 'required': True}}},
                    {'slot_conditions': {'data_type': {'name': 'data_type',
                                                       'required': True}}}],
         'close_mappings': ['uco-observable:WindowsRegistryValue'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    data: Optional[str] = Field(default=None, description="""Specifies the data contained in the registry value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsRegistryValue'], 'slot_uri': 'stix:data'} })
    data_type: Optional[StixWindowsRegistryDatatype] = Field(default=None, description="""Specifies the registry (REG_*) data type used in the registry value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixWindowsRegistryValue'], 'slot_uri': 'stix:data_type'} })


class StixX509V3Extensions(ConfiguredBaseModel):
    """
    The standard X.509 v3 extensions of a certificate.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'any_of': [{'slot_conditions': {'basic_constraints': {'name': 'basic_constraints',
                                                               'required': True}}},
                    {'slot_conditions': {'name_constraints': {'name': 'name_constraints',
                                                              'required': True}}},
                    {'slot_conditions': {'policy_constraints': {'name': 'policy_constraints',
                                                                'required': True}}},
                    {'slot_conditions': {'key_usage': {'name': 'key_usage',
                                                       'required': True}}},
                    {'slot_conditions': {'extended_key_usage': {'name': 'extended_key_usage',
                                                                'required': True}}},
                    {'slot_conditions': {'subject_key_identifier': {'name': 'subject_key_identifier',
                                                                    'required': True}}},
                    {'slot_conditions': {'authority_key_identifier': {'name': 'authority_key_identifier',
                                                                      'required': True}}},
                    {'slot_conditions': {'subject_alternative_name': {'name': 'subject_alternative_name',
                                                                      'required': True}}},
                    {'slot_conditions': {'issuer_alternative_name': {'name': 'issuer_alternative_name',
                                                                     'required': True}}},
                    {'slot_conditions': {'subject_directory_attributes': {'name': 'subject_directory_attributes',
                                                                          'required': True}}},
                    {'slot_conditions': {'crl_distribution_points': {'name': 'crl_distribution_points',
                                                                     'required': True}}},
                    {'slot_conditions': {'inhibit_any_policy': {'name': 'inhibit_any_policy',
                                                                'required': True}}},
                    {'slot_conditions': {'private_key_usage_period_not_before': {'name': 'private_key_usage_period_not_before',
                                                                                 'required': True}}},
                    {'slot_conditions': {'private_key_usage_period_not_after': {'name': 'private_key_usage_period_not_after',
                                                                                'required': True}}},
                    {'slot_conditions': {'certificate_policies': {'name': 'certificate_policies',
                                                                  'required': True}}},
                    {'slot_conditions': {'policy_mappings': {'name': 'policy_mappings',
                                                             'required': True}}}],
         'close_mappings': ['uco-observable:X509V3ExtensionsFacet'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    basic_constraints: Optional[str] = Field(default=None, description="""Specifies a multi-valued extension which indicates whether a certificate is a CA certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:basic_constraints'} })
    name_constraints: Optional[str] = Field(default=None, description="""Specifies a namespace within which all subject names in subsequent certificates in a certification path MUST be located.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:name_constraints'} })
    policy_constraints: Optional[str] = Field(default=None, description="""Specifies any constraints on path validation for certificates issued to CAs.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:policy_constraints'} })
    key_usage: Optional[str] = Field(default=None, description="""Specifies a multi-valued extension consisting of a list of names of the permitted key usages.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:key_usage'} })
    extended_key_usage: Optional[str] = Field(default=None, description="""Specifies a list of usages indicating purposes for which the certificate public key can be used for.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:extended_key_usage'} })
    subject_key_identifier: Optional[str] = Field(default=None, description="""Specifies the identifier that provides a means of identifying certificates that contain a particular public key.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:subject_key_identifier'} })
    authority_key_identifier: Optional[str] = Field(default=None, description="""Specifies the identifier that provides a means of identifying the public key corresponding to the private key used to sign a certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:authority_key_identifier'} })
    subject_alternative_name: Optional[str] = Field(default=None, description="""Specifies the additional identities to be bound to the subject of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:subject_alternative_name'} })
    issuer_alternative_name: Optional[str] = Field(default=None, description="""Specifies the additional identities to be bound to the issuer of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:issuer_alternative_name'} })
    subject_directory_attributes: Optional[str] = Field(default=None, description="""Specifies the identification attributes (e.g., nationality) of the subject.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:subject_directory_attributes'} })
    crl_distribution_points: Optional[str] = Field(default=None, description="""Specifies how CRL information is obtained.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:crl_distribution_points'} })
    inhibit_any_policy: Optional[str] = Field(default=None, description="""Specifies the number of additional certificates that may appear in the path before anyPolicy is no longer permitted.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:inhibit_any_policy'} })
    private_key_usage_period_not_before: Optional[str] = Field(default=None, description="""Specifies the date on which the validity period begins for the private key, if it is different from the validity period of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:private_key_usage_period_not_before'} })
    private_key_usage_period_not_after: Optional[str] = Field(default=None, description="""Specifies the date on which the validity period ends for the private key, if it is different from the validity period of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'],
         'slot_uri': 'stix:private_key_usage_period_not_after'} })
    certificate_policies: Optional[str] = Field(default=None, description="""Specifies a sequence of one or more policy information terms, each of which consists of an object identifier (OID) and optional qualifiers.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:certificate_policies'} })
    policy_mappings: Optional[str] = Field(default=None, description="""Specifies one or more pairs of OIDs; each pair includes an issuerDomainPolicy and a subjectDomainPolicy.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixX509V3Extensions'], 'slot_uri': 'stix:policy_mappings'} })


class StixFileExtensions(ConfiguredBaseModel):
    """
    The extensions of a file: the predefined ntfs-ext, raster-image-ext, pdf-ext, archive-ext and windows-pebinary-ext, and extensions that an extension definition defines.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'any_of': [{'range': 'StixNtfsExtension'},
                                                         {'range': 'StixRasterImageExtension'},
                                                         {'range': 'StixPdfExtension'},
                                                         {'range': 'StixArchiveExtension'},
                                                         {'range': 'StixWindowsPeBinaryExtension'},
                                                         {'range': 'StixExtension'}]}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    pass


class StixNetworkTrafficExtensions(ConfiguredBaseModel):
    """
    The extensions of network traffic: the predefined http-request-ext, icmp-ext, socket-ext and tcp-ext, and extensions that an extension definition defines.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'any_of': [{'range': 'StixHttpRequestExtension'},
                                                         {'range': 'StixIcmpExtension'},
                                                         {'range': 'StixSocketExtension'},
                                                         {'range': 'StixTcpExtension'},
                                                         {'range': 'StixExtension'}]}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    pass


class StixProcessExtensions(ConfiguredBaseModel):
    """
    The extensions of a process: the predefined windows-process-ext and windows-service-ext, and extensions that an extension definition defines.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'any_of': [{'range': 'StixWindowsProcessExtension'},
                                                         {'range': 'StixWindowsServiceExtension'},
                                                         {'range': 'StixExtension'}]}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    pass


class StixUserAccountExtensions(ConfiguredBaseModel):
    """
    The extensions of a user account: the predefined unix-account-ext, and extensions that an extension definition defines.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'any_of': [{'range': 'StixUnixAccountExtension'},
                                                         {'range': 'StixExtension'}]}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    pass


class StixSocketOptions(ConfiguredBaseModel):
    """
    The options of a network socket, as a dictionary of option names, such as SO_RCVBUF, to integer values.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'range': 'integer'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    pass


class StixExifTags(ConfiguredBaseModel):
    """
    The EXIF tags of an image file, as a dictionary of tag names to string or integer values.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'any_of': [{'range': 'string'},
                                                         {'range': 'integer'}]}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    pass


class StixPdfDocumentInfo(ConfiguredBaseModel):
    """
    The document information dictionary of a PDF file, as a dictionary of string values.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'range': 'string'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sco'})

    pass


class StixAttackPattern(StixDomainObject):
    """
    Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'attack-pattern'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^attack-pattern--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'attack-pattern', 'name': 'type'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Other names by which the object is known.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixTool'],
         'slot_uri': 'stix:aliases'} })
    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    kill_chain_phases: Optional[list[StixKillChainPhase]] = Field(default=None, description="""The kill chain phases to which the object corresponds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixMalware',
                       'StixTool'],
         'slot_uri': 'stix:kill_chain_phases'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["attack-pattern"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'attack-pattern',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^attack-pattern--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixCampaign(StixDomainObject):
    """
    A Campaign is a grouping of adversary behavior that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'campaign'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^campaign--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'campaign', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    aliases: Optional[list[str]] = Field(default=None, description="""Other names by which the object is known.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixTool'],
         'slot_uri': 'stix:aliases'} })
    first_seen: Optional[str] = Field(default=None, description="""The time at which the object was first seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:first_seen'} })
    last_seen: Optional[str] = Field(default=None, description="""The time at which the object was last seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:last_seen'} })
    objective: Optional[str] = Field(default=None, description="""This field defines the Campaign's primary goal, objective, desired outcome, or intended effect.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign'], 'slot_uri': 'stix:objective'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["campaign"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'campaign',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^campaign--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixCourseOfAction(StixDomainObject):
    """
    A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'course-of-action'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^course-of-action--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'course-of-action', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["course-of-action"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'course-of-action',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^course-of-action--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixGrouping(StixDomainObject):
    """
    A Grouping object explicitly asserts that the referenced STIX Objects have a shared content.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'grouping'}},
         'close_mappings': ['uco-core:Grouping'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'context': {'name': 'context', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^grouping--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_refs': {'name': 'object_refs', 'required': True},
                        'type': {'equals_string': 'grouping', 'name': 'type'}}})

    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    context: Union[StixGroupingContext, str] = Field(default=..., description="""A short description of the particular context shared by the content referenced by the Grouping.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixGroupingContext'}, {'range': 'string'}],
         'domain_of': ['StixGrouping'],
         'slot_uri': 'stix:context'} })
    object_refs: list[str] = Field(default=..., description="""References to the STIX objects that this object is about or holds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixGrouping',
                       'StixNote',
                       'StixObservedData',
                       'StixOpinion',
                       'StixReport'],
         'slot_uri': 'stix:object_refs'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["grouping"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'grouping',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('object_refs')
    def pattern_object_refs(cls, v):
        pattern=re.compile(r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^grouping--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixIncident(StixDomainObject):
    """
    The Incident object in STIX 2.1 is a stub, to be expanded in future STIX 2 releases.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'incident'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^incident--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'incident', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["incident"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'incident',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^incident--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixIndicator(StixDomainObject):
    """
    Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'indicator'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'pattern': {'name': 'pattern', 'required': True},
                        'pattern_type': {'name': 'pattern_type', 'required': True},
                        'type': {'equals_string': 'indicator', 'name': 'type'},
                        'valid_from': {'name': 'valid_from', 'required': True}}})

    indicator_types: Optional[list[Union[StixIndicatorType, str]]] = Field(default=None, description="""This field is an Open Vocabulary that specifies the type of indicator. Open vocab - indicator-type-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixIndicatorType'}, {'range': 'string'}],
         'domain_of': ['StixIndicator'],
         'slot_uri': 'stix:indicator_types'} })
    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    pattern: str = Field(default=..., description="""The detection pattern for this indicator.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixIndicator'], 'slot_uri': 'stix:pattern'} })
    pattern_type: Union[StixPatternType, str] = Field(default=..., description="""The type of pattern used in this indicator.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixPatternType'}, {'range': 'string'}],
         'domain_of': ['StixIndicator'],
         'slot_uri': 'stix:pattern_type'} })
    pattern_version: Optional[str] = Field(default=None, description="""The version of the pattern that is used.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixIndicator'], 'slot_uri': 'stix:pattern_version'} })
    valid_from: str = Field(default=..., description="""The time from which this indicator should be considered valuable intelligence.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixIndicator'], 'slot_uri': 'stix:valid_from'} })
    valid_until: Optional[str] = Field(default=None, description="""The time at which this indicator should no longer be considered valuable intelligence.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixIndicator'], 'slot_uri': 'stix:valid_until'} })
    kill_chain_phases: Optional[list[StixKillChainPhase]] = Field(default=None, description="""The kill chain phases to which the object corresponds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixMalware',
                       'StixTool'],
         'slot_uri': 'stix:kill_chain_phases'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["indicator"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'indicator',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixInfrastructure(StixDomainObject):
    """
    Infrastructure objects describe systems, software services, and associated physical or virtual resources.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'infrastructure'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^infrastructure--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'infrastructure', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    infrastructure_types: Optional[list[Union[StixInfrastructureType, str]]] = Field(default=None, description="""This field is an Open Vocabulary that specifies the type of infrastructure. Open vocab - infrastructure-type-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixInfrastructureType'}, {'range': 'string'}],
         'domain_of': ['StixInfrastructure'],
         'slot_uri': 'stix:infrastructure_types'} })
    aliases: Optional[list[str]] = Field(default=None, description="""Other names by which the object is known.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixTool'],
         'slot_uri': 'stix:aliases'} })
    kill_chain_phases: Optional[list[StixKillChainPhase]] = Field(default=None, description="""The kill chain phases to which the object corresponds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixMalware',
                       'StixTool'],
         'slot_uri': 'stix:kill_chain_phases'} })
    first_seen: Optional[str] = Field(default=None, description="""The time at which the object was first seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:first_seen'} })
    last_seen: Optional[str] = Field(default=None, description="""The time at which the object was last seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:last_seen'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["infrastructure"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'infrastructure',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^infrastructure--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixIntrusionSet(StixDomainObject):
    """
    An Intrusion Set is a grouped set of adversary behavior and resources with common properties that is believed to be orchestrated by a single organization.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'intrusion-set'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^intrusion-set--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'intrusion-set', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    aliases: Optional[list[str]] = Field(default=None, description="""Other names by which the object is known.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixTool'],
         'slot_uri': 'stix:aliases'} })
    first_seen: Optional[str] = Field(default=None, description="""The time at which the object was first seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:first_seen'} })
    last_seen: Optional[str] = Field(default=None, description="""The time at which the object was last seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:last_seen'} })
    goals: Optional[list[str]] = Field(default=None, description="""The high-level goals.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixIntrusionSet', 'StixThreatActor'], 'slot_uri': 'stix:goals'} })
    resource_level: Optional[Union[StixAttackResourceLevel, str]] = Field(default=None, description="""The organizational level at which the actor typically works.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAttackResourceLevel'}, {'range': 'string'}],
         'domain_of': ['StixIntrusionSet', 'StixThreatActor'],
         'slot_uri': 'stix:resource_level'} })
    primary_motivation: Optional[Union[StixAttackMotivation, str]] = Field(default=None, description="""The primary reason, motivation or purpose behind the activity.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAttackMotivation'}, {'range': 'string'}],
         'domain_of': ['StixIntrusionSet', 'StixThreatActor'],
         'slot_uri': 'stix:primary_motivation'} })
    secondary_motivations: Optional[list[Union[StixAttackMotivation, str]]] = Field(default=None, description="""The secondary reasons, motivations or purposes behind the activity.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAttackMotivation'}, {'range': 'string'}],
         'domain_of': ['StixIntrusionSet', 'StixThreatActor'],
         'slot_uri': 'stix:secondary_motivations'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["intrusion-set"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'intrusion-set',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^intrusion-set--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixLocation(StixDomainObject):
    """
    A Location represents a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'location'}},
         'any_of': [{'slot_conditions': {'region': {'name': 'region',
                                                    'required': True}}},
                    {'slot_conditions': {'country': {'name': 'country',
                                                     'required': True}}},
                    {'slot_conditions': {'latitude': {'name': 'latitude',
                                                      'required': True},
                                         'longitude': {'name': 'longitude',
                                                       'required': True}}}],
         'close_mappings': ['uco-location:Location'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'rules': [{'description': 'A latitude needs a longitude.',
                    'postconditions': {'slot_conditions': {'longitude': {'name': 'longitude',
                                                                         'required': True}}},
                    'preconditions': {'slot_conditions': {'latitude': {'name': 'latitude',
                                                                       'value_presence': 'PRESENT'}}}},
                   {'description': 'A longitude needs a latitude.',
                    'postconditions': {'slot_conditions': {'latitude': {'name': 'latitude',
                                                                        'required': True}}},
                    'preconditions': {'slot_conditions': {'longitude': {'name': 'longitude',
                                                                        'value_presence': 'PRESENT'}}}},
                   {'description': 'A precision needs a latitude and a longitude.',
                    'postconditions': {'slot_conditions': {'latitude': {'name': 'latitude',
                                                                        'required': True},
                                                           'longitude': {'name': 'longitude',
                                                                         'required': True}}},
                    'preconditions': {'slot_conditions': {'precision': {'name': 'precision',
                                                                        'value_presence': 'PRESENT'}}}}],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^location--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'equals_string': 'location', 'name': 'type'}}})

    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    latitude: Optional[float] = Field(default=None, description="""The latitude of the Location in decimal degrees.""", ge=-90, le=90, json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:latitude'} })
    longitude: Optional[float] = Field(default=None, description="""The longitude of the Location in decimal degrees.""", ge=-180, le=180, json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:longitude'} })
    precision: Optional[float] = Field(default=None, description="""Defines the precision of the coordinates specified by the latitude and longitude properties, measured in meters.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:precision'} })
    region: Optional[Union[StixRegion, str]] = Field(default=None, description="""The region that this Location describes.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixRegion'}, {'range': 'string'}],
         'domain_of': ['StixLocation'],
         'slot_uri': 'stix:region'} })
    country: Optional[str] = Field(default=None, description="""The country that this Location describes.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:country'} })
    administrative_area: Optional[str] = Field(default=None, description="""The state, province, or other sub-national administrative area that this Location describes.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:administrative_area'} })
    city: Optional[str] = Field(default=None, description="""The city that this Location describes.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:city'} })
    street_address: Optional[str] = Field(default=None, description="""The street address that this Location describes.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:street_address'} })
    postal_code: Optional[str] = Field(default=None, description="""The postal code for this Location.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixLocation'], 'slot_uri': 'stix:postal_code'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["location"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'location',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^location--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixMalware(StixDomainObject):
    """
    Malware is a type of TTP that is also known as malicious code and malicious software, refers to a program that is inserted into a system, usually covertly, with the intent of compromising the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or of otherwise annoying or disrupting the victim.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'malware'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^malware--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'is_family': {'name': 'is_family', 'required': True},
                        'type': {'equals_string': 'malware', 'name': 'type'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Other names by which the object is known.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixTool'],
         'slot_uri': 'stix:aliases'} })
    first_seen: Optional[str] = Field(default=None, description="""The time at which the object was first seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:first_seen'} })
    last_seen: Optional[str] = Field(default=None, description="""The time at which the object was last seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:last_seen'} })
    operating_system_refs: Optional[list[str]] = Field(default=None, description="""The operating systems that the malware family or malware instance is executable on.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalware'], 'slot_uri': 'stix:operating_system_refs'} })
    architecture_execution_envs: Optional[list[Union[StixProcessorArchitecture, str]]] = Field(default=None, description="""The processor architectures (e.g., x86, ARM, etc.) that the malware instance or family is executable on. Open Vocab - processor-architecture-os.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixProcessorArchitecture'}, {'range': 'string'}],
         'domain_of': ['StixMalware'],
         'slot_uri': 'stix:architecture_execution_envs'} })
    implementation_languages: Optional[list[Union[StixImplementationLanguage, str]]] = Field(default=None, description="""The programming language(s) used to implement the malware instance or family. Open Vocab - implementation-language-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixImplementationLanguage'}, {'range': 'string'}],
         'domain_of': ['StixMalware'],
         'slot_uri': 'stix:implementation_languages'} })
    capabilities: Optional[list[Union[StixMalwareCapability, str]]] = Field(default=None, description="""Specifies any capabilities identified for the malware instance or family. Open Vocab - malware-capabilities-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixMalwareCapability'}, {'range': 'string'}],
         'domain_of': ['StixMalware'],
         'slot_uri': 'stix:capabilities'} })
    sample_refs: Optional[list[str]] = Field(default=None, description="""The sample_refs property specifies a list of identifiers of the SCO file or artifact objects associated with this malware instance(s) or family.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixFile'}, {'range': 'StixArtifact'}],
         'domain_of': ['StixMalware'],
         'slot_uri': 'stix:sample_refs'} })
    malware_types: Optional[list[Union[StixMalwareType, str]]] = Field(default=None, description="""The type of malware being described. Open Vocab - malware-type-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixMalwareType'}, {'range': 'string'}],
         'domain_of': ['StixMalware'],
         'slot_uri': 'stix:malware_types'} })
    name: Optional[str] = Field(default=None, description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    kill_chain_phases: Optional[list[StixKillChainPhase]] = Field(default=None, description="""The kill chain phases to which the object corresponds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixMalware',
                       'StixTool'],
         'slot_uri': 'stix:kill_chain_phases'} })
    is_family: bool = Field(default=..., description="""Whether the object represents a malware family (if true) or a malware instance (if false).""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalware'], 'slot_uri': 'stix:is_family'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["malware"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'malware',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('operating_system_refs')
    def pattern_operating_system_refs(cls, v):
        pattern=re.compile(r"^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid operating_system_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid operating_system_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('sample_refs')
    def pattern_sample_refs(cls, v):
        pattern=re.compile(r"^(file|artifact)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid sample_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid sample_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^malware--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixMalwareAnalysis(StixDomainObject):
    """
    Malware Analysis captures the metadata and results of a particular analysis performed (static or dynamic) on the malware instance or family.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type',
                                       'value': 'malware-analysis'}},
         'any_of': [{'slot_conditions': {'result': {'name': 'result',
                                                    'required': True}}},
                    {'slot_conditions': {'analysis_sco_refs': {'name': 'analysis_sco_refs',
                                                               'required': True}}}],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^malware-analysis--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'product': {'name': 'product', 'required': True},
                        'type': {'equals_string': 'malware-analysis', 'name': 'type'}}})

    product: str = Field(default=..., description="""The name of the analysis engine or product that was used for this analysis.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:product'} })
    version: Optional[str] = Field(default=None, description="""A version, as a string; each class says of what.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixExtensionDefinition',
                       'StixSoftware',
                       'StixX509Certificate',
                       'StixPdfExtension',
                       'StixMalwareAnalysis'],
         'slot_uri': 'stix:version'} })
    configuration_version: Optional[str] = Field(default=None, description="""The version of the analysis product configuration that was used to perform this analysis.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:configuration_version'} })
    modules: Optional[list[str]] = Field(default=None, description="""The particular analysis product modules that were used to perform the analysis.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:modules'} })
    analysis_engine_version: Optional[str] = Field(default=None, description="""The version of the analysis engine or product that was used to perform this analysis.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'],
         'slot_uri': 'stix:analysis_engine_version'} })
    analysis_definition_version: Optional[str] = Field(default=None, description="""The version of the analysis definitions used by the analysis tool.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'],
         'slot_uri': 'stix:analysis_definition_version'} })
    submitted: Optional[str] = Field(default=None, description="""The date and time that this malware was first submitted for scanning or analysis.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:submitted'} })
    analysis_started: Optional[str] = Field(default=None, description="""The date and time that the malware analysis was initiated.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:analysis_started'} })
    analysis_ended: Optional[str] = Field(default=None, description="""The date and time that the malware analysis ended.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:analysis_ended'} })
    result_name: Optional[str] = Field(default=None, description="""The classification result or name assigned to the malware instance by the scanner tool.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:result_name'} })
    result: Optional[Union[StixMalwareResult, str]] = Field(default=None, description="""The classification result as determined by the scanner or tool analysis process.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixMalwareResult'}, {'range': 'string'}],
         'domain_of': ['StixMalwareAnalysis'],
         'slot_uri': 'stix:result'} })
    host_vm_ref: Optional[str] = Field(default=None, description="""A description of the virtual machine environment used to host the guest operating system (if applicable) that was used for the dynamic analysis of the malware instance or family.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:host_vm_ref'} })
    operating_system_ref: Optional[str] = Field(default=None, description="""The operating system that was used to perform the dynamic analysis.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:operating_system_ref'} })
    installed_software_refs: Optional[list[str]] = Field(default=None, description="""Any non-standard software installed on the operating system used for the dynamic analysis of the malware instance or family.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'],
         'slot_uri': 'stix:installed_software_refs'} })
    analysis_sco_refs: Optional[list[str]] = Field(default=None, description="""The list of STIX objects that were captured during the analysis process.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixMalwareAnalysis'], 'slot_uri': 'stix:analysis_sco_refs'} })
    sample_ref: Optional[str] = Field(default=None, description="""Refers to the object this analysis was performed against.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixFile'},
                    {'range': 'StixNetworkTraffic'},
                    {'range': 'StixArtifact'}],
         'domain_of': ['StixMalwareAnalysis'],
         'slot_uri': 'stix:sample_ref'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["malware-analysis"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'malware-analysis',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('host_vm_ref')
    def pattern_host_vm_ref(cls, v):
        pattern=re.compile(r"^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid host_vm_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid host_vm_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('operating_system_ref')
    def pattern_operating_system_ref(cls, v):
        pattern=re.compile(r"^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid operating_system_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid operating_system_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('installed_software_refs')
    def pattern_installed_software_refs(cls, v):
        pattern=re.compile(r"^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid installed_software_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid installed_software_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('analysis_sco_refs')
    def pattern_analysis_sco_refs(cls, v):
        pattern=re.compile(r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid analysis_sco_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid analysis_sco_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('sample_ref')
    def pattern_sample_ref(cls, v):
        pattern=re.compile(r"^(file|network-traffic|artifact)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid sample_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid sample_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^malware-analysis--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixNote(StixDomainObject):
    """
    A Note is a comment or note containing informative text to help explain the context of one or more STIX Objects (SDOs or SROs) or to provide additional analysis that is not contained in the original object.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'note'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'content': {'name': 'content', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^note--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_refs': {'name': 'object_refs', 'required': True},
                        'type': {'equals_string': 'note', 'name': 'type'}}})

    abstract: Optional[str] = Field(default=None, description="""A brief summary of the note.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNote'], 'slot_uri': 'stix:abstract'} })
    content: str = Field(default=..., description="""The content of the note.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixNote'], 'slot_uri': 'stix:content'} })
    authors: Optional[list[str]] = Field(default=None, description="""The name of the author(s) of this note (e.g., the analyst(s) that created it).""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixNote', 'StixOpinion'], 'slot_uri': 'stix:authors'} })
    object_refs: list[str] = Field(default=..., description="""References to the STIX objects that this object is about or holds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixGrouping',
                       'StixNote',
                       'StixObservedData',
                       'StixOpinion',
                       'StixReport'],
         'slot_uri': 'stix:object_refs'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["note"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'note',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('object_refs')
    def pattern_object_refs(cls, v):
        pattern=re.compile(r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^note--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixObservedData(StixDomainObject):
    """
    Observed data conveys information that was observed on systems and networks, such as log data or network traffic, using the Cyber Observable specification.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'observed-data'}},
         'any_of': [{'slot_conditions': {'objects': {'name': 'objects',
                                                     'required': True}}},
                    {'slot_conditions': {'object_refs': {'name': 'object_refs',
                                                         'required': True}}}],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'rules': [{'description': 'objects and object_refs exclude each other.',
                    'postconditions': {'slot_conditions': {'object_refs': {'name': 'object_refs',
                                                                           'value_presence': 'ABSENT'}}},
                    'preconditions': {'slot_conditions': {'objects': {'name': 'objects',
                                                                      'value_presence': 'PRESENT'}}}}],
         'slot_usage': {'first_observed': {'name': 'first_observed', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^observed-data--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'last_observed': {'name': 'last_observed', 'required': True},
                        'number_observed': {'name': 'number_observed',
                                            'required': True},
                        'object_refs': {'any_of': [{'range': 'StixCyberObservableObject'},
                                                   {'range': 'StixRelationshipObject'}],
                                        'name': 'object_refs',
                                        'pattern': '^(?!(attack-pattern|campaign|course-of-action|grouping|identity|incident|indicator|infrastructure|intrusion-set|location|malware|malware-analysis|note|observed-data|opinion|report|threat-actor|tool|vulnerability)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                        'range': 'StixObject'},
                        'objects': {'description': 'The observed cyber-observable '
                                                   'objects, as a dictionary keyed by '
                                                   'index. Deprecated in STIX 2.1; use '
                                                   'object_refs.',
                                    'inlined': True,
                                    'name': 'objects',
                                    'range': 'StixObservedObjects'},
                        'type': {'equals_string': 'observed-data', 'name': 'type'}}})

    first_observed: str = Field(default=..., description="""The beginning of the time window that the data was observed during.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObservedData'], 'slot_uri': 'stix:first_observed'} })
    last_observed: str = Field(default=..., description="""The end of the time window that the data was observed during.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObservedData'], 'slot_uri': 'stix:last_observed'} })
    number_observed: int = Field(default=..., description="""The number of times the data represented in the objects property was observed. This MUST be an integer between 1 and 999,999,999 inclusive.""", ge=1, le=999999999, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObservedData'], 'slot_uri': 'stix:number_observed'} })
    objects: Optional[StixObservedObjects] = Field(default=None, description="""The observed cyber-observable objects, as a dictionary keyed by index. Deprecated in STIX 2.1; use object_refs.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObservedData', 'StixBundle'], 'slot_uri': 'stix:objects'} })
    object_refs: Optional[list[str]] = Field(default=None, description="""References to the STIX objects that this object is about or holds.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixCyberObservableObject'},
                    {'range': 'StixRelationshipObject'}],
         'domain_of': ['StixGrouping',
                       'StixNote',
                       'StixObservedData',
                       'StixOpinion',
                       'StixReport'],
         'slot_uri': 'stix:object_refs'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["observed-data"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'observed-data',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('object_refs')
    def pattern_object_refs(cls, v):
        pattern=re.compile(r"^(?!(attack-pattern|campaign|course-of-action|grouping|identity|incident|indicator|infrastructure|intrusion-set|location|malware|malware-analysis|note|observed-data|opinion|report|threat-actor|tool|vulnerability)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^observed-data--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixOpinion(StixDomainObject):
    """
    An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity and captures the level of agreement or disagreement using a fixed scale.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'opinion'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^opinion--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_refs': {'name': 'object_refs', 'required': True},
                        'opinion': {'name': 'opinion', 'required': True},
                        'type': {'equals_string': 'opinion', 'name': 'type'}}})

    explanation: Optional[str] = Field(default=None, description="""An explanation of why the producer has this Opinion.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixOpinion'], 'slot_uri': 'stix:explanation'} })
    authors: Optional[list[str]] = Field(default=None, description="""The name of the author(s) of this note (e.g., the analyst(s) that created it).""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixNote', 'StixOpinion'], 'slot_uri': 'stix:authors'} })
    object_refs: list[str] = Field(default=..., description="""References to the STIX objects that this object is about or holds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixGrouping',
                       'StixNote',
                       'StixObservedData',
                       'StixOpinion',
                       'StixReport'],
         'slot_uri': 'stix:object_refs'} })
    opinion: StixAgreement = Field(default=..., description="""The opinion that the producer has about about all of the STIX Object(s) listed in the object_refs property.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixOpinion'], 'slot_uri': 'stix:opinion'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["opinion"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'opinion',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('object_refs')
    def pattern_object_refs(cls, v):
        pattern=re.compile(r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^opinion--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixReport(StixDomainObject):
    """
    Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and related details.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'report'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^report--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'object_refs': {'name': 'object_refs', 'required': True},
                        'published': {'name': 'published', 'required': True},
                        'type': {'equals_string': 'report', 'name': 'type'}}})

    report_types: Optional[list[Union[StixReportType, str]]] = Field(default=None, description="""This field is an Open Vocabulary that specifies the primary subject of this report. The suggested values for this field are in report-type-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixReportType'}, {'range': 'string'}],
         'domain_of': ['StixReport'],
         'slot_uri': 'stix:report_types'} })
    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    published: str = Field(default=..., description="""The date that this report object was officially published by the creator of this report.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixReport'], 'slot_uri': 'stix:published'} })
    object_refs: list[str] = Field(default=..., description="""References to the STIX objects that this object is about or holds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixGrouping',
                       'StixNote',
                       'StixObservedData',
                       'StixOpinion',
                       'StixReport'],
         'slot_uri': 'stix:object_refs'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["report"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'report',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('object_refs')
    def pattern_object_refs(cls, v):
        pattern=re.compile(r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^report--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixThreatActor(StixDomainObject):
    """
    Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'threat-actor'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^threat-actor--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'roles': {'any_of': [{'range': 'StixThreatActorRole'},
                                             {'range': 'string'}],
                                  'name': 'roles'},
                        'type': {'equals_string': 'threat-actor', 'name': 'type'}}})

    threat_actor_types: Optional[list[Union[StixThreatActorType, str]]] = Field(default=None, description="""This field specifies the type of threat actor. Open Vocab - threat-actor-type-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixThreatActorType'}, {'range': 'string'}],
         'domain_of': ['StixThreatActor'],
         'slot_uri': 'stix:threat_actor_types'} })
    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    aliases: Optional[list[str]] = Field(default=None, description="""Other names by which the object is known.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixTool'],
         'slot_uri': 'stix:aliases'} })
    roles: Optional[list[Union[StixThreatActorRole, str]]] = Field(default=None, description="""The roles that the identity or threat actor plays.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixThreatActorRole'}, {'range': 'string'}],
         'domain_of': ['StixIdentity', 'StixThreatActor'],
         'slot_uri': 'stix:roles'} })
    goals: Optional[list[str]] = Field(default=None, description="""The high-level goals.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixIntrusionSet', 'StixThreatActor'], 'slot_uri': 'stix:goals'} })
    first_seen: Optional[str] = Field(default=None, description="""The time at which the object was first seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:first_seen'} })
    last_seen: Optional[str] = Field(default=None, description="""The time at which the object was last seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:last_seen'} })
    sophistication: Optional[Union[StixThreatActorSophistication, str]] = Field(default=None, description="""The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack. Open Vocab - threat-actor-sophistication-ov.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixThreatActorSophistication'}, {'range': 'string'}],
         'domain_of': ['StixThreatActor'],
         'slot_uri': 'stix:sophistication'} })
    resource_level: Optional[Union[StixAttackResourceLevel, str]] = Field(default=None, description="""The organizational level at which the actor typically works.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAttackResourceLevel'}, {'range': 'string'}],
         'domain_of': ['StixIntrusionSet', 'StixThreatActor'],
         'slot_uri': 'stix:resource_level'} })
    primary_motivation: Optional[Union[StixAttackMotivation, str]] = Field(default=None, description="""The primary reason, motivation or purpose behind the activity.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAttackMotivation'}, {'range': 'string'}],
         'domain_of': ['StixIntrusionSet', 'StixThreatActor'],
         'slot_uri': 'stix:primary_motivation'} })
    secondary_motivations: Optional[list[Union[StixAttackMotivation, str]]] = Field(default=None, description="""The secondary reasons, motivations or purposes behind the activity.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAttackMotivation'}, {'range': 'string'}],
         'domain_of': ['StixIntrusionSet', 'StixThreatActor'],
         'slot_uri': 'stix:secondary_motivations'} })
    personal_motivations: Optional[list[Union[StixAttackMotivation, str]]] = Field(default=None, description="""The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals. Open Vocab - attack-motivation-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixAttackMotivation'}, {'range': 'string'}],
         'domain_of': ['StixThreatActor'],
         'slot_uri': 'stix:personal_motivations'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["threat-actor"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'threat-actor',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^threat-actor--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixTool(StixDomainObject):
    """
    Tools are legitimate software that can be used by threat actors to perform attacks.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'tool'}},
         'broad_mappings': ['uco-tool:Tool'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^tool--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'tool', 'name': 'type'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Other names by which the object is known.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixTool'],
         'slot_uri': 'stix:aliases'} })
    tool_types: Optional[list[Union[StixToolType, str]]] = Field(default=None, description="""The kind(s) of tool(s) being described. Open Vocab - tool-type-ov.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixToolType'}, {'range': 'string'}],
         'domain_of': ['StixTool'],
         'slot_uri': 'stix:tool_types'} })
    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    tool_version: Optional[str] = Field(default=None, description="""The version identifier associated with the tool.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixTool'], 'slot_uri': 'stix:tool_version'} })
    kill_chain_phases: Optional[list[StixKillChainPhase]] = Field(default=None, description="""The kill chain phases to which the object corresponds.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixAttackPattern',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixMalware',
                       'StixTool'],
         'slot_uri': 'stix:kill_chain_phases'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["tool"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'tool',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^tool--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixVulnerability(StixDomainObject):
    """
    A Vulnerability is a mistake in software that can be directly used by a hacker to gain access to a system or network.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'vulnerability'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^vulnerability--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'equals_string': 'vulnerability', 'name': 'type'}}})

    name: str = Field(default=..., description="""A name that identifies the object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:name'],
         'domain_of': ['StixIdentity',
                       'StixMarkingDefinition',
                       'StixExtensionDefinition',
                       'StixAutonomousSystem',
                       'StixFile',
                       'StixMutex',
                       'StixSoftware',
                       'StixAlternateDataStream',
                       'StixWindowsPeSection',
                       'StixWindowsRegistryValue',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability'],
         'slot_uri': 'stix:name'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["vulnerability"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'vulnerability',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^vulnerability--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixObservedObjects(ConfiguredBaseModel):
    """
    The cyber-observable objects of an observed data object, keyed by an index such as \"0\". STIX 2.1 deprecates this form in favour of object_refs.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'extra_slots': {'range_expression': {'inlined': True,
                                              'range': 'StixCyberObservableObject'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sdo'})

    pass


class StixRelationship(StixRelationshipObject):
    """
    The Relationship object is used to link together two SDOs in order to describe how they are related to each other.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'relationship'}},
         'close_mappings': ['uco-core:Relationship'],
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sro',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^relationship--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'relationship_type': {'name': 'relationship_type',
                                              'required': True},
                        'source_ref': {'name': 'source_ref', 'required': True},
                        'target_ref': {'name': 'target_ref', 'required': True},
                        'type': {'equals_string': 'relationship', 'name': 'type'}}})

    relationship_type: str = Field(default=..., description="""The name used to identify the type of relationship.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:kindOfRelationship'],
         'domain_of': ['StixRelationship'],
         'slot_uri': 'stix:relationship_type'} })
    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    source_ref: str = Field(default=..., description="""The ID of the source (from) object.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixDomainObject'},
                    {'range': 'StixCyberObservableObject'}],
         'close_mappings': ['uco-core:source'],
         'domain_of': ['StixRelationship'],
         'slot_uri': 'stix:source_ref'} })
    target_ref: str = Field(default=..., description="""The ID of the target (to) object.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixDomainObject'},
                    {'range': 'StixCyberObservableObject'}],
         'close_mappings': ['uco-core:target'],
         'domain_of': ['StixRelationship'],
         'slot_uri': 'stix:target_ref'} })
    start_time: Optional[str] = Field(default=None, description="""This optional timestamp represents the earliest time at which the Relationship between the objects exists. If this property is a future timestamp, at the time the updated property is defined, then this represents an estimate by the producer of the intelligence of the earliest time at which relationship will be asserted to be true.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:startTime'],
         'domain_of': ['StixRelationship'],
         'slot_uri': 'stix:start_time'} })
    stop_time: Optional[str] = Field(default=None, description="""The latest time at which the Relationship between the objects exists. If this property is a future timestamp, at the time the updated property is defined, then this represents an estimate by the producer of the intelligence of the latest time at which relationship will be asserted to be true.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:endTime'],
         'domain_of': ['StixRelationship'],
         'slot_uri': 'stix:stop_time'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["relationship"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'relationship',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('relationship_type')
    def pattern_relationship_type(cls, v):
        pattern=re.compile(r"^[a-z0-9\-]+$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid relationship_type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid relationship_type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('source_ref')
    def pattern_source_ref(cls, v):
        pattern=re.compile(r"^(?!(relationship|sighting|bundle|marking-definition|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid source_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid source_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('target_ref')
    def pattern_target_ref(cls, v):
        pattern=re.compile(r"^(?!(relationship|sighting|bundle|marking-definition|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid target_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid target_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^relationship--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixSighting(StixRelationshipObject):
    """
    A Sighting denotes the belief that something in CTI (e.g., an indicator, malware, tool, threat actor, etc.) was seen.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'sighting'}},
         'from_schema': 'https://w3id.org/lmodel/stix/stix_sro',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^sighting--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'sighting_of_ref': {'name': 'sighting_of_ref',
                                            'required': True},
                        'type': {'equals_string': 'sighting', 'name': 'type'}}})

    description: Optional[str] = Field(default=None, description="""A description of the object, which may be long.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:description'],
         'domain_of': ['StixIdentity',
                       'StixExtensionDefinition',
                       'StixExternalReference',
                       'StixAttackPattern',
                       'StixCampaign',
                       'StixCourseOfAction',
                       'StixGrouping',
                       'StixIncident',
                       'StixIndicator',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixLocation',
                       'StixMalware',
                       'StixReport',
                       'StixThreatActor',
                       'StixTool',
                       'StixVulnerability',
                       'StixRelationship',
                       'StixSighting'],
         'slot_uri': 'stix:description'} })
    first_seen: Optional[str] = Field(default=None, description="""The time at which the object was first seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:first_seen'} })
    last_seen: Optional[str] = Field(default=None, description="""The time at which the object was last seen.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCampaign',
                       'StixInfrastructure',
                       'StixIntrusionSet',
                       'StixMalware',
                       'StixThreatActor',
                       'StixSighting'],
         'slot_uri': 'stix:last_seen'} })
    count: Optional[int] = Field(default=None, description="""This is an integer between 0 and 999,999,999 inclusive and represents the number of times the object was sighted.""", ge=0, le=999999999, json_schema_extra = { "linkml_meta": {'domain_of': ['StixSighting'], 'slot_uri': 'stix:count'} })
    sighting_of_ref: str = Field(default=..., description="""An ID reference to the object that has been sighted.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSighting'], 'slot_uri': 'stix:sighting_of_ref'} })
    observed_data_refs: Optional[list[str]] = Field(default=None, description="""A list of ID references to the Observed Data objects that contain the raw cyber data for this Sighting.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixSighting'], 'slot_uri': 'stix:observed_data_refs'} })
    where_sighted_refs: Optional[list[str]] = Field(default=None, description="""A list of ID references to the Identity or Location objects describing the entities or types of entities that saw the sighting.""", min_length=1, json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'StixIdentity'}, {'range': 'StixLocation'}],
         'domain_of': ['StixSighting'],
         'slot_uri': 'stix:where_sighted_refs'} })
    summary: Optional[bool] = Field(default=None, description="""The summary property indicates whether the Sighting should be considered summary data.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixSighting'], 'slot_uri': 'stix:summary'} })
    created_by_ref: Optional[str] = Field(default=None, description="""A reference to the identity of the object's creator.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:createdBy'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created_by_ref'} })
    created: str = Field(default=..., description="""The time at which the object, or its first version, was created.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectCreatedTime'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:created'} })
    modified: str = Field(default=..., description="""The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:modifiedTime'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:modified'} })
    revoked: Optional[bool] = Field(default=None, description="""The revoked property indicates whether the object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject'], 'slot_uri': 'stix:revoked'} })
    labels: Optional[list[str]] = Field(default=None, description="""The labels property specifies a set of terms used to describe this object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:tag'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:labels'} })
    confidence: Optional[int] = Field(default=None, description="""Identifies the confidence that the creator has in the correctness of their data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:confidence'],
         'domain_of': ['StixCommonObject'],
         'slot_uri': 'stix:confidence'} })
    lang: Optional[str] = Field(default=None, description="""The language of the text content, as an RFC 5646 language code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixCommonObject', 'StixGranularMarking'],
         'slot_uri': 'stix:lang'} })
    external_references: Optional[list[StixExternalReference]] = Field(default=None, description="""References to non-STIX information about the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:externalReference'],
         'domain_of': ['StixCommonObject', 'StixMarkingDefinition'],
         'slot_uri': 'stix:external_references'} })
    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["sighting"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'sighting',
         'slot_uri': 'stix:type'} })
    spec_version: StixSpecVersion = Field(default=..., description="""The version of the STIX specification used to represent the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:spec_version'} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""References to the marking definitions that apply to the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'close_mappings': ['uco-core:objectMarking'],
         'domain_of': ['StixObject'],
         'slot_uri': 'stix:object_marking_refs'} })
    granular_markings: Optional[list[StixGranularMarking]] = Field(default=None, description="""The granular markings that apply to parts of the object.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:granular_markings'} })
    extensions: Optional[StixExtensions] = Field(default=None, description="""The object's extensions, as a dictionary keyed by extension name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject'], 'slot_uri': 'stix:extensions'} })

    @field_validator('sighting_of_ref')
    def pattern_sighting_of_ref(cls, v):
        pattern=re.compile(r"^(?!(relationship|sighting|bundle|marking-definition|language-content)--)[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid sighting_of_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid sighting_of_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('observed_data_refs')
    def pattern_observed_data_refs(cls, v):
        pattern=re.compile(r"^observed-data--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid observed_data_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid observed_data_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('where_sighted_refs')
    def pattern_where_sighted_refs(cls, v):
        pattern=re.compile(r"^(identity|location)--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid where_sighted_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid where_sighted_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created_by_ref')
    def pattern_created_by_ref(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid created_by_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid created_by_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^sighting--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class StixBundle(ConfiguredBaseModel):
    """
    A bundle: a collection of STIX objects grouped together in one container. A bundle is a container for transport, not a STIX object, so it carries no spec_version.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'annotations': {'stix_type': {'tag': 'stix_type', 'value': 'bundle'}},
         'close_mappings': ['uco-core:Bundle'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^bundle--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'objects': {'description': 'The STIX objects in the bundle.',
                                    'inlined_as_list': True,
                                    'minimum_cardinality': 1,
                                    'multivalued': True,
                                    'name': 'objects',
                                    'range': 'StixObject'},
                        'type': {'equals_string': 'bundle', 'name': 'type'}},
         'tree_root': True})

    id: str = Field(default=..., description="""The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'], 'slot_uri': 'stix:id'} })
    type: Literal["bundle"] = Field(default=..., description="""The STIX type name of the object, such as attack-pattern. Each class pins its own.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixObject', 'StixBundle'],
         'equals_string': 'bundle',
         'slot_uri': 'stix:type'} })
    objects: Optional[list[StixObject]] = Field(default=None, description="""The STIX objects in the bundle.""", min_length=1, json_schema_extra = { "linkml_meta": {'domain_of': ['StixObservedData', 'StixBundle'], 'slot_uri': 'stix:objects'} })

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^bundle--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.search(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.search(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v


# Model rebuild
# see https://pydantic-docs.helpmanual.io/usage/models/#rebuilding-a-model
StixObject.model_rebuild()
StixCommonObject.model_rebuild()
StixDomainObject.model_rebuild()
StixRelationshipObject.model_rebuild()
StixCyberObservableObject.model_rebuild()
StixIdentity.model_rebuild()
StixMarkingDefinition.model_rebuild()
StixLanguageContent.model_rebuild()
StixExtensionDefinition.model_rebuild()
StixExternalReference.model_rebuild()
StixKillChainPhase.model_rebuild()
StixGranularMarking.model_rebuild()
StixStatementMarking.model_rebuild()
StixTlpMarking.model_rebuild()
StixExtension.model_rebuild()
StixHashes.model_rebuild()
StixExtensions.model_rebuild()
StixDictionary.model_rebuild()
StixLanguageContents.model_rebuild()
StixArtifact.model_rebuild()
StixAutonomousSystem.model_rebuild()
StixDirectory.model_rebuild()
StixDomainName.model_rebuild()
StixEmailAddress.model_rebuild()
StixEmailMessage.model_rebuild()
StixFile.model_rebuild()
StixIpv4Address.model_rebuild()
StixIpv6Address.model_rebuild()
StixMacAddress.model_rebuild()
StixMutex.model_rebuild()
StixNetworkTraffic.model_rebuild()
StixProcess.model_rebuild()
StixSoftware.model_rebuild()
StixUrl.model_rebuild()
StixUserAccount.model_rebuild()
StixWindowsRegistryKey.model_rebuild()
StixX509Certificate.model_rebuild()
StixNtfsExtension.model_rebuild()
StixRasterImageExtension.model_rebuild()
StixPdfExtension.model_rebuild()
StixArchiveExtension.model_rebuild()
StixWindowsPeBinaryExtension.model_rebuild()
StixHttpRequestExtension.model_rebuild()
StixIcmpExtension.model_rebuild()
StixSocketExtension.model_rebuild()
StixTcpExtension.model_rebuild()
StixWindowsProcessExtension.model_rebuild()
StixWindowsServiceExtension.model_rebuild()
StixUnixAccountExtension.model_rebuild()
StixAlternateDataStream.model_rebuild()
StixWindowsPeSection.model_rebuild()
StixWindowsPeOptionalHeader.model_rebuild()
StixMimePart.model_rebuild()
StixWindowsRegistryValue.model_rebuild()
StixX509V3Extensions.model_rebuild()
StixFileExtensions.model_rebuild()
StixNetworkTrafficExtensions.model_rebuild()
StixProcessExtensions.model_rebuild()
StixUserAccountExtensions.model_rebuild()
StixSocketOptions.model_rebuild()
StixExifTags.model_rebuild()
StixPdfDocumentInfo.model_rebuild()
StixAttackPattern.model_rebuild()
StixCampaign.model_rebuild()
StixCourseOfAction.model_rebuild()
StixGrouping.model_rebuild()
StixIncident.model_rebuild()
StixIndicator.model_rebuild()
StixInfrastructure.model_rebuild()
StixIntrusionSet.model_rebuild()
StixLocation.model_rebuild()
StixMalware.model_rebuild()
StixMalwareAnalysis.model_rebuild()
StixNote.model_rebuild()
StixObservedData.model_rebuild()
StixOpinion.model_rebuild()
StixReport.model_rebuild()
StixThreatActor.model_rebuild()
StixTool.model_rebuild()
StixVulnerability.model_rebuild()
StixObservedObjects.model_rebuild()
StixRelationship.model_rebuild()
StixSighting.model_rebuild()
StixBundle.model_rebuild()
