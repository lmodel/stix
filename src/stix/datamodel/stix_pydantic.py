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


metamodel_version = "1.7.0"
version = "None"


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


linkml_meta = LinkMLMeta({'comments': ['For constraints we use LinkML, and validator comments.'],
     'default_prefix': 'stix',
     'default_range': 'string',
     'description': 'Structured Threat Information Expression (STIX): LinkML '
                    'Schema\n'
                    'derived from OASIS CTI STIX 2.1 JSON Schemas.',
     'id': 'https://w3id.org/lmodel/stix',
     'imports': ['linkml:types'],
     'license': 'Apache-2.0',
     'name': 'stix',
     'prefixes': {'linkml': {'prefix_prefix': 'linkml',
                             'prefix_reference': 'https://w3id.org/linkml/'},
                  'schema': {'prefix_prefix': 'schema',
                             'prefix_reference': 'http://schema.org/'},
                  'stix': {'prefix_prefix': 'stix',
                           'prefix_reference': 'https://w3id.org/lmodel/stix/'},
                  'unified_cyber_ontology': {'prefix_prefix': 'unified_cyber_ontology',
                                             'prefix_reference': 'https://w3id.org/lmodel/uco-master/'}},
     'see_also': ['https://lmodel.github.io/stix',
                  'https://github.com/oasis-open/cti-stix2-json-schemas'],
     'source': 'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas',
     'source_file': 'src/stix/schema/stix.yaml',
     'subsets': {'common': {'description': 'Classes from '
                                           'stix/schemas/common/*.json',
                            'from_schema': 'https://w3id.org/lmodel/stix',
                            'name': 'common'},
                 'observables': {'description': 'Classes from '
                                                'stix/schemas/observables/*.json',
                                 'from_schema': 'https://w3id.org/lmodel/stix',
                                 'name': 'observables'},
                 'sdos': {'description': 'Classes from stix/schemas/sdos/*.json',
                          'from_schema': 'https://w3id.org/lmodel/stix',
                          'name': 'sdos'},
                 'sros': {'description': 'Classes from stix/schemas/sros/*.json',
                          'from_schema': 'https://w3id.org/lmodel/stix',
                          'name': 'sros'}},
     'title': 'STIX',
     'types': {'stix_identifier': {'base': 'str',
                                   'from_schema': 'https://w3id.org/lmodel/stix',
                                   'name': 'stix_identifier',
                                   'pattern': '^[a-z][a-z0-9-]*--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                   'uri': 'xsd:string'},
               'stix_type_name': {'base': 'str',
                                  'from_schema': 'https://w3id.org/lmodel/stix',
                                  'name': 'stix_type_name',
                                  'pattern': '^([a-z][a-z0-9]*)+(-[a-z0-9]+)*-?$',
                                  'uri': 'xsd:string'}}} )

class SpecVersionEnum(str, Enum):
    """
    STIX specification versions allowed by the upstream JSON Schema.
    """
    number_2FULL_STOP0 = "2.0"
    number_2FULL_STOP1 = "2.1"


class OpinionEnum(str, Enum):
    """
    Opinion vocabulary from STIX opinion object.
    """
    strongly_disagree = "strongly-disagree"
    disagree = "disagree"
    neutral = "neutral"
    agree = "agree"
    strongly_agree = "strongly-agree"


class ExtensionTypeEnum(str, Enum):
    """
    Extension-definition extension type vocabulary.
    """
    new_sdo = "new-sdo"
    new_sco = "new-sco"
    new_sro = "new-sro"
    property_extension = "property-extension"
    toplevel_property_extension = "toplevel-property-extension"


class RegistryDataTypeEnum(str, Enum):
    """
    Windows registry data type vocabulary.
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


class IdentityClassOv(str, Enum):
    """
    Open vocabulary for identity class (identity-class-ov). Additional string values are allowed.
    """
    individual = "individual"
    group = "group"
    system = "system"
    organization = "organization"
    class_ = "class"
    unknown = "unknown"


class IndustrySectorOv(str, Enum):
    """
    Open vocabulary for industry sector (industry-sector-ov). Additional string values are allowed.
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
    infrastructure_dams = "infrastructure-dams"
    infrastructure_nuclear = "infrastructure-nuclear"
    infrastructure_water = "infrastructure-water"
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


class ThreatActorTypeOv(str, Enum):
    """
    Open vocabulary for threat actor type (threat-actor-type-ov). Additional string values are allowed.
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


class ThreatActorRoleOv(str, Enum):
    """
    Open vocabulary for threat actor role (threat-actor-role-ov). Additional string values are allowed.
    """
    agent = "agent"
    director = "director"
    independent = "independent"
    infrastructure_architect = "infrastructure-architect"
    infrastructure_operator = "infrastructure-operator"
    malware_author = "malware-author"
    sponsor = "sponsor"


class ThreatActorSophisticationOv(str, Enum):
    """
    Open vocabulary for threat actor sophistication (threat-actor-sophistication-ov). Additional string values are allowed.
    """
    none = "none"
    minimal = "minimal"
    intermediate = "intermediate"
    advanced = "advanced"
    expert = "expert"
    innovator = "innovator"
    strategic = "strategic"


class AttackResourceLevelOv(str, Enum):
    """
    Open vocabulary for attack resource level (attack-resource-level-ov). Additional string values are allowed.
    """
    individual = "individual"
    club = "club"
    contest = "contest"
    team = "team"
    organization = "organization"
    government = "government"


class AttackMotivationOv(str, Enum):
    """
    Open vocabulary for attack motivation (attack-motivation-ov). Additional string values are allowed.
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


class MalwareTypeOv(str, Enum):
    """
    Open vocabulary for malware type (malware-type-ov). Additional string values are allowed.
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


class MalwareCapabilityOv(str, Enum):
    """
    Open vocabulary for malware capabilities (malware-capabilities-ov). Additional string values are allowed.
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


class InfrastructureTypeOv(str, Enum):
    """
    Open vocabulary for infrastructure type (infrastructure-type-ov). Additional string values are allowed.
    """
    amplification = "amplification"
    anonymization = "anonymization"
    botnet = "botnet"
    command_and_control = "command-and-control"
    exfiltration = "exfiltration"
    hosting_malware = "hosting-malware"
    hosting_target_lists = "hosting-target-lists"
    phishing = "phishing"
    reconnaissance = "reconnaissance"
    staging = "staging"
    undefined = "undefined"


class ToolTypeOv(str, Enum):
    """
    Open vocabulary for tool type (tool-type-ov). Additional string values are allowed.
    """
    denial_of_service = "denial-of-service"
    exploitation = "exploitation"
    information_gathering = "information-gathering"
    network_capture = "network-capture"
    credential_exploitation = "credential-exploitation"
    remote_access = "remote-access"
    vulnerability_scanning = "vulnerability-scanning"
    unknown = "unknown"


class ReportTypeOv(str, Enum):
    """
    Open vocabulary for report type (report-type-ov). Additional string values are allowed.
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


class IndicatorTypeOv(str, Enum):
    """
    Open vocabulary for indicator type (indicator-type-ov). Additional string values are allowed.
    """
    anomalous_activity = "anomalous-activity"
    anonymization = "anonymization"
    benign = "benign"
    compromised = "compromised"
    malicious_activity = "malicious-activity"
    attribution = "attribution"
    unknown = "unknown"


class PatternTypeOv(str, Enum):
    """
    Open vocabulary for pattern type (pattern-type-ov). Additional string values are allowed.
    """
    stix = "stix"
    pcre = "pcre"
    sigma = "sigma"
    snort = "snort"
    suricata = "suricata"
    yara = "yara"


class MalwareAvResultOv(str, Enum):
    """
    Open vocabulary for malware AV result (malware-av-result-ov). Additional string values are allowed.
    """
    malicious = "malicious"
    suspicious = "suspicious"
    benign = "benign"
    unknown = "unknown"


class ImplementationLanguageOv(str, Enum):
    """
    Open vocabulary for implementation languages (implementation-language-ov). Additional string values are allowed.
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


class ProcessorArchitectureOv(str, Enum):
    """
    Open vocabulary for processor architecture (processor-architecture-ov). Additional string values are allowed.
    """
    alpha = "alpha"
    arm = "arm"
    ia_64 = "ia-64"
    mips = "mips"
    powerpc = "powerpc"
    sparc = "sparc"
    x86 = "x86"
    x86_64 = "x86-64"


class AccountTypeOv(str, Enum):
    """
    Open vocabulary for user account type (account-type-ov). Additional string values are allowed.
    """
    unix = "unix"
    windows_local = "windows-local"
    windows_domain = "windows-domain"
    ldap = "ldap"
    tacacs = "tacacs"
    radius = "radius"
    nis = "nis"
    openid = "openid"
    facebook = "facebook"
    skype = "skype"
    twitter = "twitter"
    kavi = "kavi"


class WindowsIntegrityLevelEnum(str, Enum):
    """
    Windows process integrity level (trustworthiness) enumeration.
    """
    low = "low"
    medium = "medium"
    high = "high"
    system = "system"


class WindowsServiceStartEnum(str, Enum):
    """
    Windows service start type enumeration.
    """
    SERVICE_AUTO_START = "SERVICE_AUTO_START"
    SERVICE_BOOT_START = "SERVICE_BOOT_START"
    SERVICE_DEMAND_START = "SERVICE_DEMAND_START"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    SERVICE_SYSTEM_ALERT = "SERVICE_SYSTEM_ALERT"


class WindowsServiceTypeEnum(str, Enum):
    """
    Windows service type enumeration.
    """
    SERVICE_KERNEL_DRIVER = "SERVICE_KERNEL_DRIVER"
    SERVICE_FILE_SYSTEM_DRIVER = "SERVICE_FILE_SYSTEM_DRIVER"
    SERVICE_WIN32_OWN_PROCESS = "SERVICE_WIN32_OWN_PROCESS"
    SERVICE_WIN32_SHARE_PROCESS = "SERVICE_WIN32_SHARE_PROCESS"


class WindowsServiceStatusEnum(str, Enum):
    """
    Windows service status enumeration.
    """
    SERVICE_CONTINUE_PENDING = "SERVICE_CONTINUE_PENDING"
    SERVICE_PAUSE_PENDING = "SERVICE_PAUSE_PENDING"
    SERVICE_PAUSED = "SERVICE_PAUSED"
    SERVICE_RUNNING = "SERVICE_RUNNING"
    SERVICE_START_PENDING = "SERVICE_START_PENDING"
    SERVICE_STOP_PENDING = "SERVICE_STOP_PENDING"
    SERVICE_STOPPED = "SERVICE_STOPPED"


class NetworkSocketAddressFamilyEnum(str, Enum):
    """
    Network socket address family enumeration.
    """
    AF_UNSPEC = "AF_UNSPEC"
    AF_INET = "AF_INET"
    AF_IPX = "AF_IPX"
    AF_APPLETALK = "AF_APPLETALK"
    AF_NETBIOS = "AF_NETBIOS"
    AF_INET6 = "AF_INET6"
    AF_IRDA = "AF_IRDA"
    AF_BTH = "AF_BTH"


class NetworkSocketTypeEnum(str, Enum):
    """
    Network socket type enumeration.
    """
    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"
    SOCK_RAW = "SOCK_RAW"
    SOCK_RDM = "SOCK_RDM"
    SOCK_SEQPACKET = "SOCK_SEQPACKET"


class WindowsPEBinaryTypeOv(str, Enum):
    """
    Open vocabulary for Windows PE binary type (windows-pebinary-type-ov). Suggested values are exe, dll, sys; additional string values are allowed.
    """
    exe = "exe"
    dll = "dll"
    sys = "sys"



class StixEntity(ConfiguredBaseModel):
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix'})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class CommonSchemaComponent(StixEntity):
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix'})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class Bundle(CommonSchemaComponent):
    """
    A Bundle is a collection of arbitrary STIX Objects and Marking Definitions grouped together in a single container. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf+oneOf validator_hint: '
                      'validate-bundle-object-members jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/bundle.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'notes': ['JSON Schema defines bundle objects as a heterogeneous anyOf/oneOf '
                   'set including custom objects.'],
         'slot_usage': {'bundle_objects': {'comments': ['jsonschema_minItems: "1"'],
                                           'name': 'bundle_objects'},
                        'id': {'name': 'id',
                               'pattern': '^bundle--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                               'required': True},
                        'type': {'name': 'type',
                                 'pattern': '^bundle$',
                                 'required': True}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    bundle_objects: Optional[list[StixEntity]] = Field(default=None, description="""Objects contained in a bundle.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Bundle']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^bundle$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^bundle--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class Core(CommonSchemaComponent):
    """
    Common properties and behavior across all STIX Domain Objects and STIX Relationship Objects. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True,
         'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/core.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'slot_usage': {'created': {'name': 'created',
                                    'notes': ['STIX core timestamps require '
                                              'millisecond precision.'],
                                    'pattern': 'T\\d{2}:\\d{2}:\\d{2}\\.\\d{3,}Z$',
                                    'required': True},
                        'external_references': {'comments': ['jsonschema_minItems: '
                                                             '"1"'],
                                                'name': 'external_references'},
                        'granular_markings': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'granular_markings'},
                        'id': {'name': 'id', 'required': True},
                        'labels': {'comments': ['jsonschema_minItems: "1"'],
                                   'name': 'labels'},
                        'modified': {'name': 'modified',
                                     'notes': ['STIX core timestamps require '
                                               'millisecond precision.'],
                                     'pattern': 'T\\d{2}:\\d{2}:\\d{2}\\.\\d{3,}Z$',
                                     'required': True},
                        'object_marking_refs': {'comments': ['jsonschema_minItems: '
                                                             '"1"'],
                                                'name': 'object_marking_refs'},
                        'spec_version': {'name': 'spec_version', 'required': True},
                        'type': {'name': 'type', 'required': True}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class StixDomainObject(Core):
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix'})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class StixRelationshipObject(Core):
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix'})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class CyberObservableCore(CommonSchemaComponent):
    """
    Common properties and behavior across all Cyber Observable Objects. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True,
         'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/cyber-observable-core.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'slot_usage': {'granular_markings': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'granular_markings'},
                        'id': {'name': 'id', 'required': True},
                        'object_marking_refs': {'comments': ['jsonschema_minItems: '
                                                             '"1"'],
                                                'name': 'object_marking_refs'},
                        'type': {'name': 'type', 'required': True}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class CyberObservableObject(CyberObservableCore):
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'abstract': True, 'from_schema': 'https://w3id.org/lmodel/stix'})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class Dictionary(CommonSchemaComponent):
    """
    A dictionary captures a set of key/value pairs 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/dictionary.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class ExtensionDefinition(Core):
    """
    The STIX Extension Definition object allows producers of threat intelligence to extend existing STIX objects or to create entirely new STIX objects in a standardized way. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: if-then validator_hint: '
                      'extension-definition-top-level-property-constraint '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/extension-definition.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'slot_usage': {'extension_properties': {'comments': ['jsonschema_minItems: '
                                                              '"1" '
                                                              'jsonschema_conditional_required: '
                                                              '"required when '
                                                              'extension_types '
                                                              'contains '
                                                              'toplevel-property-extension"'],
                                                 'name': 'extension_properties'},
                        'extension_types': {'comments': ['jsonschema_minItems: "1"'],
                                            'name': 'extension_types',
                                            'required': True},
                        'id': {'name': 'id',
                               'pattern': '^extension-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'schema': {'name': 'schema', 'required': True},
                        'type': {'name': 'type', 'pattern': '^extension-definition$'},
                        'version': {'name': 'version', 'required': True}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })
    schema: str = Field(default=..., description="""Extension schema definition or URL.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExtensionDefinition']} })
    version: str = Field(default=..., description="""Version string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExtensionDefinition',
                       'Software',
                       'PdfExt',
                       'X509Certificate',
                       'MalwareAnalysis']} })
    extension_types: list[ExtensionTypeEnum] = Field(default=..., description="""Extension-definition type list.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['ExtensionDefinition']} })
    extension_properties: Optional[list[str]] = Field(default=None, description="""Extension-defined property names.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1" jsonschema_conditional_required: '
                      '"required when extension_types contains '
                      'toplevel-property-extension"'],
         'domain_of': ['ExtensionDefinition']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^extension-definition$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^extension-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Extension(CommonSchemaComponent):
    """
    Converted from common/extension.json
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_minProperties: "1" jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/extension.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'slot_usage': {'extension_type': {'name': 'extension_type', 'required': True}}})

    extension_type: ExtensionTypeEnum = Field(default=..., description="""Type discriminator for extension payloads.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Extension']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class ExternalReference(CommonSchemaComponent):
    """
    External references are used to describe pointers to information represented outside of STIX. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: oneOf validator_hint: '
                      'external-reference-branch-validation jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/external-reference.json'],
         'exact_mappings': ['unified_cyber_ontology:ExternalReference'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'notes': ['Upstream JSON Schema uses oneOf branches keyed by source_name; '
                   'exact branch logic is delegated to validator tooling.'],
         'slot_usage': {'source_name': {'name': 'source_name', 'required': True},
                        'url': {'name': 'url', 'pattern': '^\\w+:'}}})

    source_name: str = Field(default=..., description="""Name of the external source.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:name'],
         'domain_of': ['ExternalReference']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })
    url: Optional[str] = Field(default=None, description="""A URL reference to an external resource.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExternalReference', 'Artifact'],
         'related_mappings': ['unified_cyber_ontology:URL']} })
    hashes: Optional[HashesType] = Field(default=None, description="""Specifies a dictionary of hashes for the file or content.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExternalReference', 'Artifact', 'File', 'X509Certificate'],
         'exact_mappings': ['unified_cyber_ontology:hashes']} })
    external_id: Optional[str] = Field(default=None, description="""An identifier for the external reference content.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExternalReference']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })

    @field_validator('url')
    def pattern_url(cls, v):
        pattern=re.compile(r"^\w+:")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid url format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid url format: {v}"
            raise ValueError(err_msg)
        return v


class GranularMarking(CommonSchemaComponent):
    """
    The granular-marking type defines how the list of marking-definition objects referenced by the marking_refs property to apply to a set of content identified by the list of selectors in the selectors property. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/granular-marking.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'slot_usage': {'marking_ref': {'name': 'marking_ref',
                                        'pattern': '^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                                        'required': True},
                        'selectors': {'comments': ['jsonschema_minItems: "1"'],
                                      'name': 'selectors',
                                      'required': True}}})

    marking_ref: str = Field(default=..., description="""Marking-definition reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['GranularMarking']} })
    selectors: list[str] = Field(default=..., description="""A list of selectors for content contained within the STIX object in which this property appears.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['GranularMarking']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('marking_ref')
    def pattern_marking_ref(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid marking_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid marking_ref format: {v}"
            raise ValueError(err_msg)
        return v


class HashesType(CommonSchemaComponent):
    """
    The Hashes type represents one or more cryptographic hashes, as a special set of key/value pairs 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: patternProperties+additionalProperties=false '
                      'validator_hint: validate-hash-key-specific-patterns '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/hashes-type.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'notes': ['JSON Schema defines strict hash key patternProperties with '
                   'algorithm-specific regex value constraints.']})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class Hex(CommonSchemaComponent):
    """
    The hex data type encodes an array of octets (8-bit bytes) as hexadecimal. The string MUST consist of an even number of hexadecimal characters, which are the digits '0' through '9' and the letters 'a' through 'f'. In order to allow pattern matching on custom objects, all properties that use the hex type, the property name MUST end with '_hex'. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_type: string jsonschema_pattern: '
                      '"^([a-fA-F0-9]{2})+$" jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/hex.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class Identifier(CommonSchemaComponent):
    """
    Represents identifiers across the CTI specifications. The format consists of the name of the top-level object being identified, followed by two dashes (--), followed by a UUIDv4. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['backed_by_type: stix_identifier jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/identifier.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class KillChainPhase(CommonSchemaComponent):
    """
    The kill-chain-phase represents a phase in a kill chain. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/kill-chain-phase.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    kill_chain_name: str = Field(default=..., description="""Name of the kill chain.""", json_schema_extra = { "linkml_meta": {'domain_of': ['KillChainPhase']} })
    phase_name: str = Field(default=..., description="""Name of the kill chain phase.""", json_schema_extra = { "linkml_meta": {'domain_of': ['KillChainPhase']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class LanguageContent(Core):
    """
    The language-content object represents text content for STIX Objects represented in languages other than that of the original object. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: not validator_hint: '
                      'language-content-object-ref-restrictions jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/language-content.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'notes': ['object_ref cannot target bundle or language-content IDs.'],
         'slot_usage': {'contents': {'name': 'contents', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^language-content--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_ref': {'name': 'object_ref', 'required': True},
                        'type': {'name': 'type', 'pattern': '^language-content$'}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_ref: str = Field(default=..., description="""Single object reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['LanguageContent']} })
    object_modified: Optional[datetime ] = Field(default=None, description="""Referenced object modified timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['LanguageContent']} })
    contents: str = Field(default=..., description="""Language content dictionary payload.""", json_schema_extra = { "linkml_meta": {'domain_of': ['LanguageContent']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^language-content$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^language-content--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class MarkingDefinition(CommonSchemaComponent):
    """
    The marking-definition object represents a specific marking. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: oneOf+if-then validator_hint: '
                      'enforce-marking-definition-branches jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/marking-definition.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'notes': ['TLP and statement variants use oneOf/if-then logic in JSON Schema '
                   'and are represented with validator hints.'],
         'slot_usage': {'created': {'name': 'created', 'required': True},
                        'definition': {'comments': ['jsonschema_conditional_required: '
                                                    '"required unless extensions '
                                                    'present"'],
                                       'name': 'definition'},
                        'definition_type': {'comments': ['jsonschema_conditional_required: '
                                                         '"required unless extensions '
                                                         'present"'],
                                            'name': 'definition_type'},
                        'external_references': {'comments': ['jsonschema_minItems: '
                                                             '"1"'],
                                                'name': 'external_references'},
                        'granular_markings': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'granular_markings'},
                        'id': {'name': 'id',
                               'pattern': '^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
                               'required': True},
                        'object_marking_refs': {'comments': ['jsonschema_minItems: '
                                                             '"1"'],
                                                'name': 'object_marking_refs',
                                                'pattern': '^marking-definition--'},
                        'spec_version': {'name': 'spec_version', 'required': True},
                        'type': {'name': 'type',
                                 'pattern': '^marking-definition$',
                                 'required': True}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    definition_type: Optional[str] = Field(default=None, description="""Type discriminator for marking definition content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_conditional_required: "required unless extensions '
                      'present"'],
         'domain_of': ['MarkingDefinition']} })
    definition: Optional[str] = Field(default=None, description="""Marking definition payload.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_conditional_required: "required unless extensions '
                      'present"'],
         'domain_of': ['MarkingDefinition']} })
    statement: Optional[str] = Field(default=None, description="""A statement (e.g., copyright, terms of use) applied to the content marked by this marking definition.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MarkingDefinition']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^marking-definition$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('object_marking_refs')
    def pattern_object_marking_refs(cls, v):
        pattern=re.compile(r"^marking-definition--")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid object_marking_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid object_marking_refs format: {v}"
            raise ValueError(err_msg)
        return v


class Properties(CommonSchemaComponent):
    """
    Rules for custom properties 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: patternProperties+additionalProperties=false '
                      'validator_hint: validate-custom-properties jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/properties.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class Timestamp(CommonSchemaComponent):
    """
    Represents timestamps across the CTI specifications. The format is an RFC3339 timestamp, with a required timezone specification of 'Z'. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_type: string jsonschema_pattern: '
                      '"^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\\\\.[0-9]+)?Z$" '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/timestamp.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class UrlRegex(CommonSchemaComponent):
    """
    Matches a URI according to RFC 3986. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_type: string jsonschema_format: uri '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/common/url-regex.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class Artifact(CyberObservableObject):
    """
    The Artifact Object permits capturing an array of bytes (8-bits), as a base64-encoded string string, or linking to a file-like payload. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: oneOf validator_hint: '
                      'enforce-artifact-exclusive-payload-and-encryption-rules '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/artifact.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema enforces oneOf for payload_bin vs url+hashes and '
                   'conditional decryption rules.'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'mime_type': {'name': 'mime_type',
                                      'pattern': '^(application|audio|font|image|message|model|multipart|text|video)/[a-zA-Z0-9.+_-]+'},
                        'type': {'name': 'type', 'pattern': '^artifact$'}}})

    mime_type: Optional[str] = Field(default=None, description="""MIME type value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Artifact', 'File']} })
    payload_bin: Optional[str] = Field(default=None, description="""Base64 binary payload.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Artifact']} })
    url: Optional[str] = Field(default=None, description="""A URL reference to an external resource.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExternalReference', 'Artifact'],
         'related_mappings': ['unified_cyber_ontology:URL']} })
    hashes: Optional[HashesType] = Field(default=None, description="""Specifies a dictionary of hashes for the file or content.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExternalReference', 'Artifact', 'File', 'X509Certificate'],
         'exact_mappings': ['unified_cyber_ontology:hashes']} })
    encryption_algorithm: Optional[str] = Field(default=None, description="""Artifact encryption algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Artifact']} })
    decryption_key: Optional[str] = Field(default=None, description="""Decryption key material.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Artifact']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('mime_type')
    def pattern_mime_type(cls, v):
        pattern=re.compile(r"^(application|audio|font|image|message|model|multipart|text|video)/[a-zA-Z0-9.+_-]+")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid mime_type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid mime_type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^artifact$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^artifact--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class AutonomousSystem(CyberObservableObject):
    """
    The AS object represents the properties of an Autonomous Systems (AS). 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/autonomous-system.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'number': {'name': 'number', 'required': True},
                        'type': {'name': 'type', 'pattern': '^autonomous-system$'}}})

    number: int = Field(default=..., description="""Numeric identifier value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['AutonomousSystem']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    rir: Optional[str] = Field(default=None, description="""Regional Internet Registry name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['AutonomousSystem']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^autonomous-system$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^autonomous-system--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class Directory(CyberObservableObject):
    """
    The Directory Object represents the properties common to a file system directory. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/directory.json'],
         'exact_mappings': ['unified_cyber_ontology:Directory'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'contains_refs': {'comments': ['jsonschema_minItems: "1"'],
                                          'name': 'contains_refs'},
                        'id': {'name': 'id',
                               'pattern': '^directory--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'path': {'name': 'path', 'required': True},
                        'type': {'name': 'type', 'pattern': '^directory$'}}})

    path: str = Field(default=..., description="""Filesystem path.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory']} })
    path_enc: Optional[str] = Field(default=None, description="""Encoding used for a filesystem path.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory']} })
    ctime: Optional[datetime ] = Field(default=None, description="""Creation time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory', 'File']} })
    mtime: Optional[datetime ] = Field(default=None, description="""Last modification time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory', 'File']} })
    atime: Optional[datetime ] = Field(default=None, description="""Last access time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory', 'File']} })
    contains_refs: Optional[list[str]] = Field(default=None, description="""References to contained objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Directory', 'File', 'ArchiveExt']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('path_enc')
    def pattern_path_enc(cls, v):
        pattern=re.compile(r"^[a-zA-Z0-9/\.+_:-]{2,250}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid path_enc format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid path_enc format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^directory$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^directory--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class DomainName(CyberObservableObject):
    """
    The Domain Name represents the properties of a network domain name. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/domain-name.json'],
         'exact_mappings': ['unified_cyber_ontology:DomainName'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^domain-name--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'resolves_to_refs': {'comments': ['jsonschema_minItems: "1"'],
                                             'name': 'resolves_to_refs'},
                        'type': {'name': 'type', 'pattern': '^domain-name$'},
                        'value': {'name': 'value', 'required': True}}})

    value: str = Field(default=..., description="""Canonical string value for simple cyber observables.""", json_schema_extra = { "linkml_meta": {'domain_of': ['DomainName',
                       'EmailAddr',
                       'Ipv4Addr',
                       'Ipv6Addr',
                       'MacAddr',
                       'Url']} })
    resolves_to_refs: Optional[list[str]] = Field(default=None, description="""References this observable resolves to.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['DomainName', 'Ipv4Addr', 'Ipv6Addr']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^domain-name$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^domain-name--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class EmailAddr(CyberObservableObject):
    """
    The Email Address Object represents a single email address. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['unified_cyber_ontology:EmailAddress'],
         'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/email-addr.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'name': 'type', 'pattern': '^email-addr$'},
                        'value': {'name': 'value',
                                  'pattern': '^[^@]+@[^@]+$',
                                  'required': True}}})

    value: str = Field(default=..., description="""Canonical string value for simple cyber observables.""", json_schema_extra = { "linkml_meta": {'domain_of': ['DomainName',
                       'EmailAddr',
                       'Ipv4Addr',
                       'Ipv6Addr',
                       'MacAddr',
                       'Url']} })
    display_name: Optional[str] = Field(default=None, description="""Human-friendly display name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailAddr', 'UserAccount', 'WindowsServiceExt']} })
    belongs_to_ref: Optional[str] = Field(default=None, description="""Single reference this observable belongs to.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailAddr']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('value')
    def pattern_value(cls, v):
        pattern=re.compile(r"^[^@]+@[^@]+$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid value format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid value format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^email-addr$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^email-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class EmailMessage(CyberObservableObject):
    """
    The Email Message Object represents an instance of an email message. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: oneOf validator_hint: '
                      'enforce-email-message-multipart-constraints jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/email-message.json'],
         'exact_mappings': ['unified_cyber_ontology:EmailMessage'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema includes oneOf multipart semantics between body and '
                   'body_multipart.'],
         'slot_usage': {'bcc_refs': {'comments': ['jsonschema_minItems: "1"'],
                                     'name': 'bcc_refs'},
                        'cc_refs': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'cc_refs'},
                        'id': {'name': 'id',
                               'pattern': '^email-message--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'to_refs': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'to_refs'},
                        'type': {'name': 'type', 'pattern': '^email-message$'}}})

    email_date: Optional[datetime ] = Field(default=None, description="""Date/time the email message was sent.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    content_type: Optional[str] = Field(default=None, description="""Specifies the value of the 'Content-Type' header of the email message.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage', 'MimePartType']} })
    from_ref: Optional[str] = Field(default=None, description="""Sender mailbox reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    sender_ref: Optional[str] = Field(default=None, description="""Sender reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    to_refs: Optional[list[str]] = Field(default=None, description="""To-recipient references.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['EmailMessage']} })
    cc_refs: Optional[list[str]] = Field(default=None, description="""Cc-recipient references.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['EmailMessage']} })
    bcc_refs: Optional[list[str]] = Field(default=None, description="""Bcc-recipient references.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['EmailMessage']} })
    message_id: Optional[str] = Field(default=None, description="""Message identifier field.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    subject: Optional[str] = Field(default=None, description="""Subject value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage', 'X509Certificate']} })
    received_lines: Optional[list[str]] = Field(default=None, description="""Received header lines.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    additional_header_fields: Optional[str] = Field(default=None, description="""Additional email headers.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    raw_email_ref: Optional[str] = Field(default=None, description="""Reference to raw email artifact.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    is_multipart: Optional[bool] = Field(default=None, description="""Indicates whether the email body contains multiple MIME parts.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    body: Optional[str] = Field(default=None, description="""Specifies a string containing the email body. This field MAY only be used if is_multipart is false.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage', 'MimePartType']} })
    body_multipart: Optional[list[MimePartType]] = Field(default=None, description="""List of MIME parts comprising the email body (multipart emails only).""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^email-message$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^email-message--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class File(CyberObservableObject):
    """
    The File Object represents the properties of a file. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf exactly_one_of_hint: '
                      '"hashes|name-at-least-one" jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json'],
         'exact_mappings': ['unified_cyber_ontology:File'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema requires at least one of hashes or name.'],
         'slot_usage': {'contains_refs': {'comments': ['jsonschema_minItems: "1"'],
                                          'name': 'contains_refs'},
                        'id': {'name': 'id',
                               'pattern': '^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'name': 'type', 'pattern': '^file$'}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    hashes: Optional[HashesType] = Field(default=None, description="""Specifies a dictionary of hashes for the file or content.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExternalReference', 'Artifact', 'File', 'X509Certificate'],
         'exact_mappings': ['unified_cyber_ontology:hashes']} })
    size: Optional[int] = Field(default=None, description="""Object size in bytes.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['File']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    name_enc: Optional[str] = Field(default=None, description="""Encoding for a name field.""", json_schema_extra = { "linkml_meta": {'domain_of': ['File']} })
    magic_number_hex: Optional[str] = Field(default=None, description="""Hex magic number.""", json_schema_extra = { "linkml_meta": {'domain_of': ['File']} })
    mime_type: Optional[str] = Field(default=None, description="""MIME type value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Artifact', 'File']} })
    ctime: Optional[datetime ] = Field(default=None, description="""Creation time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory', 'File']} })
    mtime: Optional[datetime ] = Field(default=None, description="""Last modification time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory', 'File']} })
    atime: Optional[datetime ] = Field(default=None, description="""Last access time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Directory', 'File']} })
    parent_directory_ref: Optional[str] = Field(default=None, description="""Parent directory reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['File']} })
    contains_refs: Optional[list[str]] = Field(default=None, description="""References to contained objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Directory', 'File', 'ArchiveExt']} })
    content_ref: Optional[str] = Field(default=None, description="""Referenced content object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['File']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^file$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^file--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('name_enc')
    def pattern_name_enc(cls, v):
        pattern=re.compile(r"^[a-zA-Z0-9/\.+_:-]{2,250}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid name_enc format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid name_enc format: {v}"
            raise ValueError(err_msg)
        return v


class Ipv4Addr(CyberObservableObject):
    """
    The IPv4 Address Object represents one or more IPv4 addresses expressed using CIDR notation. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['unified_cyber_ontology:IPv4Address'],
         'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/ipv4-addr.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'belongs_to_refs': {'comments': ['jsonschema_minItems: "1"'],
                                            'name': 'belongs_to_refs'},
                        'id': {'name': 'id',
                               'pattern': '^ipv4-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'resolves_to_refs': {'comments': ['jsonschema_minItems: "1"'],
                                             'name': 'resolves_to_refs'},
                        'type': {'name': 'type', 'pattern': '^ipv4-addr$'},
                        'value': {'name': 'value',
                                  'pattern': '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(3[0-2]|[1-2][0-9]|[0-9]))?$',
                                  'required': True}}})

    value: str = Field(default=..., description="""Canonical string value for simple cyber observables.""", json_schema_extra = { "linkml_meta": {'domain_of': ['DomainName',
                       'EmailAddr',
                       'Ipv4Addr',
                       'Ipv6Addr',
                       'MacAddr',
                       'Url']} })
    resolves_to_refs: Optional[list[str]] = Field(default=None, description="""References this observable resolves to.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['DomainName', 'Ipv4Addr', 'Ipv6Addr']} })
    belongs_to_refs: Optional[list[str]] = Field(default=None, description="""References this observable belongs to.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Ipv4Addr', 'Ipv6Addr']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('value')
    def pattern_value(cls, v):
        pattern=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))?$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid value format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid value format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^ipv4-addr$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^ipv4-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class Ipv6Addr(CyberObservableObject):
    """
    The IPv6 Address Object represents one or more IPv6 addresses expressed using CIDR notation. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['unified_cyber_ontology:IPv6Address'],
         'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/ipv6-addr.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'belongs_to_refs': {'comments': ['jsonschema_minItems: "1"'],
                                            'name': 'belongs_to_refs'},
                        'id': {'name': 'id',
                               'pattern': '^ipv6-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'resolves_to_refs': {'comments': ['jsonschema_minItems: "1"'],
                                             'name': 'resolves_to_refs'},
                        'type': {'name': 'type', 'pattern': '^ipv6-addr$'},
                        'value': {'name': 'value', 'required': True}}})

    value: str = Field(default=..., description="""Canonical string value for simple cyber observables.""", json_schema_extra = { "linkml_meta": {'domain_of': ['DomainName',
                       'EmailAddr',
                       'Ipv4Addr',
                       'Ipv6Addr',
                       'MacAddr',
                       'Url']} })
    resolves_to_refs: Optional[list[str]] = Field(default=None, description="""References this observable resolves to.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['DomainName', 'Ipv4Addr', 'Ipv6Addr']} })
    belongs_to_refs: Optional[list[str]] = Field(default=None, description="""References this observable belongs to.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Ipv4Addr', 'Ipv6Addr']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^ipv6-addr$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^ipv6-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class MacAddr(CyberObservableObject):
    """
    The MAC Address Object represents a single Media Access Control (MAC) address. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['unified_cyber_ontology:MACAddress'],
         'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/mac-addr.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'name': 'type', 'pattern': '^mac-addr$'},
                        'value': {'name': 'value',
                                  'pattern': '^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$',
                                  'required': True}}})

    value: str = Field(default=..., description="""Canonical string value for simple cyber observables.""", json_schema_extra = { "linkml_meta": {'domain_of': ['DomainName',
                       'EmailAddr',
                       'Ipv4Addr',
                       'Ipv6Addr',
                       'MacAddr',
                       'Url']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('value')
    def pattern_value(cls, v):
        pattern=re.compile(r"^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid value format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid value format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^mac-addr$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^mac-addr--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class Mutex(CyberObservableObject):
    """
    The Mutex Object represents the properties of a mutual exclusion (mutex) object. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/mutex.json'],
         'exact_mappings': ['unified_cyber_ontology:Mutex'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^mutex--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^mutex$'}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^mutex$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^mutex--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class NetworkTraffic(CyberObservableObject):
    """
    The Network Traffic Object represents arbitrary network traffic that originates from a source and is addressed to a destination. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf+oneOf validator_hint: '
                      'enforce-network-traffic-endpoint-and-active-rules '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/network-traffic.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema requires at least one of src_ref or dst_ref and '
                   'constrains is_active/end combinations.'],
         'slot_usage': {'encapsulates_refs': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'encapsulates_refs'},
                        'id': {'name': 'id',
                               'pattern': '^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'protocols': {'comments': ['jsonschema_minItems: "1"'],
                                      'name': 'protocols',
                                      'required': True},
                        'type': {'name': 'type', 'pattern': '^network-traffic$'}}})

    start: Optional[datetime ] = Field(default=None, description="""Network traffic start time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    end: Optional[datetime ] = Field(default=None, description="""Network traffic end time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    src_ref: Optional[str] = Field(default=None, description="""Source observable reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    dst_ref: Optional[str] = Field(default=None, description="""Destination observable reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    src_port: Optional[int] = Field(default=None, description="""Source port number.""", ge=0, le=65535, json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    dst_port: Optional[int] = Field(default=None, description="""Destination port number.""", ge=0, le=65535, json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    protocols: list[str] = Field(default=..., description="""Network protocols list.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['NetworkTraffic'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    src_byte_count: Optional[int] = Field(default=None, description="""Bytes sent source to destination.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    dst_byte_count: Optional[int] = Field(default=None, description="""Bytes sent destination to source.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    src_packets: Optional[int] = Field(default=None, description="""Source-to-destination packet count.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    dst_packets: Optional[int] = Field(default=None, description="""Destination-to-source packet count.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    ipfix: Optional[str] = Field(default=None, description="""Specifies any IP Flow Information Export (IPFIX) data for the traffic.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    src_payload_ref: Optional[str] = Field(default=None, description="""Source payload reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    dst_payload_ref: Optional[str] = Field(default=None, description="""Destination payload reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    encapsulates_refs: Optional[list[str]] = Field(default=None, description="""Referenced encapsulated network-traffic objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['NetworkTraffic']} })
    encapsulated_by_ref: Optional[str] = Field(default=None, description="""Referencing encapsulating network-traffic object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    is_active: Optional[bool] = Field(default=None, description="""Indicates traffic is still active.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NetworkTraffic']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^network-traffic$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^network-traffic--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class Process(CyberObservableObject):
    """
    The Process Object represents common properties of an instance of a computer program as executed on an operating system. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf validator_hint: '
                      'process-any-of-field-presence jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/process.json'],
         'exact_mappings': ['unified_cyber_ontology:Process'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema uses anyOf presence constraints across many optional '
                   'process fields.'],
         'slot_usage': {'child_refs': {'comments': ['jsonschema_minItems: "1"'],
                                       'name': 'child_refs'},
                        'id': {'name': 'id',
                               'pattern': '^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'opened_connection_refs': {'comments': ['jsonschema_minItems: '
                                                                '"1"'],
                                                   'name': 'opened_connection_refs'},
                        'type': {'name': 'type', 'pattern': '^process$'}}})

    is_hidden: Optional[bool] = Field(default=None, description="""Specifies whether the process is hidden.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    pid: Optional[int] = Field(default=None, description="""Specifies the Process ID, or PID, of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    created_time: Optional[datetime ] = Field(default=None, description="""Process creation time.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    cwd: Optional[str] = Field(default=None, description="""Current working directory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    command_line: Optional[str] = Field(default=None, description="""Process command line.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    environment_variables: Optional[str] = Field(default=None, description="""Environment variable payload.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    opened_connection_refs: Optional[list[str]] = Field(default=None, description="""Referenced opened network connections.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Process']} })
    creator_user_ref: Optional[str] = Field(default=None, description="""Creating user reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process', 'WindowsRegistryKey']} })
    image_ref: Optional[str] = Field(default=None, description="""Process image file reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    parent_ref: Optional[str] = Field(default=None, description="""Parent process reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process']} })
    child_refs: Optional[list[str]] = Field(default=None, description="""Child process references.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Process']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^process$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^process--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class Software(CyberObservableObject):
    """
    The Software Object represents high-level properties associated with software, including software products. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/software.json'],
         'exact_mappings': ['unified_cyber_ontology:Software'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'languages': {'comments': ['jsonschema_minItems: "1"'],
                                      'name': 'languages'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^software$'}}})

    cpe: Optional[str] = Field(default=None, description="""Specifies the Common Platform Enumeration (CPE) entry for the software.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Software']} })
    swid: Optional[str] = Field(default=None, description="""SWID tag value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Software']} })
    languages: Optional[list[str]] = Field(default=None, description="""Specifies the languages supported by the software.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Software']} })
    vendor: Optional[str] = Field(default=None, description="""Vendor name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Software']} })
    version: Optional[str] = Field(default=None, description="""Version string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExtensionDefinition',
                       'Software',
                       'PdfExt',
                       'X509Certificate',
                       'MalwareAnalysis']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^software$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^software--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class Url(CyberObservableObject):
    """
    The URL Object represents the properties of a uniform resource locator (URL). 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'close_mappings': ['unified_cyber_ontology:URL'],
         'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/url.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^url--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'name': 'type', 'pattern': '^url$'},
                        'value': {'name': 'value', 'required': True}}})

    value: str = Field(default=..., description="""Canonical string value for simple cyber observables.""", json_schema_extra = { "linkml_meta": {'domain_of': ['DomainName',
                       'EmailAddr',
                       'Ipv4Addr',
                       'Ipv6Addr',
                       'MacAddr',
                       'Url']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^url$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^url--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class UserAccount(CyberObservableObject):
    """
    The User Account Object represents an instance of any type of user account, including but not limited to operating system, device, messaging service, and social media platform accounts. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf validator_hint: '
                      'user-account-at-least-one-property jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/user-account.json'],
         'exact_mappings': ['unified_cyber_ontology:UserAccount'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema defines anyOf presence constraints requiring at least '
                   'one key identity/account property.'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'name': 'type', 'pattern': '^user-account$'}}})

    user_id: Optional[str] = Field(default=None, description="""User account identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    credential: Optional[str] = Field(default=None, description="""Account credential value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    account_login: Optional[str] = Field(default=None, description="""Account login string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    account_type: Optional[Union[AccountTypeOv, str]] = Field(default=None, description="""Account type value (account-type-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AccountTypeOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: AccountTypeOv'],
         'domain_of': ['UserAccount'],
         'exact_mappings': ['unified_cyber_ontology:accountType']} })
    display_name: Optional[str] = Field(default=None, description="""Human-friendly display name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailAddr', 'UserAccount', 'WindowsServiceExt']} })
    is_service_account: Optional[bool] = Field(default=None, description="""Service account flag.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    is_privileged: Optional[bool] = Field(default=None, description="""Privileged account flag.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    can_escalate_privs: Optional[bool] = Field(default=None, description="""Privilege escalation capability flag.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    is_disabled: Optional[bool] = Field(default=None, description="""Disabled account flag.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    account_created: Optional[datetime ] = Field(default=None, description="""Account creation timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    account_expires: Optional[datetime ] = Field(default=None, description="""Account expiration timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    credential_last_changed: Optional[datetime ] = Field(default=None, description="""Credential last-changed timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    account_first_login: Optional[datetime ] = Field(default=None, description="""Account first-login timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    account_last_login: Optional[datetime ] = Field(default=None, description="""Account last-login timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UserAccount']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^user-account$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^user-account--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class WindowsRegistryValue(CommonSchemaComponent):
    """
    Structured value entry under a Windows registry key.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf validator_hint: '
                      'windows-registry-value-at-least-one-field jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/windows-registry-key.json#/definitions/windows-registry-value-type'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'notes': ['Source JSON schema uses anyOf to require at least one of name, '
                   'data, or data_type.']})

    registry_value_name: Optional[str] = Field(default=None, description="""Registry value name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsRegistryValue']} })
    registry_value_data: Optional[str] = Field(default=None, description="""Registry value data content.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsRegistryValue']} })
    registry_value_data_type: Optional[RegistryDataTypeEnum] = Field(default=None, description="""Registry value data type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsRegistryValue']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class MimePartType(CommonSchemaComponent):
    """
    Specifies a component of a multi-part email body as defined in the email-message observable.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: oneOf validator_hint: '
                      'enforce-mime-part-body-or-body-raw-ref-exclusive '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/email-message.json#/definitions/mime-part-type'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'notes': ['JSON Schema requires exactly one of body (for text/* content) or '
                   'body_raw_ref (for non-text content).']})

    body: Optional[str] = Field(default=None, description="""Specifies a string containing the email body. This field MAY only be used if is_multipart is false.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage', 'MimePartType']} })
    body_raw_ref: Optional[str] = Field(default=None, description="""Reference to an Artifact or File object for non-textual MIME part content.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MimePartType']} })
    content_type: Optional[str] = Field(default=None, description="""Specifies the value of the 'Content-Type' header of the email message.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage', 'MimePartType']} })
    content_disposition: Optional[str] = Field(default=None, description="""Value of the Content-Disposition header field of the MIME part.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MimePartType']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class WindowsProcessExt(CommonSchemaComponent):
    """
    The Windows Process extension specifies properties specific to Windows processes. Used as the value of the 'windows-process-ext' key in a Process object's extensions dictionary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: windows-process-ext stix_parent_type: '
                      'process jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/process.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables']})

    aslr_enabled: Optional[bool] = Field(default=None, description="""Specifies whether Address Space Layout Randomization (ASLR) is enabled for the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsProcessExt']} })
    dep_enabled: Optional[bool] = Field(default=None, description="""Specifies whether Data Execution Prevention (DEP) is enabled for the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsProcessExt']} })
    priority: Optional[str] = Field(default=None, description="""Specifies the current priority class of the process in Windows.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsProcessExt']} })
    owner_sid: Optional[str] = Field(default=None, description="""Specifies the Security ID (SID) value of the owner of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsProcessExt']} })
    window_title: Optional[str] = Field(default=None, description="""Specifies the title of the main window of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsProcessExt']} })
    startup_info: Optional[str] = Field(default=None, description="""Specifies the STARTUP_INFO struct used by the process.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-startup-info-dictionary'],
         'domain_of': ['WindowsProcessExt']} })
    integrity_level: Optional[WindowsIntegrityLevelEnum] = Field(default=None, description="""Specifies the Windows integrity level of the process.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsProcessExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class WindowsServiceExt(CommonSchemaComponent):
    """
    The Windows Service extension specifies properties specific to Windows services. Used as the value of the 'windows-service-ext' key in a Process object's extensions dictionary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: windows-service-ext stix_parent_type: '
                      'process jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/process.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'descriptions': {'comments': ['jsonschema_minItems: "1"'],
                                         'name': 'descriptions'},
                        'service_dll_refs': {'comments': ['jsonschema_minItems: "1"'],
                                             'name': 'service_dll_refs'}}})

    service_name: Optional[str] = Field(default=None, description="""Specifies the name of the service.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsServiceExt']} })
    descriptions: Optional[list[str]] = Field(default=None, description="""Specifies the descriptions defined for the service.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['WindowsServiceExt']} })
    display_name: Optional[str] = Field(default=None, description="""Human-friendly display name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailAddr', 'UserAccount', 'WindowsServiceExt']} })
    group_name: Optional[str] = Field(default=None, description="""Specifies the name of the load ordering group of which the service is a member.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsServiceExt']} })
    start_type: Optional[WindowsServiceStartEnum] = Field(default=None, description="""Specifies the start options defined for the service.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsServiceExt']} })
    service_dll_refs: Optional[list[str]] = Field(default=None, description="""Specifies the DLLs loaded by the service.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['WindowsServiceExt']} })
    service_type: Optional[WindowsServiceTypeEnum] = Field(default=None, description="""Specifies the type of the service.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsServiceExt']} })
    service_status: Optional[WindowsServiceStatusEnum] = Field(default=None, description="""Specifies the current status of the service.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsServiceExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class HttpRequestExt(CommonSchemaComponent):
    """
    The HTTP Request extension specifies a default extension for capturing network traffic properties specific to HTTP requests. Used as the value of the 'http-request-ext' key in a NetworkTraffic object's extensions dictionary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: http-request-ext stix_parent_type: '
                      'network-traffic jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/network-traffic.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'request_method': {'name': 'request_method', 'required': True},
                        'request_value': {'name': 'request_value', 'required': True}}})

    request_method: str = Field(default=..., description="""Specifies the HTTP method portion of the HTTP request line.""", json_schema_extra = { "linkml_meta": {'domain_of': ['HttpRequestExt']} })
    request_value: str = Field(default=..., description="""Specifies the value (typically a resource path) portion of the HTTP request line.""", json_schema_extra = { "linkml_meta": {'domain_of': ['HttpRequestExt']} })
    request_version: Optional[str] = Field(default=None, description="""Specifies the HTTP version portion of the HTTP request line.""", json_schema_extra = { "linkml_meta": {'domain_of': ['HttpRequestExt']} })
    request_header: Optional[str] = Field(default=None, description="""Specifies all of the HTTP header fields that may be found in the HTTP client request.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-http-request-header-dictionary'],
         'domain_of': ['HttpRequestExt']} })
    message_body_length: Optional[int] = Field(default=None, description="""Specifies the length of the HTTP message body, if included in the request.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['HttpRequestExt']} })
    message_body_data_ref: Optional[str] = Field(default=None, description="""Specifies the data contained in the HTTP message body, as a reference to an Artifact object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['HttpRequestExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class IcmpExt(CommonSchemaComponent):
    """
    The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP. Used as the value of the 'icmp-ext' key in a NetworkTraffic object's extensions dictionary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: icmp-ext stix_parent_type: network-traffic '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/network-traffic.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'icmp_code_hex': {'name': 'icmp_code_hex', 'required': True},
                        'icmp_type_hex': {'name': 'icmp_type_hex', 'required': True}}})

    icmp_type_hex: str = Field(default=..., description="""Specifies the ICMP type byte.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'], 'domain_of': ['IcmpExt']} })
    icmp_code_hex: str = Field(default=..., description="""Specifies the ICMP code byte.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'], 'domain_of': ['IcmpExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class SocketExt(CommonSchemaComponent):
    """
    The Socket extension specifies a default extension for capturing network traffic properties specific to network sockets. Used as the value of the 'socket-ext' key in a NetworkTraffic object's extensions dictionary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: socket-ext stix_parent_type: '
                      'network-traffic jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/network-traffic.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'address_family': {'name': 'address_family', 'required': True}}})

    address_family: NetworkSocketAddressFamilyEnum = Field(default=..., description="""Specifies the address family (AF_*) that the socket is configured for.""", json_schema_extra = { "linkml_meta": {'domain_of': ['SocketExt']} })
    is_blocking: Optional[bool] = Field(default=None, description="""Specifies whether the socket is in blocking mode.""", json_schema_extra = { "linkml_meta": {'domain_of': ['SocketExt']} })
    is_listening: Optional[bool] = Field(default=None, description="""Specifies whether the socket is in listening mode.""", json_schema_extra = { "linkml_meta": {'domain_of': ['SocketExt']} })
    socket_options: Optional[str] = Field(default=None, description="""Specifies any options (SO_*) that may be used by the socket.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-socket-options-dictionary'],
         'domain_of': ['SocketExt']} })
    socket_type: Optional[NetworkSocketTypeEnum] = Field(default=None, description="""Specifies the type of the socket.""", json_schema_extra = { "linkml_meta": {'domain_of': ['SocketExt']} })
    socket_descriptor: Optional[int] = Field(default=None, description="""Specifies the socket file descriptor value associated with the socket.""", json_schema_extra = { "linkml_meta": {'domain_of': ['SocketExt']} })
    socket_handle: Optional[int] = Field(default=None, description="""Specifies the handle or inode value associated with the socket.""", json_schema_extra = { "linkml_meta": {'domain_of': ['SocketExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class TcpExt(CommonSchemaComponent):
    """
    The TCP extension specifies a default extension for capturing network traffic properties specific to TCP. Used as the value of the 'tcp-ext' key in a NetworkTraffic object's extensions dictionary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: tcp-ext stix_parent_type: network-traffic '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/network-traffic.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables']})

    src_flags_hex: Optional[str] = Field(default=None, description="""Specifies the source TCP flags, as the union of all TCP flags observed between the start and end of the session.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'], 'domain_of': ['TcpExt']} })
    dst_flags_hex: Optional[str] = Field(default=None, description="""Specifies the destination TCP flags, as the union of all TCP flags observed between the start and end of the session.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'], 'domain_of': ['TcpExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class UnixAccountExt(CommonSchemaComponent):
    """
    The Unix Account extension specifies a default extension for capturing the additional information for an account on a Unix system. Used as the value of the 'unix-account-ext' key in a UserAccount object's extensions dictionary.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: unix-account-ext stix_parent_type: '
                      'user-account jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/user-account.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'groups': {'comments': ['jsonschema_minItems: "1"'],
                                   'name': 'groups'}}})

    gid: Optional[int] = Field(default=None, description="""Specifies the primary group ID of the account.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UnixAccountExt']} })
    groups: Optional[list[str]] = Field(default=None, description="""Specifies a list of names of groups the account is a member of.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['UnixAccountExt']} })
    home_dir: Optional[str] = Field(default=None, description="""Specifies the home directory of the account.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UnixAccountExt']} })
    shell: Optional[str] = Field(default=None, description="""Specifies the account's command shell.""", json_schema_extra = { "linkml_meta": {'domain_of': ['UnixAccountExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class X509V3ExtensionsType(CommonSchemaComponent):
    """
    Specifies any standard X.509 v3 extensions that may be used in the certificate.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/x509-certificate.json#/definitions/x509-v3-extensions-type'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common']})

    basic_constraints: Optional[str] = Field(default=None, description="""Specifies a multi-valued extension which indicates whether a certificate is a CA certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    name_constraints: Optional[str] = Field(default=None, description="""Specifies a namespace within which all subject names in subsequent certificates in a certification path must be located.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    policy_constraints: Optional[str] = Field(default=None, description="""Specifies any constraints on path validation for certificates issued to CAs.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    key_usage: Optional[str] = Field(default=None, description="""Specifies a multi-valued extension consisting of a list of names of the permitted key usages.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    extended_key_usage: Optional[str] = Field(default=None, description="""Specifies a list of usages indicating purposes for which the certificate public key can be used.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    subject_key_identifier: Optional[str] = Field(default=None, description="""Specifies the identifier that provides a means of identifying certificates that contain a particular public key.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    authority_key_identifier: Optional[str] = Field(default=None, description="""Specifies the identifier that provides a means of identifying the public key corresponding to the private key used to sign a certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    subject_alternative_name: Optional[str] = Field(default=None, description="""Specifies the additional identities to be bound to the subject of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    issuer_alternative_name: Optional[str] = Field(default=None, description="""Specifies the additional identities to be bound to the issuer of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    subject_directory_attributes: Optional[str] = Field(default=None, description="""Specifies the identification attributes (e.g., nationality) of the subject.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    crl_distribution_points: Optional[str] = Field(default=None, description="""Specifies how CRL information is obtained.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    inhibit_any_policy: Optional[str] = Field(default=None, description="""Specifies the number of additional certificates that may appear in the path before anyPolicy is no longer permitted.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    private_key_usage_period_not_before: Optional[datetime ] = Field(default=None, description="""Specifies the date on which the validity period begins for the private key, if it is different from the validity period of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    private_key_usage_period_not_after: Optional[datetime ] = Field(default=None, description="""Specifies the date on which the validity period ends for the private key, if it is different from the validity period of the certificate.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    certificate_policies: Optional[str] = Field(default=None, description="""Specifies a sequence of one or more policy information terms, each of which consists of an object identifier (OID) and optional qualifiers.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    policy_mappings: Optional[str] = Field(default=None, description="""Specifies one or more pairs of OIDs; each pair includes an issuerDomainPolicy and a subjectDomainPolicy.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509V3ExtensionsType']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class AlternateDataStreamType(CommonSchemaComponent):
    """
    Specifies properties of an NTFS alternate data stream.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json#/definitions/ntfs-ext/properties/alternate_data_streams/items'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['common'],
         'slot_usage': {'ads_name': {'name': 'ads_name', 'required': True}}})

    ads_name: str = Field(default=..., description="""Specifies the name of the alternate data stream.""", json_schema_extra = { "linkml_meta": {'domain_of': ['AlternateDataStreamType']} })
    ads_size: Optional[int] = Field(default=None, description="""Specifies the size of the alternate data stream, in bytes.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['AlternateDataStreamType']} })
    ads_hashes: Optional[HashesType] = Field(default=None, description="""Specifies a dictionary of hashes for the alternate data stream.""", json_schema_extra = { "linkml_meta": {'domain_of': ['AlternateDataStreamType']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class NtfsExt(CommonSchemaComponent):
    """
    The NTFS extension specifies a default extension for capturing properties specific to the storage of the file on the NTFS file system.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: ntfs-ext stix_parent_type: file '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables']})

    sid: Optional[str] = Field(default=None, description="""Specifies the security ID (SID) value assigned to the file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NtfsExt']} })
    alternate_data_streams: Optional[list[AlternateDataStreamType]] = Field(default=None, description="""Specifies a list of NTFS alternate data streams that exist for the file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['NtfsExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class RasterImageExt(CommonSchemaComponent):
    """
    The Raster Image extension specifies a default extension for capturing properties specific to raster image files.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: raster-image-ext stix_parent_type: file '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables']})

    image_height: Optional[int] = Field(default=None, description="""Specifies the height of the image in the image file, in pixels.""", json_schema_extra = { "linkml_meta": {'domain_of': ['RasterImageExt']} })
    image_width: Optional[int] = Field(default=None, description="""Specifies the width of the image in the image file, in pixels.""", json_schema_extra = { "linkml_meta": {'domain_of': ['RasterImageExt']} })
    bits_per_pixel: Optional[int] = Field(default=None, description="""Specifies the sum of bits used for each color channel in the image in the image file, and thus the total number of pixels used for expressing the color depth of the image.""", json_schema_extra = { "linkml_meta": {'domain_of': ['RasterImageExt']} })
    exif_tags: Optional[str] = Field(default=None, description="""Specifies the set of EXIF tags found in the image file, as a dictionary. Each key/value pair in the dictionary represents the name/value of a single EXIF tag.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-exif-tags-dictionary'],
         'domain_of': ['RasterImageExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class PdfExt(CommonSchemaComponent):
    """
    The PDF extension specifies a default extension for capturing properties specific to PDF files.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: pdf-ext stix_parent_type: file '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables']})

    version: Optional[str] = Field(default=None, description="""Version string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExtensionDefinition',
                       'Software',
                       'PdfExt',
                       'X509Certificate',
                       'MalwareAnalysis']} })
    is_optimized: Optional[bool] = Field(default=None, description="""Specifies whether the PDF file has been optimized.""", json_schema_extra = { "linkml_meta": {'domain_of': ['PdfExt']} })
    document_info_dict: Optional[str] = Field(default=None, description="""Specifies details of the PDF document information dictionary (DID), which includes properties like the document creation date and producer, as a dictionary.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-pdf-document-info-dictionary'],
         'domain_of': ['PdfExt']} })
    pdfid0: Optional[str] = Field(default=None, description="""Specifies the first file identifier found for the PDF file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['PdfExt']} })
    pdfid1: Optional[str] = Field(default=None, description="""Specifies the second file identifier found for the PDF file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['PdfExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class ArchiveExt(CommonSchemaComponent):
    """
    The Archive File extension specifies a default extension for capturing properties specific to archive files, such as ZIP.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: archive-ext stix_parent_type: file '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'contains_refs': {'comments': ['jsonschema_minItems: "1"'],
                                          'name': 'contains_refs',
                                          'required': True}}})

    contains_refs: list[str] = Field(default=..., description="""References to contained objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Directory', 'File', 'ArchiveExt']} })
    comment: Optional[str] = Field(default=None, description="""Specifies a comment included as part of the archive file.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ArchiveExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class WindowsPESection(CommonSchemaComponent):
    """
    The Windows PE Section type specifies metadata about a PE file section.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json#/definitions/windows-pe-section'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'pe_section_name': {'name': 'pe_section_name',
                                            'required': True}}})

    pe_section_name: str = Field(default=..., description="""Specifies the name of the PE section.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPESection']} })
    pe_section_size: Optional[int] = Field(default=None, description="""Specifies the size of the PE section, in bytes.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPESection']} })
    entropy: Optional[float] = Field(default=None, description="""Specifies the calculated entropy for the section, as calculated using the Shannon algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPESection']} })
    pe_section_hashes: Optional[HashesType] = Field(default=None, description="""Specifies any hashes computed over the section.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPESection']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class WindowsPEOptionalHeaderType(CommonSchemaComponent):
    """
    The Windows PE Optional Header type represents the properties of the PE optional header. At least one property from this type MUST be included.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: minProperties=1 jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json#/definitions/windows-pe-optional-header-type'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema requires at least one property (minProperties=1).']})

    magic_hex: Optional[str] = Field(default=None, description="""Specifies the unsigned integer that indicates the type of the PE binary (e.g. PE32 or PE32+).""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'],
         'domain_of': ['WindowsPEOptionalHeaderType']} })
    major_linker_version: Optional[int] = Field(default=None, description="""Specifies the linker major version number.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    minor_linker_version: Optional[int] = Field(default=None, description="""Specifies the linker minor version number.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_code: Optional[int] = Field(default=None, description="""Specifies the size of the code (text) section. If there are multiple such sections, this refers to the sum of the sizes of each section.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_initialized_data: Optional[int] = Field(default=None, description="""Specifies the size of the initialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_uninitialized_data: Optional[int] = Field(default=None, description="""Specifies the size of the uninitialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    address_of_entry_point: Optional[int] = Field(default=None, description="""Specifies the address of the entry point relative to the image base when the executable is loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    base_of_code: Optional[int] = Field(default=None, description="""Specifies the address that is relative to the image base of the beginning-of-code section when it is loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    base_of_data: Optional[int] = Field(default=None, description="""Specifies the address that is relative to the image base of the beginning-of-data section when it is loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    image_base: Optional[int] = Field(default=None, description="""Specifies the preferred address of the first byte of the image when it is loaded into memory.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    section_alignment: Optional[int] = Field(default=None, description="""Specifies the alignment (in bytes) of PE sections when they are loaded into memory.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    file_alignment: Optional[int] = Field(default=None, description="""Specifies the factor (in bytes) that is used to align the raw data of sections in the image file.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    major_os_version: Optional[int] = Field(default=None, description="""Specifies the major version number of the required operating system.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    minor_os_version: Optional[int] = Field(default=None, description="""Specifies the minor version number of the required operating system.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    major_image_version: Optional[int] = Field(default=None, description="""Specifies the major version number of the image.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    minor_image_version: Optional[int] = Field(default=None, description="""Specifies the minor version number of the image.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    major_subsystem_version: Optional[int] = Field(default=None, description="""Specifies the major version number of the subsystem.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    minor_subsystem_version: Optional[int] = Field(default=None, description="""Specifies the minor version number of the subsystem.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    win32_version_value_hex: Optional[str] = Field(default=None, description="""Specifies the reserved win32 version value.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'],
         'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_image: Optional[int] = Field(default=None, description="""Specifies the size, in bytes, of the image, including all headers, as the image is loaded in memory.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_headers: Optional[int] = Field(default=None, description="""Specifies the combined size of the MS-DOS, PE header, and section headers, rounded to a multiple of the value specified in file_alignment.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    checksum_hex: Optional[str] = Field(default=None, description="""Specifies the checksum of the PE binary.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'],
         'domain_of': ['WindowsPEOptionalHeaderType']} })
    subsystem_hex: Optional[str] = Field(default=None, description="""Specifies the subsystem (e.g., GUI, device driver, etc.) that is required to run this image.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'],
         'domain_of': ['WindowsPEOptionalHeaderType']} })
    dll_characteristics_hex: Optional[str] = Field(default=None, description="""Specifies the flags that characterize the PE binary.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'],
         'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_stack_reserve: Optional[int] = Field(default=None, description="""Specifies the size of the stack to reserve.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_stack_commit: Optional[int] = Field(default=None, description="""Specifies the size of the stack to commit.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_heap_reserve: Optional[int] = Field(default=None, description="""Specifies the size of the local heap space to reserve.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    size_of_heap_commit: Optional[int] = Field(default=None, description="""Specifies the size of the local heap space to commit.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    loader_flags_hex: Optional[str] = Field(default=None, description="""Specifies the reserved loader flags.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'],
         'domain_of': ['WindowsPEOptionalHeaderType']} })
    number_of_rva_and_sizes: Optional[int] = Field(default=None, description="""Specifies the number of data-directory entries in the remainder of the optional header.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsPEOptionalHeaderType']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class PEBinaryExt(CommonSchemaComponent):
    """
    The Windows PE Binary File extension specifies a default extension for capturing properties specific to Windows portable executable (PE) files.
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['stix_extension_key: windows-pebinary-ext stix_parent_type: file '
                      'jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/file.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'slot_usage': {'pe_type': {'name': 'pe_type', 'required': True},
                        'sections': {'comments': ['jsonschema_minItems: "1"'],
                                     'name': 'sections'}}})

    pe_type: Union[WindowsPEBinaryTypeOv, str] = Field(default=..., description="""Specifies the type of the PE binary. Open Vocabulary - windows-pebinary-type-ov""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'WindowsPEBinaryTypeOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: WindowsPEBinaryTypeOv'],
         'domain_of': ['PEBinaryExt']} })
    imphash: Optional[str] = Field(default=None, description="""Specifies the special import hash, or 'imphash', calculated for the PE binary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['PEBinaryExt']} })
    machine_hex: Optional[str] = Field(default=None, description="""Specifies the type of target machine.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'], 'domain_of': ['PEBinaryExt']} })
    number_of_sections: Optional[int] = Field(default=None, description="""Specifies the number of sections in the PE binary, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['PEBinaryExt']} })
    time_date_stamp: Optional[datetime ] = Field(default=None, description="""Specifies the time when the PE binary was created. The timestamp value MUST BE precise to the second.""", json_schema_extra = { "linkml_meta": {'domain_of': ['PEBinaryExt']} })
    pointer_to_symbol_table_hex: Optional[str] = Field(default=None, description="""Specifies the file offset of the COFF symbol table.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'], 'domain_of': ['PEBinaryExt']} })
    number_of_symbols: Optional[int] = Field(default=None, description="""Specifies the number of entries in the symbol table of the PE binary, as a non-negative integer.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['PEBinaryExt']} })
    size_of_optional_header: Optional[int] = Field(default=None, description="""Specifies the size of the optional header of the PE binary.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['PEBinaryExt']} })
    characteristics_hex: Optional[str] = Field(default=None, description="""Specifies the flags that indicate the file's characteristics.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_format: hex'], 'domain_of': ['PEBinaryExt']} })
    file_header_hashes: Optional[HashesType] = Field(default=None, description="""Specifies any hashes that were computed for the file header.""", json_schema_extra = { "linkml_meta": {'domain_of': ['PEBinaryExt']} })
    optional_header: Optional[WindowsPEOptionalHeaderType] = Field(default=None, description="""Specifies the PE optional header of the PE binary.""", json_schema_extra = { "linkml_meta": {'domain_of': ['PEBinaryExt']} })
    sections: Optional[list[WindowsPESection]] = Field(default=None, description="""Specifies metadata about the sections in the PE file.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['PEBinaryExt']} })
    id: Optional[str] = Field(default=None, description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: Optional[str] = Field(default=None, description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })


class WindowsRegistryKey(CyberObservableObject):
    """
    The Registry Key Object represents the properties of a Windows registry key. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf validator_hint: '
                      'registry-key-presence-requirements jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/windows-registry-key.json'],
         'exact_mappings': ['unified_cyber_ontology:WindowsRegistryKey'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema uses anyOf for key/value/modified/creator/subkey '
                   'presence requirements.'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^windows-registry-key--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'key': {'name': 'key',
                                'pattern': '^(?!HKLM|HKCC|HKCR|HKCU|HKU|hklm|hkcc|hkcr|hkcu|hku).*$'},
                        'type': {'name': 'type', 'pattern': '^windows-registry-key$'}}})

    key: Optional[str] = Field(default=None, description="""Registry key path.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsRegistryKey']} })
    values: Optional[list[WindowsRegistryValue]] = Field(default=None, description="""Registry value entries.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsRegistryKey']} })
    modified_time: Optional[datetime ] = Field(default=None, description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsRegistryKey']} })
    creator_user_ref: Optional[str] = Field(default=None, description="""Creating user reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Process', 'WindowsRegistryKey']} })
    number_of_subkeys: Optional[int] = Field(default=None, description="""Number of registry subkeys.""", json_schema_extra = { "linkml_meta": {'domain_of': ['WindowsRegistryKey']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('key')
    def pattern_key(cls, v):
        pattern=re.compile(r"^(?!HKLM|HKCC|HKCR|HKCU|HKU|hklm|hkcc|hkcr|hkcu|hku).*$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid key format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid key format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^windows-registry-key$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^windows-registry-key--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class X509Certificate(CyberObservableObject):
    """
    The X509 Certificate Object represents the properties of an X.509 certificate. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf validator_hint: '
                      'x509-at-least-one-detail-field jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/observables/x509-certificate.json'],
         'exact_mappings': ['unified_cyber_ontology:X509Certificate'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['observables'],
         'notes': ['JSON Schema defines anyOf requiring at least one certificate '
                   'detail field.'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^x509-certificate--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'name': 'type', 'pattern': '^x509-certificate$'}}})

    is_self_signed: Optional[bool] = Field(default=None, description="""Specifies whether the certificate is self-signed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    hashes: Optional[HashesType] = Field(default=None, description="""Specifies a dictionary of hashes for the file or content.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExternalReference', 'Artifact', 'File', 'X509Certificate'],
         'exact_mappings': ['unified_cyber_ontology:hashes']} })
    version: Optional[str] = Field(default=None, description="""Version string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExtensionDefinition',
                       'Software',
                       'PdfExt',
                       'X509Certificate',
                       'MalwareAnalysis']} })
    serial_number: Optional[str] = Field(default=None, description="""X509 serial number.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    signature_algorithm: Optional[str] = Field(default=None, description="""X509 signature algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    issuer: Optional[str] = Field(default=None, description="""Certificate issuer.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    validity_not_before: Optional[datetime ] = Field(default=None, description="""Certificate validity start.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    validity_not_after: Optional[datetime ] = Field(default=None, description="""Certificate validity end.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    subject: Optional[str] = Field(default=None, description="""Subject value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['EmailMessage', 'X509Certificate']} })
    subject_public_key_algorithm: Optional[str] = Field(default=None, description="""Subject public key algorithm.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    subject_public_key_modulus: Optional[str] = Field(default=None, description="""Subject public key modulus.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    subject_public_key_exponent: Optional[int] = Field(default=None, description="""Subject public key exponent.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    x509_v3_extensions: Optional[X509V3ExtensionsType] = Field(default=None, description="""X509 v3 extensions payload.""", json_schema_extra = { "linkml_meta": {'domain_of': ['X509Certificate']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: Optional[SpecVersionEnum] = Field(default=None, description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    defanged: Optional[bool] = Field(default=None, description="""Defines whether or not the data contained within the object has been defanged.""", json_schema_extra = { "linkml_meta": {'domain_of': ['CyberObservableCore']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^x509-certificate$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^x509-certificate--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v


class AttackPattern(StixDomainObject):
    """
    Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/attack-pattern.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'related_mappings': ['unified_cyber_ontology:Action'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^attack-pattern--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'kill_chain_phases': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'kill_chain_phases'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^attack-pattern$'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Alternative names for the object.""", json_schema_extra = { "linkml_meta": {'domain_of': ['AttackPattern',
                       'Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Tool']} })
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(default=None, description="""Kill chain phases associated with this object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Indicator',
                       'Infrastructure',
                       'Malware',
                       'Tool']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^attack-pattern$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^attack-pattern--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Campaign(StixDomainObject):
    """
    A Campaign is a grouping of adversary behavior that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/campaign.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'related_mappings': ['unified_cyber_ontology:Grouping'],
         'slot_usage': {'aliases': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'aliases'},
                        'id': {'name': 'id',
                               'pattern': '^campaign--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^campaign$'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Alternative names for the object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Tool']} })
    first_seen: Optional[datetime ] = Field(default=None, description="""First time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    last_seen: Optional[datetime ] = Field(default=None, description="""Last time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    objective: Optional[str] = Field(default=None, description="""Campaign objective.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^campaign$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^campaign--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class CourseOfAction(StixDomainObject):
    """
    A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/course-of-action.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'narrow_mappings': ['unified_cyber_ontology:Action'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^course-of-action--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^course-of-action$'}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^course-of-action$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^course-of-action--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Grouping(StixDomainObject):
    """
    A Grouping object explicitly asserts that the referenced STIX Objects have a shared content. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/grouping.json'],
         'exact_mappings': ['unified_cyber_ontology:Grouping'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'context': {'name': 'context', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^grouping--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_refs': {'comments': ['jsonschema_minItems: "1"'],
                                        'name': 'object_refs',
                                        'required': True},
                        'type': {'name': 'type', 'pattern': '^grouping$'}}})

    context: str = Field(default=..., description="""Grouping context classifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Grouping']} })
    object_refs: list[str] = Field(default=..., description="""Referenced STIX objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Grouping', 'Note', 'ObservedData', 'Opinion', 'Report'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^grouping$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^grouping--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Identity(StixDomainObject):
    """
    Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, or groups. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/identity.json'],
         'exact_mappings': ['unified_cyber_ontology:Identity'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'roles': {'comments': ['jsonschema_minItems: "1"'],
                                  'name': 'roles'},
                        'sectors': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'sectors'},
                        'type': {'name': 'type', 'pattern': '^identity$'}}})

    roles: Optional[list[Union[ThreatActorRoleOv, str]]] = Field(default=None, description="""Open-vocabulary threat actor roles.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ThreatActorRoleOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Identity', 'ThreatActor'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    identity_class: Optional[Union[IdentityClassOv, str]] = Field(default=None, description="""Identity class value (identity-class-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'IdentityClassOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: IdentityClassOv'],
         'domain_of': ['Identity'],
         'related_mappings': ['unified_cyber_ontology:Identity']} })
    sectors: Optional[list[Union[IndustrySectorOv, str]]] = Field(default=None, description="""Identity sector values (industry-sector-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'IndustrySectorOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Identity'],
         'related_mappings': ['unified_cyber_ontology:Location']} })
    contact_information: Optional[str] = Field(default=None, description="""Identity contact information.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Identity']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^identity$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Incident(StixDomainObject):
    """
    The Incident object in STIX 2.1 is a stub, to be expanded in future STIX 2 releases. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/incident.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^incident--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^incident$'}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^incident$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^incident--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Indicator(StixDomainObject):
    """
    Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/indicator.json '
                      'source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/pattern_grammar/STIXPattern.g4 '
                      'validator_hint: validate-indicator-pattern-with-antlr'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'notes': ['pattern syntax and parse validity are enforced by the STIX pattern '
                   'ANTLR grammar.'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'indicator_types': {'comments': ['jsonschema_minItems: "1"'],
                                            'name': 'indicator_types'},
                        'kill_chain_phases': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'kill_chain_phases'},
                        'pattern': {'name': 'pattern', 'required': True},
                        'pattern_type': {'name': 'pattern_type', 'required': True},
                        'type': {'name': 'type', 'pattern': '^indicator$'},
                        'valid_from': {'name': 'valid_from', 'required': True}}})

    indicator_types: Optional[list[Union[IndicatorTypeOv, str]]] = Field(default=None, description="""This field is an Open Vocabulary that specifies the type of indicator. Open vocab - indicator-type-ov""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'IndicatorTypeOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Indicator']} })
    pattern: str = Field(default=..., description="""The detection pattern for this indicator.""", json_schema_extra = { "linkml_meta": {'comments': ['validator_hint: parse-with-stix-pattern-antlr-grammar'],
         'domain_of': ['Indicator'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    pattern_type: Union[PatternTypeOv, str] = Field(default=..., description="""The type of pattern used in this indicator.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'PatternTypeOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: PatternTypeOv'],
         'domain_of': ['Indicator'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    pattern_version: Optional[str] = Field(default=None, description="""The version of the pattern that is used.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Indicator'],
         'related_mappings': ['unified_cyber_ontology:specVersion']} })
    valid_from: datetime  = Field(default=..., description="""The time from which this indicator should be considered valuable intelligence.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Indicator']} })
    valid_until: Optional[datetime ] = Field(default=None, description="""The time at which this indicator should no longer be considered valuable intelligence.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Indicator']} })
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(default=None, description="""Kill chain phases associated with this object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Indicator',
                       'Infrastructure',
                       'Malware',
                       'Tool']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('pattern_type')
    def pattern_pattern_type(cls, v):
        pattern=re.compile(r"^[a-z0-9\-]+$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid pattern_type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid pattern_type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^indicator$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Infrastructure(StixDomainObject):
    """
    Infrastructure objects describe systems, software services, and associated physical or virtual resources. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/infrastructure.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'aliases': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'aliases'},
                        'id': {'name': 'id',
                               'pattern': '^infrastructure--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'infrastructure_types': {'comments': ['jsonschema_minItems: '
                                                              '"1"'],
                                                 'name': 'infrastructure_types'},
                        'kill_chain_phases': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'kill_chain_phases'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^infrastructure$'}}})

    infrastructure_types: Optional[list[Union[InfrastructureTypeOv, str]]] = Field(default=None, description="""Open-vocabulary infrastructure categories (infrastructure-type-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'InfrastructureTypeOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Infrastructure']} })
    aliases: Optional[list[str]] = Field(default=None, description="""Alternative names for the object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Tool']} })
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(default=None, description="""Kill chain phases associated with this object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Indicator',
                       'Infrastructure',
                       'Malware',
                       'Tool']} })
    first_seen: Optional[datetime ] = Field(default=None, description="""First time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    last_seen: Optional[datetime ] = Field(default=None, description="""Last time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^infrastructure$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^infrastructure--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class IntrusionSet(StixDomainObject):
    """
    An Intrusion Set is a grouped set of adversary behavior and resources with common properties that is believed to be orchestrated by a single organization. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/intrusion-set.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'aliases': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'aliases'},
                        'goals': {'comments': ['jsonschema_minItems: "1"'],
                                  'name': 'goals'},
                        'id': {'name': 'id',
                               'pattern': '^intrusion-set--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'secondary_motivations': {'comments': ['jsonschema_minItems: '
                                                               '"1"'],
                                                  'name': 'secondary_motivations'},
                        'type': {'name': 'type', 'pattern': '^intrusion-set$'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Alternative names for the object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Tool']} })
    first_seen: Optional[datetime ] = Field(default=None, description="""First time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    last_seen: Optional[datetime ] = Field(default=None, description="""Last time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    goals: Optional[list[str]] = Field(default=None, description="""Threat actor goals.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['IntrusionSet', 'ThreatActor'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    resource_level: Optional[Union[AttackResourceLevelOv, str]] = Field(default=None, description="""Threat actor resource level (attack-resource-level-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AttackResourceLevelOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: AttackResourceLevelOv'],
         'domain_of': ['IntrusionSet', 'ThreatActor']} })
    primary_motivation: Optional[Union[AttackMotivationOv, str]] = Field(default=None, description="""Primary motivation (attack-motivation-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AttackMotivationOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: AttackMotivationOv'],
         'domain_of': ['IntrusionSet', 'ThreatActor']} })
    secondary_motivations: Optional[list[Union[AttackMotivationOv, str]]] = Field(default=None, description="""Secondary motivations (attack-motivation-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AttackMotivationOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['IntrusionSet', 'ThreatActor']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^intrusion-set$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^intrusion-set--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Location(StixDomainObject):
    """
    A Location represents a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf+oneOf validator_hint: '
                      'enforce-location-coordinate-and-region-rules jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/location.json'],
         'exact_mappings': ['unified_cyber_ontology:Location'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'notes': ['JSON Schema requires one of region, country, or latitude+longitude '
                   'and constrains precision usage.'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^location--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'type': {'name': 'type', 'pattern': '^location$'}}})

    latitude: Optional[float] = Field(default=None, description="""Latitude in decimal degrees.""", ge=-90, le=90, json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    longitude: Optional[float] = Field(default=None, description="""Longitude in decimal degrees.""", ge=-180, le=180, json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    precision: Optional[float] = Field(default=None, description="""Coordinate precision in meters.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    region: Optional[str] = Field(default=None, description="""Geographic region.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    country: Optional[str] = Field(default=None, description="""Country name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    administrative_area: Optional[str] = Field(default=None, description="""Sub-national administrative area.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    city: Optional[str] = Field(default=None, description="""City name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    street_address: Optional[str] = Field(default=None, description="""Street address.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    postal_code: Optional[str] = Field(default=None, description="""Postal code.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Location']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^location$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^location--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class MalwareAnalysis(StixDomainObject):
    """
    Malware Analysis captures the metadata and results of a particular analysis performed (static or dynamic) on the malware instance or family. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: anyOf validator_hint: '
                      'malware-analysis-result-or-analysis-sco-refs jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/malware-analysis.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'notes': ['JSON Schema requires either result or analysis_sco_refs.'],
         'slot_usage': {'analysis_sco_refs': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'analysis_sco_refs'},
                        'host_vm_ref': {'name': 'host_vm_ref',
                                        'pattern': '^software--'},
                        'id': {'name': 'id',
                               'pattern': '^malware-analysis--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'installed_software_refs': {'comments': ['jsonschema_minItems: '
                                                                 '"1"'],
                                                    'name': 'installed_software_refs',
                                                    'pattern': '^software--'},
                        'modules': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'modules'},
                        'operating_system_ref': {'name': 'operating_system_ref',
                                                 'pattern': '^software--'},
                        'product': {'name': 'product', 'required': True},
                        'sample_ref': {'name': 'sample_ref',
                                       'pattern': '^(artifact--|file--|network-traffic--)'},
                        'type': {'name': 'type', 'pattern': '^malware-analysis$'}}})

    product: str = Field(default=..., description="""Malware analysis product name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    version: Optional[str] = Field(default=None, description="""Version string.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ExtensionDefinition',
                       'Software',
                       'PdfExt',
                       'X509Certificate',
                       'MalwareAnalysis']} })
    configuration_version: Optional[str] = Field(default=None, description="""Malware analysis product configuration version.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    modules: Optional[list[str]] = Field(default=None, description="""Malware analysis module names.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['MalwareAnalysis']} })
    analysis_engine_version: Optional[str] = Field(default=None, description="""Malware analysis engine version.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    analysis_definition_version: Optional[str] = Field(default=None, description="""Malware analysis definition version.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    submitted: Optional[datetime ] = Field(default=None, description="""Malware sample submission timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    analysis_started: Optional[datetime ] = Field(default=None, description="""Analysis start timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    analysis_ended: Optional[datetime ] = Field(default=None, description="""Analysis end timestamp.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    result_name: Optional[str] = Field(default=None, description="""Analysis result name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    result: Optional[Union[MalwareAvResultOv, str]] = Field(default=None, description="""Malware analysis result value (malware-av-result-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'MalwareAvResultOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: MalwareAvResultOv'],
         'domain_of': ['MalwareAnalysis']} })
    host_vm_ref: Optional[str] = Field(default=None, description="""Host VM software reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    operating_system_ref: Optional[str] = Field(default=None, description="""Operating system software reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    installed_software_refs: Optional[list[str]] = Field(default=None, description="""Installed software references.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['MalwareAnalysis']} })
    analysis_sco_refs: Optional[list[str]] = Field(default=None, description="""Referenced SCOs captured in analysis.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['MalwareAnalysis']} })
    sample_ref: Optional[str] = Field(default=None, description="""Analysis subject sample reference.""", json_schema_extra = { "linkml_meta": {'domain_of': ['MalwareAnalysis']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('host_vm_ref')
    def pattern_host_vm_ref(cls, v):
        pattern=re.compile(r"^software--")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid host_vm_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid host_vm_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('operating_system_ref')
    def pattern_operating_system_ref(cls, v):
        pattern=re.compile(r"^software--")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid operating_system_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid operating_system_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('installed_software_refs')
    def pattern_installed_software_refs(cls, v):
        pattern=re.compile(r"^software--")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid installed_software_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid installed_software_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('sample_ref')
    def pattern_sample_ref(cls, v):
        pattern=re.compile(r"^(artifact--|file--|network-traffic--)")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid sample_ref format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid sample_ref format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^malware-analysis$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^malware-analysis--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Malware(StixDomainObject):
    """
    Malware is a type of TTP that is also known as malicious code and malicious software, refers to a program that is inserted into a system, usually covertly, with the intent of compromising the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or of otherwise annoying or disrupting the victim. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: oneOf validator_hint: '
                      'enforce-malware-family-name-constraint jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/malware.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'narrow_mappings': ['unified_cyber_ontology:Software'],
         'notes': ['JSON Schema includes oneOf semantics where name is required when '
                   'is_family=true.'],
         'slot_usage': {'aliases': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'aliases'},
                        'architecture_execution_envs': {'comments': ['jsonschema_minItems: '
                                                                     '"1"'],
                                                        'name': 'architecture_execution_envs'},
                        'capabilities': {'comments': ['jsonschema_minItems: "1"'],
                                         'name': 'capabilities'},
                        'id': {'name': 'id',
                               'pattern': '^malware--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'implementation_languages': {'comments': ['jsonschema_minItems: '
                                                                  '"1"'],
                                                     'name': 'implementation_languages'},
                        'is_family': {'name': 'is_family', 'required': True},
                        'kill_chain_phases': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'kill_chain_phases'},
                        'malware_types': {'comments': ['jsonschema_minItems: "1"'],
                                          'name': 'malware_types'},
                        'operating_system_refs': {'comments': ['jsonschema_minItems: '
                                                               '"1"'],
                                                  'name': 'operating_system_refs',
                                                  'pattern': '^software--'},
                        'sample_refs': {'comments': ['jsonschema_minItems: "1"'],
                                        'name': 'sample_refs'},
                        'type': {'name': 'type', 'pattern': '^malware$'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Alternative names for the object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Tool']} })
    first_seen: Optional[datetime ] = Field(default=None, description="""First time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    last_seen: Optional[datetime ] = Field(default=None, description="""Last time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    operating_system_refs: Optional[list[str]] = Field(default=None, description="""References to software operating systems.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Malware']} })
    architecture_execution_envs: Optional[list[Union[ProcessorArchitectureOv, str]]] = Field(default=None, description="""Open-vocabulary processor architectures (processor-architecture-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ProcessorArchitectureOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Malware']} })
    implementation_languages: Optional[list[Union[ImplementationLanguageOv, str]]] = Field(default=None, description="""Open-vocabulary implementation languages (implementation-language-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ImplementationLanguageOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Malware']} })
    capabilities: Optional[list[Union[MalwareCapabilityOv, str]]] = Field(default=None, description="""Open-vocabulary malware capabilities (malware-capabilities-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'MalwareCapabilityOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Malware']} })
    sample_refs: Optional[list[str]] = Field(default=None, description="""References to associated sample artifacts/files.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Malware']} })
    malware_types: Optional[list[Union[MalwareTypeOv, str]]] = Field(default=None, description="""Open-vocabulary malware types (malware-type-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'MalwareTypeOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Malware']} })
    is_family: bool = Field(default=..., description="""Indicates if malware object is a family.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Malware']} })
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(default=None, description="""Kill chain phases associated with this object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Indicator',
                       'Infrastructure',
                       'Malware',
                       'Tool']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('operating_system_refs')
    def pattern_operating_system_refs(cls, v):
        pattern=re.compile(r"^software--")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid operating_system_refs format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid operating_system_refs format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^malware$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^malware--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Note(StixDomainObject):
    """
    A Note is a comment or note containing informative text to help explain the context of one or more STIX Objects (SDOs or SROs) or to provide additional analysis that is not contained in the original object. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/note.json'],
         'exact_mappings': ['unified_cyber_ontology:Note'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'authors': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'authors'},
                        'content': {'name': 'content', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^note--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_refs': {'comments': ['jsonschema_minItems: "1"'],
                                        'name': 'object_refs',
                                        'required': True},
                        'type': {'name': 'type', 'pattern': '^note$'}}})

    abstract: Optional[str] = Field(default=None, description="""Brief summary text.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Note']} })
    content: str = Field(default=..., description="""Main text content payload.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Note']} })
    authors: Optional[list[str]] = Field(default=None, description="""Author list.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Note', 'Opinion']} })
    object_refs: list[str] = Field(default=..., description="""Referenced STIX objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Grouping', 'Note', 'ObservedData', 'Opinion', 'Report'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^note$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^note--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class ObservedData(StixDomainObject):
    """
    Observed data conveys information that was observed on systems and networks, such as log data or network traffic, using the Cyber Observable specification. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: oneOf validator_hint: '
                      'observed-data-objects-or-object-refs jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/observed-data.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'notes': ['JSON Schema requires one of objects or object_refs.'],
         'slot_usage': {'first_observed': {'name': 'first_observed', 'required': True},
                        'id': {'name': 'id',
                               'pattern': '^observed-data--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'last_observed': {'name': 'last_observed', 'required': True},
                        'number_observed': {'name': 'number_observed',
                                            'required': True},
                        'object_refs': {'comments': ['jsonschema_minItems: "1"'],
                                        'name': 'object_refs'},
                        'type': {'name': 'type', 'pattern': '^observed-data$'}}})

    first_observed: datetime  = Field(default=..., description="""Start of observation window.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ObservedData']} })
    last_observed: datetime  = Field(default=..., description="""End of observation window.""", json_schema_extra = { "linkml_meta": {'domain_of': ['ObservedData']} })
    number_observed: int = Field(default=..., description="""Number of observations.""", ge=1, le=999999999, json_schema_extra = { "linkml_meta": {'domain_of': ['ObservedData']} })
    objects: Optional[list[CyberObservableObject]] = Field(default=None, description="""Embedded cyber observable dictionary payload.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties+oneOf validator_hint: '
                      'validate-observed-data-objects-dictionary'],
         'domain_of': ['ObservedData'],
         'notes': ['JSON Schema models this as a pattern-keyed dictionary of SCO '
                   'objects.']} })
    object_refs: Optional[list[str]] = Field(default=None, description="""Referenced STIX objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Grouping', 'Note', 'ObservedData', 'Opinion', 'Report'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^observed-data$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^observed-data--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Opinion(StixDomainObject):
    """
    An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity and captures the level of agreement or disagreement using a fixed scale. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/opinion.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'authors': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'authors'},
                        'id': {'name': 'id',
                               'pattern': '^opinion--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'object_refs': {'comments': ['jsonschema_minItems: "1"'],
                                        'name': 'object_refs',
                                        'required': True},
                        'opinion': {'name': 'opinion', 'required': True},
                        'type': {'name': 'type', 'pattern': '^opinion$'}}})

    explanation: Optional[str] = Field(default=None, description="""Explanation text for an opinion.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Opinion']} })
    authors: Optional[list[str]] = Field(default=None, description="""Author list.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Note', 'Opinion']} })
    object_refs: list[str] = Field(default=..., description="""Referenced STIX objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Grouping', 'Note', 'ObservedData', 'Opinion', 'Report'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    opinion: OpinionEnum = Field(default=..., description="""Opinion value.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Opinion']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^opinion$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^opinion--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Report(StixDomainObject):
    """
    Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and related details. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/report.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'related_mappings': ['unified_cyber_ontology:Note'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^report--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'object_refs': {'comments': ['jsonschema_minItems: "1"'],
                                        'name': 'object_refs',
                                        'required': True},
                        'published': {'name': 'published', 'required': True},
                        'report_types': {'comments': ['jsonschema_minItems: "1"'],
                                         'name': 'report_types'},
                        'type': {'name': 'type', 'pattern': '^report$'}}})

    report_types: Optional[list[Union[ReportTypeOv, str]]] = Field(default=None, description="""Open-vocabulary report categories.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ReportTypeOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Report'],
         'related_mappings': ['unified_cyber_ontology:tag']} })
    published: datetime  = Field(default=..., description="""Timestamp when a report was published.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Report']} })
    object_refs: list[str] = Field(default=..., description="""Referenced STIX objects.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Grouping', 'Note', 'ObservedData', 'Opinion', 'Report'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^report$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^report--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class ThreatActor(StixDomainObject):
    """
    Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/threat-actor.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'narrow_mappings': ['unified_cyber_ontology:Identity'],
         'slot_usage': {'aliases': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'aliases'},
                        'goals': {'comments': ['jsonschema_minItems: "1"'],
                                  'name': 'goals'},
                        'id': {'name': 'id',
                               'pattern': '^threat-actor--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'personal_motivations': {'comments': ['jsonschema_minItems: '
                                                              '"1"'],
                                                 'name': 'personal_motivations'},
                        'roles': {'comments': ['jsonschema_minItems: "1"'],
                                  'name': 'roles'},
                        'secondary_motivations': {'comments': ['jsonschema_minItems: '
                                                               '"1"'],
                                                  'name': 'secondary_motivations'},
                        'threat_actor_types': {'comments': ['jsonschema_minItems: "1"'],
                                               'name': 'threat_actor_types'},
                        'type': {'name': 'type', 'pattern': '^threat-actor$'}}})

    threat_actor_types: Optional[list[Union[ThreatActorTypeOv, str]]] = Field(default=None, description="""Open-vocabulary threat actor categories.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ThreatActorTypeOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['ThreatActor'],
         'related_mappings': ['unified_cyber_ontology:tag']} })
    aliases: Optional[list[str]] = Field(default=None, description="""Alternative names for the object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Tool']} })
    roles: Optional[list[Union[ThreatActorRoleOv, str]]] = Field(default=None, description="""Open-vocabulary threat actor roles.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ThreatActorRoleOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Identity', 'ThreatActor'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    goals: Optional[list[str]] = Field(default=None, description="""Threat actor goals.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['IntrusionSet', 'ThreatActor'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    first_seen: Optional[datetime ] = Field(default=None, description="""First time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    last_seen: Optional[datetime ] = Field(default=None, description="""Last time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    sophistication: Optional[Union[ThreatActorSophisticationOv, str]] = Field(default=None, description="""Threat actor sophistication level.""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ThreatActorSophisticationOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: ThreatActorSophisticationOv'],
         'domain_of': ['ThreatActor']} })
    resource_level: Optional[Union[AttackResourceLevelOv, str]] = Field(default=None, description="""Threat actor resource level (attack-resource-level-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AttackResourceLevelOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: AttackResourceLevelOv'],
         'domain_of': ['IntrusionSet', 'ThreatActor']} })
    primary_motivation: Optional[Union[AttackMotivationOv, str]] = Field(default=None, description="""Primary motivation (attack-motivation-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AttackMotivationOv'}, {'range': 'string'}],
         'comments': ['open_vocabulary: AttackMotivationOv'],
         'domain_of': ['IntrusionSet', 'ThreatActor']} })
    secondary_motivations: Optional[list[Union[AttackMotivationOv, str]]] = Field(default=None, description="""Secondary motivations (attack-motivation-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AttackMotivationOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['IntrusionSet', 'ThreatActor']} })
    personal_motivations: Optional[list[Union[AttackMotivationOv, str]]] = Field(default=None, description="""Personal motivations of the threat actor (attack-motivation-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'AttackMotivationOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['ThreatActor']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^threat-actor$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^threat-actor--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Tool(StixDomainObject):
    """
    Tools are legitimate software that can be used by threat actors to perform attacks. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/tool.json'],
         'exact_mappings': ['unified_cyber_ontology:Tool'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'aliases': {'comments': ['jsonschema_minItems: "1"'],
                                    'name': 'aliases'},
                        'id': {'name': 'id',
                               'pattern': '^tool--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'kill_chain_phases': {'comments': ['jsonschema_minItems: "1"'],
                                              'name': 'kill_chain_phases'},
                        'name': {'name': 'name', 'required': True},
                        'tool_types': {'comments': ['jsonschema_minItems: "1"'],
                                       'name': 'tool_types'},
                        'type': {'name': 'type', 'pattern': '^tool$'}}})

    aliases: Optional[list[str]] = Field(default=None, description="""Alternative names for the object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Tool']} })
    tool_types: Optional[list[Union[ToolTypeOv, str]]] = Field(default=None, description="""Open-vocabulary tool categories (tool-type-ov).""", json_schema_extra = { "linkml_meta": {'any_of': [{'range': 'ToolTypeOv'}, {'range': 'string'}],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Tool']} })
    tool_version: Optional[str] = Field(default=None, description="""Version identifier for a tool.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Tool']} })
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(default=None, description="""Kill chain phases associated with this object.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['AttackPattern',
                       'Indicator',
                       'Infrastructure',
                       'Malware',
                       'Tool']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^tool$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^tool--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Vulnerability(StixDomainObject):
    """
    A Vulnerability is a mistake in software that can be directly used by a hacker to gain access to a system or network. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sdos/vulnerability.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sdos'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^vulnerability--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'name': {'name': 'name', 'required': True},
                        'type': {'name': 'type', 'pattern': '^vulnerability$'}}})

    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: str = Field(default=..., description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^vulnerability$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^vulnerability--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Relationship(StixRelationshipObject):
    """
    The Relationship object is used to link together two SDOs in order to describe how they are related to each other. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_rule: not validator_hint: '
                      'relationship-ref-prefix-exclusion jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sros/relationship.json'],
         'exact_mappings': ['unified_cyber_ontology:Relationship'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sros'],
         'notes': ['source_ref and target_ref cannot target relationship, sighting, '
                   'bundle, marking-definition, or language-content IDs.'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^relationship--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'relationship_type': {'name': 'relationship_type',
                                              'required': True},
                        'source_ref': {'name': 'source_ref', 'required': True},
                        'target_ref': {'name': 'target_ref', 'required': True},
                        'type': {'name': 'type', 'pattern': '^relationship$'}}})

    relationship_type: str = Field(default=..., description="""Name of the relationship type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Relationship'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    source_ref: str = Field(default=..., description="""Relationship source object reference.""", json_schema_extra = { "linkml_meta": {'comments': ['validator_hint: reject-disallowed-source-prefixes'],
         'domain_of': ['Relationship']} })
    target_ref: str = Field(default=..., description="""Relationship target object reference.""", json_schema_extra = { "linkml_meta": {'comments': ['validator_hint: reject-disallowed-target-prefixes'],
         'domain_of': ['Relationship']} })
    start_time: Optional[datetime ] = Field(default=None, description="""Start timestamp for temporal relationship validity.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Relationship']} })
    stop_time: Optional[datetime ] = Field(default=None, description="""End timestamp for temporal relationship validity.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Relationship']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('relationship_type')
    def pattern_relationship_type(cls, v):
        pattern=re.compile(r"^[a-z0-9\-]+$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid relationship_type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid relationship_type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^relationship$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^relationship--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


class Sighting(StixRelationshipObject):
    """
    A Sighting denotes the belief that something in CTI (e.g., an indicator, malware, tool, threat actor, etc.) was seen. 
    """
    linkml_meta: ClassVar[LinkMLMeta] = LinkMLMeta({'comments': ['jsonschema_source: '
                      'https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/schemas/sros/sighting.json'],
         'from_schema': 'https://w3id.org/lmodel/stix',
         'in_subset': ['sros'],
         'related_mappings': ['unified_cyber_ontology:Relationship'],
         'slot_usage': {'id': {'name': 'id',
                               'pattern': '^sighting--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'},
                        'sighting_of_ref': {'name': 'sighting_of_ref',
                                            'required': True},
                        'type': {'name': 'type', 'pattern': '^sighting$'},
                        'where_sighted_refs': {'comments': ['jsonschema_minItems: "1"'],
                                               'name': 'where_sighted_refs'}}})

    sighting_of_ref: str = Field(default=..., description="""Reference to the object being sighted.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Sighting']} })
    observed_data_refs: Optional[list[str]] = Field(default=None, description="""References to observed-data objects.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Sighting']} })
    where_sighted_refs: Optional[list[str]] = Field(default=None, description="""References to identities or locations where sighted.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'], 'domain_of': ['Sighting']} })
    first_seen: Optional[datetime ] = Field(default=None, description="""First time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    last_seen: Optional[datetime ] = Field(default=None, description="""Last time observed.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Campaign',
                       'Infrastructure',
                       'IntrusionSet',
                       'Malware',
                       'ThreatActor',
                       'Sighting']} })
    count: Optional[int] = Field(default=None, description="""This is an integer between 0 and 999,999,999 inclusive and represents the number of times the object was sighted.""", ge=0, json_schema_extra = { "linkml_meta": {'domain_of': ['Sighting']} })
    summary: Optional[bool] = Field(default=None, description="""The summary property indicates whether the Sighting should be considered summary data.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Sighting']} })
    type: str = Field(default=..., description="""STIX object type.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:state']} })
    spec_version: SpecVersionEnum = Field(default=..., description="""STIX specification version.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:specVersion'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    id: str = Field(default=..., description="""STIX object identifier.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'Bundle',
                       'Core',
                       'CyberObservableCore',
                       'ExtensionDefinition',
                       'LanguageContent',
                       'MarkingDefinition',
                       'File'],
         'related_mappings': ['unified_cyber_ontology:externalReference']} })
    created: datetime  = Field(default=..., description="""Creation timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectCreatedTime'],
         'domain_of': ['Core', 'MarkingDefinition'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    modified: datetime  = Field(default=..., description="""Modification timestamp.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:modifiedTime'],
         'domain_of': ['Core'],
         'notes': ['STIX core timestamps require millisecond precision.']} })
    created_by_ref: Optional[str] = Field(default=None, description="""ID of the object that created this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:createdBy'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    labels: Optional[list[str]] = Field(default=None, description="""Terms used to describe this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:tag'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core']} })
    revoked: Optional[bool] = Field(default=None, description="""Indicates whether this object has been revoked.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    confidence: Optional[int] = Field(default=None, description="""Confidence that the producer has in this data.""", ge=0, le=100, json_schema_extra = { "linkml_meta": {'domain_of': ['Core']} })
    lang: Optional[str] = Field(default=None, description="""Language of textual properties.""", json_schema_extra = { "linkml_meta": {'domain_of': ['Core', 'GranularMarking']} })
    external_references: Optional[list[ExternalReference]] = Field(default=None, description="""External references to non-STIX information.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:externalReference'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'MarkingDefinition']} })
    object_marking_refs: Optional[list[str]] = Field(default=None, description="""Marking definition references applied to this object.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:objectMarking'],
         'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition']} })
    granular_markings: Optional[list[GranularMarking]] = Field(default=None, description="""Granular markings that apply to selected content.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_minItems: "1"'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition'],
         'narrow_mappings': ['unified_cyber_ontology:objectMarking']} })
    extensions: Optional[list[str]] = Field(default=None, description="""Open-ended extension payloads.""", json_schema_extra = { "linkml_meta": {'comments': ['jsonschema_rule: patternProperties validator_hint: '
                      'validate-extension-keys-and-values'],
         'domain_of': ['Core', 'CyberObservableCore', 'MarkingDefinition', 'File'],
         'notes': ['JSON Schema uses patternProperties for extension keys; exact key '
                   'validation is delegated to validator tooling.'],
         'related_mappings': ['unified_cyber_ontology:hasFacet']} })
    name: Optional[str] = Field(default=None, description="""Human-readable name.""", json_schema_extra = { "linkml_meta": {'domain_of': ['StixEntity',
                       'ExtensionDefinition',
                       'MarkingDefinition',
                       'AutonomousSystem',
                       'File'],
         'exact_mappings': ['unified_cyber_ontology:name']} })
    description: Optional[str] = Field(default=None, description="""Human-readable description.""", json_schema_extra = { "linkml_meta": {'close_mappings': ['unified_cyber_ontology:description'],
         'domain_of': ['StixEntity', 'ExtensionDefinition', 'ExternalReference']} })

    @field_validator('type')
    def pattern_type(cls, v):
        pattern=re.compile(r"^sighting$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid type format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid type format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('id')
    def pattern_id(cls, v):
        pattern=re.compile(r"^sighting--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid id format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid id format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('created')
    def pattern_created(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid created format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid created format: {v}"
            raise ValueError(err_msg)
        return v

    @field_validator('modified')
    def pattern_modified(cls, v):
        pattern=re.compile(r"T\d{2}:\d{2}:\d{2}\.\d{3,}Z$")
        if isinstance(v, list):
            for element in v:
                if isinstance(element, str) and not pattern.match(element):
                    err_msg = f"Invalid modified format: {element}"
                    raise ValueError(err_msg)
        elif isinstance(v, str) and not pattern.match(v):
            err_msg = f"Invalid modified format: {v}"
            raise ValueError(err_msg)
        return v


# Model rebuild
# see https://pydantic-docs.helpmanual.io/usage/models/#rebuilding-a-model
StixEntity.model_rebuild()
CommonSchemaComponent.model_rebuild()
Bundle.model_rebuild()
Core.model_rebuild()
StixDomainObject.model_rebuild()
StixRelationshipObject.model_rebuild()
CyberObservableCore.model_rebuild()
CyberObservableObject.model_rebuild()
Dictionary.model_rebuild()
ExtensionDefinition.model_rebuild()
Extension.model_rebuild()
ExternalReference.model_rebuild()
GranularMarking.model_rebuild()
HashesType.model_rebuild()
Hex.model_rebuild()
Identifier.model_rebuild()
KillChainPhase.model_rebuild()
LanguageContent.model_rebuild()
MarkingDefinition.model_rebuild()
Properties.model_rebuild()
Timestamp.model_rebuild()
UrlRegex.model_rebuild()
Artifact.model_rebuild()
AutonomousSystem.model_rebuild()
Directory.model_rebuild()
DomainName.model_rebuild()
EmailAddr.model_rebuild()
EmailMessage.model_rebuild()
File.model_rebuild()
Ipv4Addr.model_rebuild()
Ipv6Addr.model_rebuild()
MacAddr.model_rebuild()
Mutex.model_rebuild()
NetworkTraffic.model_rebuild()
Process.model_rebuild()
Software.model_rebuild()
Url.model_rebuild()
UserAccount.model_rebuild()
WindowsRegistryValue.model_rebuild()
MimePartType.model_rebuild()
WindowsProcessExt.model_rebuild()
WindowsServiceExt.model_rebuild()
HttpRequestExt.model_rebuild()
IcmpExt.model_rebuild()
SocketExt.model_rebuild()
TcpExt.model_rebuild()
UnixAccountExt.model_rebuild()
X509V3ExtensionsType.model_rebuild()
AlternateDataStreamType.model_rebuild()
NtfsExt.model_rebuild()
RasterImageExt.model_rebuild()
PdfExt.model_rebuild()
ArchiveExt.model_rebuild()
WindowsPESection.model_rebuild()
WindowsPEOptionalHeaderType.model_rebuild()
PEBinaryExt.model_rebuild()
WindowsRegistryKey.model_rebuild()
X509Certificate.model_rebuild()
AttackPattern.model_rebuild()
Campaign.model_rebuild()
CourseOfAction.model_rebuild()
Grouping.model_rebuild()
Identity.model_rebuild()
Incident.model_rebuild()
Indicator.model_rebuild()
Infrastructure.model_rebuild()
IntrusionSet.model_rebuild()
Location.model_rebuild()
MalwareAnalysis.model_rebuild()
Malware.model_rebuild()
Note.model_rebuild()
ObservedData.model_rebuild()
Opinion.model_rebuild()
Report.model_rebuild()
ThreatActor.model_rebuild()
Tool.model_rebuild()
Vulnerability.model_rebuild()
Relationship.model_rebuild()
Sighting.model_rebuild()
