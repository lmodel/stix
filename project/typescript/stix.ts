export type StixObjectId = string;
export type StixCommonObjectId = string;
export type StixDomainObjectId = string;
export type StixRelationshipObjectId = string;
export type StixCyberObservableObjectId = string;
export type StixIdentityId = string;
export type StixMarkingDefinitionId = string;
export type StixLanguageContentId = string;
export type StixExtensionDefinitionId = string;
export type StixArtifactId = string;
export type StixAutonomousSystemId = string;
export type StixDirectoryId = string;
export type StixDomainNameId = string;
export type StixEmailAddressId = string;
export type StixEmailMessageId = string;
export type StixFileId = string;
export type StixIpv4AddressId = string;
export type StixIpv6AddressId = string;
export type StixMacAddressId = string;
export type StixMutexId = string;
export type StixNetworkTrafficId = string;
export type StixProcessId = string;
export type StixSoftwareId = string;
export type StixUrlId = string;
export type StixUserAccountId = string;
export type StixWindowsRegistryKeyId = string;
export type StixX509CertificateId = string;
export type StixAttackPatternId = string;
export type StixCampaignId = string;
export type StixCourseOfActionId = string;
export type StixGroupingId = string;
export type StixIncidentId = string;
export type StixIndicatorId = string;
export type StixInfrastructureId = string;
export type StixIntrusionSetId = string;
export type StixLocationId = string;
export type StixMalwareId = string;
export type StixMalwareAnalysisId = string;
export type StixNoteId = string;
export type StixObservedDataId = string;
export type StixOpinionId = string;
export type StixReportId = string;
export type StixThreatActorId = string;
export type StixToolId = string;
export type StixVulnerabilityId = string;
export type StixRelationshipId = string;
export type StixSightingId = string;
export type StixBundleId = string;
/**
* Types of user account. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixAccountType {
    
    facebook = "facebook",
    ldap = "ldap",
    nis = "nis",
    openid = "openid",
    radius = "radius",
    skype = "skype",
    tacacs = "tacacs",
    twitter = "twitter",
    unix = "unix",
    windows_local = "windows-local",
    windows_domain = "windows-domain",
};
/**
* Reasons, motivations or purposes behind an attack. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixAttackMotivation {
    
    accidental = "accidental",
    coercion = "coercion",
    dominance = "dominance",
    ideology = "ideology",
    notoriety = "notoriety",
    organizational_gain = "organizational-gain",
    personal_gain = "personal-gain",
    personal_satisfaction = "personal-satisfaction",
    revenge = "revenge",
    unpredictable = "unpredictable",
};
/**
* Levels of the resources that an actor may have, from an individual to a government. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixAttackResourceLevel {
    
    individual = "individual",
    club = "club",
    contest = "contest",
    team = "team",
    organization = "organization",
    government = "government",
};
/**
* Encryption algorithms for sharing defanged or confidential artifacts. A closed enumeration: no other value is valid.
*/
export enum StixEncryptionAlgorithm {
    
    AES_256_GCM = "AES-256-GCM",
    ChaCha20_Poly1305 = "ChaCha20-Poly1305",
    mime_type_indicated = "mime-type-indicated",
};
/**
* The kinds of extension that an extension definition can define. A closed enumeration: no other value is valid.
*/
export enum StixExtensionType {
    
    new_sdo = "new-sdo",
    new_sco = "new-sco",
    new_sro = "new-sro",
    property_extension = "property-extension",
    toplevel_property_extension = "toplevel-property-extension",
};
/**
* Contexts of a grouping. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixGroupingContext {
    
    suspicious_activity = "suspicious-activity",
    malware_analysis = "malware-analysis",
    unspecified = "unspecified",
};
/**
* Hash algorithms, as the keys of a hashes dictionary name them. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixHashAlgorithm {
    
    MD5 = "MD5",
    SHA_1 = "SHA-1",
    SHA_256 = "SHA-256",
    SHA_512 = "SHA-512",
    SHA3_256 = "SHA3-256",
    SHA3_512 = "SHA3-512",
    SSDEEP = "SSDEEP",
    TLSH = "TLSH",
};
/**
* Kinds of entity that an identity describes. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixIdentityClass {
    
    individual = "individual",
    group = "group",
    system = "system",
    organization = "organization",
    class = "class",
    unknown = "unknown",
};
/**
* Programming languages in which malware may be implemented. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixImplementationLanguage {
    
    applescript = "applescript",
    bash = "bash",
    c = "c",
    cPLUS_SIGNPLUS_SIGN = "c++",
    cNUMBER_SIGN = "c#",
    go = "go",
    java = "java",
    javascript = "javascript",
    lua = "lua",
    objective_c = "objective-c",
    perl = "perl",
    php = "php",
    powershell = "powershell",
    python = "python",
    ruby = "ruby",
    scala = "scala",
    swift = "swift",
    typescript = "typescript",
    visual_basic = "visual-basic",
    x86_32 = "x86-32",
    x86_64 = "x86-64",
};
/**
* High-level categories of indicator. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixIndicatorType {
    
    anomalous_activity = "anomalous-activity",
    anonymization = "anonymization",
    benign = "benign",
    compromised = "compromised",
    malicious_activity = "malicious-activity",
    attribution = "attribution",
    unknown = "unknown",
};
/**
* Industrial and commercial sectors. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixIndustrySector {
    
    agriculture = "agriculture",
    aerospace = "aerospace",
    automotive = "automotive",
    chemical = "chemical",
    commercial = "commercial",
    communications = "communications",
    construction = "construction",
    defense = "defense",
    education = "education",
    energy = "energy",
    entertainment = "entertainment",
    financial_services = "financial-services",
    government = "government",
    emergency_services = "emergency-services",
    government_local = "government-local",
    government_national = "government-national",
    government_public_services = "government-public-services",
    government_regional = "government-regional",
    healthcare = "healthcare",
    hospitality_leisure = "hospitality-leisure",
    infrastructure = "infrastructure",
    dams = "dams",
    nuclear = "nuclear",
    water = "water",
    insurance = "insurance",
    manufacturing = "manufacturing",
    mining = "mining",
    non_profit = "non-profit",
    pharmaceuticals = "pharmaceuticals",
    retail = "retail",
    technology = "technology",
    telecommunications = "telecommunications",
    transportation = "transportation",
    utilities = "utilities",
};
/**
* Types of infrastructure. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixInfrastructureType {
    
    amplification = "amplification",
    anonymization = "anonymization",
    botnet = "botnet",
    command_and_control = "command-and-control",
    control_system = "control-system",
    exfiltration = "exfiltration",
    firewall = "firewall",
    hosting_malware = "hosting-malware",
    hosting_target_lists = "hosting-target-lists",
    phishing = "phishing",
    reconnaissance = "reconnaissance",
    routers_switches = "routers-switches",
    staging = "staging",
    workstation = "workstation",
    unknown = "unknown",
};
/**
* Results of a scanner's or tool's analysis of malware. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixMalwareResult {
    
    malicious = "malicious",
    suspicious = "suspicious",
    benign = "benign",
    unknown = "unknown",
};
/**
* Capabilities that malware may have. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixMalwareCapability {
    
    accesses_remote_machines = "accesses-remote-machines",
    anti_debugging = "anti-debugging",
    anti_disassembly = "anti-disassembly",
    anti_emulation = "anti-emulation",
    anti_memory_forensics = "anti-memory-forensics",
    anti_sandbox = "anti-sandbox",
    anti_vm = "anti-vm",
    captures_input_peripherals = "captures-input-peripherals",
    captures_output_peripherals = "captures-output-peripherals",
    captures_system_state_data = "captures-system-state-data",
    cleans_traces_of_infection = "cleans-traces-of-infection",
    commits_fraud = "commits-fraud",
    communicates_with_c2 = "communicates-with-c2",
    compromises_data_availability = "compromises-data-availability",
    compromises_data_integrity = "compromises-data-integrity",
    compromises_system_availability = "compromises-system-availability",
    controls_local_machine = "controls-local-machine",
    degrades_security_software = "degrades-security-software",
    degrades_system_updates = "degrades-system-updates",
    determines_c2_server = "determines-c2-server",
    emails_spam = "emails-spam",
    escalates_privileges = "escalates-privileges",
    evades_av = "evades-av",
    exfiltrates_data = "exfiltrates-data",
    fingerprints_host = "fingerprints-host",
    hides_artifacts = "hides-artifacts",
    hides_executing_code = "hides-executing-code",
    infects_files = "infects-files",
    infects_remote_machines = "infects-remote-machines",
    installs_other_components = "installs-other-components",
    persists_after_system_reboot = "persists-after-system-reboot",
    prevents_artifact_access = "prevents-artifact-access",
    prevents_artifact_deletion = "prevents-artifact-deletion",
    probes_network_environment = "probes-network-environment",
    self_modifies = "self-modifies",
    steals_authentication_credentials = "steals-authentication-credentials",
    violates_system_operational_integrity = "violates-system-operational-integrity",
};
/**
* Types of malware. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixMalwareType {
    
    adware = "adware",
    backdoor = "backdoor",
    bot = "bot",
    bootkit = "bootkit",
    ddos = "ddos",
    downloader = "downloader",
    dropper = "dropper",
    exploit_kit = "exploit-kit",
    keylogger = "keylogger",
    ransomware = "ransomware",
    remote_access_trojan = "remote-access-trojan",
    resource_exploitation = "resource-exploitation",
    rogue_security_software = "rogue-security-software",
    rootkit = "rootkit",
    screen_capture = "screen-capture",
    spyware = "spyware",
    trojan = "trojan",
    unknown = "unknown",
    virus = "virus",
    webshell = "webshell",
    wiper = "wiper",
    worm = "worm",
};
/**
* Address families of a network socket. A closed enumeration: no other value is valid.
*/
export enum StixNetworkSocketAddressFamily {
    
    AF_UNSPEC = "AF_UNSPEC",
    AF_INET = "AF_INET",
    AF_IPX = "AF_IPX",
    AF_APPLETALK = "AF_APPLETALK",
    AF_NETBIOS = "AF_NETBIOS",
    AF_INET6 = "AF_INET6",
    AF_IRDA = "AF_IRDA",
    AF_BTH = "AF_BTH",
};
/**
* Types of network socket. A closed enumeration: no other value is valid.
*/
export enum StixNetworkSocketType {
    
    SOCK_STREAM = "SOCK_STREAM",
    SOCK_DGRAM = "SOCK_DGRAM",
    SOCK_RAW = "SOCK_RAW",
    SOCK_RDM = "SOCK_RDM",
    SOCK_SEQPACKET = "SOCK_SEQPACKET",
};
/**
* Degrees of agreement with the information in a STIX object, from disagreement to agreement. A closed enumeration: no other value is valid.
*/
export enum StixAgreement {
    
    strongly_disagree = "strongly-disagree",
    disagree = "disagree",
    neutral = "neutral",
    agree = "agree",
    strongly_agree = "strongly-agree",
};
/**
* Pattern languages in which an indicator's pattern may be written. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixPatternType {
    
    stix = "stix",
    pcre = "pcre",
    sigma = "sigma",
    snort = "snort",
    suricata = "suricata",
    yara = "yara",
};
/**
* Processor architectures. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixProcessorArchitecture {
    
    alpha = "alpha",
    arm = "arm",
    ia_64 = "ia-64",
    mips = "mips",
    powerpc = "powerpc",
    sparc = "sparc",
    x86 = "x86",
    x86_64 = "x86-64",
};
/**
* World regions, after the United Nations geoscheme (UNSD M49). An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixRegion {
    
    africa = "africa",
    eastern_africa = "eastern-africa",
    middle_africa = "middle-africa",
    northern_africa = "northern-africa",
    southern_africa = "southern-africa",
    western_africa = "western-africa",
    americas = "americas",
    caribbean = "caribbean",
    central_america = "central-america",
    latin_america_caribbean = "latin-america-caribbean",
    northern_america = "northern-america",
    south_america = "south-america",
    asia = "asia",
    central_asia = "central-asia",
    eastern_asia = "eastern-asia",
    southern_asia = "southern-asia",
    south_eastern_asia = "south-eastern-asia",
    western_asia = "western-asia",
    europe = "europe",
    eastern_europe = "eastern-europe",
    northern_europe = "northern-europe",
    southern_europe = "southern-europe",
    western_europe = "western-europe",
    oceania = "oceania",
    antarctica = "antarctica",
    australia_new_zealand = "australia-new-zealand",
    melanesia = "melanesia",
    micronesia = "micronesia",
    polynesia = "polynesia",
};
/**
* Primary subjects of a report. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixReportType {
    
    attack_pattern = "attack-pattern",
    campaign = "campaign",
    identity = "identity",
    indicator = "indicator",
    intrusion_set = "intrusion-set",
    malware = "malware",
    observed_data = "observed-data",
    threat_actor = "threat-actor",
    threat_report = "threat-report",
    tool = "tool",
    vulnerability = "vulnerability",
};
/**
* Types of threat actor. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixThreatActorType {
    
    activist = "activist",
    competitor = "competitor",
    crime_syndicate = "crime-syndicate",
    criminal = "criminal",
    hacker = "hacker",
    insider_accidental = "insider-accidental",
    insider_disgruntled = "insider-disgruntled",
    nation_state = "nation-state",
    sensationalist = "sensationalist",
    spy = "spy",
    terrorist = "terrorist",
    unknown = "unknown",
};
/**
* Roles that a threat actor may play. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixThreatActorRole {
    
    agent = "agent",
    director = "director",
    independent = "independent",
    infrastructure_architect = "infrastructure-architect",
    infrastructure_operator = "infrastructure-operator",
    malware_author = "malware-author",
    sponsor = "sponsor",
};
/**
* Skill levels of a threat actor. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixThreatActorSophistication {
    
    none = "none",
    minimal = "minimal",
    intermediate = "intermediate",
    advanced = "advanced",
    expert = "expert",
    innovator = "innovator",
    strategic = "strategic",
};
/**
* Categories of tool that may be used to perform attacks. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixToolType {
    
    denial_of_service = "denial-of-service",
    exploitation = "exploitation",
    information_gathering = "information-gathering",
    network_capture = "network-capture",
    credential_exploitation = "credential-exploitation",
    remote_access = "remote-access",
    vulnerability_scanning = "vulnerability-scanning",
    unknown = "unknown",
};
/**
* Windows integrity levels. A closed enumeration: no other value is valid.
*/
export enum StixWindowsIntegrityLevel {
    
    low = "low",
    medium = "medium",
    high = "high",
    system = "system",
};
/**
* Types of Windows PE binary. An open vocabulary: a slot that names it also takes any other string.
*/
export enum StixWindowsPeBinaryType {
    
    dll = "dll",
    exe = "exe",
    sys = "sys",
};
/**
* Data types of a Windows registry value. A closed enumeration: no other value is valid.
*/
export enum StixWindowsRegistryDatatype {
    
    REG_NONE = "REG_NONE",
    REG_SZ = "REG_SZ",
    REG_EXPAND_SZ = "REG_EXPAND_SZ",
    REG_BINARY = "REG_BINARY",
    REG_DWORD = "REG_DWORD",
    REG_DWORD_BIG_ENDIAN = "REG_DWORD_BIG_ENDIAN",
    REG_DWORD_LITTLE_ENDIAN = "REG_DWORD_LITTLE_ENDIAN",
    REG_LINK = "REG_LINK",
    REG_MULTI_SZ = "REG_MULTI_SZ",
    REG_RESOURCE_LIST = "REG_RESOURCE_LIST",
    REG_FULL_RESOURCE_DESCRIPTION = "REG_FULL_RESOURCE_DESCRIPTION",
    REG_RESOURCE_REQUIREMENTS_LIST = "REG_RESOURCE_REQUIREMENTS_LIST",
    REG_QWORD = "REG_QWORD",
    REG_INVALID_TYPE = "REG_INVALID_TYPE",
};
/**
* Start types of a Windows service. A closed enumeration: no other value is valid.
*/
export enum StixWindowsServiceStartType {
    
    SERVICE_AUTO_START = "SERVICE_AUTO_START",
    SERVICE_BOOT_START = "SERVICE_BOOT_START",
    SERVICE_DEMAND_START = "SERVICE_DEMAND_START",
    SERVICE_DISABLED = "SERVICE_DISABLED",
    SERVICE_SYSTEM_ALERT = "SERVICE_SYSTEM_ALERT",
};
/**
* Types of Windows service. A closed enumeration: no other value is valid.
*/
export enum StixWindowsServiceType {
    
    SERVICE_KERNEL_DRIVER = "SERVICE_KERNEL_DRIVER",
    SERVICE_FILE_SYSTEM_DRIVER = "SERVICE_FILE_SYSTEM_DRIVER",
    SERVICE_WIN32_OWN_PROCESS = "SERVICE_WIN32_OWN_PROCESS",
    SERVICE_WIN32_SHARE_PROCESS = "SERVICE_WIN32_SHARE_PROCESS",
};
/**
* Statuses of a Windows service. A closed enumeration: no other value is valid.
*/
export enum StixWindowsServiceStatus {
    
    SERVICE_CONTINUE_PENDING = "SERVICE_CONTINUE_PENDING",
    SERVICE_PAUSE_PENDING = "SERVICE_PAUSE_PENDING",
    SERVICE_PAUSED = "SERVICE_PAUSED",
    SERVICE_RUNNING = "SERVICE_RUNNING",
    SERVICE_START_PENDING = "SERVICE_START_PENDING",
    SERVICE_STOP_PENDING = "SERVICE_STOP_PENDING",
    SERVICE_STOPPED = "SERVICE_STOPPED",
};
/**
* The STIX versions that an object may declare. The JSON schemas accept 2.0 beside 2.1. A closed enumeration.
*/
export enum StixSpecVersion {
    
    number_2FULL_STOP0 = "2.0",
    number_2FULL_STOP1 = "2.1",
};
/**
* The four levels of the Traffic Light Protocol (TLP) that STIX 2.1 defines marking definitions for. A closed enumeration.
*/
export enum StixTlpLevel {
    
    white = "white",
    green = "green",
    amber = "amber",
    red = "red",
};
/**
* The marking definition types that STIX 2.1 defines, statement and tlp. A slot that names it also takes any other string, as the JSON schemas do.
*/
export enum StixMarkingDefinitionType {
    
    statement = "statement",
    tlp = "tlp",
};


/**
 * Any STIX object: the base of the domain, relationship and cyber-observable objects and of the meta objects.
 */
export interface StixObject {
    /** The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type. */
    id: string,
    /** The STIX type name of the object, such as attack-pattern. Each class pins its own. */
    type: string,
    /** The version of the STIX specification used to represent the object. */
    spec_version?: string,
    /** References to the marking definitions that apply to the object. */
    object_marking_refs?: StixMarkingDefinitionId[],
    /** The granular markings that apply to parts of the object. */
    granular_markings?: StixGranularMarking[],
    /** The object's extensions, as a dictionary keyed by extension name. */
    extensions?: StixExtensions,
}


/**
 * The base of the objects that carry STIX's common properties: the domain and relationship objects, language content and extension definitions.
 */
export interface StixCommonObject extends StixObject {
    /** A reference to the identity of the object's creator. */
    created_by_ref?: StixIdentityId,
    /** The time at which the object, or its first version, was created. */
    created: string,
    /** The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond. */
    modified: string,
    /** The revoked property indicates whether the object has been revoked. */
    revoked?: boolean,
    /** The labels property specifies a set of terms used to describe this object. */
    labels?: string[],
    /** Identifies the confidence that the creator has in the correctness of their data. */
    confidence?: number,
    /** The language of the text content, as an RFC 5646 language code. */
    lang?: string,
    /** References to non-STIX information about the object. */
    external_references?: StixExternalReference[],
}


/**
 * A STIX Domain Object (SDO): a higher-level concept of cyber threat intelligence, such as an attack pattern, a malware family or a threat actor.
 */
export interface StixDomainObject extends StixCommonObject {
}


/**
 * A STIX Relationship Object (SRO): a relationship or a sighting that links other objects.
 */
export interface StixRelationshipObject extends StixCommonObject {
}


/**
 * A STIX Cyber-observable Object (SCO): a fact observed on a network or host, such as a file, an address or a process.
 */
export interface StixCyberObservableObject extends StixObject {
    /** Defines whether or not the data contained within the object has been defanged. */
    defanged?: boolean,
}


/**
 * Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, or groups.
 */
export interface StixIdentity extends StixDomainObject {
    /** The roles that the identity or threat actor plays. */
    roles?: string[],
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The type of entity that this Identity describes, e.g., an individual or organization. Open Vocab - identity-class-ov. */
    identity_class?: string,
    /** The list of sectors that this Identity belongs to. Open Vocab - industry-sector-ov. */
    sectors?: string[],
    /** The contact information (e-mail, phone number, etc.) for this Identity. */
    contact_information?: string,
}


/**
 * A marking definition: a statement, a Traffic Light Protocol (TLP) level or another marking that applies to the objects that reference it.
 */
export interface StixMarkingDefinition extends StixObject {
    /** A reference to the identity of the object's creator. */
    created_by_ref?: StixIdentityId,
    /** The time at which the object, or its first version, was created. */
    created: string,
    /** References to non-STIX information about the object. */
    external_references?: StixExternalReference[],
    /** A name that identifies the object. */
    name?: string,
    /** The type of the marking definition, such as statement or tlp. */
    definition_type?: string,
    /** The marking itself: a statement, or a Traffic Light Protocol (TLP) level. */
    definition?: string,
}


/**
 * The language-content object represents text content for STIX Objects represented in languages other than that of the original object.
 */
export interface StixLanguageContent extends StixCommonObject {
    /** Identifies the object that this Language Content applies to. */
    object_ref: StixObjectId,
    /** Identifies the modified time of the object that this Language Content applies to. */
    object_modified?: string,
    /** Contains the actual Language Content (translation). */
    contents: StixLanguageContents,
}


/**
 * The STIX Extension Definition object allows producers of threat intelligence to extend existing STIX objects or to create entirely new STIX objects in a standardized way.
 */
export interface StixExtensionDefinition extends StixCommonObject {
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The normative definition of the extension, either as a URL or as plain text explaining the definition. */
    schema: string,
    /** A version, as a string; each class says of what. */
    version: string,
    /** Which extension types are contained within this extension. */
    extension_types: string,
    /** The list of new property names that are added to an object by this extension. */
    extension_properties?: string[],
}


/**
 * External references are used to describe pointers to information represented outside of STIX.
 */
export interface StixExternalReference {
    /** The source, such as a system, registry or organization, that defines the reference. */
    source_name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** A URL. */
    url?: string,
    /** A dictionary of hashes of the content, keyed by hash algorithm. */
    hashes?: StixHashes,
    /** An identifier of the external content in its source, such as CVE-2016-1234. */
    external_id?: string,
}


/**
 * A phase in a kill chain, named by the chain and the phase.
 */
export interface StixKillChainPhase {
    /** The name of the kill chain. */
    kill_chain_name: string,
    /** The name of the phase in the kill chain. */
    phase_name: string,
}


/**
 * A marking of parts of an object: the properties its selectors name, marked either by a marking definition or with a language.
 */
export interface StixGranularMarking {
    /** The marking_ref property specifies the ID of the marking-definition object that describes the marking. */
    marking_ref?: StixMarkingDefinitionId,
    /** A list of selectors for content contained within the STIX object in which this property appears. */
    selectors: string[],
    /** The language of the text content, as an RFC 5646 language code. */
    lang?: string,
}


/**
 * The definition of a statement marking: a statement, such as a copyright or terms of use.
 */
export interface StixStatementMarking {
    /** A statement, such as a copyright or terms of use, that applies to the marked content. */
    statement: string,
}


/**
 * The definition of a Traffic Light Protocol (TLP) marking: its level.
 */
export interface StixTlpMarking {
    /** The Traffic Light Protocol level. */
    tlp: string,
}


/**
 * An extension of an object that an extension definition defines. Besides its extension type it carries the properties that its definition's schema states.
 */
export interface StixExtension {
    /** The kind of extension, as the extension's definition declares it. */
    extension_type: string,
}


/**
 * A dictionary of hashes. Each key names a hash algorithm, from the hash-algorithm-ov vocabulary (StixHashAlgorithm) or a custom one, and each value is the hash as a string.
 */
export interface StixHashes {
}


/**
 * A dictionary of extensions, keyed by an extension definition's identifier.
 */
export interface StixExtensions {
}


/**
 * A dictionary of key and value pairs that STIX leaves open.
 */
export interface StixDictionary {
}


/**
 * The translations of a language content object, keyed by language code. Each value maps the translated properties to their translations.
 */
export interface StixLanguageContents {
}


/**
 * The Artifact Object permits capturing an array of bytes (8-bits), as a base64-encoded string string, or linking to a file-like payload.
 */
export interface StixArtifact extends StixCyberObservableObject {
    /** The value of this property MUST be a valid MIME type as specified in the IANA Media Types registry. */
    mime_type?: string,
    /** Specifies the binary data contained in the artifact as a base64-encoded string. */
    payload_bin?: string,
    /** A URL. */
    url?: string,
    /** A dictionary of hashes of the content, keyed by hash algorithm. */
    hashes?: StixHashes,
    /** If the artifact is encrypted, specifies the type of encryption algorithm the binary data (either via payload_bin or url) is encoded in. */
    encryption_algorithm?: string,
    /** Specifies the decryption key for the encrypted binary data (either via payload_bin or url). */
    decryption_key?: string,
}


/**
 * The AS object represents the properties of an Autonomous Systems (AS).
 */
export interface StixAutonomousSystem extends StixCyberObservableObject {
    /** Specifies the number assigned to the AS. Such assignments are typically performed by a Regional Internet Registries (RIR). */
    number: number,
    /** A name that identifies the object. */
    name?: string,
    /** Specifies the name of the Regional Internet Registry (RIR) that assigned the number to the AS. */
    rir?: string,
}


/**
 * The Directory Object represents the properties common to a file system directory.
 */
export interface StixDirectory extends StixCyberObservableObject {
    /** A path, as it was observed. */
    path: string,
    /** Specifies the observed encoding for the path. */
    path_enc?: string,
    /** The time at which the object was created. */
    ctime?: string,
    /** The time at which the object was last written to. */
    mtime?: string,
    /** The time at which the object was last accessed. */
    atime?: string,
    /** References to other cyber-observable objects that this one contains. */
    contains_refs?: StixCyberObservableObjectId[],
}


/**
 * The Domain Name represents the properties of a network domain name.
 */
export interface StixDomainName extends StixCyberObservableObject {
    /** The value of the observable, in the form each class states. */
    value: string,
    /** References to the cyber-observable objects that this one resolves to. */
    resolves_to_refs?: StixCyberObservableObjectId[],
}


/**
 * The Email Address Object represents a single email address.
 */
export interface StixEmailAddress extends StixCyberObservableObject {
    /** The value of the observable, in the form each class states. */
    value: string,
    /** A name for display. */
    display_name?: string,
    /** Specifies the user account that the email address belongs to, as a reference to a User Account Object. */
    belongs_to_ref?: StixUserAccountId,
}


/**
 * The Email Message Object represents an instance of an email message.
 */
export interface StixEmailMessage extends StixCyberObservableObject {
    /** Specifies the date/time that the email message was sent. */
    date?: string,
    /** The value of a Content-Type header field. */
    content_type?: string,
    /** Specifies the value of the 'From:' header of the email message. */
    from_ref?: StixEmailAddressId,
    /** Specifies the value of the 'From' field of the email message. */
    sender_ref?: StixEmailAddressId,
    /** Specifies the mailboxes that are 'To:' recipients of the email message. */
    to_refs?: StixEmailAddressId[],
    /** Specifies the mailboxes that are 'CC:' recipients of the email message. */
    cc_refs?: StixEmailAddressId[],
    /** Specifies the mailboxes that are 'BCC:' recipients of the email message. */
    bcc_refs?: StixEmailAddressId[],
    /** Specifies the Message-ID field of the email message. */
    message_id?: string,
    /** A subject, as a string; each class says of what. */
    subject?: string,
    /** Specifies one or more Received header fields that may be included in the email headers. */
    received_lines?: string[],
    /** Specifies any other header fields found in the email message, as a dictionary. */
    additional_header_fields?: StixDictionary,
    /** Specifies the raw binary contents of the email message, including both the headers and body, as a reference to an Artifact Object. */
    raw_email_ref?: StixArtifactId,
    /** Indicates whether the email body contains multiple MIME parts. */
    is_multipart: boolean,
    /** A body of text. */
    body?: string,
    /** Specifies a list of the MIME parts that make up the email body. This property MAY only be used if is_multipart is true. */
    body_multipart?: StixMimePart[],
}


/**
 * The File Object represents the properties of a file.
 */
export interface StixFile extends StixCyberObservableObject {
    /** A dictionary of hashes of the content, keyed by hash algorithm. */
    hashes?: StixHashes,
    /** A size in bytes, as a non-negative integer. */
    size?: number,
    /** A name that identifies the object. */
    name?: string,
    /** Specifies the observed encoding for the name of the file. */
    name_enc?: string,
    /** Specifies the hexadecimal constant ('magic number') associated with a specific file format that corresponds to the file, if applicable. */
    magic_number_hex?: string,
    /** The value of this property MUST be a valid MIME type as specified in the IANA Media Types registry. */
    mime_type?: string,
    /** The time at which the object was created. */
    ctime?: string,
    /** The time at which the object was last written to. */
    mtime?: string,
    /** The time at which the object was last accessed. */
    atime?: string,
    /** Specifies the parent directory of the file, as a reference to a Directory Object. */
    parent_directory_ref?: StixDirectoryId,
    /** References to other cyber-observable objects that this one contains. */
    contains_refs?: StixCyberObservableObjectId[],
    /** Specifies the content of the file, represented as an Artifact Object. */
    content_ref?: StixArtifactId,
}


/**
 * The IPv4 Address Object represents one or more IPv4 addresses expressed using CIDR notation.
 */
export interface StixIpv4Address extends StixCyberObservableObject {
    /** The value of the observable, in the form each class states. */
    value: string,
    /** References to the cyber-observable objects that this one resolves to. */
    resolves_to_refs?: StixMacAddressId[],
    /** References to the autonomous systems that this address belongs to. */
    belongs_to_refs?: StixAutonomousSystemId[],
}


/**
 * The IPv6 Address Object represents one or more IPv6 addresses expressed using CIDR notation.
 */
export interface StixIpv6Address extends StixCyberObservableObject {
    /** The value of the observable, in the form each class states. */
    value: string,
    /** References to the cyber-observable objects that this one resolves to. */
    resolves_to_refs?: StixMacAddressId[],
    /** References to the autonomous systems that this address belongs to. */
    belongs_to_refs?: StixAutonomousSystemId[],
}


/**
 * The MAC Address Object represents a single Media Access Control (MAC) address.
 */
export interface StixMacAddress extends StixCyberObservableObject {
    /** The value of the observable, in the form each class states. */
    value: string,
}


/**
 * The Mutex Object represents the properties of a mutual exclusion (mutex) object.
 */
export interface StixMutex extends StixCyberObservableObject {
    /** A name that identifies the object. */
    name: string,
}


/**
 * The Network Traffic Object represents arbitrary network traffic that originates from a source and is addressed to a destination.
 */
export interface StixNetworkTraffic extends StixCyberObservableObject {
    /** Specifies the date/time the network traffic was initiated, if known. */
    start?: string,
    /** Specifies the date/time the network traffic ended, if known. */
    end?: string,
    /** Specifies the source of the network traffic, as a reference to an Observable Object. */
    src_ref?: StixCyberObservableObjectId,
    /** Specifies the destination of the network traffic, as a reference to an Observable Object. */
    dst_ref?: StixCyberObservableObjectId,
    /** Specifies the source port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535. */
    src_port?: number,
    /** Specifies the destination port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535. */
    dst_port?: number,
    /** Specifies the protocols observed in the network traffic, along with their corresponding state. */
    protocols: string[],
    /** Specifies the number of bytes sent from the source to the destination. */
    src_byte_count?: number,
    /** Specifies the number of bytes sent from the destination to the source. */
    dst_byte_count?: number,
    /** Specifies the number of packets sent from the source to the destination. */
    src_packets?: number,
    /** Specifies the number of packets sent destination to the source. */
    dst_packets?: number,
    /** Specifies any IP Flow Information Export (IPFIX) data for the traffic. */
    ipfix?: StixDictionary,
    /** Specifies the bytes sent from the source to the destination. */
    src_payload_ref?: StixArtifactId,
    /** Specifies the bytes sent from the source to the destination. */
    dst_payload_ref?: StixArtifactId,
    /** Links to other network-traffic objects encapsulated by a network-traffic. */
    encapsulates_refs?: StixNetworkTrafficId[],
    /** Links to another network-traffic object which encapsulates this object. */
    encapsulated_by_ref?: StixNetworkTrafficId,
    /** Indicates whether the network traffic is still ongoing. */
    is_active?: boolean,
}


/**
 * The Process Object represents common properties of an instance of a computer program as executed on an operating system.
 */
export interface StixProcess extends StixCyberObservableObject {
    /** Specifies whether the process is hidden. */
    is_hidden?: boolean,
    /** Specifies the Process ID, or PID, of the process. */
    pid?: number,
    /** Specifies the date/time at which the process was created. */
    created_time?: string,
    /** Specifies the current working directory of the process. */
    cwd?: string,
    /** Specifies the full command line used in executing the process, including the process name (which may be specified individually via the binary_ref.name property) and any arguments. */
    command_line?: string,
    /** Specifies the list of environment variables associated with the process as a dictionary. */
    environment_variables?: StixDictionary,
    /** Specifies the list of network connections opened by the process, as a reference to one or more Network Traffic Objects. */
    opened_connection_refs?: StixNetworkTrafficId[],
    /** A reference to the user account that created the object. */
    creator_user_ref?: StixUserAccountId,
    /** Specifies the executable binary that was executed as the process image, as a reference to a File Object. */
    image_ref?: StixFileId,
    /** Specifies the other process that spawned (i.e. is the parent of) this one, as represented by a Process Object. */
    parent_ref?: StixProcessId,
    /** Specifies the other processes that were spawned by (i.e. children of) this process, as a reference to one or more other Process Objects. */
    child_refs?: StixProcessId[],
}


/**
 * The Software Object represents high-level properties associated with software, including software products.
 */
export interface StixSoftware extends StixCyberObservableObject {
    /** A name that identifies the object. */
    name: string,
    /** Specifies the Common Platform Enumeration (CPE) entry for the software, if available. The value for this property MUST be a CPE v2.3 entry from the official NVD CPE Dictionary. */
    cpe?: string,
    /** Specifies the Software Identification (SWID) Tags entry for the software, if available. */
    swid?: string,
    /** Specifies the languages supported by the software. The value of each list member MUST be an RFC 5646 language code. ISO 639-2 codes are accepted for backward compatibility. */
    languages?: string[],
    /** Specifies the name of the vendor of the software. */
    vendor?: string,
    /** A version, as a string; each class says of what. */
    version?: string,
}


/**
 * The URL Object represents the properties of a uniform resource locator (URL).
 */
export interface StixUrl extends StixCyberObservableObject {
    /** The value of the observable, in the form each class states. */
    value: string,
}


/**
 * The User Account Object represents an instance of any type of user account, including but not limited to operating system, device, messaging service, and social media platform accounts.
 */
export interface StixUserAccount extends StixCyberObservableObject {
    /** Specifies the identifier of the account. */
    user_id?: string,
    /** Specifies a cleartext credential. This is only intended to be used in capturing metadata from malware analysis (e.g., a hard-coded domain administrator password that the malware attempts to use for lateral movement) and SHOULD NOT be used for sharing of PII. */
    credential?: string,
    /** Specifies the account login string, used in cases where the user_id property specifies something other than what a user would type when they login. */
    account_login?: string,
    /** Specifies the type of the account. This is an open vocabulary and values SHOULD come from the account-type-ov vocabulary. */
    account_type?: string,
    /** A name for display. */
    display_name?: string,
    /** Indicates that the account is associated with a network service or system process (daemon), not a specific individual. */
    is_service_account?: boolean,
    /** Specifies that the account has elevated privileges (i.e., in the case of root on Unix or the Windows Administrator account). */
    is_privileged?: boolean,
    /** Specifies that the account has the ability to escalate privileges (i.e., in the case of sudo on Unix or a Windows Domain Admin account). */
    can_escalate_privs?: boolean,
    /** Specifies if the account is disabled. */
    is_disabled?: boolean,
    /** Specifies when the account was created. */
    account_created?: string,
    /** Specifies the expiration date of the account. */
    account_expires?: string,
    /** Specifies when the account credential was last changed. */
    credential_last_changed?: string,
    /** Specifies when the account was first accessed. */
    account_first_login?: string,
    /** Specifies when the account was last accessed. */
    account_last_login?: string,
}


/**
 * The Registry Key Object represents the properties of a Windows registry key.
 */
export interface StixWindowsRegistryKey extends StixCyberObservableObject {
    /** Specifies the full registry key including the hive. */
    key?: string,
    /** Specifies the values found under the registry key. */
    values?: StixWindowsRegistryValue[],
    /** Specifies the last date/time that the registry key was modified. */
    modified_time?: string,
    /** A reference to the user account that created the object. */
    creator_user_ref?: StixUserAccountId,
    /** Specifies the number of subkeys contained under the registry key. */
    number_of_subkeys?: number,
}


/**
 * The X509 Certificate Object represents the properties of an X.509 certificate.
 */
export interface StixX509Certificate extends StixCyberObservableObject {
    /** Specifies whether the certificate is self-signed, i.e., whether it is signed by the same entity whose identity it certifies. */
    is_self_signed?: boolean,
    /** A dictionary of hashes of the content, keyed by hash algorithm. */
    hashes?: StixHashes,
    /** A version, as a string; each class says of what. */
    version?: string,
    /** Specifies the unique identifier for the certificate, as issued by a specific Certificate Authority. */
    serial_number?: string,
    /** Specifies the name of the algorithm used to sign the certificate. */
    signature_algorithm?: string,
    /** Specifies the name of the Certificate Authority that issued the certificate. */
    issuer?: string,
    /** Specifies the date on which the certificate validity period begins. */
    validity_not_before?: string,
    /** Specifies the date on which the certificate validity period ends. */
    validity_not_after?: string,
    /** A subject, as a string; each class says of what. */
    subject?: string,
    /** Specifies the name of the algorithm with which to encrypt data being sent to the subject. */
    subject_public_key_algorithm?: string,
    /** Specifies the modulus portion of the subject's public RSA key. */
    subject_public_key_modulus?: string,
    /** Specifies the exponent portion of the subject's public RSA key, as an integer. */
    subject_public_key_exponent?: number,
    /** Specifies any standard X.509 v3 extensions that may be used in the certificate. */
    x509_v3_extensions?: StixX509V3Extensions,
}


/**
 * The NTFS file extension specifies a default extension for capturing properties specific to the storage of the file on the NTFS file system.
 */
export interface StixNtfsExtension {
    /** Specifies the security ID (SID) value assigned to the file. */
    sid?: string,
    /** Specifies a list of NTFS alternate data streams that exist for the file. */
    alternate_data_streams?: StixAlternateDataStream[],
}


/**
 * The Raster Image file extension specifies a default extension for capturing properties specific to image files.
 */
export interface StixRasterImageExtension {
    /** Specifies the height of the image in the image file, in pixels. */
    image_height?: number,
    /** Specifies the width of the image in the image file, in pixels. */
    image_width?: number,
    /** Specifies the sum of bits used for each color channel in the image in the image file, and thus the total number of pixels used for expressing the color depth of the image. */
    bits_per_pixel?: number,
    /** Specifies the set of EXIF tags found in the image file, as a dictionary. Each key/value pair in the dictionary represents the name/value of a single EXIF tag. */
    exif_tags?: StixExifTags,
}


/**
 * The PDF file extension specifies a default extension for capturing properties specific to PDF files.
 */
export interface StixPdfExtension {
    /** A version, as a string; each class says of what. */
    version?: string,
    /** Specifies whether the PDF file has been optimized. */
    is_optimized?: boolean,
    /** Specifies details of the PDF document information dictionary (DID), which includes properties like the document creation data and producer, as a dictionary. */
    document_info_dict?: StixPdfDocumentInfo,
    /** Specifies the first file identifier found for the PDF file. */
    pdfid0?: string,
    /** Specifies the second file identifier found for the PDF file. */
    pdfid1?: string,
}


/**
 * The Archive File extension specifies a default extension for capturing properties specific to archive files.
 */
export interface StixArchiveExtension {
    /** References to other cyber-observable objects that this one contains. */
    contains_refs: StixCyberObservableObjectId[],
    /** Specifies a comment included as part of the archive file. */
    comment?: string,
}


/**
 * The Windows PE Binary File extension specifies a default extension for capturing properties specific to Windows portable executable (PE) files.
 */
export interface StixWindowsPeBinaryExtension {
    /** Specifies the type of the PE binary. Open Vocabulary - windows-pebinary-type-ov. */
    pe_type: string,
    /** Specifies the special import hash, or 'imphash', calculated for the PE Binary based on its imported libraries and functions. */
    imphash?: string,
    /** Specifies the type of target machine. */
    machine_hex?: string,
    /** Specifies the number of sections in the PE binary, as a non-negative integer. */
    number_of_sections?: number,
    /** Specifies the time when the PE binary was created. The timestamp value MUST BE precise to the second. */
    time_date_stamp?: string,
    /** Specifies the file offset of the COFF symbol table. */
    pointer_to_symbol_table_hex?: string,
    /** Specifies the number of entries in the symbol table of the PE binary, as a non-negative integer. */
    number_of_symbols?: number,
    /** Specifies the size of the optional header of the PE binary. */
    size_of_optional_header?: number,
    /** Specifies the flags that indicate the file's characteristics. */
    characteristics_hex?: string,
    /** Specifies any hashes that were computed for the file header. */
    file_header_hashes?: StixHashes,
    /** Specifies the PE optional header of the PE binary. */
    optional_header?: StixWindowsPeOptionalHeader,
    /** Specifies metadata about the sections in the PE file. */
    sections?: StixWindowsPeSection[],
}


/**
 * The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP requests.
 */
export interface StixHttpRequestExtension {
    /** Specifies the HTTP method portion of the HTTP request line, as a lowercase string. */
    request_method: string,
    /** Specifies the value (typically a resource path) portion of the HTTP request line. */
    request_value: string,
    /** Specifies the HTTP version portion of the HTTP request line, as a lowercase string. */
    request_version?: string,
    /** Specifies all of the HTTP header fields that may be found in the HTTP client request, as a dictionary. */
    request_header?: StixDictionary,
    /** Specifies the length of the HTTP message body, if included, in bytes. */
    message_body_length?: number,
    /** Specifies the data contained in the HTTP message body, if included. */
    message_body_data_ref?: StixArtifactId,
}


/**
 * The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP.
 */
export interface StixIcmpExtension {
    /** Specifies the ICMP type byte. */
    icmp_type_hex: string,
    /** Specifies the ICMP code byte. */
    icmp_code_hex: string,
}


/**
 * The Network Socket extension specifies a default extension for capturing network traffic properties associated with network sockets.
 */
export interface StixSocketExtension {
    /** Specifies the address family (AF_*) that the socket is configured for. */
    address_family: string,
    /** Specifies whether the socket is in blocking mode. */
    is_blocking?: boolean,
    /** Specifies whether the socket is in listening mode. */
    is_listening?: boolean,
    /** Specifies any options (SO_*) that may be used by the socket, as a dictionary. */
    options?: StixSocketOptions,
    /** Specifies the type of the socket. */
    socket_type?: string,
    /** Specifies the socket file descriptor value associated with the socket, as a non-negative integer. */
    socket_descriptor?: number,
    /** Specifies the handle or inode value associated with the socket. */
    socket_handle?: number,
}


/**
 * The TCP extension specifies a default extension for capturing network traffic properties specific to TCP.
 */
export interface StixTcpExtension {
    /** Specifies the source TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property). */
    src_flags_hex?: string,
    /** Specifies the destination TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property). */
    dst_flags_hex?: string,
}


/**
 * The Windows Process extension specifies a default extension for capturing properties specific to Windows processes.
 */
export interface StixWindowsProcessExtension {
    /** Specifies whether Address Space Layout Randomization (ASLR) is enabled for the process. */
    aslr_enabled?: boolean,
    /** Specifies whether Data Execution Prevention (DEP) is enabled for the process. */
    dep_enabled?: boolean,
    /** Specifies the current priority class of the process in Windows. */
    priority?: string,
    /** Specifies the Security ID (SID) value of the owner of the process. */
    owner_sid?: string,
    /** Specifies the title of the main window of the process. */
    window_title?: string,
    /** Specifies the STARTUP_INFO struct used by the process, as a dictionary. */
    startup_info?: StixDictionary,
    /** Specifies the Windows integrity level, or trustworthiness, of the process. */
    integrity_level?: string,
}


/**
 * The Windows Service extension specifies a default extension for capturing properties specific to Windows services.
 */
export interface StixWindowsServiceExtension {
    /** Specifies the name of the service. */
    service_name?: string,
    /** Specifies the descriptions defined for the service. */
    descriptions?: string[],
    /** A name for display. */
    display_name?: string,
    /** Specifies the name of the load ordering group of which the service is a member. */
    group_name?: string,
    /** Specifies the start options defined for the service. windows-service-start-enum. */
    start_type?: string,
    /** Specifies the DLLs loaded by the service, as a reference to one or more File Objects. */
    service_dll_refs?: StixFileId[],
    /** Specifies the type of the service. windows-service-enum. */
    service_type?: string,
    /** Specifies the current status of the service. windows-service-status-enum. */
    service_status?: string,
}


/**
 * The User Account Object defines the following extensions. In addition to these, producers MAY create their own.
 */
export interface StixUnixAccountExtension {
    /** Specifies the primary group ID of the account. */
    gid?: number,
    /** Specifies a list of names of groups that the account is a member of. */
    groups?: string[],
    /** Specifies the home directory of the account. */
    home_dir?: string,
    /** Specifies the account's command shell. */
    shell?: string,
}


/**
 * An NTFS alternate data stream of a file.
 */
export interface StixAlternateDataStream {
    /** A name that identifies the object. */
    name: string,
    /** A dictionary of hashes of the content, keyed by hash algorithm. */
    hashes?: StixHashes,
    /** A size in bytes, as a non-negative integer. */
    size?: number,
}


/**
 * A section of a Windows PE binary.
 */
export interface StixWindowsPeSection {
    /** A name that identifies the object. */
    name: string,
    /** A size in bytes, as a non-negative integer. */
    size?: number,
    /** Specifies the calculated entropy for the section, as calculated using the Shannon algorithm. */
    entropy?: number,
    /** A dictionary of hashes of the content, keyed by hash algorithm. */
    hashes?: StixHashes,
}


/**
 * The optional header of a Windows PE binary.
 */
export interface StixWindowsPeOptionalHeader {
    /** Specifies the unsigned integer that indicates the type of the PE binary. */
    magic_hex?: string,
    /** Specifies the linker major version number. */
    major_linker_version?: number,
    /** Specifies the linker minor version number. */
    minor_linker_version?: number,
    /** Specifies the size of the code (text) section. If there are multiple such sections, this refers to the sum of the sizes of each section. */
    size_of_code?: number,
    /** Specifies the size of the initialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section. */
    size_of_initialized_data?: number,
    /** Specifies the size of the uninitialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section. */
    size_of_uninitialized_data?: number,
    /** Specifies the address of the entry point relative to the image base when the executable is loaded into memory. */
    address_of_entry_point?: number,
    /** Specifies the address that is relative to the image base of the beginning-of-code section when it is loaded into memory. */
    base_of_code?: number,
    /** Specifies the address that is relative to the image base of the beginning-of-data section when it is loaded into memory. */
    base_of_data?: number,
    /** Specifies the preferred address of the first byte of the image when loaded into memory. */
    image_base?: number,
    /** Specifies the alignment (in bytes) of PE sections when they are loaded into memory. */
    section_alignment?: number,
    /** Specifies the factor (in bytes) that is used to align the raw data of sections in the image file. */
    file_alignment?: number,
    /** Specifies the major version number of the required operating system. */
    major_os_version?: number,
    /** Specifies the minor version number of the required operating system. */
    minor_os_version?: number,
    /** Specifies the major version number of the image. */
    major_image_version?: number,
    /** Specifies the minor version number of the image. */
    minor_image_version?: number,
    /** Specifies the major version number of the subsystem. */
    major_subsystem_version?: number,
    /** Specifies the minor version number of the subsystem. */
    minor_subsystem_version?: number,
    /** Specifies the reserved win32 version value. */
    win32_version_value_hex?: string,
    /** Specifies the size, in bytes, of the image, including all headers, as the image is loaded in memory. */
    size_of_image?: number,
    /** Specifies the combined size of the MS-DOS, PE header, and section headers, rounded up a multiple of the value specified in the file_alignment header. */
    size_of_headers?: number,
    /** Specifies the checksum of the PE binary. */
    checksum_hex?: string,
    /** Specifies the subsystem (e.g., GUI, device driver, etc.) that is required to run this image. */
    subsystem_hex?: string,
    /** Specifies the flags that characterize the PE binary. */
    dll_characteristics_hex?: string,
    /** Specifies the size of the stack to reserve. */
    size_of_stack_reserve?: number,
    /** Specifies the size of the stack to commit. */
    size_of_stack_commit?: number,
    /** Specifies the size of the local heap space to reserve. */
    size_of_heap_reserve?: number,
    /** Specifies the size of the local heap space to commit. */
    size_of_heap_commit?: number,
    /** Specifies the reserved loader flags. */
    loader_flags_hex?: string,
    /** Specifies the number of data-directory entries in the remainder of the optional header. */
    number_of_rva_and_sizes?: number,
    /** A dictionary of hashes of the content, keyed by hash algorithm. */
    hashes?: StixHashes,
}


/**
 * One MIME part of a multipart email body.
 */
export interface StixMimePart {
    /** A body of text. */
    body?: string,
    /** Specifies the contents of non-textual MIME parts, that is those whose content_type does not start with text/, as a reference to an Artifact Object or File Object. */
    body_raw_ref?: StixCyberObservableObjectId,
    /** The value of a Content-Type header field. */
    content_type?: string,
    /** Specifies the value of the 'Content-Disposition' header field of the MIME part. */
    content_disposition?: string,
}


/**
 * A value found under a Windows registry key.
 */
export interface StixWindowsRegistryValue {
    /** A name that identifies the object. */
    name?: string,
    /** Specifies the data contained in the registry value. */
    data?: string,
    /** Specifies the registry (REG_*) data type used in the registry value. */
    data_type?: string,
}


/**
 * The standard X.509 v3 extensions of a certificate.
 */
export interface StixX509V3Extensions {
    /** Specifies a multi-valued extension which indicates whether a certificate is a CA certificate. */
    basic_constraints?: string,
    /** Specifies a namespace within which all subject names in subsequent certificates in a certification path MUST be located. */
    name_constraints?: string,
    /** Specifies any constraints on path validation for certificates issued to CAs. */
    policy_constraints?: string,
    /** Specifies a multi-valued extension consisting of a list of names of the permitted key usages. */
    key_usage?: string,
    /** Specifies a list of usages indicating purposes for which the certificate public key can be used for. */
    extended_key_usage?: string,
    /** Specifies the identifier that provides a means of identifying certificates that contain a particular public key. */
    subject_key_identifier?: string,
    /** Specifies the identifier that provides a means of identifying the public key corresponding to the private key used to sign a certificate. */
    authority_key_identifier?: string,
    /** Specifies the additional identities to be bound to the subject of the certificate. */
    subject_alternative_name?: string,
    /** Specifies the additional identities to be bound to the issuer of the certificate. */
    issuer_alternative_name?: string,
    /** Specifies the identification attributes (e.g., nationality) of the subject. */
    subject_directory_attributes?: string,
    /** Specifies how CRL information is obtained. */
    crl_distribution_points?: string,
    /** Specifies the number of additional certificates that may appear in the path before anyPolicy is no longer permitted. */
    inhibit_any_policy?: string,
    /** Specifies the date on which the validity period begins for the private key, if it is different from the validity period of the certificate. */
    private_key_usage_period_not_before?: string,
    /** Specifies the date on which the validity period ends for the private key, if it is different from the validity period of the certificate. */
    private_key_usage_period_not_after?: string,
    /** Specifies a sequence of one or more policy information terms, each of which consists of an object identifier (OID) and optional qualifiers. */
    certificate_policies?: string,
    /** Specifies one or more pairs of OIDs; each pair includes an issuerDomainPolicy and a subjectDomainPolicy. */
    policy_mappings?: string,
}


/**
 * The extensions of a file: the predefined ntfs-ext, raster-image-ext, pdf-ext, archive-ext and windows-pebinary-ext, and extensions that an extension definition defines.
 */
export interface StixFileExtensions {
}


/**
 * The extensions of network traffic: the predefined http-request-ext, icmp-ext, socket-ext and tcp-ext, and extensions that an extension definition defines.
 */
export interface StixNetworkTrafficExtensions {
}


/**
 * The extensions of a process: the predefined windows-process-ext and windows-service-ext, and extensions that an extension definition defines.
 */
export interface StixProcessExtensions {
}


/**
 * The extensions of a user account: the predefined unix-account-ext, and extensions that an extension definition defines.
 */
export interface StixUserAccountExtensions {
}


/**
 * The options of a network socket, as a dictionary of option names, such as SO_RCVBUF, to integer values.
 */
export interface StixSocketOptions {
}


/**
 * The EXIF tags of an image file, as a dictionary of tag names to string or integer values.
 */
export interface StixExifTags {
}


/**
 * The document information dictionary of a PDF file, as a dictionary of string values.
 */
export interface StixPdfDocumentInfo {
}


/**
 * Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets.
 */
export interface StixAttackPattern extends StixDomainObject {
    /** Other names by which the object is known. */
    aliases?: string[],
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The kill chain phases to which the object corresponds. */
    kill_chain_phases?: StixKillChainPhase[],
}


/**
 * A Campaign is a grouping of adversary behavior that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.
 */
export interface StixCampaign extends StixDomainObject {
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** Other names by which the object is known. */
    aliases?: string[],
    /** The time at which the object was first seen. */
    first_seen?: string,
    /** The time at which the object was last seen. */
    last_seen?: string,
    /** This field defines the Campaign's primary goal, objective, desired outcome, or intended effect. */
    objective?: string,
}


/**
 * A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress.
 */
export interface StixCourseOfAction extends StixDomainObject {
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
}


/**
 * A Grouping object explicitly asserts that the referenced STIX Objects have a shared content.
 */
export interface StixGrouping extends StixDomainObject {
    /** A name that identifies the object. */
    name?: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** A short description of the particular context shared by the content referenced by the Grouping. */
    context: string,
    /** References to the STIX objects that this object is about or holds. */
    object_refs: StixObjectId[],
}


/**
 * The Incident object in STIX 2.1 is a stub, to be expanded in future STIX 2 releases.
 */
export interface StixIncident extends StixDomainObject {
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
}


/**
 * Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity.
 */
export interface StixIndicator extends StixDomainObject {
    /** This field is an Open Vocabulary that specifies the type of indicator. Open vocab - indicator-type-ov. */
    indicator_types?: string[],
    /** A name that identifies the object. */
    name?: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The detection pattern for this indicator. */
    pattern: string,
    /** The type of pattern used in this indicator. */
    pattern_type: string,
    /** The version of the pattern that is used. */
    pattern_version?: string,
    /** The time from which this indicator should be considered valuable intelligence. */
    valid_from: string,
    /** The time at which this indicator should no longer be considered valuable intelligence. */
    valid_until?: string,
    /** The kill chain phases to which the object corresponds. */
    kill_chain_phases?: StixKillChainPhase[],
}


/**
 * Infrastructure objects describe systems, software services, and associated physical or virtual resources.
 */
export interface StixInfrastructure extends StixDomainObject {
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** This field is an Open Vocabulary that specifies the type of infrastructure. Open vocab - infrastructure-type-ov. */
    infrastructure_types?: string[],
    /** Other names by which the object is known. */
    aliases?: string[],
    /** The kill chain phases to which the object corresponds. */
    kill_chain_phases?: StixKillChainPhase[],
    /** The time at which the object was first seen. */
    first_seen?: string,
    /** The time at which the object was last seen. */
    last_seen?: string,
}


/**
 * An Intrusion Set is a grouped set of adversary behavior and resources with common properties that is believed to be orchestrated by a single organization.
 */
export interface StixIntrusionSet extends StixDomainObject {
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** Other names by which the object is known. */
    aliases?: string[],
    /** The time at which the object was first seen. */
    first_seen?: string,
    /** The time at which the object was last seen. */
    last_seen?: string,
    /** The high-level goals. */
    goals?: string[],
    /** The organizational level at which the actor typically works. */
    resource_level?: string,
    /** The primary reason, motivation or purpose behind the activity. */
    primary_motivation?: string,
    /** The secondary reasons, motivations or purposes behind the activity. */
    secondary_motivations?: string[],
}


/**
 * A Location represents a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude.
 */
export interface StixLocation extends StixDomainObject {
    /** A description of the object, which may be long. */
    description?: string,
    /** A name that identifies the object. */
    name?: string,
    /** The latitude of the Location in decimal degrees. */
    latitude?: number,
    /** The longitude of the Location in decimal degrees. */
    longitude?: number,
    /** Defines the precision of the coordinates specified by the latitude and longitude properties, measured in meters. */
    precision?: number,
    /** The region that this Location describes. */
    region?: string,
    /** The country that this Location describes. */
    country?: string,
    /** The state, province, or other sub-national administrative area that this Location describes. */
    administrative_area?: string,
    /** The city that this Location describes. */
    city?: string,
    /** The street address that this Location describes. */
    street_address?: string,
    /** The postal code for this Location. */
    postal_code?: string,
}


/**
 * Malware is a type of TTP that is also known as malicious code and malicious software, refers to a program that is inserted into a system, usually covertly, with the intent of compromising the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or of otherwise annoying or disrupting the victim.
 */
export interface StixMalware extends StixDomainObject {
    /** Other names by which the object is known. */
    aliases?: string[],
    /** The time at which the object was first seen. */
    first_seen?: string,
    /** The time at which the object was last seen. */
    last_seen?: string,
    /** The operating systems that the malware family or malware instance is executable on. */
    operating_system_refs?: StixSoftwareId[],
    /** The processor architectures (e.g., x86, ARM, etc.) that the malware instance or family is executable on. Open Vocab - processor-architecture-os. */
    architecture_execution_envs?: string[],
    /** The programming language(s) used to implement the malware instance or family. Open Vocab - implementation-language-ov. */
    implementation_languages?: string[],
    /** Specifies any capabilities identified for the malware instance or family. Open Vocab - malware-capabilities-ov. */
    capabilities?: string[],
    /** The sample_refs property specifies a list of identifiers of the SCO file or artifact objects associated with this malware instance(s) or family. */
    sample_refs?: StixCyberObservableObjectId[],
    /** The type of malware being described. Open Vocab - malware-type-ov. */
    malware_types?: string[],
    /** A name that identifies the object. */
    name?: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The kill chain phases to which the object corresponds. */
    kill_chain_phases?: StixKillChainPhase[],
    /** Whether the object represents a malware family (if true) or a malware instance (if false). */
    is_family: boolean,
}


/**
 * Malware Analysis captures the metadata and results of a particular analysis performed (static or dynamic) on the malware instance or family.
 */
export interface StixMalwareAnalysis extends StixDomainObject {
    /** The name of the analysis engine or product that was used for this analysis. */
    product: string,
    /** A version, as a string; each class says of what. */
    version?: string,
    /** The version of the analysis product configuration that was used to perform this analysis. */
    configuration_version?: string,
    /** The particular analysis product modules that were used to perform the analysis. */
    modules?: string[],
    /** The version of the analysis engine or product that was used to perform this analysis. */
    analysis_engine_version?: string,
    /** The version of the analysis definitions used by the analysis tool. */
    analysis_definition_version?: string,
    /** The date and time that this malware was first submitted for scanning or analysis. */
    submitted?: string,
    /** The date and time that the malware analysis was initiated. */
    analysis_started?: string,
    /** The date and time that the malware analysis ended. */
    analysis_ended?: string,
    /** The classification result or name assigned to the malware instance by the scanner tool. */
    result_name?: string,
    /** The classification result as determined by the scanner or tool analysis process. */
    result?: string,
    /** A description of the virtual machine environment used to host the guest operating system (if applicable) that was used for the dynamic analysis of the malware instance or family. */
    host_vm_ref?: StixSoftwareId,
    /** The operating system that was used to perform the dynamic analysis. */
    operating_system_ref?: StixSoftwareId,
    /** Any non-standard software installed on the operating system used for the dynamic analysis of the malware instance or family. */
    installed_software_refs?: StixSoftwareId[],
    /** The cyber-observable objects captured during the analysis. */
    analysis_sco_refs?: StixCyberObservableObjectId[],
    /** Refers to the object this analysis was performed against. */
    sample_ref?: StixCyberObservableObjectId,
}


/**
 * A Note is a comment or note containing informative text to help explain the context of one or more STIX Objects (SDOs or SROs) or to provide additional analysis that is not contained in the original object.
 */
export interface StixNote extends StixDomainObject {
    /** A brief summary of the note. */
    abstract?: string,
    /** The content of the note. */
    content: string,
    /** The name of the author(s) of this note (e.g., the analyst(s) that created it). */
    authors?: string[],
    /** References to the STIX objects that this object is about or holds. */
    object_refs: StixObjectId[],
}


/**
 * Observed data conveys information that was observed on systems and networks, such as log data or network traffic, using the Cyber Observable specification.
 */
export interface StixObservedData extends StixDomainObject {
    /** The beginning of the time window that the data was observed during. */
    first_observed: string,
    /** The end of the time window that the data was observed during. */
    last_observed: string,
    /** The number of times the data represented in the objects property was observed. This MUST be an integer between 1 and 999,999,999 inclusive. */
    number_observed: number,
    /** The observed cyber-observable objects, as a dictionary keyed by index. Deprecated in STIX 2.1; use object_refs. */
    objects?: StixObservedObjects,
    /** References to the STIX objects that this object is about or holds. */
    object_refs?: StixObjectId[],
}


/**
 * An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity and captures the level of agreement or disagreement using a fixed scale.
 */
export interface StixOpinion extends StixDomainObject {
    /** An explanation of why the producer has this Opinion. */
    explanation?: string,
    /** The name of the author(s) of this note (e.g., the analyst(s) that created it). */
    authors?: string[],
    /** References to the STIX objects that this object is about or holds. */
    object_refs: StixObjectId[],
    /** The opinion that the producer has about about all of the STIX Object(s) listed in the object_refs property. */
    opinion: string,
}


/**
 * Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and related details.
 */
export interface StixReport extends StixDomainObject {
    /** This field is an Open Vocabulary that specifies the primary subject of this report. The suggested values for this field are in report-type-ov. */
    report_types?: string[],
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The date that this report object was officially published by the creator of this report. */
    published: string,
    /** References to the STIX objects that this object is about or holds. */
    object_refs: StixObjectId[],
}


/**
 * Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.
 */
export interface StixThreatActor extends StixDomainObject {
    /** This field specifies the type of threat actor. Open Vocab - threat-actor-type-ov. */
    threat_actor_types?: string[],
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** Other names by which the object is known. */
    aliases?: string[],
    /** The roles that the identity or threat actor plays. */
    roles?: string[],
    /** The high-level goals. */
    goals?: string[],
    /** The time at which the object was first seen. */
    first_seen?: string,
    /** The time at which the object was last seen. */
    last_seen?: string,
    /** The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack. Open Vocab - threat-actor-sophistication-ov. */
    sophistication?: string,
    /** The organizational level at which the actor typically works. */
    resource_level?: string,
    /** The primary reason, motivation or purpose behind the activity. */
    primary_motivation?: string,
    /** The secondary reasons, motivations or purposes behind the activity. */
    secondary_motivations?: string[],
    /** The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals. Open Vocab - attack-motivation-ov. */
    personal_motivations?: string[],
}


/**
 * Tools are legitimate software that can be used by threat actors to perform attacks.
 */
export interface StixTool extends StixDomainObject {
    /** Other names by which the object is known. */
    aliases?: string[],
    /** The kind(s) of tool(s) being described. Open Vocab - tool-type-ov. */
    tool_types?: string[],
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The version identifier associated with the tool. */
    tool_version?: string,
    /** The kill chain phases to which the object corresponds. */
    kill_chain_phases?: StixKillChainPhase[],
}


/**
 * A Vulnerability is a mistake in software that can be directly used by a hacker to gain access to a system or network.
 */
export interface StixVulnerability extends StixDomainObject {
    /** A name that identifies the object. */
    name: string,
    /** A description of the object, which may be long. */
    description?: string,
}


/**
 * The cyber-observable objects of an observed data object, keyed by an index such as "0". STIX 2.1 deprecates this form in favour of object_refs.
 */
export interface StixObservedObjects {
}


/**
 * The Relationship object is used to link together two SDOs in order to describe how they are related to each other.
 */
export interface StixRelationship extends StixRelationshipObject {
    /** The name used to identify the type of relationship. */
    relationship_type: string,
    /** A description of the object, which may be long. */
    description?: string,
    /** The ID of the source (from) object. */
    source_ref: StixObjectId,
    /** The ID of the target (to) object. */
    target_ref: StixObjectId,
    /** This optional timestamp represents the earliest time at which the Relationship between the objects exists. If this property is a future timestamp, at the time the updated property is defined, then this represents an estimate by the producer of the intelligence of the earliest time at which relationship will be asserted to be true. */
    start_time?: string,
    /** The latest time at which the Relationship between the objects exists. If this property is a future timestamp, at the time the updated property is defined, then this represents an estimate by the producer of the intelligence of the latest time at which relationship will be asserted to be true. */
    stop_time?: string,
}


/**
 * A Sighting denotes the belief that something in CTI (e.g., an indicator, malware, tool, threat actor, etc.) was seen.
 */
export interface StixSighting extends StixRelationshipObject {
    /** A description of the object, which may be long. */
    description?: string,
    /** The time at which the object was first seen. */
    first_seen?: string,
    /** The time at which the object was last seen. */
    last_seen?: string,
    /** This is an integer between 0 and 999,999,999 inclusive and represents the number of times the object was sighted. */
    count?: number,
    /** A reference to the domain object that was sighted. */
    sighting_of_ref: StixDomainObjectId,
    /** A list of ID references to the Observed Data objects that contain the raw cyber data for this Sighting. */
    observed_data_refs?: StixObservedDataId[],
    /** A list of ID references to the Identity or Location objects describing the entities or types of entities that saw the sighting. */
    where_sighted_refs?: StixDomainObjectId[],
    /** The summary property indicates whether the Sighting should be considered summary data. */
    summary?: boolean,
}


/**
 * A bundle: a collection of STIX objects grouped together in one container. A bundle is a container for transport, not a STIX object, so it carries no spec_version.
 */
export interface StixBundle {
    /** The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type. */
    id: string,
    /** The STIX type name of the object, such as attack-pattern. Each class pins its own. */
    type: string,
    /** The STIX objects in the bundle. */
    objects?: StixObject[],
}



