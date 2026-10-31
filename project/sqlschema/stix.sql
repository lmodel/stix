-- # Class: StixBundle Description: A bundle: a collection of STIX objects grouped together in one container. A bundle is a container for transport, not a STIX object, so it carries no spec_version.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
-- # Abstract Class: StixObject Description: Any STIX object: the base of the domain, relationship and cyber-observable objects and of the meta objects.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: StixBundle_id Description: Autocreated FK slot
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Abstract Class: StixCommonObject Description: The base of the objects that carry STIX's common properties: the domain and relationship objects, language content and extension definitions.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Abstract Class: StixDomainObject Description: A STIX Domain Object (SDO): a higher-level concept of cyber threat intelligence, such as an attack pattern, a malware family or a threat actor.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Abstract Class: StixRelationshipObject Description: A STIX Relationship Object (SRO): a relationship or a sighting that links other objects.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Abstract Class: StixCyberObservableObject Description: A STIX Cyber-observable Object (SCO): a fact observed on a network or host, such as a file, an address or a process.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixIdentity Description: Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, or groups.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: identity_class Description: The type of entity that this Identity describes, e.g., an individual or organization. Open Vocab - identity-class-ov.
--     * Slot: contact_information Description: The contact information (e-mail, phone number, etc.) for this Identity.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixMarkingDefinition Description: A marking definition: a statement, a Traffic Light Protocol (TLP) level or another marking that applies to the objects that reference it.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: definition_type Description: The type of the marking definition, such as statement or tlp.
--     * Slot: definition Description: The marking itself: a statement, or a Traffic Light Protocol (TLP) level.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixLanguageContent Description: The language-content object represents text content for STIX Objects represented in languages other than that of the original object.
--     * Slot: object_ref Description: Identifies the object that this Language Content applies to.
--     * Slot: object_modified Description: Identifies the modified time of the object that this Language Content applies to.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: contents_id Description: Contains the actual Language Content (translation).
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixExtensionDefinition Description: The STIX Extension Definition object allows producers of threat intelligence to extend existing STIX objects or to create entirely new STIX objects in a standardized way.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: schema Description: The normative definition of the extension, either as a URL or as plain text explaining the definition.
--     * Slot: version Description: A version, as a string; each class says of what.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixExternalReference Description: External references are used to describe pointers to information represented outside of STIX.
--     * Slot: id
--     * Slot: source_name Description: The source, such as a system, registry or organization, that defines the reference.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: url Description: A URL.
--     * Slot: external_id Description: An identifier of the external content in its source, such as CVE-2016-1234.
--     * Slot: StixCommonObject_id Description: Autocreated FK slot
--     * Slot: StixDomainObject_id Description: Autocreated FK slot
--     * Slot: StixRelationshipObject_id Description: Autocreated FK slot
--     * Slot: StixIdentity_id Description: Autocreated FK slot
--     * Slot: StixMarkingDefinition_id Description: Autocreated FK slot
--     * Slot: StixLanguageContent_id Description: Autocreated FK slot
--     * Slot: StixExtensionDefinition_id Description: Autocreated FK slot
--     * Slot: StixAttackPattern_id Description: Autocreated FK slot
--     * Slot: StixCampaign_id Description: Autocreated FK slot
--     * Slot: StixCourseOfAction_id Description: Autocreated FK slot
--     * Slot: StixGrouping_id Description: Autocreated FK slot
--     * Slot: StixIncident_id Description: Autocreated FK slot
--     * Slot: StixIndicator_id Description: Autocreated FK slot
--     * Slot: StixInfrastructure_id Description: Autocreated FK slot
--     * Slot: StixIntrusionSet_id Description: Autocreated FK slot
--     * Slot: StixLocation_id Description: Autocreated FK slot
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: StixMalwareAnalysis_id Description: Autocreated FK slot
--     * Slot: StixNote_id Description: Autocreated FK slot
--     * Slot: StixObservedData_id Description: Autocreated FK slot
--     * Slot: StixOpinion_id Description: Autocreated FK slot
--     * Slot: StixReport_id Description: Autocreated FK slot
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: StixTool_id Description: Autocreated FK slot
--     * Slot: StixVulnerability_id Description: Autocreated FK slot
--     * Slot: StixRelationship_id Description: Autocreated FK slot
--     * Slot: StixSighting_id Description: Autocreated FK slot
--     * Slot: hashes_id Description: A dictionary of hashes of the content, keyed by hash algorithm.
-- # Class: StixKillChainPhase Description: A phase in a kill chain, named by the chain and the phase.
--     * Slot: id
--     * Slot: kill_chain_name Description: The name of the kill chain.
--     * Slot: phase_name Description: The name of the phase in the kill chain.
--     * Slot: StixAttackPattern_id Description: Autocreated FK slot
--     * Slot: StixIndicator_id Description: Autocreated FK slot
--     * Slot: StixInfrastructure_id Description: Autocreated FK slot
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: StixTool_id Description: Autocreated FK slot
-- # Class: StixGranularMarking Description: The granular-marking type defines how the list of marking-definition objects referenced by the marking_refs property to apply to a set of content identified by the list of selectors in the selectors property.
--     * Slot: id
--     * Slot: marking_ref Description: The marking_ref property specifies the ID of the marking-definition object that describes the marking.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: StixObject_id Description: Autocreated FK slot
--     * Slot: StixCommonObject_id Description: Autocreated FK slot
--     * Slot: StixDomainObject_id Description: Autocreated FK slot
--     * Slot: StixRelationshipObject_id Description: Autocreated FK slot
--     * Slot: StixCyberObservableObject_id Description: Autocreated FK slot
--     * Slot: StixIdentity_id Description: Autocreated FK slot
--     * Slot: StixMarkingDefinition_id Description: Autocreated FK slot
--     * Slot: StixLanguageContent_id Description: Autocreated FK slot
--     * Slot: StixExtensionDefinition_id Description: Autocreated FK slot
--     * Slot: StixArtifact_id Description: Autocreated FK slot
--     * Slot: StixAutonomousSystem_id Description: Autocreated FK slot
--     * Slot: StixDirectory_id Description: Autocreated FK slot
--     * Slot: StixDomainName_id Description: Autocreated FK slot
--     * Slot: StixEmailAddress_id Description: Autocreated FK slot
--     * Slot: StixEmailMessage_id Description: Autocreated FK slot
--     * Slot: StixFile_id Description: Autocreated FK slot
--     * Slot: StixIpv4Address_id Description: Autocreated FK slot
--     * Slot: StixIpv6Address_id Description: Autocreated FK slot
--     * Slot: StixMacAddress_id Description: Autocreated FK slot
--     * Slot: StixMutex_id Description: Autocreated FK slot
--     * Slot: StixNetworkTraffic_id Description: Autocreated FK slot
--     * Slot: StixProcess_id Description: Autocreated FK slot
--     * Slot: StixSoftware_id Description: Autocreated FK slot
--     * Slot: StixUrl_id Description: Autocreated FK slot
--     * Slot: StixUserAccount_id Description: Autocreated FK slot
--     * Slot: StixWindowsRegistryKey_id Description: Autocreated FK slot
--     * Slot: StixX509Certificate_id Description: Autocreated FK slot
--     * Slot: StixAttackPattern_id Description: Autocreated FK slot
--     * Slot: StixCampaign_id Description: Autocreated FK slot
--     * Slot: StixCourseOfAction_id Description: Autocreated FK slot
--     * Slot: StixGrouping_id Description: Autocreated FK slot
--     * Slot: StixIncident_id Description: Autocreated FK slot
--     * Slot: StixIndicator_id Description: Autocreated FK slot
--     * Slot: StixInfrastructure_id Description: Autocreated FK slot
--     * Slot: StixIntrusionSet_id Description: Autocreated FK slot
--     * Slot: StixLocation_id Description: Autocreated FK slot
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: StixMalwareAnalysis_id Description: Autocreated FK slot
--     * Slot: StixNote_id Description: Autocreated FK slot
--     * Slot: StixObservedData_id Description: Autocreated FK slot
--     * Slot: StixOpinion_id Description: Autocreated FK slot
--     * Slot: StixReport_id Description: Autocreated FK slot
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: StixTool_id Description: Autocreated FK slot
--     * Slot: StixVulnerability_id Description: Autocreated FK slot
--     * Slot: StixRelationship_id Description: Autocreated FK slot
--     * Slot: StixSighting_id Description: Autocreated FK slot
-- # Class: StixStatementMarking Description: The definition of a statement marking: a statement, such as a copyright or terms of use.
--     * Slot: id
--     * Slot: statement Description: A statement, such as a copyright or terms of use, that applies to the marked content.
-- # Class: StixTlpMarking Description: The definition of a Traffic Light Protocol (TLP) marking: its level.
--     * Slot: id
--     * Slot: tlp Description: The Traffic Light Protocol level.
-- # Class: StixExtension Description: An extension of an object that an extension definition defines. Besides its extension type it carries the properties that its definition's schema states.
--     * Slot: id
--     * Slot: extension_type Description: The kind of extension, as the extension's definition declares it.
-- # Class: StixHashes Description: A dictionary of hashes. Each key names a hash algorithm, from the hash-algorithm-ov vocabulary (StixHashAlgorithm) or a custom one, and each value is the hash as a string.
--     * Slot: id
-- # Class: StixExtensions Description: A dictionary of extensions, keyed by an extension definition's identifier.
--     * Slot: id
-- # Class: StixDictionary Description: A dictionary of key and value pairs that STIX leaves open.
--     * Slot: id
-- # Class: StixLanguageContents Description: The translations of a language content object, keyed by language code. Each value maps the translated properties to their translations.
--     * Slot: id
-- # Class: StixArtifact Description: The Artifact Object permits capturing an array of bytes (8-bits), as a base64-encoded string string, or linking to a file-like payload.
--     * Slot: mime_type Description: The value of this property MUST be a valid MIME type as specified in the IANA Media Types registry.
--     * Slot: payload_bin Description: Specifies the binary data contained in the artifact as a base64-encoded string.
--     * Slot: url Description: A URL.
--     * Slot: encryption_algorithm Description: If the artifact is encrypted, specifies the type of encryption algorithm the binary data (either via payload_bin or url) is encoded in.
--     * Slot: decryption_key Description: Specifies the decryption key for the encrypted binary data (either via payload_bin or url).
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: hashes_id Description: A dictionary of hashes of the content, keyed by hash algorithm.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixAutonomousSystem Description: The AS object represents the properties of an Autonomous Systems (AS).
--     * Slot: number Description: Specifies the number assigned to the AS. Such assignments are typically performed by a Regional Internet Registries (RIR).
--     * Slot: name Description: A name that identifies the object.
--     * Slot: rir Description: Specifies the name of the Regional Internet Registry (RIR) that assigned the number to the AS.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixDirectory Description: The Directory Object represents the properties common to a file system directory.
--     * Slot: path Description: A path, as it was observed.
--     * Slot: path_enc Description: Specifies the observed encoding for the path.
--     * Slot: ctime Description: The time at which the object was created.
--     * Slot: mtime Description: The time at which the object was last written to.
--     * Slot: atime Description: The time at which the object was last accessed.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixDomainName Description: The Domain Name represents the properties of a network domain name.
--     * Slot: value Description: The value of the observable, in the form each class states.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixEmailAddress Description: The Email Address Object represents a single email address.
--     * Slot: value Description: The value of the observable, in the form each class states.
--     * Slot: display_name Description: A name for display.
--     * Slot: belongs_to_ref Description: Specifies the user account that the email address belongs to, as a reference to a User Account Object.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixEmailMessage Description: The Email Message Object represents an instance of an email message.
--     * Slot: date Description: Specifies the date/time that the email message was sent.
--     * Slot: content_type Description: The value of a Content-Type header field.
--     * Slot: from_ref Description: Specifies the value of the 'From:' header of the email message.
--     * Slot: sender_ref Description: Specifies the value of the 'From' field of the email message.
--     * Slot: message_id Description: Specifies the Message-ID field of the email message.
--     * Slot: subject Description: A subject, as a string; each class says of what.
--     * Slot: raw_email_ref Description: Specifies the raw binary contents of the email message, including both the headers and body, as a reference to an Artifact Object.
--     * Slot: is_multipart Description: Indicates whether the email body contains multiple MIME parts.
--     * Slot: body Description: A body of text.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: additional_header_fields_id Description: Specifies any other header fields found in the email message, as a dictionary.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixFile Description: The File Object represents the properties of a file.
--     * Slot: size Description: A size in bytes, as a non-negative integer.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: name_enc Description: Specifies the observed encoding for the name of the file.
--     * Slot: magic_number_hex Description: Specifies the hexadecimal constant ('magic number') associated with a specific file format that corresponds to the file, if applicable.
--     * Slot: mime_type Description: The value of this property MUST be a valid MIME type as specified in the IANA Media Types registry.
--     * Slot: ctime Description: The time at which the object was created.
--     * Slot: mtime Description: The time at which the object was last written to.
--     * Slot: atime Description: The time at which the object was last accessed.
--     * Slot: parent_directory_ref Description: Specifies the parent directory of the file, as a reference to a Directory Object.
--     * Slot: content_ref Description: Specifies the content of the file, represented as an Artifact Object.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: hashes_id Description: A dictionary of hashes of the content, keyed by hash algorithm.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixIpv4Address Description: The IPv4 Address Object represents one or more IPv4 addresses expressed using CIDR notation.
--     * Slot: value Description: The value of the observable, in the form each class states.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixIpv6Address Description: The IPv6 Address Object represents one or more IPv6 addresses expressed using CIDR notation.
--     * Slot: value Description: The value of the observable, in the form each class states.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixMacAddress Description: The MAC Address Object represents a single Media Access Control (MAC) address.
--     * Slot: value Description: The value of the observable, in the form each class states.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixMutex Description: The Mutex Object represents the properties of a mutual exclusion (mutex) object.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixNetworkTraffic Description: The Network Traffic Object represents arbitrary network traffic that originates from a source and is addressed to a destination.
--     * Slot: start Description: Specifies the date/time the network traffic was initiated, if known.
--     * Slot: end Description: Specifies the date/time the network traffic ended, if known.
--     * Slot: src_ref Description: Specifies the source of the network traffic, as a reference to an Observable Object.
--     * Slot: dst_ref Description: Specifies the destination of the network traffic, as a reference to an Observable Object.
--     * Slot: src_port Description: Specifies the source port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535.
--     * Slot: dst_port Description: Specifies the destination port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535.
--     * Slot: src_byte_count Description: Specifies the number of bytes sent from the source to the destination.
--     * Slot: dst_byte_count Description: Specifies the number of bytes sent from the destination to the source.
--     * Slot: src_packets Description: Specifies the number of packets sent from the source to the destination.
--     * Slot: dst_packets Description: Specifies the number of packets sent destination to the source.
--     * Slot: src_payload_ref Description: Specifies the bytes sent from the source to the destination.
--     * Slot: dst_payload_ref Description: Specifies the bytes sent from the source to the destination.
--     * Slot: encapsulated_by_ref Description: Links to another network-traffic object which encapsulates this object.
--     * Slot: is_active Description: Indicates whether the network traffic is still ongoing.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: ipfix_id Description: Specifies any IP Flow Information Export (IPFIX) data for the traffic.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixProcess Description: The Process Object represents common properties of an instance of a computer program as executed on an operating system.
--     * Slot: is_hidden Description: Specifies whether the process is hidden.
--     * Slot: pid Description: Specifies the Process ID, or PID, of the process.
--     * Slot: created_time Description: Specifies the date/time at which the process was created.
--     * Slot: cwd Description: Specifies the current working directory of the process.
--     * Slot: command_line Description: Specifies the full command line used in executing the process, including the process name (which may be specified individually via the binary_ref.name property) and any arguments.
--     * Slot: creator_user_ref Description: A reference to the user account that created the object.
--     * Slot: image_ref Description: Specifies the executable binary that was executed as the process image, as a reference to a File Object.
--     * Slot: parent_ref Description: Specifies the other process that spawned (i.e. is the parent of) this one, as represented by a Process Object.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: environment_variables_id Description: Specifies the list of environment variables associated with the process as a dictionary.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixSoftware Description: The Software Object represents high-level properties associated with software, including software products.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: cpe Description: Specifies the Common Platform Enumeration (CPE) entry for the software, if available. The value for this property MUST be a CPE v2.3 entry from the official NVD CPE Dictionary.
--     * Slot: swid Description: Specifies the Software Identification (SWID) Tags entry for the software, if available.
--     * Slot: vendor Description: Specifies the name of the vendor of the software.
--     * Slot: version Description: A version, as a string; each class says of what.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixUrl Description: The URL Object represents the properties of a uniform resource locator (URL).
--     * Slot: value Description: The value of the observable, in the form each class states.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixUserAccount Description: The User Account Object represents an instance of any type of user account, including but not limited to operating system, device, messaging service, and social media platform accounts.
--     * Slot: user_id Description: Specifies the identifier of the account.
--     * Slot: credential Description: Specifies a cleartext credential. This is only intended to be used in capturing metadata from malware analysis (e.g., a hard-coded domain administrator password that the malware attempts to use for lateral movement) and SHOULD NOT be used for sharing of PII.
--     * Slot: account_login Description: Specifies the account login string, used in cases where the user_id property specifies something other than what a user would type when they login.
--     * Slot: account_type Description: Specifies the type of the account. This is an open vocabulary and values SHOULD come from the account-type-ov vocabulary.
--     * Slot: display_name Description: A name for display.
--     * Slot: is_service_account Description: Indicates that the account is associated with a network service or system process (daemon), not a specific individual.
--     * Slot: is_privileged Description: Specifies that the account has elevated privileges (i.e., in the case of root on Unix or the Windows Administrator account).
--     * Slot: can_escalate_privs Description: Specifies that the account has the ability to escalate privileges (i.e., in the case of sudo on Unix or a Windows Domain Admin account).
--     * Slot: is_disabled Description: Specifies if the account is disabled.
--     * Slot: account_created Description: Specifies when the account was created.
--     * Slot: account_expires Description: Specifies the expiration date of the account.
--     * Slot: credential_last_changed Description: Specifies when the account credential was last changed.
--     * Slot: account_first_login Description: Specifies when the account was first accessed.
--     * Slot: account_last_login Description: Specifies when the account was last accessed.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixWindowsRegistryKey Description: The Registry Key Object represents the properties of a Windows registry key.
--     * Slot: key Description: Specifies the full registry key including the hive.
--     * Slot: modified_time Description: Specifies the last date/time that the registry key was modified.
--     * Slot: creator_user_ref Description: A reference to the user account that created the object.
--     * Slot: number_of_subkeys Description: Specifies the number of subkeys contained under the registry key.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixX509Certificate Description: The X509 Certificate Object represents the properties of an X.509 certificate.
--     * Slot: is_self_signed Description: Specifies whether the certificate is self-signed, i.e., whether it is signed by the same entity whose identity it certifies.
--     * Slot: version Description: A version, as a string; each class says of what.
--     * Slot: serial_number Description: Specifies the unique identifier for the certificate, as issued by a specific Certificate Authority.
--     * Slot: signature_algorithm Description: Specifies the name of the algorithm used to sign the certificate.
--     * Slot: issuer Description: Specifies the name of the Certificate Authority that issued the certificate.
--     * Slot: validity_not_before Description: Specifies the date on which the certificate validity period begins.
--     * Slot: validity_not_after Description: Specifies the date on which the certificate validity period ends.
--     * Slot: subject Description: A subject, as a string; each class says of what.
--     * Slot: subject_public_key_algorithm Description: Specifies the name of the algorithm with which to encrypt data being sent to the subject.
--     * Slot: subject_public_key_modulus Description: Specifies the modulus portion of the subject's public RSA key.
--     * Slot: subject_public_key_exponent Description: Specifies the exponent portion of the subject's public RSA key, as an integer.
--     * Slot: defanged Description: Defines whether or not the data contained within the object has been defanged.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: hashes_id Description: A dictionary of hashes of the content, keyed by hash algorithm.
--     * Slot: x509_v3_extensions_id Description: Specifies any standard X.509 v3 extensions that may be used in the certificate.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixNtfsExtension Description: The NTFS file extension specifies a default extension for capturing properties specific to the storage of the file on the NTFS file system.
--     * Slot: id
--     * Slot: sid Description: Specifies the security ID (SID) value assigned to the file.
-- # Class: StixRasterImageExtension Description: The Raster Image file extension specifies a default extension for capturing properties specific to image files.
--     * Slot: id
--     * Slot: image_height Description: Specifies the height of the image in the image file, in pixels.
--     * Slot: image_width Description: Specifies the width of the image in the image file, in pixels.
--     * Slot: bits_per_pixel Description: Specifies the sum of bits used for each color channel in the image in the image file, and thus the total number of pixels used for expressing the color depth of the image.
--     * Slot: exif_tags_id Description: Specifies the set of EXIF tags found in the image file, as a dictionary. Each key/value pair in the dictionary represents the name/value of a single EXIF tag.
-- # Class: StixPdfExtension Description: The PDF file extension specifies a default extension for capturing properties specific to PDF files.
--     * Slot: id
--     * Slot: version Description: A version, as a string; each class says of what.
--     * Slot: is_optimized Description: Specifies whether the PDF file has been optimized.
--     * Slot: pdfid0 Description: Specifies the first file identifier found for the PDF file.
--     * Slot: pdfid1 Description: Specifies the second file identifier found for the PDF file.
--     * Slot: document_info_dict_id Description: Specifies details of the PDF document information dictionary (DID), which includes properties like the document creation data and producer, as a dictionary.
-- # Class: StixArchiveExtension Description: The Archive File extension specifies a default extension for capturing properties specific to archive files.
--     * Slot: id
--     * Slot: comment Description: Specifies a comment included as part of the archive file.
-- # Class: StixWindowsPeBinaryExtension Description: The Windows PE Binary File extension specifies a default extension for capturing properties specific to Windows portable executable (PE) files.
--     * Slot: id
--     * Slot: pe_type Description: Specifies the type of the PE binary. Open Vocabulary - windows-pebinary-type-ov.
--     * Slot: imphash Description: Specifies the special import hash, or 'imphash', calculated for the PE Binary based on its imported libraries and functions.
--     * Slot: machine_hex Description: Specifies the type of target machine.
--     * Slot: number_of_sections Description: Specifies the number of sections in the PE binary, as a non-negative integer.
--     * Slot: time_date_stamp Description: Specifies the time when the PE binary was created. The timestamp value MUST BE precise to the second.
--     * Slot: pointer_to_symbol_table_hex Description: Specifies the file offset of the COFF symbol table.
--     * Slot: number_of_symbols Description: Specifies the number of entries in the symbol table of the PE binary, as a non-negative integer.
--     * Slot: size_of_optional_header Description: Specifies the size of the optional header of the PE binary.
--     * Slot: characteristics_hex Description: Specifies the flags that indicate the file's characteristics.
--     * Slot: file_header_hashes_id Description: Specifies any hashes that were computed for the file header.
--     * Slot: optional_header_id Description: Specifies the PE optional header of the PE binary.
-- # Class: StixHttpRequestExtension Description: The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP requests.
--     * Slot: id
--     * Slot: request_method Description: Specifies the HTTP method portion of the HTTP request line, as a lowercase string.
--     * Slot: request_value Description: Specifies the value (typically a resource path) portion of the HTTP request line.
--     * Slot: request_version Description: Specifies the HTTP version portion of the HTTP request line, as a lowercase string.
--     * Slot: message_body_length Description: Specifies the length of the HTTP message body, if included, in bytes.
--     * Slot: message_body_data_ref Description: Specifies the data contained in the HTTP message body, if included.
--     * Slot: request_header_id Description: Specifies all of the HTTP header fields that may be found in the HTTP client request, as a dictionary.
-- # Class: StixIcmpExtension Description: The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP.
--     * Slot: id
--     * Slot: icmp_type_hex Description: Specifies the ICMP type byte.
--     * Slot: icmp_code_hex Description: Specifies the ICMP code byte.
-- # Class: StixSocketExtension Description: The Network Socket extension specifies a default extension for capturing network traffic properties associated with network sockets.
--     * Slot: id
--     * Slot: address_family Description: Specifies the address family (AF_*) that the socket is configured for.
--     * Slot: is_blocking Description: Specifies whether the socket is in blocking mode.
--     * Slot: is_listening Description: Specifies whether the socket is in listening mode.
--     * Slot: socket_type Description: Specifies the type of the socket.
--     * Slot: socket_descriptor Description: Specifies the socket file descriptor value associated with the socket, as a non-negative integer.
--     * Slot: socket_handle Description: Specifies the handle or inode value associated with the socket.
--     * Slot: options_id Description: Specifies any options (SO_*) that may be used by the socket, as a dictionary.
-- # Class: StixTcpExtension Description: The TCP extension specifies a default extension for capturing network traffic properties specific to TCP.
--     * Slot: id
--     * Slot: src_flags_hex Description: Specifies the source TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).
--     * Slot: dst_flags_hex Description: Specifies the destination TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).
-- # Class: StixWindowsProcessExtension Description: The Windows Process extension specifies a default extension for capturing properties specific to Windows processes.
--     * Slot: id
--     * Slot: aslr_enabled Description: Specifies whether Address Space Layout Randomization (ASLR) is enabled for the process.
--     * Slot: dep_enabled Description: Specifies whether Data Execution Prevention (DEP) is enabled for the process.
--     * Slot: priority Description: Specifies the current priority class of the process in Windows.
--     * Slot: owner_sid Description: Specifies the Security ID (SID) value of the owner of the process.
--     * Slot: window_title Description: Specifies the title of the main window of the process.
--     * Slot: integrity_level Description: Specifies the Windows integrity level, or trustworthiness, of the process.
--     * Slot: startup_info_id Description: Specifies the STARTUP_INFO struct used by the process, as a dictionary.
-- # Class: StixWindowsServiceExtension Description: The Windows Service extension specifies a default extension for capturing properties specific to Windows services.
--     * Slot: id
--     * Slot: service_name Description: Specifies the name of the service.
--     * Slot: display_name Description: A name for display.
--     * Slot: group_name Description: Specifies the name of the load ordering group of which the service is a member.
--     * Slot: start_type Description: Specifies the start options defined for the service. windows-service-start-enum.
--     * Slot: service_type Description: Specifies the type of the service. windows-service-enum.
--     * Slot: service_status Description: Specifies the current status of the service. windows-service-status-enum.
-- # Class: StixUnixAccountExtension Description: The User Account Object defines the following extensions. In addition to these, producers MAY create their own.
--     * Slot: id
--     * Slot: gid Description: Specifies the primary group ID of the account.
--     * Slot: home_dir Description: Specifies the home directory of the account.
--     * Slot: shell Description: Specifies the account's command shell.
-- # Class: StixAlternateDataStream Description: An NTFS alternate data stream of a file.
--     * Slot: id
--     * Slot: name Description: A name that identifies the object.
--     * Slot: size Description: A size in bytes, as a non-negative integer.
--     * Slot: StixNtfsExtension_id Description: Autocreated FK slot
--     * Slot: hashes_id Description: A dictionary of hashes of the content, keyed by hash algorithm.
-- # Class: StixWindowsPeSection Description: A section of a Windows PE binary.
--     * Slot: id
--     * Slot: name Description: A name that identifies the object.
--     * Slot: size Description: A size in bytes, as a non-negative integer.
--     * Slot: entropy Description: Specifies the calculated entropy for the section, as calculated using the Shannon algorithm.
--     * Slot: StixWindowsPeBinaryExtension_id Description: Autocreated FK slot
--     * Slot: hashes_id Description: A dictionary of hashes of the content, keyed by hash algorithm.
-- # Class: StixWindowsPeOptionalHeader Description: The optional header of a Windows PE binary.
--     * Slot: id
--     * Slot: magic_hex Description: Specifies the unsigned integer that indicates the type of the PE binary.
--     * Slot: major_linker_version Description: Specifies the linker major version number.
--     * Slot: minor_linker_version Description: Specifies the linker minor version number.
--     * Slot: size_of_code Description: Specifies the size of the code (text) section. If there are multiple such sections, this refers to the sum of the sizes of each section.
--     * Slot: size_of_initialized_data Description: Specifies the size of the initialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.
--     * Slot: size_of_uninitialized_data Description: Specifies the size of the uninitialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.
--     * Slot: address_of_entry_point Description: Specifies the address of the entry point relative to the image base when the executable is loaded into memory.
--     * Slot: base_of_code Description: Specifies the address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
--     * Slot: base_of_data Description: Specifies the address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
--     * Slot: image_base Description: Specifies the preferred address of the first byte of the image when loaded into memory.
--     * Slot: section_alignment Description: Specifies the alignment (in bytes) of PE sections when they are loaded into memory.
--     * Slot: file_alignment Description: Specifies the factor (in bytes) that is used to align the raw data of sections in the image file.
--     * Slot: major_os_version Description: Specifies the major version number of the required operating system.
--     * Slot: minor_os_version Description: Specifies the minor version number of the required operating system.
--     * Slot: major_image_version Description: Specifies the major version number of the image.
--     * Slot: minor_image_version Description: Specifies the minor version number of the image.
--     * Slot: major_subsystem_version Description: Specifies the major version number of the subsystem.
--     * Slot: minor_subsystem_version Description: Specifies the minor version number of the subsystem.
--     * Slot: win32_version_value_hex Description: Specifies the reserved win32 version value.
--     * Slot: size_of_image Description: Specifies the size, in bytes, of the image, including all headers, as the image is loaded in memory.
--     * Slot: size_of_headers Description: Specifies the combined size of the MS-DOS, PE header, and section headers, rounded up a multiple of the value specified in the file_alignment header.
--     * Slot: checksum_hex Description: Specifies the checksum of the PE binary.
--     * Slot: subsystem_hex Description: Specifies the subsystem (e.g., GUI, device driver, etc.) that is required to run this image.
--     * Slot: dll_characteristics_hex Description: Specifies the flags that characterize the PE binary.
--     * Slot: size_of_stack_reserve Description: Specifies the size of the stack to reserve.
--     * Slot: size_of_stack_commit Description: Specifies the size of the stack to commit.
--     * Slot: size_of_heap_reserve Description: Specifies the size of the local heap space to reserve.
--     * Slot: size_of_heap_commit Description: Specifies the size of the local heap space to commit.
--     * Slot: loader_flags_hex Description: Specifies the reserved loader flags.
--     * Slot: number_of_rva_and_sizes Description: Specifies the number of data-directory entries in the remainder of the optional header.
--     * Slot: hashes_id Description: A dictionary of hashes of the content, keyed by hash algorithm.
-- # Class: StixMimePart Description: One MIME part of a multipart email body.
--     * Slot: id
--     * Slot: body Description: A body of text.
--     * Slot: body_raw_ref Description: Specifies the contents of non-textual MIME parts, that is those whose content_type does not start with text/, as a reference to an Artifact Object or File Object.
--     * Slot: content_type Description: The value of a Content-Type header field.
--     * Slot: content_disposition Description: Specifies the value of the 'Content-Disposition' header field of the MIME part.
--     * Slot: StixEmailMessage_id Description: Autocreated FK slot
-- # Class: StixWindowsRegistryValue Description: A value found under a Windows registry key.
--     * Slot: id
--     * Slot: name Description: A name that identifies the object.
--     * Slot: data Description: Specifies the data contained in the registry value.
--     * Slot: data_type Description: Specifies the registry (REG_*) data type used in the registry value.
--     * Slot: StixWindowsRegistryKey_id Description: Autocreated FK slot
-- # Class: StixX509V3Extensions Description: The standard X.509 v3 extensions of a certificate.
--     * Slot: id
--     * Slot: basic_constraints Description: Specifies a multi-valued extension which indicates whether a certificate is a CA certificate.
--     * Slot: name_constraints Description: Specifies a namespace within which all subject names in subsequent certificates in a certification path MUST be located.
--     * Slot: policy_constraints Description: Specifies any constraints on path validation for certificates issued to CAs.
--     * Slot: key_usage Description: Specifies a multi-valued extension consisting of a list of names of the permitted key usages.
--     * Slot: extended_key_usage Description: Specifies a list of usages indicating purposes for which the certificate public key can be used for.
--     * Slot: subject_key_identifier Description: Specifies the identifier that provides a means of identifying certificates that contain a particular public key.
--     * Slot: authority_key_identifier Description: Specifies the identifier that provides a means of identifying the public key corresponding to the private key used to sign a certificate.
--     * Slot: subject_alternative_name Description: Specifies the additional identities to be bound to the subject of the certificate.
--     * Slot: issuer_alternative_name Description: Specifies the additional identities to be bound to the issuer of the certificate.
--     * Slot: subject_directory_attributes Description: Specifies the identification attributes (e.g., nationality) of the subject.
--     * Slot: crl_distribution_points Description: Specifies how CRL information is obtained.
--     * Slot: inhibit_any_policy Description: Specifies the number of additional certificates that may appear in the path before anyPolicy is no longer permitted.
--     * Slot: private_key_usage_period_not_before Description: Specifies the date on which the validity period begins for the private key, if it is different from the validity period of the certificate.
--     * Slot: private_key_usage_period_not_after Description: Specifies the date on which the validity period ends for the private key, if it is different from the validity period of the certificate.
--     * Slot: certificate_policies Description: Specifies a sequence of one or more policy information terms, each of which consists of an object identifier (OID) and optional qualifiers.
--     * Slot: policy_mappings Description: Specifies one or more pairs of OIDs; each pair includes an issuerDomainPolicy and a subjectDomainPolicy.
-- # Class: StixFileExtensions Description: The extensions of a file: the predefined ntfs-ext, raster-image-ext, pdf-ext, archive-ext and windows-pebinary-ext, and extensions that an extension definition defines.
--     * Slot: id
-- # Class: StixNetworkTrafficExtensions Description: The extensions of network traffic: the predefined http-request-ext, icmp-ext, socket-ext and tcp-ext, and extensions that an extension definition defines.
--     * Slot: id
-- # Class: StixProcessExtensions Description: The extensions of a process: the predefined windows-process-ext and windows-service-ext, and extensions that an extension definition defines.
--     * Slot: id
-- # Class: StixUserAccountExtensions Description: The extensions of a user account: the predefined unix-account-ext, and extensions that an extension definition defines.
--     * Slot: id
-- # Class: StixSocketOptions Description: The options of a network socket, as a dictionary of option names, such as SO_RCVBUF, to integer values.
--     * Slot: id
-- # Class: StixExifTags Description: The EXIF tags of an image file, as a dictionary of tag names to string or integer values.
--     * Slot: id
-- # Class: StixPdfDocumentInfo Description: The document information dictionary of a PDF file, as a dictionary of string values.
--     * Slot: id
-- # Class: StixAttackPattern Description: Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixCampaign Description: A Campaign is a grouping of adversary behavior that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: first_seen Description: The time at which the object was first seen.
--     * Slot: last_seen Description: The time at which the object was last seen.
--     * Slot: objective Description: This field defines the Campaign's primary goal, objective, desired outcome, or intended effect.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixCourseOfAction Description: A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixGrouping Description: A Grouping object explicitly asserts that the referenced STIX Objects have a shared content.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: context Description: A short description of the particular context shared by the content referenced by the Grouping.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixIncident Description: The Incident object in STIX 2.1 is a stub, to be expanded in future STIX 2 releases.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixIndicator Description: Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: pattern Description: The detection pattern for this indicator.
--     * Slot: pattern_type Description: The type of pattern used in this indicator.
--     * Slot: pattern_version Description: The version of the pattern that is used.
--     * Slot: valid_from Description: The time from which this indicator should be considered valuable intelligence.
--     * Slot: valid_until Description: The time at which this indicator should no longer be considered valuable intelligence.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixInfrastructure Description: Infrastructure objects describe systems, software services, and associated physical or virtual resources.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: first_seen Description: The time at which the object was first seen.
--     * Slot: last_seen Description: The time at which the object was last seen.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixIntrusionSet Description: An Intrusion Set is a grouped set of adversary behavior and resources with common properties that is believed to be orchestrated by a single organization.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: first_seen Description: The time at which the object was first seen.
--     * Slot: last_seen Description: The time at which the object was last seen.
--     * Slot: resource_level Description: The organizational level at which the actor typically works.
--     * Slot: primary_motivation Description: The primary reason, motivation or purpose behind the activity.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixLocation Description: A Location represents a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: latitude Description: The latitude of the Location in decimal degrees.
--     * Slot: longitude Description: The longitude of the Location in decimal degrees.
--     * Slot: precision Description: Defines the precision of the coordinates specified by the latitude and longitude properties, measured in meters.
--     * Slot: region Description: The region that this Location describes.
--     * Slot: country Description: The country that this Location describes.
--     * Slot: administrative_area Description: The state, province, or other sub-national administrative area that this Location describes.
--     * Slot: city Description: The city that this Location describes.
--     * Slot: street_address Description: The street address that this Location describes.
--     * Slot: postal_code Description: The postal code for this Location.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixMalware Description: Malware is a type of TTP that is also known as malicious code and malicious software, refers to a program that is inserted into a system, usually covertly, with the intent of compromising the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or of otherwise annoying or disrupting the victim.
--     * Slot: first_seen Description: The time at which the object was first seen.
--     * Slot: last_seen Description: The time at which the object was last seen.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: is_family Description: Whether the object represents a malware family (if true) or a malware instance (if false).
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixMalwareAnalysis Description: Malware Analysis captures the metadata and results of a particular analysis performed (static or dynamic) on the malware instance or family.
--     * Slot: product Description: The name of the analysis engine or product that was used for this analysis.
--     * Slot: version Description: A version, as a string; each class says of what.
--     * Slot: configuration_version Description: The version of the analysis product configuration that was used to perform this analysis.
--     * Slot: analysis_engine_version Description: The version of the analysis engine or product that was used to perform this analysis.
--     * Slot: analysis_definition_version Description: The version of the analysis definitions used by the analysis tool.
--     * Slot: submitted Description: The date and time that this malware was first submitted for scanning or analysis.
--     * Slot: analysis_started Description: The date and time that the malware analysis was initiated.
--     * Slot: analysis_ended Description: The date and time that the malware analysis ended.
--     * Slot: result_name Description: The classification result or name assigned to the malware instance by the scanner tool.
--     * Slot: result Description: The classification result as determined by the scanner or tool analysis process.
--     * Slot: host_vm_ref Description: A description of the virtual machine environment used to host the guest operating system (if applicable) that was used for the dynamic analysis of the malware instance or family.
--     * Slot: operating_system_ref Description: The operating system that was used to perform the dynamic analysis.
--     * Slot: sample_ref Description: Refers to the object this analysis was performed against.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixNote Description: A Note is a comment or note containing informative text to help explain the context of one or more STIX Objects (SDOs or SROs) or to provide additional analysis that is not contained in the original object.
--     * Slot: abstract Description: A brief summary of the note.
--     * Slot: content Description: The content of the note.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixObservedData Description: Observed data conveys information that was observed on systems and networks, such as log data or network traffic, using the Cyber Observable specification.
--     * Slot: first_observed Description: The beginning of the time window that the data was observed during.
--     * Slot: last_observed Description: The end of the time window that the data was observed during.
--     * Slot: number_observed Description: The number of times the data represented in the objects property was observed. This MUST be an integer between 1 and 999,999,999 inclusive.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: objects_id Description: The observed cyber-observable objects, as a dictionary keyed by index. Deprecated in STIX 2.1; use object_refs.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixOpinion Description: An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity and captures the level of agreement or disagreement using a fixed scale.
--     * Slot: explanation Description: An explanation of why the producer has this Opinion.
--     * Slot: opinion Description: The opinion that the producer has about about all of the STIX Object(s) listed in the object_refs property.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixReport Description: Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and related details.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: published Description: The date that this report object was officially published by the creator of this report.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixThreatActor Description: Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: first_seen Description: The time at which the object was first seen.
--     * Slot: last_seen Description: The time at which the object was last seen.
--     * Slot: sophistication Description: The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack. Open Vocab - threat-actor-sophistication-ov.
--     * Slot: resource_level Description: The organizational level at which the actor typically works.
--     * Slot: primary_motivation Description: The primary reason, motivation or purpose behind the activity.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixTool Description: Tools are legitimate software that can be used by threat actors to perform attacks.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: tool_version Description: The version identifier associated with the tool.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixVulnerability Description: A Vulnerability is a mistake in software that can be directly used by a hacker to gain access to a system or network.
--     * Slot: name Description: A name that identifies the object.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixObservedObjects Description: The cyber-observable objects of an observed data object, keyed by an index such as "0". STIX 2.1 deprecates this form in favour of object_refs.
--     * Slot: id
-- # Class: StixRelationship Description: The Relationship object is used to link together two SDOs in order to describe how they are related to each other.
--     * Slot: relationship_type Description: The name used to identify the type of relationship.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: source_ref Description: The ID of the source (from) object.
--     * Slot: target_ref Description: The ID of the target (to) object.
--     * Slot: start_time Description: This optional timestamp represents the earliest time at which the Relationship between the objects exists. If this property is a future timestamp, at the time the updated property is defined, then this represents an estimate by the producer of the intelligence of the earliest time at which relationship will be asserted to be true.
--     * Slot: stop_time Description: The latest time at which the Relationship between the objects exists. If this property is a future timestamp, at the time the updated property is defined, then this represents an estimate by the producer of the intelligence of the latest time at which relationship will be asserted to be true.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixSighting Description: A Sighting denotes the belief that something in CTI (e.g., an indicator, malware, tool, threat actor, etc.) was seen.
--     * Slot: description Description: A description of the object, which may be long.
--     * Slot: first_seen Description: The time at which the object was first seen.
--     * Slot: last_seen Description: The time at which the object was last seen.
--     * Slot: count Description: This is an integer between 0 and 999,999,999 inclusive and represents the number of times the object was sighted.
--     * Slot: sighting_of_ref Description: An ID reference to the object that has been sighted.
--     * Slot: summary Description: The summary property indicates whether the Sighting should be considered summary data.
--     * Slot: created_by_ref Description: A reference to the identity of the object's creator.
--     * Slot: created Description: The time at which the object, or its first version, was created.
--     * Slot: modified Description: The modified property represents the time that this particular version of the object was modified. The timestamp value MUST be precise to the nearest millisecond.
--     * Slot: revoked Description: The revoked property indicates whether the object has been revoked.
--     * Slot: confidence Description: Identifies the confidence that the creator has in the correctness of their data.
--     * Slot: lang Description: The language of the text content, as an RFC 5646 language code.
--     * Slot: id Description: The identifier of the object: its STIX type, two hyphens and a UUID. Each class narrows the type.
--     * Slot: type Description: The STIX type name of the object, such as attack-pattern. Each class pins its own.
--     * Slot: spec_version Description: The version of the STIX specification used to represent the object.
--     * Slot: extensions_id Description: The object's extensions, as a dictionary keyed by extension name.
-- # Class: StixObject_object_marking_refs
--     * Slot: StixObject_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixCommonObject_labels
--     * Slot: StixCommonObject_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixCommonObject_object_marking_refs
--     * Slot: StixCommonObject_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixDomainObject_labels
--     * Slot: StixDomainObject_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixDomainObject_object_marking_refs
--     * Slot: StixDomainObject_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixRelationshipObject_labels
--     * Slot: StixRelationshipObject_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixRelationshipObject_object_marking_refs
--     * Slot: StixRelationshipObject_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixCyberObservableObject_object_marking_refs
--     * Slot: StixCyberObservableObject_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixIdentity_roles
--     * Slot: StixIdentity_id Description: Autocreated FK slot
--     * Slot: roles Description: The roles that the identity or threat actor plays.
-- # Class: StixIdentity_sectors
--     * Slot: StixIdentity_id Description: Autocreated FK slot
--     * Slot: sectors Description: The list of sectors that this Identity belongs to. Open Vocab - industry-sector-ov.
-- # Class: StixIdentity_labels
--     * Slot: StixIdentity_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixIdentity_object_marking_refs
--     * Slot: StixIdentity_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixMarkingDefinition_object_marking_refs
--     * Slot: StixMarkingDefinition_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixLanguageContent_labels
--     * Slot: StixLanguageContent_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixLanguageContent_object_marking_refs
--     * Slot: StixLanguageContent_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixExtensionDefinition_extension_types
--     * Slot: StixExtensionDefinition_id Description: Autocreated FK slot
--     * Slot: extension_types Description: Which extension types are contained within this extension.
-- # Class: StixExtensionDefinition_extension_properties
--     * Slot: StixExtensionDefinition_id Description: Autocreated FK slot
--     * Slot: extension_properties Description: The list of new property names that are added to an object by this extension.
-- # Class: StixExtensionDefinition_labels
--     * Slot: StixExtensionDefinition_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixExtensionDefinition_object_marking_refs
--     * Slot: StixExtensionDefinition_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixGranularMarking_selectors
--     * Slot: StixGranularMarking_id Description: Autocreated FK slot
--     * Slot: selectors Description: A list of selectors for content contained within the STIX object in which this property appears.
-- # Class: StixArtifact_object_marking_refs
--     * Slot: StixArtifact_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixAutonomousSystem_object_marking_refs
--     * Slot: StixAutonomousSystem_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixDirectory_contains_refs
--     * Slot: StixDirectory_id Description: Autocreated FK slot
--     * Slot: contains_refs_id Description: References to other cyber-observable objects that this one contains.
-- # Class: StixDirectory_object_marking_refs
--     * Slot: StixDirectory_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixDomainName_resolves_to_refs
--     * Slot: StixDomainName_id Description: Autocreated FK slot
--     * Slot: resolves_to_refs_id Description: References to the cyber-observable objects that this one resolves to.
-- # Class: StixDomainName_object_marking_refs
--     * Slot: StixDomainName_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixEmailAddress_object_marking_refs
--     * Slot: StixEmailAddress_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixEmailMessage_to_refs
--     * Slot: StixEmailMessage_id Description: Autocreated FK slot
--     * Slot: to_refs_id Description: Specifies the mailboxes that are 'To:' recipients of the email message.
-- # Class: StixEmailMessage_cc_refs
--     * Slot: StixEmailMessage_id Description: Autocreated FK slot
--     * Slot: cc_refs_id Description: Specifies the mailboxes that are 'CC:' recipients of the email message.
-- # Class: StixEmailMessage_bcc_refs
--     * Slot: StixEmailMessage_id Description: Autocreated FK slot
--     * Slot: bcc_refs_id Description: Specifies the mailboxes that are 'BCC:' recipients of the email message.
-- # Class: StixEmailMessage_received_lines
--     * Slot: StixEmailMessage_id Description: Autocreated FK slot
--     * Slot: received_lines Description: Specifies one or more Received header fields that may be included in the email headers.
-- # Class: StixEmailMessage_object_marking_refs
--     * Slot: StixEmailMessage_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixFile_contains_refs
--     * Slot: StixFile_id Description: Autocreated FK slot
--     * Slot: contains_refs_id Description: References to other cyber-observable objects that this one contains.
-- # Class: StixFile_object_marking_refs
--     * Slot: StixFile_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixIpv4Address_resolves_to_refs
--     * Slot: StixIpv4Address_id Description: Autocreated FK slot
--     * Slot: resolves_to_refs_id Description: References to the cyber-observable objects that this one resolves to.
-- # Class: StixIpv4Address_belongs_to_refs
--     * Slot: StixIpv4Address_id Description: Autocreated FK slot
--     * Slot: belongs_to_refs_id Description: References to the autonomous systems that this address belongs to.
-- # Class: StixIpv4Address_object_marking_refs
--     * Slot: StixIpv4Address_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixIpv6Address_resolves_to_refs
--     * Slot: StixIpv6Address_id Description: Autocreated FK slot
--     * Slot: resolves_to_refs_id Description: References to the cyber-observable objects that this one resolves to.
-- # Class: StixIpv6Address_belongs_to_refs
--     * Slot: StixIpv6Address_id Description: Autocreated FK slot
--     * Slot: belongs_to_refs_id Description: References to the autonomous systems that this address belongs to.
-- # Class: StixIpv6Address_object_marking_refs
--     * Slot: StixIpv6Address_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixMacAddress_object_marking_refs
--     * Slot: StixMacAddress_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixMutex_object_marking_refs
--     * Slot: StixMutex_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixNetworkTraffic_protocols
--     * Slot: StixNetworkTraffic_id Description: Autocreated FK slot
--     * Slot: protocols Description: Specifies the protocols observed in the network traffic, along with their corresponding state.
-- # Class: StixNetworkTraffic_encapsulates_refs
--     * Slot: StixNetworkTraffic_id Description: Autocreated FK slot
--     * Slot: encapsulates_refs_id Description: Links to other network-traffic objects encapsulated by a network-traffic.
-- # Class: StixNetworkTraffic_object_marking_refs
--     * Slot: StixNetworkTraffic_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixProcess_opened_connection_refs
--     * Slot: StixProcess_id Description: Autocreated FK slot
--     * Slot: opened_connection_refs_id Description: Specifies the list of network connections opened by the process, as a reference to one or more Network Traffic Objects.
-- # Class: StixProcess_child_refs
--     * Slot: StixProcess_id Description: Autocreated FK slot
--     * Slot: child_refs_id Description: Specifies the other processes that were spawned by (i.e. children of) this process, as a reference to one or more other Process Objects.
-- # Class: StixProcess_object_marking_refs
--     * Slot: StixProcess_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixSoftware_languages
--     * Slot: StixSoftware_id Description: Autocreated FK slot
--     * Slot: languages Description: Specifies the languages supported by the software. The value of each list member MUST be an RFC 5646 language code. ISO 639-2 codes are accepted for backward compatibility.
-- # Class: StixSoftware_object_marking_refs
--     * Slot: StixSoftware_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixUrl_object_marking_refs
--     * Slot: StixUrl_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixUserAccount_object_marking_refs
--     * Slot: StixUserAccount_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixWindowsRegistryKey_object_marking_refs
--     * Slot: StixWindowsRegistryKey_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixX509Certificate_object_marking_refs
--     * Slot: StixX509Certificate_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixArchiveExtension_contains_refs
--     * Slot: StixArchiveExtension_id Description: Autocreated FK slot
--     * Slot: contains_refs_id Description: References to other cyber-observable objects that this one contains.
-- # Class: StixWindowsServiceExtension_descriptions
--     * Slot: StixWindowsServiceExtension_id Description: Autocreated FK slot
--     * Slot: descriptions Description: Specifies the descriptions defined for the service.
-- # Class: StixWindowsServiceExtension_service_dll_refs
--     * Slot: StixWindowsServiceExtension_id Description: Autocreated FK slot
--     * Slot: service_dll_refs_id Description: Specifies the DLLs loaded by the service, as a reference to one or more File Objects.
-- # Class: StixUnixAccountExtension_groups
--     * Slot: StixUnixAccountExtension_id Description: Autocreated FK slot
--     * Slot: groups Description: Specifies a list of names of groups that the account is a member of.
-- # Class: StixAttackPattern_aliases
--     * Slot: StixAttackPattern_id Description: Autocreated FK slot
--     * Slot: aliases Description: Other names by which the object is known.
-- # Class: StixAttackPattern_labels
--     * Slot: StixAttackPattern_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixAttackPattern_object_marking_refs
--     * Slot: StixAttackPattern_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixCampaign_aliases
--     * Slot: StixCampaign_id Description: Autocreated FK slot
--     * Slot: aliases Description: Other names by which the object is known.
-- # Class: StixCampaign_labels
--     * Slot: StixCampaign_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixCampaign_object_marking_refs
--     * Slot: StixCampaign_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixCourseOfAction_labels
--     * Slot: StixCourseOfAction_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixCourseOfAction_object_marking_refs
--     * Slot: StixCourseOfAction_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixGrouping_object_refs
--     * Slot: StixGrouping_id Description: Autocreated FK slot
--     * Slot: object_refs_id Description: References to the STIX objects that this object is about or holds.
-- # Class: StixGrouping_labels
--     * Slot: StixGrouping_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixGrouping_object_marking_refs
--     * Slot: StixGrouping_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixIncident_labels
--     * Slot: StixIncident_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixIncident_object_marking_refs
--     * Slot: StixIncident_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixIndicator_indicator_types
--     * Slot: StixIndicator_id Description: Autocreated FK slot
--     * Slot: indicator_types Description: This field is an Open Vocabulary that specifies the type of indicator. Open vocab - indicator-type-ov.
-- # Class: StixIndicator_labels
--     * Slot: StixIndicator_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixIndicator_object_marking_refs
--     * Slot: StixIndicator_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixInfrastructure_infrastructure_types
--     * Slot: StixInfrastructure_id Description: Autocreated FK slot
--     * Slot: infrastructure_types Description: This field is an Open Vocabulary that specifies the type of infrastructure. Open vocab - infrastructure-type-ov.
-- # Class: StixInfrastructure_aliases
--     * Slot: StixInfrastructure_id Description: Autocreated FK slot
--     * Slot: aliases Description: Other names by which the object is known.
-- # Class: StixInfrastructure_labels
--     * Slot: StixInfrastructure_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixInfrastructure_object_marking_refs
--     * Slot: StixInfrastructure_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixIntrusionSet_aliases
--     * Slot: StixIntrusionSet_id Description: Autocreated FK slot
--     * Slot: aliases Description: Other names by which the object is known.
-- # Class: StixIntrusionSet_goals
--     * Slot: StixIntrusionSet_id Description: Autocreated FK slot
--     * Slot: goals Description: The high-level goals.
-- # Class: StixIntrusionSet_secondary_motivations
--     * Slot: StixIntrusionSet_id Description: Autocreated FK slot
--     * Slot: secondary_motivations Description: The secondary reasons, motivations or purposes behind the activity.
-- # Class: StixIntrusionSet_labels
--     * Slot: StixIntrusionSet_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixIntrusionSet_object_marking_refs
--     * Slot: StixIntrusionSet_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixLocation_labels
--     * Slot: StixLocation_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixLocation_object_marking_refs
--     * Slot: StixLocation_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixMalware_aliases
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: aliases Description: Other names by which the object is known.
-- # Class: StixMalware_operating_system_refs
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: operating_system_refs_id Description: The operating systems that the malware family or malware instance is executable on.
-- # Class: StixMalware_architecture_execution_envs
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: architecture_execution_envs Description: The processor architectures (e.g., x86, ARM, etc.) that the malware instance or family is executable on. Open Vocab - processor-architecture-os.
-- # Class: StixMalware_implementation_languages
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: implementation_languages Description: The programming language(s) used to implement the malware instance or family. Open Vocab - implementation-language-ov.
-- # Class: StixMalware_capabilities
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: capabilities Description: Specifies any capabilities identified for the malware instance or family. Open Vocab - malware-capabilities-ov.
-- # Class: StixMalware_sample_refs
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: sample_refs_id Description: The sample_refs property specifies a list of identifiers of the SCO file or artifact objects associated with this malware instance(s) or family.
-- # Class: StixMalware_malware_types
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: malware_types Description: The type of malware being described. Open Vocab - malware-type-ov.
-- # Class: StixMalware_labels
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixMalware_object_marking_refs
--     * Slot: StixMalware_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixMalwareAnalysis_modules
--     * Slot: StixMalwareAnalysis_id Description: Autocreated FK slot
--     * Slot: modules Description: The particular analysis product modules that were used to perform the analysis.
-- # Class: StixMalwareAnalysis_installed_software_refs
--     * Slot: StixMalwareAnalysis_id Description: Autocreated FK slot
--     * Slot: installed_software_refs_id Description: Any non-standard software installed on the operating system used for the dynamic analysis of the malware instance or family.
-- # Class: StixMalwareAnalysis_analysis_sco_refs
--     * Slot: StixMalwareAnalysis_id Description: Autocreated FK slot
--     * Slot: analysis_sco_refs_id Description: The list of STIX objects that were captured during the analysis process.
-- # Class: StixMalwareAnalysis_labels
--     * Slot: StixMalwareAnalysis_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixMalwareAnalysis_object_marking_refs
--     * Slot: StixMalwareAnalysis_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixNote_authors
--     * Slot: StixNote_id Description: Autocreated FK slot
--     * Slot: authors Description: The name of the author(s) of this note (e.g., the analyst(s) that created it).
-- # Class: StixNote_object_refs
--     * Slot: StixNote_id Description: Autocreated FK slot
--     * Slot: object_refs_id Description: References to the STIX objects that this object is about or holds.
-- # Class: StixNote_labels
--     * Slot: StixNote_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixNote_object_marking_refs
--     * Slot: StixNote_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixObservedData_object_refs
--     * Slot: StixObservedData_id Description: Autocreated FK slot
--     * Slot: object_refs_id Description: References to the STIX objects that this object is about or holds.
-- # Class: StixObservedData_labels
--     * Slot: StixObservedData_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixObservedData_object_marking_refs
--     * Slot: StixObservedData_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixOpinion_authors
--     * Slot: StixOpinion_id Description: Autocreated FK slot
--     * Slot: authors Description: The name of the author(s) of this note (e.g., the analyst(s) that created it).
-- # Class: StixOpinion_object_refs
--     * Slot: StixOpinion_id Description: Autocreated FK slot
--     * Slot: object_refs_id Description: References to the STIX objects that this object is about or holds.
-- # Class: StixOpinion_labels
--     * Slot: StixOpinion_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixOpinion_object_marking_refs
--     * Slot: StixOpinion_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixReport_report_types
--     * Slot: StixReport_id Description: Autocreated FK slot
--     * Slot: report_types Description: This field is an Open Vocabulary that specifies the primary subject of this report. The suggested values for this field are in report-type-ov.
-- # Class: StixReport_object_refs
--     * Slot: StixReport_id Description: Autocreated FK slot
--     * Slot: object_refs_id Description: References to the STIX objects that this object is about or holds.
-- # Class: StixReport_labels
--     * Slot: StixReport_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixReport_object_marking_refs
--     * Slot: StixReport_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixThreatActor_threat_actor_types
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: threat_actor_types Description: This field specifies the type of threat actor. Open Vocab - threat-actor-type-ov.
-- # Class: StixThreatActor_aliases
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: aliases Description: Other names by which the object is known.
-- # Class: StixThreatActor_roles
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: roles Description: The roles that the identity or threat actor plays.
-- # Class: StixThreatActor_goals
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: goals Description: The high-level goals.
-- # Class: StixThreatActor_secondary_motivations
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: secondary_motivations Description: The secondary reasons, motivations or purposes behind the activity.
-- # Class: StixThreatActor_personal_motivations
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: personal_motivations Description: The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals. Open Vocab - attack-motivation-ov.
-- # Class: StixThreatActor_labels
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixThreatActor_object_marking_refs
--     * Slot: StixThreatActor_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixTool_aliases
--     * Slot: StixTool_id Description: Autocreated FK slot
--     * Slot: aliases Description: Other names by which the object is known.
-- # Class: StixTool_tool_types
--     * Slot: StixTool_id Description: Autocreated FK slot
--     * Slot: tool_types Description: The kind(s) of tool(s) being described. Open Vocab - tool-type-ov.
-- # Class: StixTool_labels
--     * Slot: StixTool_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixTool_object_marking_refs
--     * Slot: StixTool_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixVulnerability_labels
--     * Slot: StixVulnerability_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixVulnerability_object_marking_refs
--     * Slot: StixVulnerability_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixRelationship_labels
--     * Slot: StixRelationship_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixRelationship_object_marking_refs
--     * Slot: StixRelationship_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.
-- # Class: StixSighting_observed_data_refs
--     * Slot: StixSighting_id Description: Autocreated FK slot
--     * Slot: observed_data_refs_id Description: A list of ID references to the Observed Data objects that contain the raw cyber data for this Sighting.
-- # Class: StixSighting_where_sighted_refs
--     * Slot: StixSighting_id Description: Autocreated FK slot
--     * Slot: where_sighted_refs_id Description: A list of ID references to the Identity or Location objects describing the entities or types of entities that saw the sighting.
-- # Class: StixSighting_labels
--     * Slot: StixSighting_id Description: Autocreated FK slot
--     * Slot: labels Description: The labels property specifies a set of terms used to describe this object.
-- # Class: StixSighting_object_marking_refs
--     * Slot: StixSighting_id Description: Autocreated FK slot
--     * Slot: object_marking_refs_id Description: References to the marking definitions that apply to the object.

CREATE TABLE "StixBundle" (
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixBundle_id" ON "StixBundle" (id);

CREATE TABLE "StixStatementMarking" (
	id INTEGER NOT NULL,
	statement TEXT NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixStatementMarking_id" ON "StixStatementMarking" (id);

CREATE TABLE "StixTlpMarking" (
	id INTEGER NOT NULL,
	tlp VARCHAR(5) NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixTlpMarking_id" ON "StixTlpMarking" (id);

CREATE TABLE "StixExtension" (
	id INTEGER NOT NULL,
	extension_type VARCHAR(27) NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixExtension_id" ON "StixExtension" (id);

CREATE TABLE "StixHashes" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixHashes_id" ON "StixHashes" (id);

CREATE TABLE "StixExtensions" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixExtensions_id" ON "StixExtensions" (id);

CREATE TABLE "StixDictionary" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixDictionary_id" ON "StixDictionary" (id);

CREATE TABLE "StixLanguageContents" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixLanguageContents_id" ON "StixLanguageContents" (id);

CREATE TABLE "StixNtfsExtension" (
	id INTEGER NOT NULL,
	sid TEXT,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixNtfsExtension_id" ON "StixNtfsExtension" (id);

CREATE TABLE "StixArchiveExtension" (
	id INTEGER NOT NULL,
	comment TEXT,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixArchiveExtension_id" ON "StixArchiveExtension" (id);

CREATE TABLE "StixIcmpExtension" (
	id INTEGER NOT NULL,
	icmp_type_hex TEXT NOT NULL,
	icmp_code_hex TEXT NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixIcmpExtension_id" ON "StixIcmpExtension" (id);

CREATE TABLE "StixTcpExtension" (
	id INTEGER NOT NULL,
	src_flags_hex TEXT,
	dst_flags_hex TEXT,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixTcpExtension_id" ON "StixTcpExtension" (id);

CREATE TABLE "StixWindowsServiceExtension" (
	id INTEGER NOT NULL,
	service_name TEXT,
	display_name TEXT,
	group_name TEXT,
	start_type VARCHAR(20),
	service_type VARCHAR(27),
	service_status VARCHAR(24),
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixWindowsServiceExtension_id" ON "StixWindowsServiceExtension" (id);

CREATE TABLE "StixUnixAccountExtension" (
	id INTEGER NOT NULL,
	gid FLOAT,
	home_dir TEXT,
	shell TEXT,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixUnixAccountExtension_id" ON "StixUnixAccountExtension" (id);

CREATE TABLE "StixX509V3Extensions" (
	id INTEGER NOT NULL,
	basic_constraints TEXT,
	name_constraints TEXT,
	policy_constraints TEXT,
	key_usage TEXT,
	extended_key_usage TEXT,
	subject_key_identifier TEXT,
	authority_key_identifier TEXT,
	subject_alternative_name TEXT,
	issuer_alternative_name TEXT,
	subject_directory_attributes TEXT,
	crl_distribution_points TEXT,
	inhibit_any_policy TEXT,
	private_key_usage_period_not_before TEXT,
	private_key_usage_period_not_after TEXT,
	certificate_policies TEXT,
	policy_mappings TEXT,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixX509V3Extensions_id" ON "StixX509V3Extensions" (id);

CREATE TABLE "StixFileExtensions" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixFileExtensions_id" ON "StixFileExtensions" (id);

CREATE TABLE "StixNetworkTrafficExtensions" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixNetworkTrafficExtensions_id" ON "StixNetworkTrafficExtensions" (id);

CREATE TABLE "StixProcessExtensions" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixProcessExtensions_id" ON "StixProcessExtensions" (id);

CREATE TABLE "StixUserAccountExtensions" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixUserAccountExtensions_id" ON "StixUserAccountExtensions" (id);

CREATE TABLE "StixSocketOptions" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixSocketOptions_id" ON "StixSocketOptions" (id);

CREATE TABLE "StixExifTags" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixExifTags_id" ON "StixExifTags" (id);

CREATE TABLE "StixPdfDocumentInfo" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixPdfDocumentInfo_id" ON "StixPdfDocumentInfo" (id);

CREATE TABLE "StixObservedObjects" (
	id INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX "ix_StixObservedObjects_id" ON "StixObservedObjects" (id);

CREATE TABLE "StixObject" (
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	"StixBundle_id" TEXT,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY("StixBundle_id") REFERENCES "StixBundle" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixObject_id" ON "StixObject" (id);

CREATE TABLE "StixCyberObservableObject" (
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixCyberObservableObject_id" ON "StixCyberObservableObject" (id);

CREATE TABLE "StixIdentity" (
	name TEXT NOT NULL,
	description TEXT,
	identity_class TEXT,
	contact_information TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixIdentity_id" ON "StixIdentity" (id);

CREATE TABLE "StixArtifact" (
	mime_type TEXT,
	payload_bin TEXT,
	url TEXT,
	encryption_algorithm VARCHAR(19),
	decryption_key TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	hashes_id INTEGER,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(hashes_id) REFERENCES "StixHashes" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixArtifact_id" ON "StixArtifact" (id);

CREATE TABLE "StixAutonomousSystem" (
	number INTEGER NOT NULL,
	name TEXT,
	rir TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixAutonomousSystem_id" ON "StixAutonomousSystem" (id);

CREATE TABLE "StixDirectory" (
	path TEXT NOT NULL,
	path_enc TEXT,
	ctime TEXT,
	mtime TEXT,
	atime TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixDirectory_id" ON "StixDirectory" (id);

CREATE TABLE "StixDomainName" (
	value TEXT NOT NULL,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixDomainName_id" ON "StixDomainName" (id);

CREATE TABLE "StixIpv4Address" (
	value TEXT NOT NULL,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixIpv4Address_id" ON "StixIpv4Address" (id);

CREATE TABLE "StixIpv6Address" (
	value TEXT NOT NULL,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixIpv6Address_id" ON "StixIpv6Address" (id);

CREATE TABLE "StixMacAddress" (
	value TEXT NOT NULL,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixMacAddress_id" ON "StixMacAddress" (id);

CREATE TABLE "StixMutex" (
	name TEXT NOT NULL,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixMutex_id" ON "StixMutex" (id);

CREATE TABLE "StixSoftware" (
	name TEXT NOT NULL,
	cpe TEXT,
	swid TEXT,
	vendor TEXT,
	version TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixSoftware_id" ON "StixSoftware" (id);

CREATE TABLE "StixUrl" (
	value TEXT NOT NULL,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixUrl_id" ON "StixUrl" (id);

CREATE TABLE "StixUserAccount" (
	user_id TEXT,
	credential TEXT,
	account_login TEXT,
	account_type TEXT,
	display_name TEXT,
	is_service_account BOOLEAN,
	is_privileged BOOLEAN,
	can_escalate_privs BOOLEAN,
	is_disabled BOOLEAN,
	account_created TEXT,
	account_expires TEXT,
	credential_last_changed TEXT,
	account_first_login TEXT,
	account_last_login TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixUserAccountExtensions" (id)
);
CREATE INDEX "ix_StixUserAccount_id" ON "StixUserAccount" (id);

CREATE TABLE "StixX509Certificate" (
	is_self_signed BOOLEAN,
	version TEXT,
	serial_number TEXT,
	signature_algorithm TEXT,
	issuer TEXT,
	validity_not_before TEXT,
	validity_not_after TEXT,
	subject TEXT,
	subject_public_key_algorithm TEXT,
	subject_public_key_modulus TEXT,
	subject_public_key_exponent INTEGER,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	hashes_id INTEGER,
	x509_v3_extensions_id INTEGER,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(hashes_id) REFERENCES "StixHashes" (id),
	FOREIGN KEY(x509_v3_extensions_id) REFERENCES "StixX509V3Extensions" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixX509Certificate_id" ON "StixX509Certificate" (id);

CREATE TABLE "StixRasterImageExtension" (
	id INTEGER NOT NULL,
	image_height INTEGER,
	image_width INTEGER,
	bits_per_pixel INTEGER,
	exif_tags_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(exif_tags_id) REFERENCES "StixExifTags" (id)
);
CREATE INDEX "ix_StixRasterImageExtension_id" ON "StixRasterImageExtension" (id);

CREATE TABLE "StixPdfExtension" (
	id INTEGER NOT NULL,
	version TEXT,
	is_optimized BOOLEAN,
	pdfid0 TEXT,
	pdfid1 TEXT,
	document_info_dict_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(document_info_dict_id) REFERENCES "StixPdfDocumentInfo" (id)
);
CREATE INDEX "ix_StixPdfExtension_id" ON "StixPdfExtension" (id);

CREATE TABLE "StixSocketExtension" (
	id INTEGER NOT NULL,
	address_family VARCHAR(12) NOT NULL,
	is_blocking BOOLEAN,
	is_listening BOOLEAN,
	socket_type VARCHAR(14),
	socket_descriptor INTEGER,
	socket_handle INTEGER,
	options_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(options_id) REFERENCES "StixSocketOptions" (id)
);
CREATE INDEX "ix_StixSocketExtension_id" ON "StixSocketExtension" (id);

CREATE TABLE "StixWindowsProcessExtension" (
	id INTEGER NOT NULL,
	aslr_enabled BOOLEAN,
	dep_enabled BOOLEAN,
	priority TEXT,
	owner_sid TEXT,
	window_title TEXT,
	integrity_level VARCHAR(6),
	startup_info_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(startup_info_id) REFERENCES "StixDictionary" (id)
);
CREATE INDEX "ix_StixWindowsProcessExtension_id" ON "StixWindowsProcessExtension" (id);

CREATE TABLE "StixAlternateDataStream" (
	id INTEGER NOT NULL,
	name TEXT NOT NULL,
	size INTEGER,
	"StixNtfsExtension_id" INTEGER,
	hashes_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY("StixNtfsExtension_id") REFERENCES "StixNtfsExtension" (id),
	FOREIGN KEY(hashes_id) REFERENCES "StixHashes" (id)
);
CREATE INDEX "ix_StixAlternateDataStream_id" ON "StixAlternateDataStream" (id);

CREATE TABLE "StixWindowsPeOptionalHeader" (
	id INTEGER NOT NULL,
	magic_hex TEXT,
	major_linker_version INTEGER,
	minor_linker_version INTEGER,
	size_of_code INTEGER,
	size_of_initialized_data INTEGER,
	size_of_uninitialized_data INTEGER,
	address_of_entry_point INTEGER,
	base_of_code INTEGER,
	base_of_data INTEGER,
	image_base INTEGER,
	section_alignment INTEGER,
	file_alignment INTEGER,
	major_os_version INTEGER,
	minor_os_version INTEGER,
	major_image_version INTEGER,
	minor_image_version INTEGER,
	major_subsystem_version INTEGER,
	minor_subsystem_version INTEGER,
	win32_version_value_hex TEXT,
	size_of_image INTEGER,
	size_of_headers INTEGER,
	checksum_hex TEXT,
	subsystem_hex TEXT,
	dll_characteristics_hex TEXT,
	size_of_stack_reserve INTEGER,
	size_of_stack_commit INTEGER,
	size_of_heap_reserve INTEGER,
	size_of_heap_commit INTEGER,
	loader_flags_hex TEXT,
	number_of_rva_and_sizes INTEGER,
	hashes_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(hashes_id) REFERENCES "StixHashes" (id)
);
CREATE INDEX "ix_StixWindowsPeOptionalHeader_id" ON "StixWindowsPeOptionalHeader" (id);

CREATE TABLE "StixWindowsServiceExtension_descriptions" (
	"StixWindowsServiceExtension_id" INTEGER,
	descriptions TEXT,
	PRIMARY KEY ("StixWindowsServiceExtension_id", descriptions),
	FOREIGN KEY("StixWindowsServiceExtension_id") REFERENCES "StixWindowsServiceExtension" (id)
);
CREATE INDEX "ix_StixWindowsServiceExtension_descriptions_descriptions" ON "StixWindowsServiceExtension_descriptions" (descriptions);
CREATE INDEX "ix_StixWindowsServiceExtension_descriptions_StixWindowsServiceExtension_id" ON "StixWindowsServiceExtension_descriptions" ("StixWindowsServiceExtension_id");

CREATE TABLE "StixUnixAccountExtension_groups" (
	"StixUnixAccountExtension_id" INTEGER,
	groups TEXT,
	PRIMARY KEY ("StixUnixAccountExtension_id", groups),
	FOREIGN KEY("StixUnixAccountExtension_id") REFERENCES "StixUnixAccountExtension" (id)
);
CREATE INDEX "ix_StixUnixAccountExtension_groups_groups" ON "StixUnixAccountExtension_groups" (groups);
CREATE INDEX "ix_StixUnixAccountExtension_groups_StixUnixAccountExtension_id" ON "StixUnixAccountExtension_groups" ("StixUnixAccountExtension_id");

CREATE TABLE "StixCommonObject" (
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixCommonObject_id" ON "StixCommonObject" (id);

CREATE TABLE "StixDomainObject" (
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixDomainObject_id" ON "StixDomainObject" (id);

CREATE TABLE "StixRelationshipObject" (
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixRelationshipObject_id" ON "StixRelationshipObject" (id);

CREATE TABLE "StixMarkingDefinition" (
	created_by_ref TEXT,
	created TEXT NOT NULL,
	name TEXT,
	definition_type TEXT,
	definition TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixMarkingDefinition_id" ON "StixMarkingDefinition" (id);

CREATE TABLE "StixLanguageContent" (
	object_ref TEXT NOT NULL,
	object_modified TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	contents_id INTEGER NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(object_ref) REFERENCES "StixObject" (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(contents_id) REFERENCES "StixLanguageContents" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixLanguageContent_id" ON "StixLanguageContent" (id);

CREATE TABLE "StixExtensionDefinition" (
	name TEXT NOT NULL,
	description TEXT,
	schema TEXT NOT NULL,
	version TEXT NOT NULL,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixExtensionDefinition_id" ON "StixExtensionDefinition" (id);

CREATE TABLE "StixEmailAddress" (
	value TEXT NOT NULL,
	display_name TEXT,
	belongs_to_ref TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(belongs_to_ref) REFERENCES "StixUserAccount" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixEmailAddress_id" ON "StixEmailAddress" (id);

CREATE TABLE "StixFile" (
	size INTEGER,
	name TEXT,
	name_enc TEXT,
	magic_number_hex TEXT,
	mime_type TEXT,
	ctime TEXT,
	mtime TEXT,
	atime TEXT,
	parent_directory_ref TEXT,
	content_ref TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	hashes_id INTEGER,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(parent_directory_ref) REFERENCES "StixDirectory" (id),
	FOREIGN KEY(content_ref) REFERENCES "StixArtifact" (id),
	FOREIGN KEY(hashes_id) REFERENCES "StixHashes" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixFileExtensions" (id)
);
CREATE INDEX "ix_StixFile_id" ON "StixFile" (id);

CREATE TABLE "StixNetworkTraffic" (
	start TEXT,
	"end" TEXT,
	src_ref TEXT,
	dst_ref TEXT,
	src_port INTEGER,
	dst_port INTEGER,
	src_byte_count INTEGER,
	dst_byte_count INTEGER,
	src_packets INTEGER,
	dst_packets INTEGER,
	src_payload_ref TEXT,
	dst_payload_ref TEXT,
	encapsulated_by_ref TEXT,
	is_active BOOLEAN,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	ipfix_id INTEGER,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(src_ref) REFERENCES "StixCyberObservableObject" (id),
	FOREIGN KEY(dst_ref) REFERENCES "StixCyberObservableObject" (id),
	FOREIGN KEY(src_payload_ref) REFERENCES "StixArtifact" (id),
	FOREIGN KEY(dst_payload_ref) REFERENCES "StixArtifact" (id),
	FOREIGN KEY(encapsulated_by_ref) REFERENCES "StixNetworkTraffic" (id),
	FOREIGN KEY(ipfix_id) REFERENCES "StixDictionary" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixNetworkTrafficExtensions" (id)
);
CREATE INDEX "ix_StixNetworkTraffic_id" ON "StixNetworkTraffic" (id);

CREATE TABLE "StixWindowsRegistryKey" (
	"key" TEXT,
	modified_time TEXT,
	creator_user_ref TEXT,
	number_of_subkeys INTEGER,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(creator_user_ref) REFERENCES "StixUserAccount" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixWindowsRegistryKey_id" ON "StixWindowsRegistryKey" (id);

CREATE TABLE "StixWindowsPeBinaryExtension" (
	id INTEGER NOT NULL,
	pe_type TEXT NOT NULL,
	imphash TEXT,
	machine_hex TEXT,
	number_of_sections INTEGER,
	time_date_stamp TEXT,
	pointer_to_symbol_table_hex TEXT,
	number_of_symbols INTEGER,
	size_of_optional_header INTEGER,
	characteristics_hex TEXT,
	file_header_hashes_id INTEGER,
	optional_header_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(file_header_hashes_id) REFERENCES "StixHashes" (id),
	FOREIGN KEY(optional_header_id) REFERENCES "StixWindowsPeOptionalHeader" (id)
);
CREATE INDEX "ix_StixWindowsPeBinaryExtension_id" ON "StixWindowsPeBinaryExtension" (id);

CREATE TABLE "StixHttpRequestExtension" (
	id INTEGER NOT NULL,
	request_method TEXT NOT NULL,
	request_value TEXT NOT NULL,
	request_version TEXT,
	message_body_length INTEGER,
	message_body_data_ref TEXT,
	request_header_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(message_body_data_ref) REFERENCES "StixArtifact" (id),
	FOREIGN KEY(request_header_id) REFERENCES "StixDictionary" (id)
);
CREATE INDEX "ix_StixHttpRequestExtension_id" ON "StixHttpRequestExtension" (id);

CREATE TABLE "StixAttackPattern" (
	name TEXT NOT NULL,
	description TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixAttackPattern_id" ON "StixAttackPattern" (id);

CREATE TABLE "StixCampaign" (
	name TEXT NOT NULL,
	description TEXT,
	first_seen TEXT,
	last_seen TEXT,
	objective TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixCampaign_id" ON "StixCampaign" (id);

CREATE TABLE "StixCourseOfAction" (
	name TEXT NOT NULL,
	description TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixCourseOfAction_id" ON "StixCourseOfAction" (id);

CREATE TABLE "StixGrouping" (
	name TEXT,
	description TEXT,
	context TEXT NOT NULL,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixGrouping_id" ON "StixGrouping" (id);

CREATE TABLE "StixIncident" (
	name TEXT NOT NULL,
	description TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixIncident_id" ON "StixIncident" (id);

CREATE TABLE "StixIndicator" (
	name TEXT,
	description TEXT,
	pattern TEXT NOT NULL,
	pattern_type TEXT NOT NULL,
	pattern_version TEXT,
	valid_from TEXT NOT NULL,
	valid_until TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixIndicator_id" ON "StixIndicator" (id);

CREATE TABLE "StixInfrastructure" (
	name TEXT NOT NULL,
	description TEXT,
	first_seen TEXT,
	last_seen TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixInfrastructure_id" ON "StixInfrastructure" (id);

CREATE TABLE "StixIntrusionSet" (
	name TEXT NOT NULL,
	description TEXT,
	first_seen TEXT,
	last_seen TEXT,
	resource_level TEXT,
	primary_motivation TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixIntrusionSet_id" ON "StixIntrusionSet" (id);

CREATE TABLE "StixLocation" (
	description TEXT,
	name TEXT,
	latitude FLOAT,
	longitude FLOAT,
	precision FLOAT,
	region TEXT,
	country TEXT,
	administrative_area TEXT,
	city TEXT,
	street_address TEXT,
	postal_code TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixLocation_id" ON "StixLocation" (id);

CREATE TABLE "StixMalware" (
	first_seen TEXT,
	last_seen TEXT,
	name TEXT,
	description TEXT,
	is_family BOOLEAN NOT NULL,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixMalware_id" ON "StixMalware" (id);

CREATE TABLE "StixMalwareAnalysis" (
	product TEXT NOT NULL,
	version TEXT,
	configuration_version TEXT,
	analysis_engine_version TEXT,
	analysis_definition_version TEXT,
	submitted TEXT,
	analysis_started TEXT,
	analysis_ended TEXT,
	result_name TEXT,
	result TEXT,
	host_vm_ref TEXT,
	operating_system_ref TEXT,
	sample_ref TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(host_vm_ref) REFERENCES "StixSoftware" (id),
	FOREIGN KEY(operating_system_ref) REFERENCES "StixSoftware" (id),
	FOREIGN KEY(sample_ref) REFERENCES "StixCyberObservableObject" (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixMalwareAnalysis_id" ON "StixMalwareAnalysis" (id);

CREATE TABLE "StixNote" (
	abstract TEXT,
	content TEXT NOT NULL,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixNote_id" ON "StixNote" (id);

CREATE TABLE "StixObservedData" (
	first_observed TEXT NOT NULL,
	last_observed TEXT NOT NULL,
	number_observed INTEGER NOT NULL,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	objects_id INTEGER,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(objects_id) REFERENCES "StixObservedObjects" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixObservedData_id" ON "StixObservedData" (id);

CREATE TABLE "StixOpinion" (
	explanation TEXT,
	opinion VARCHAR(17) NOT NULL,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixOpinion_id" ON "StixOpinion" (id);

CREATE TABLE "StixReport" (
	name TEXT NOT NULL,
	description TEXT,
	published TEXT NOT NULL,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixReport_id" ON "StixReport" (id);

CREATE TABLE "StixThreatActor" (
	name TEXT NOT NULL,
	description TEXT,
	first_seen TEXT,
	last_seen TEXT,
	sophistication TEXT,
	resource_level TEXT,
	primary_motivation TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixThreatActor_id" ON "StixThreatActor" (id);

CREATE TABLE "StixTool" (
	name TEXT NOT NULL,
	description TEXT,
	tool_version TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixTool_id" ON "StixTool" (id);

CREATE TABLE "StixVulnerability" (
	name TEXT NOT NULL,
	description TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixVulnerability_id" ON "StixVulnerability" (id);

CREATE TABLE "StixRelationship" (
	relationship_type TEXT NOT NULL,
	description TEXT,
	source_ref TEXT NOT NULL,
	target_ref TEXT NOT NULL,
	start_time TEXT,
	stop_time TEXT,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(source_ref) REFERENCES "StixObject" (id),
	FOREIGN KEY(target_ref) REFERENCES "StixObject" (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixRelationship_id" ON "StixRelationship" (id);

CREATE TABLE "StixIdentity_roles" (
	"StixIdentity_id" TEXT,
	roles TEXT,
	PRIMARY KEY ("StixIdentity_id", roles),
	FOREIGN KEY("StixIdentity_id") REFERENCES "StixIdentity" (id)
);
CREATE INDEX "ix_StixIdentity_roles_StixIdentity_id" ON "StixIdentity_roles" ("StixIdentity_id");
CREATE INDEX "ix_StixIdentity_roles_roles" ON "StixIdentity_roles" (roles);

CREATE TABLE "StixIdentity_sectors" (
	"StixIdentity_id" TEXT,
	sectors TEXT,
	PRIMARY KEY ("StixIdentity_id", sectors),
	FOREIGN KEY("StixIdentity_id") REFERENCES "StixIdentity" (id)
);
CREATE INDEX "ix_StixIdentity_sectors_StixIdentity_id" ON "StixIdentity_sectors" ("StixIdentity_id");
CREATE INDEX "ix_StixIdentity_sectors_sectors" ON "StixIdentity_sectors" (sectors);

CREATE TABLE "StixIdentity_labels" (
	"StixIdentity_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixIdentity_id", labels),
	FOREIGN KEY("StixIdentity_id") REFERENCES "StixIdentity" (id)
);
CREATE INDEX "ix_StixIdentity_labels_StixIdentity_id" ON "StixIdentity_labels" ("StixIdentity_id");
CREATE INDEX "ix_StixIdentity_labels_labels" ON "StixIdentity_labels" (labels);

CREATE TABLE "StixDirectory_contains_refs" (
	"StixDirectory_id" TEXT,
	contains_refs_id TEXT,
	PRIMARY KEY ("StixDirectory_id", contains_refs_id),
	FOREIGN KEY("StixDirectory_id") REFERENCES "StixDirectory" (id),
	FOREIGN KEY(contains_refs_id) REFERENCES "StixCyberObservableObject" (id)
);
CREATE INDEX "ix_StixDirectory_contains_refs_StixDirectory_id" ON "StixDirectory_contains_refs" ("StixDirectory_id");
CREATE INDEX "ix_StixDirectory_contains_refs_contains_refs_id" ON "StixDirectory_contains_refs" (contains_refs_id);

CREATE TABLE "StixDomainName_resolves_to_refs" (
	"StixDomainName_id" TEXT,
	resolves_to_refs_id TEXT,
	PRIMARY KEY ("StixDomainName_id", resolves_to_refs_id),
	FOREIGN KEY("StixDomainName_id") REFERENCES "StixDomainName" (id),
	FOREIGN KEY(resolves_to_refs_id) REFERENCES "StixCyberObservableObject" (id)
);
CREATE INDEX "ix_StixDomainName_resolves_to_refs_resolves_to_refs_id" ON "StixDomainName_resolves_to_refs" (resolves_to_refs_id);
CREATE INDEX "ix_StixDomainName_resolves_to_refs_StixDomainName_id" ON "StixDomainName_resolves_to_refs" ("StixDomainName_id");

CREATE TABLE "StixIpv4Address_resolves_to_refs" (
	"StixIpv4Address_id" TEXT,
	resolves_to_refs_id TEXT,
	PRIMARY KEY ("StixIpv4Address_id", resolves_to_refs_id),
	FOREIGN KEY("StixIpv4Address_id") REFERENCES "StixIpv4Address" (id),
	FOREIGN KEY(resolves_to_refs_id) REFERENCES "StixMacAddress" (id)
);
CREATE INDEX "ix_StixIpv4Address_resolves_to_refs_StixIpv4Address_id" ON "StixIpv4Address_resolves_to_refs" ("StixIpv4Address_id");
CREATE INDEX "ix_StixIpv4Address_resolves_to_refs_resolves_to_refs_id" ON "StixIpv4Address_resolves_to_refs" (resolves_to_refs_id);

CREATE TABLE "StixIpv4Address_belongs_to_refs" (
	"StixIpv4Address_id" TEXT,
	belongs_to_refs_id TEXT,
	PRIMARY KEY ("StixIpv4Address_id", belongs_to_refs_id),
	FOREIGN KEY("StixIpv4Address_id") REFERENCES "StixIpv4Address" (id),
	FOREIGN KEY(belongs_to_refs_id) REFERENCES "StixAutonomousSystem" (id)
);
CREATE INDEX "ix_StixIpv4Address_belongs_to_refs_StixIpv4Address_id" ON "StixIpv4Address_belongs_to_refs" ("StixIpv4Address_id");
CREATE INDEX "ix_StixIpv4Address_belongs_to_refs_belongs_to_refs_id" ON "StixIpv4Address_belongs_to_refs" (belongs_to_refs_id);

CREATE TABLE "StixIpv6Address_resolves_to_refs" (
	"StixIpv6Address_id" TEXT,
	resolves_to_refs_id TEXT,
	PRIMARY KEY ("StixIpv6Address_id", resolves_to_refs_id),
	FOREIGN KEY("StixIpv6Address_id") REFERENCES "StixIpv6Address" (id),
	FOREIGN KEY(resolves_to_refs_id) REFERENCES "StixMacAddress" (id)
);
CREATE INDEX "ix_StixIpv6Address_resolves_to_refs_resolves_to_refs_id" ON "StixIpv6Address_resolves_to_refs" (resolves_to_refs_id);
CREATE INDEX "ix_StixIpv6Address_resolves_to_refs_StixIpv6Address_id" ON "StixIpv6Address_resolves_to_refs" ("StixIpv6Address_id");

CREATE TABLE "StixIpv6Address_belongs_to_refs" (
	"StixIpv6Address_id" TEXT,
	belongs_to_refs_id TEXT,
	PRIMARY KEY ("StixIpv6Address_id", belongs_to_refs_id),
	FOREIGN KEY("StixIpv6Address_id") REFERENCES "StixIpv6Address" (id),
	FOREIGN KEY(belongs_to_refs_id) REFERENCES "StixAutonomousSystem" (id)
);
CREATE INDEX "ix_StixIpv6Address_belongs_to_refs_StixIpv6Address_id" ON "StixIpv6Address_belongs_to_refs" ("StixIpv6Address_id");
CREATE INDEX "ix_StixIpv6Address_belongs_to_refs_belongs_to_refs_id" ON "StixIpv6Address_belongs_to_refs" (belongs_to_refs_id);

CREATE TABLE "StixSoftware_languages" (
	"StixSoftware_id" TEXT,
	languages TEXT,
	PRIMARY KEY ("StixSoftware_id", languages),
	FOREIGN KEY("StixSoftware_id") REFERENCES "StixSoftware" (id)
);
CREATE INDEX "ix_StixSoftware_languages_languages" ON "StixSoftware_languages" (languages);
CREATE INDEX "ix_StixSoftware_languages_StixSoftware_id" ON "StixSoftware_languages" ("StixSoftware_id");

CREATE TABLE "StixArchiveExtension_contains_refs" (
	"StixArchiveExtension_id" INTEGER,
	contains_refs_id TEXT NOT NULL,
	PRIMARY KEY ("StixArchiveExtension_id", contains_refs_id),
	FOREIGN KEY("StixArchiveExtension_id") REFERENCES "StixArchiveExtension" (id),
	FOREIGN KEY(contains_refs_id) REFERENCES "StixCyberObservableObject" (id)
);
CREATE INDEX "ix_StixArchiveExtension_contains_refs_contains_refs_id" ON "StixArchiveExtension_contains_refs" (contains_refs_id);
CREATE INDEX "ix_StixArchiveExtension_contains_refs_StixArchiveExtension_id" ON "StixArchiveExtension_contains_refs" ("StixArchiveExtension_id");

CREATE TABLE "StixKillChainPhase" (
	id INTEGER NOT NULL,
	kill_chain_name TEXT NOT NULL,
	phase_name TEXT NOT NULL,
	"StixAttackPattern_id" TEXT,
	"StixIndicator_id" TEXT,
	"StixInfrastructure_id" TEXT,
	"StixMalware_id" TEXT,
	"StixTool_id" TEXT,
	PRIMARY KEY (id),
	FOREIGN KEY("StixAttackPattern_id") REFERENCES "StixAttackPattern" (id),
	FOREIGN KEY("StixIndicator_id") REFERENCES "StixIndicator" (id),
	FOREIGN KEY("StixInfrastructure_id") REFERENCES "StixInfrastructure" (id),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id),
	FOREIGN KEY("StixTool_id") REFERENCES "StixTool" (id)
);
CREATE INDEX "ix_StixKillChainPhase_id" ON "StixKillChainPhase" (id);

CREATE TABLE "StixEmailMessage" (
	date TEXT,
	content_type TEXT,
	from_ref TEXT,
	sender_ref TEXT,
	message_id TEXT,
	subject TEXT,
	raw_email_ref TEXT,
	is_multipart BOOLEAN NOT NULL,
	body TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	additional_header_fields_id INTEGER,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(from_ref) REFERENCES "StixEmailAddress" (id),
	FOREIGN KEY(sender_ref) REFERENCES "StixEmailAddress" (id),
	FOREIGN KEY(raw_email_ref) REFERENCES "StixArtifact" (id),
	FOREIGN KEY(additional_header_fields_id) REFERENCES "StixDictionary" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixEmailMessage_id" ON "StixEmailMessage" (id);

CREATE TABLE "StixProcess" (
	is_hidden BOOLEAN,
	pid INTEGER,
	created_time TEXT,
	cwd TEXT,
	command_line TEXT,
	creator_user_ref TEXT,
	image_ref TEXT,
	parent_ref TEXT,
	defanged BOOLEAN,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3),
	environment_variables_id INTEGER,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(creator_user_ref) REFERENCES "StixUserAccount" (id),
	FOREIGN KEY(image_ref) REFERENCES "StixFile" (id),
	FOREIGN KEY(parent_ref) REFERENCES "StixProcess" (id),
	FOREIGN KEY(environment_variables_id) REFERENCES "StixDictionary" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixProcessExtensions" (id)
);
CREATE INDEX "ix_StixProcess_id" ON "StixProcess" (id);

CREATE TABLE "StixWindowsPeSection" (
	id INTEGER NOT NULL,
	name TEXT NOT NULL,
	size INTEGER,
	entropy FLOAT,
	"StixWindowsPeBinaryExtension_id" INTEGER,
	hashes_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY("StixWindowsPeBinaryExtension_id") REFERENCES "StixWindowsPeBinaryExtension" (id),
	FOREIGN KEY(hashes_id) REFERENCES "StixHashes" (id)
);
CREATE INDEX "ix_StixWindowsPeSection_id" ON "StixWindowsPeSection" (id);

CREATE TABLE "StixWindowsRegistryValue" (
	id INTEGER NOT NULL,
	name TEXT,
	data TEXT,
	data_type VARCHAR(30),
	"StixWindowsRegistryKey_id" TEXT,
	PRIMARY KEY (id),
	FOREIGN KEY("StixWindowsRegistryKey_id") REFERENCES "StixWindowsRegistryKey" (id)
);
CREATE INDEX "ix_StixWindowsRegistryValue_id" ON "StixWindowsRegistryValue" (id);

CREATE TABLE "StixSighting" (
	description TEXT,
	first_seen TEXT,
	last_seen TEXT,
	count INTEGER,
	sighting_of_ref TEXT NOT NULL,
	summary BOOLEAN,
	created_by_ref TEXT,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	revoked BOOLEAN,
	confidence INTEGER,
	lang TEXT,
	id TEXT NOT NULL,
	type TEXT NOT NULL,
	spec_version VARCHAR(3) NOT NULL,
	extensions_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(sighting_of_ref) REFERENCES "StixDomainObject" (id),
	FOREIGN KEY(created_by_ref) REFERENCES "StixIdentity" (id),
	FOREIGN KEY(extensions_id) REFERENCES "StixExtensions" (id)
);
CREATE INDEX "ix_StixSighting_id" ON "StixSighting" (id);

CREATE TABLE "StixObject_object_marking_refs" (
	"StixObject_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixObject_id", object_marking_refs_id),
	FOREIGN KEY("StixObject_id") REFERENCES "StixObject" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixObject_object_marking_refs_StixObject_id" ON "StixObject_object_marking_refs" ("StixObject_id");
CREATE INDEX "ix_StixObject_object_marking_refs_object_marking_refs_id" ON "StixObject_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixCommonObject_labels" (
	"StixCommonObject_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixCommonObject_id", labels),
	FOREIGN KEY("StixCommonObject_id") REFERENCES "StixCommonObject" (id)
);
CREATE INDEX "ix_StixCommonObject_labels_StixCommonObject_id" ON "StixCommonObject_labels" ("StixCommonObject_id");
CREATE INDEX "ix_StixCommonObject_labels_labels" ON "StixCommonObject_labels" (labels);

CREATE TABLE "StixCommonObject_object_marking_refs" (
	"StixCommonObject_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixCommonObject_id", object_marking_refs_id),
	FOREIGN KEY("StixCommonObject_id") REFERENCES "StixCommonObject" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixCommonObject_object_marking_refs_StixCommonObject_id" ON "StixCommonObject_object_marking_refs" ("StixCommonObject_id");
CREATE INDEX "ix_StixCommonObject_object_marking_refs_object_marking_refs_id" ON "StixCommonObject_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixDomainObject_labels" (
	"StixDomainObject_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixDomainObject_id", labels),
	FOREIGN KEY("StixDomainObject_id") REFERENCES "StixDomainObject" (id)
);
CREATE INDEX "ix_StixDomainObject_labels_StixDomainObject_id" ON "StixDomainObject_labels" ("StixDomainObject_id");
CREATE INDEX "ix_StixDomainObject_labels_labels" ON "StixDomainObject_labels" (labels);

CREATE TABLE "StixDomainObject_object_marking_refs" (
	"StixDomainObject_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixDomainObject_id", object_marking_refs_id),
	FOREIGN KEY("StixDomainObject_id") REFERENCES "StixDomainObject" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixDomainObject_object_marking_refs_StixDomainObject_id" ON "StixDomainObject_object_marking_refs" ("StixDomainObject_id");
CREATE INDEX "ix_StixDomainObject_object_marking_refs_object_marking_refs_id" ON "StixDomainObject_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixRelationshipObject_labels" (
	"StixRelationshipObject_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixRelationshipObject_id", labels),
	FOREIGN KEY("StixRelationshipObject_id") REFERENCES "StixRelationshipObject" (id)
);
CREATE INDEX "ix_StixRelationshipObject_labels_labels" ON "StixRelationshipObject_labels" (labels);
CREATE INDEX "ix_StixRelationshipObject_labels_StixRelationshipObject_id" ON "StixRelationshipObject_labels" ("StixRelationshipObject_id");

CREATE TABLE "StixRelationshipObject_object_marking_refs" (
	"StixRelationshipObject_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixRelationshipObject_id", object_marking_refs_id),
	FOREIGN KEY("StixRelationshipObject_id") REFERENCES "StixRelationshipObject" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixRelationshipObject_object_marking_refs_StixRelationshipObject_id" ON "StixRelationshipObject_object_marking_refs" ("StixRelationshipObject_id");
CREATE INDEX "ix_StixRelationshipObject_object_marking_refs_object_marking_refs_id" ON "StixRelationshipObject_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixCyberObservableObject_object_marking_refs" (
	"StixCyberObservableObject_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixCyberObservableObject_id", object_marking_refs_id),
	FOREIGN KEY("StixCyberObservableObject_id") REFERENCES "StixCyberObservableObject" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixCyberObservableObject_object_marking_refs_StixCyberObservableObject_id" ON "StixCyberObservableObject_object_marking_refs" ("StixCyberObservableObject_id");
CREATE INDEX "ix_StixCyberObservableObject_object_marking_refs_object_marking_refs_id" ON "StixCyberObservableObject_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixIdentity_object_marking_refs" (
	"StixIdentity_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixIdentity_id", object_marking_refs_id),
	FOREIGN KEY("StixIdentity_id") REFERENCES "StixIdentity" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixIdentity_object_marking_refs_object_marking_refs_id" ON "StixIdentity_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixIdentity_object_marking_refs_StixIdentity_id" ON "StixIdentity_object_marking_refs" ("StixIdentity_id");

CREATE TABLE "StixMarkingDefinition_object_marking_refs" (
	"StixMarkingDefinition_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixMarkingDefinition_id", object_marking_refs_id),
	FOREIGN KEY("StixMarkingDefinition_id") REFERENCES "StixMarkingDefinition" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixMarkingDefinition_object_marking_refs_object_marking_refs_id" ON "StixMarkingDefinition_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixMarkingDefinition_object_marking_refs_StixMarkingDefinition_id" ON "StixMarkingDefinition_object_marking_refs" ("StixMarkingDefinition_id");

CREATE TABLE "StixLanguageContent_labels" (
	"StixLanguageContent_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixLanguageContent_id", labels),
	FOREIGN KEY("StixLanguageContent_id") REFERENCES "StixLanguageContent" (id)
);
CREATE INDEX "ix_StixLanguageContent_labels_labels" ON "StixLanguageContent_labels" (labels);
CREATE INDEX "ix_StixLanguageContent_labels_StixLanguageContent_id" ON "StixLanguageContent_labels" ("StixLanguageContent_id");

CREATE TABLE "StixLanguageContent_object_marking_refs" (
	"StixLanguageContent_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixLanguageContent_id", object_marking_refs_id),
	FOREIGN KEY("StixLanguageContent_id") REFERENCES "StixLanguageContent" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixLanguageContent_object_marking_refs_StixLanguageContent_id" ON "StixLanguageContent_object_marking_refs" ("StixLanguageContent_id");
CREATE INDEX "ix_StixLanguageContent_object_marking_refs_object_marking_refs_id" ON "StixLanguageContent_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixExtensionDefinition_extension_types" (
	"StixExtensionDefinition_id" TEXT,
	extension_types VARCHAR(27) NOT NULL,
	PRIMARY KEY ("StixExtensionDefinition_id", extension_types),
	FOREIGN KEY("StixExtensionDefinition_id") REFERENCES "StixExtensionDefinition" (id)
);
CREATE INDEX "ix_StixExtensionDefinition_extension_types_StixExtensionDefinition_id" ON "StixExtensionDefinition_extension_types" ("StixExtensionDefinition_id");
CREATE INDEX "ix_StixExtensionDefinition_extension_types_extension_types" ON "StixExtensionDefinition_extension_types" (extension_types);

CREATE TABLE "StixExtensionDefinition_extension_properties" (
	"StixExtensionDefinition_id" TEXT,
	extension_properties TEXT,
	PRIMARY KEY ("StixExtensionDefinition_id", extension_properties),
	FOREIGN KEY("StixExtensionDefinition_id") REFERENCES "StixExtensionDefinition" (id)
);
CREATE INDEX "ix_StixExtensionDefinition_extension_properties_StixExtensionDefinition_id" ON "StixExtensionDefinition_extension_properties" ("StixExtensionDefinition_id");
CREATE INDEX "ix_StixExtensionDefinition_extension_properties_extension_properties" ON "StixExtensionDefinition_extension_properties" (extension_properties);

CREATE TABLE "StixExtensionDefinition_labels" (
	"StixExtensionDefinition_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixExtensionDefinition_id", labels),
	FOREIGN KEY("StixExtensionDefinition_id") REFERENCES "StixExtensionDefinition" (id)
);
CREATE INDEX "ix_StixExtensionDefinition_labels_labels" ON "StixExtensionDefinition_labels" (labels);
CREATE INDEX "ix_StixExtensionDefinition_labels_StixExtensionDefinition_id" ON "StixExtensionDefinition_labels" ("StixExtensionDefinition_id");

CREATE TABLE "StixExtensionDefinition_object_marking_refs" (
	"StixExtensionDefinition_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixExtensionDefinition_id", object_marking_refs_id),
	FOREIGN KEY("StixExtensionDefinition_id") REFERENCES "StixExtensionDefinition" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixExtensionDefinition_object_marking_refs_StixExtensionDefinition_id" ON "StixExtensionDefinition_object_marking_refs" ("StixExtensionDefinition_id");
CREATE INDEX "ix_StixExtensionDefinition_object_marking_refs_object_marking_refs_id" ON "StixExtensionDefinition_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixArtifact_object_marking_refs" (
	"StixArtifact_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixArtifact_id", object_marking_refs_id),
	FOREIGN KEY("StixArtifact_id") REFERENCES "StixArtifact" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixArtifact_object_marking_refs_object_marking_refs_id" ON "StixArtifact_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixArtifact_object_marking_refs_StixArtifact_id" ON "StixArtifact_object_marking_refs" ("StixArtifact_id");

CREATE TABLE "StixAutonomousSystem_object_marking_refs" (
	"StixAutonomousSystem_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixAutonomousSystem_id", object_marking_refs_id),
	FOREIGN KEY("StixAutonomousSystem_id") REFERENCES "StixAutonomousSystem" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixAutonomousSystem_object_marking_refs_object_marking_refs_id" ON "StixAutonomousSystem_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixAutonomousSystem_object_marking_refs_StixAutonomousSystem_id" ON "StixAutonomousSystem_object_marking_refs" ("StixAutonomousSystem_id");

CREATE TABLE "StixDirectory_object_marking_refs" (
	"StixDirectory_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixDirectory_id", object_marking_refs_id),
	FOREIGN KEY("StixDirectory_id") REFERENCES "StixDirectory" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixDirectory_object_marking_refs_StixDirectory_id" ON "StixDirectory_object_marking_refs" ("StixDirectory_id");
CREATE INDEX "ix_StixDirectory_object_marking_refs_object_marking_refs_id" ON "StixDirectory_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixDomainName_object_marking_refs" (
	"StixDomainName_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixDomainName_id", object_marking_refs_id),
	FOREIGN KEY("StixDomainName_id") REFERENCES "StixDomainName" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixDomainName_object_marking_refs_object_marking_refs_id" ON "StixDomainName_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixDomainName_object_marking_refs_StixDomainName_id" ON "StixDomainName_object_marking_refs" ("StixDomainName_id");

CREATE TABLE "StixEmailAddress_object_marking_refs" (
	"StixEmailAddress_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixEmailAddress_id", object_marking_refs_id),
	FOREIGN KEY("StixEmailAddress_id") REFERENCES "StixEmailAddress" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixEmailAddress_object_marking_refs_StixEmailAddress_id" ON "StixEmailAddress_object_marking_refs" ("StixEmailAddress_id");
CREATE INDEX "ix_StixEmailAddress_object_marking_refs_object_marking_refs_id" ON "StixEmailAddress_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixFile_contains_refs" (
	"StixFile_id" TEXT,
	contains_refs_id TEXT,
	PRIMARY KEY ("StixFile_id", contains_refs_id),
	FOREIGN KEY("StixFile_id") REFERENCES "StixFile" (id),
	FOREIGN KEY(contains_refs_id) REFERENCES "StixCyberObservableObject" (id)
);
CREATE INDEX "ix_StixFile_contains_refs_StixFile_id" ON "StixFile_contains_refs" ("StixFile_id");
CREATE INDEX "ix_StixFile_contains_refs_contains_refs_id" ON "StixFile_contains_refs" (contains_refs_id);

CREATE TABLE "StixFile_object_marking_refs" (
	"StixFile_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixFile_id", object_marking_refs_id),
	FOREIGN KEY("StixFile_id") REFERENCES "StixFile" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixFile_object_marking_refs_object_marking_refs_id" ON "StixFile_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixFile_object_marking_refs_StixFile_id" ON "StixFile_object_marking_refs" ("StixFile_id");

CREATE TABLE "StixIpv4Address_object_marking_refs" (
	"StixIpv4Address_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixIpv4Address_id", object_marking_refs_id),
	FOREIGN KEY("StixIpv4Address_id") REFERENCES "StixIpv4Address" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixIpv4Address_object_marking_refs_object_marking_refs_id" ON "StixIpv4Address_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixIpv4Address_object_marking_refs_StixIpv4Address_id" ON "StixIpv4Address_object_marking_refs" ("StixIpv4Address_id");

CREATE TABLE "StixIpv6Address_object_marking_refs" (
	"StixIpv6Address_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixIpv6Address_id", object_marking_refs_id),
	FOREIGN KEY("StixIpv6Address_id") REFERENCES "StixIpv6Address" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixIpv6Address_object_marking_refs_StixIpv6Address_id" ON "StixIpv6Address_object_marking_refs" ("StixIpv6Address_id");
CREATE INDEX "ix_StixIpv6Address_object_marking_refs_object_marking_refs_id" ON "StixIpv6Address_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixMacAddress_object_marking_refs" (
	"StixMacAddress_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixMacAddress_id", object_marking_refs_id),
	FOREIGN KEY("StixMacAddress_id") REFERENCES "StixMacAddress" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixMacAddress_object_marking_refs_object_marking_refs_id" ON "StixMacAddress_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixMacAddress_object_marking_refs_StixMacAddress_id" ON "StixMacAddress_object_marking_refs" ("StixMacAddress_id");

CREATE TABLE "StixMutex_object_marking_refs" (
	"StixMutex_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixMutex_id", object_marking_refs_id),
	FOREIGN KEY("StixMutex_id") REFERENCES "StixMutex" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixMutex_object_marking_refs_object_marking_refs_id" ON "StixMutex_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixMutex_object_marking_refs_StixMutex_id" ON "StixMutex_object_marking_refs" ("StixMutex_id");

CREATE TABLE "StixNetworkTraffic_protocols" (
	"StixNetworkTraffic_id" TEXT,
	protocols TEXT NOT NULL,
	PRIMARY KEY ("StixNetworkTraffic_id", protocols),
	FOREIGN KEY("StixNetworkTraffic_id") REFERENCES "StixNetworkTraffic" (id)
);
CREATE INDEX "ix_StixNetworkTraffic_protocols_StixNetworkTraffic_id" ON "StixNetworkTraffic_protocols" ("StixNetworkTraffic_id");
CREATE INDEX "ix_StixNetworkTraffic_protocols_protocols" ON "StixNetworkTraffic_protocols" (protocols);

CREATE TABLE "StixNetworkTraffic_encapsulates_refs" (
	"StixNetworkTraffic_id" TEXT,
	encapsulates_refs_id TEXT,
	PRIMARY KEY ("StixNetworkTraffic_id", encapsulates_refs_id),
	FOREIGN KEY("StixNetworkTraffic_id") REFERENCES "StixNetworkTraffic" (id),
	FOREIGN KEY(encapsulates_refs_id) REFERENCES "StixNetworkTraffic" (id)
);
CREATE INDEX "ix_StixNetworkTraffic_encapsulates_refs_StixNetworkTraffic_id" ON "StixNetworkTraffic_encapsulates_refs" ("StixNetworkTraffic_id");
CREATE INDEX "ix_StixNetworkTraffic_encapsulates_refs_encapsulates_refs_id" ON "StixNetworkTraffic_encapsulates_refs" (encapsulates_refs_id);

CREATE TABLE "StixNetworkTraffic_object_marking_refs" (
	"StixNetworkTraffic_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixNetworkTraffic_id", object_marking_refs_id),
	FOREIGN KEY("StixNetworkTraffic_id") REFERENCES "StixNetworkTraffic" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixNetworkTraffic_object_marking_refs_object_marking_refs_id" ON "StixNetworkTraffic_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixNetworkTraffic_object_marking_refs_StixNetworkTraffic_id" ON "StixNetworkTraffic_object_marking_refs" ("StixNetworkTraffic_id");

CREATE TABLE "StixSoftware_object_marking_refs" (
	"StixSoftware_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixSoftware_id", object_marking_refs_id),
	FOREIGN KEY("StixSoftware_id") REFERENCES "StixSoftware" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixSoftware_object_marking_refs_StixSoftware_id" ON "StixSoftware_object_marking_refs" ("StixSoftware_id");
CREATE INDEX "ix_StixSoftware_object_marking_refs_object_marking_refs_id" ON "StixSoftware_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixUrl_object_marking_refs" (
	"StixUrl_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixUrl_id", object_marking_refs_id),
	FOREIGN KEY("StixUrl_id") REFERENCES "StixUrl" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixUrl_object_marking_refs_object_marking_refs_id" ON "StixUrl_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixUrl_object_marking_refs_StixUrl_id" ON "StixUrl_object_marking_refs" ("StixUrl_id");

CREATE TABLE "StixUserAccount_object_marking_refs" (
	"StixUserAccount_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixUserAccount_id", object_marking_refs_id),
	FOREIGN KEY("StixUserAccount_id") REFERENCES "StixUserAccount" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixUserAccount_object_marking_refs_object_marking_refs_id" ON "StixUserAccount_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixUserAccount_object_marking_refs_StixUserAccount_id" ON "StixUserAccount_object_marking_refs" ("StixUserAccount_id");

CREATE TABLE "StixWindowsRegistryKey_object_marking_refs" (
	"StixWindowsRegistryKey_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixWindowsRegistryKey_id", object_marking_refs_id),
	FOREIGN KEY("StixWindowsRegistryKey_id") REFERENCES "StixWindowsRegistryKey" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixWindowsRegistryKey_object_marking_refs_StixWindowsRegistryKey_id" ON "StixWindowsRegistryKey_object_marking_refs" ("StixWindowsRegistryKey_id");
CREATE INDEX "ix_StixWindowsRegistryKey_object_marking_refs_object_marking_refs_id" ON "StixWindowsRegistryKey_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixX509Certificate_object_marking_refs" (
	"StixX509Certificate_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixX509Certificate_id", object_marking_refs_id),
	FOREIGN KEY("StixX509Certificate_id") REFERENCES "StixX509Certificate" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixX509Certificate_object_marking_refs_StixX509Certificate_id" ON "StixX509Certificate_object_marking_refs" ("StixX509Certificate_id");
CREATE INDEX "ix_StixX509Certificate_object_marking_refs_object_marking_refs_id" ON "StixX509Certificate_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixWindowsServiceExtension_service_dll_refs" (
	"StixWindowsServiceExtension_id" INTEGER,
	service_dll_refs_id TEXT,
	PRIMARY KEY ("StixWindowsServiceExtension_id", service_dll_refs_id),
	FOREIGN KEY("StixWindowsServiceExtension_id") REFERENCES "StixWindowsServiceExtension" (id),
	FOREIGN KEY(service_dll_refs_id) REFERENCES "StixFile" (id)
);
CREATE INDEX "ix_StixWindowsServiceExtension_service_dll_refs_StixWindowsServiceExtension_id" ON "StixWindowsServiceExtension_service_dll_refs" ("StixWindowsServiceExtension_id");
CREATE INDEX "ix_StixWindowsServiceExtension_service_dll_refs_service_dll_refs_id" ON "StixWindowsServiceExtension_service_dll_refs" (service_dll_refs_id);

CREATE TABLE "StixAttackPattern_aliases" (
	"StixAttackPattern_id" TEXT,
	aliases TEXT,
	PRIMARY KEY ("StixAttackPattern_id", aliases),
	FOREIGN KEY("StixAttackPattern_id") REFERENCES "StixAttackPattern" (id)
);
CREATE INDEX "ix_StixAttackPattern_aliases_StixAttackPattern_id" ON "StixAttackPattern_aliases" ("StixAttackPattern_id");
CREATE INDEX "ix_StixAttackPattern_aliases_aliases" ON "StixAttackPattern_aliases" (aliases);

CREATE TABLE "StixAttackPattern_labels" (
	"StixAttackPattern_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixAttackPattern_id", labels),
	FOREIGN KEY("StixAttackPattern_id") REFERENCES "StixAttackPattern" (id)
);
CREATE INDEX "ix_StixAttackPattern_labels_labels" ON "StixAttackPattern_labels" (labels);
CREATE INDEX "ix_StixAttackPattern_labels_StixAttackPattern_id" ON "StixAttackPattern_labels" ("StixAttackPattern_id");

CREATE TABLE "StixAttackPattern_object_marking_refs" (
	"StixAttackPattern_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixAttackPattern_id", object_marking_refs_id),
	FOREIGN KEY("StixAttackPattern_id") REFERENCES "StixAttackPattern" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixAttackPattern_object_marking_refs_object_marking_refs_id" ON "StixAttackPattern_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixAttackPattern_object_marking_refs_StixAttackPattern_id" ON "StixAttackPattern_object_marking_refs" ("StixAttackPattern_id");

CREATE TABLE "StixCampaign_aliases" (
	"StixCampaign_id" TEXT,
	aliases TEXT,
	PRIMARY KEY ("StixCampaign_id", aliases),
	FOREIGN KEY("StixCampaign_id") REFERENCES "StixCampaign" (id)
);
CREATE INDEX "ix_StixCampaign_aliases_StixCampaign_id" ON "StixCampaign_aliases" ("StixCampaign_id");
CREATE INDEX "ix_StixCampaign_aliases_aliases" ON "StixCampaign_aliases" (aliases);

CREATE TABLE "StixCampaign_labels" (
	"StixCampaign_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixCampaign_id", labels),
	FOREIGN KEY("StixCampaign_id") REFERENCES "StixCampaign" (id)
);
CREATE INDEX "ix_StixCampaign_labels_StixCampaign_id" ON "StixCampaign_labels" ("StixCampaign_id");
CREATE INDEX "ix_StixCampaign_labels_labels" ON "StixCampaign_labels" (labels);

CREATE TABLE "StixCampaign_object_marking_refs" (
	"StixCampaign_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixCampaign_id", object_marking_refs_id),
	FOREIGN KEY("StixCampaign_id") REFERENCES "StixCampaign" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixCampaign_object_marking_refs_object_marking_refs_id" ON "StixCampaign_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixCampaign_object_marking_refs_StixCampaign_id" ON "StixCampaign_object_marking_refs" ("StixCampaign_id");

CREATE TABLE "StixCourseOfAction_labels" (
	"StixCourseOfAction_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixCourseOfAction_id", labels),
	FOREIGN KEY("StixCourseOfAction_id") REFERENCES "StixCourseOfAction" (id)
);
CREATE INDEX "ix_StixCourseOfAction_labels_labels" ON "StixCourseOfAction_labels" (labels);
CREATE INDEX "ix_StixCourseOfAction_labels_StixCourseOfAction_id" ON "StixCourseOfAction_labels" ("StixCourseOfAction_id");

CREATE TABLE "StixCourseOfAction_object_marking_refs" (
	"StixCourseOfAction_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixCourseOfAction_id", object_marking_refs_id),
	FOREIGN KEY("StixCourseOfAction_id") REFERENCES "StixCourseOfAction" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixCourseOfAction_object_marking_refs_StixCourseOfAction_id" ON "StixCourseOfAction_object_marking_refs" ("StixCourseOfAction_id");
CREATE INDEX "ix_StixCourseOfAction_object_marking_refs_object_marking_refs_id" ON "StixCourseOfAction_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixGrouping_object_refs" (
	"StixGrouping_id" TEXT,
	object_refs_id TEXT NOT NULL,
	PRIMARY KEY ("StixGrouping_id", object_refs_id),
	FOREIGN KEY("StixGrouping_id") REFERENCES "StixGrouping" (id),
	FOREIGN KEY(object_refs_id) REFERENCES "StixObject" (id)
);
CREATE INDEX "ix_StixGrouping_object_refs_object_refs_id" ON "StixGrouping_object_refs" (object_refs_id);
CREATE INDEX "ix_StixGrouping_object_refs_StixGrouping_id" ON "StixGrouping_object_refs" ("StixGrouping_id");

CREATE TABLE "StixGrouping_labels" (
	"StixGrouping_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixGrouping_id", labels),
	FOREIGN KEY("StixGrouping_id") REFERENCES "StixGrouping" (id)
);
CREATE INDEX "ix_StixGrouping_labels_labels" ON "StixGrouping_labels" (labels);
CREATE INDEX "ix_StixGrouping_labels_StixGrouping_id" ON "StixGrouping_labels" ("StixGrouping_id");

CREATE TABLE "StixGrouping_object_marking_refs" (
	"StixGrouping_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixGrouping_id", object_marking_refs_id),
	FOREIGN KEY("StixGrouping_id") REFERENCES "StixGrouping" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixGrouping_object_marking_refs_StixGrouping_id" ON "StixGrouping_object_marking_refs" ("StixGrouping_id");
CREATE INDEX "ix_StixGrouping_object_marking_refs_object_marking_refs_id" ON "StixGrouping_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixIncident_labels" (
	"StixIncident_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixIncident_id", labels),
	FOREIGN KEY("StixIncident_id") REFERENCES "StixIncident" (id)
);
CREATE INDEX "ix_StixIncident_labels_StixIncident_id" ON "StixIncident_labels" ("StixIncident_id");
CREATE INDEX "ix_StixIncident_labels_labels" ON "StixIncident_labels" (labels);

CREATE TABLE "StixIncident_object_marking_refs" (
	"StixIncident_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixIncident_id", object_marking_refs_id),
	FOREIGN KEY("StixIncident_id") REFERENCES "StixIncident" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixIncident_object_marking_refs_StixIncident_id" ON "StixIncident_object_marking_refs" ("StixIncident_id");
CREATE INDEX "ix_StixIncident_object_marking_refs_object_marking_refs_id" ON "StixIncident_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixIndicator_indicator_types" (
	"StixIndicator_id" TEXT,
	indicator_types TEXT,
	PRIMARY KEY ("StixIndicator_id", indicator_types),
	FOREIGN KEY("StixIndicator_id") REFERENCES "StixIndicator" (id)
);
CREATE INDEX "ix_StixIndicator_indicator_types_indicator_types" ON "StixIndicator_indicator_types" (indicator_types);
CREATE INDEX "ix_StixIndicator_indicator_types_StixIndicator_id" ON "StixIndicator_indicator_types" ("StixIndicator_id");

CREATE TABLE "StixIndicator_labels" (
	"StixIndicator_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixIndicator_id", labels),
	FOREIGN KEY("StixIndicator_id") REFERENCES "StixIndicator" (id)
);
CREATE INDEX "ix_StixIndicator_labels_StixIndicator_id" ON "StixIndicator_labels" ("StixIndicator_id");
CREATE INDEX "ix_StixIndicator_labels_labels" ON "StixIndicator_labels" (labels);

CREATE TABLE "StixIndicator_object_marking_refs" (
	"StixIndicator_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixIndicator_id", object_marking_refs_id),
	FOREIGN KEY("StixIndicator_id") REFERENCES "StixIndicator" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixIndicator_object_marking_refs_object_marking_refs_id" ON "StixIndicator_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixIndicator_object_marking_refs_StixIndicator_id" ON "StixIndicator_object_marking_refs" ("StixIndicator_id");

CREATE TABLE "StixInfrastructure_infrastructure_types" (
	"StixInfrastructure_id" TEXT,
	infrastructure_types TEXT,
	PRIMARY KEY ("StixInfrastructure_id", infrastructure_types),
	FOREIGN KEY("StixInfrastructure_id") REFERENCES "StixInfrastructure" (id)
);
CREATE INDEX "ix_StixInfrastructure_infrastructure_types_infrastructure_types" ON "StixInfrastructure_infrastructure_types" (infrastructure_types);
CREATE INDEX "ix_StixInfrastructure_infrastructure_types_StixInfrastructure_id" ON "StixInfrastructure_infrastructure_types" ("StixInfrastructure_id");

CREATE TABLE "StixInfrastructure_aliases" (
	"StixInfrastructure_id" TEXT,
	aliases TEXT,
	PRIMARY KEY ("StixInfrastructure_id", aliases),
	FOREIGN KEY("StixInfrastructure_id") REFERENCES "StixInfrastructure" (id)
);
CREATE INDEX "ix_StixInfrastructure_aliases_StixInfrastructure_id" ON "StixInfrastructure_aliases" ("StixInfrastructure_id");
CREATE INDEX "ix_StixInfrastructure_aliases_aliases" ON "StixInfrastructure_aliases" (aliases);

CREATE TABLE "StixInfrastructure_labels" (
	"StixInfrastructure_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixInfrastructure_id", labels),
	FOREIGN KEY("StixInfrastructure_id") REFERENCES "StixInfrastructure" (id)
);
CREATE INDEX "ix_StixInfrastructure_labels_StixInfrastructure_id" ON "StixInfrastructure_labels" ("StixInfrastructure_id");
CREATE INDEX "ix_StixInfrastructure_labels_labels" ON "StixInfrastructure_labels" (labels);

CREATE TABLE "StixInfrastructure_object_marking_refs" (
	"StixInfrastructure_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixInfrastructure_id", object_marking_refs_id),
	FOREIGN KEY("StixInfrastructure_id") REFERENCES "StixInfrastructure" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixInfrastructure_object_marking_refs_object_marking_refs_id" ON "StixInfrastructure_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixInfrastructure_object_marking_refs_StixInfrastructure_id" ON "StixInfrastructure_object_marking_refs" ("StixInfrastructure_id");

CREATE TABLE "StixIntrusionSet_aliases" (
	"StixIntrusionSet_id" TEXT,
	aliases TEXT,
	PRIMARY KEY ("StixIntrusionSet_id", aliases),
	FOREIGN KEY("StixIntrusionSet_id") REFERENCES "StixIntrusionSet" (id)
);
CREATE INDEX "ix_StixIntrusionSet_aliases_aliases" ON "StixIntrusionSet_aliases" (aliases);
CREATE INDEX "ix_StixIntrusionSet_aliases_StixIntrusionSet_id" ON "StixIntrusionSet_aliases" ("StixIntrusionSet_id");

CREATE TABLE "StixIntrusionSet_goals" (
	"StixIntrusionSet_id" TEXT,
	goals TEXT,
	PRIMARY KEY ("StixIntrusionSet_id", goals),
	FOREIGN KEY("StixIntrusionSet_id") REFERENCES "StixIntrusionSet" (id)
);
CREATE INDEX "ix_StixIntrusionSet_goals_StixIntrusionSet_id" ON "StixIntrusionSet_goals" ("StixIntrusionSet_id");
CREATE INDEX "ix_StixIntrusionSet_goals_goals" ON "StixIntrusionSet_goals" (goals);

CREATE TABLE "StixIntrusionSet_secondary_motivations" (
	"StixIntrusionSet_id" TEXT,
	secondary_motivations TEXT,
	PRIMARY KEY ("StixIntrusionSet_id", secondary_motivations),
	FOREIGN KEY("StixIntrusionSet_id") REFERENCES "StixIntrusionSet" (id)
);
CREATE INDEX "ix_StixIntrusionSet_secondary_motivations_StixIntrusionSet_id" ON "StixIntrusionSet_secondary_motivations" ("StixIntrusionSet_id");
CREATE INDEX "ix_StixIntrusionSet_secondary_motivations_secondary_motivations" ON "StixIntrusionSet_secondary_motivations" (secondary_motivations);

CREATE TABLE "StixIntrusionSet_labels" (
	"StixIntrusionSet_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixIntrusionSet_id", labels),
	FOREIGN KEY("StixIntrusionSet_id") REFERENCES "StixIntrusionSet" (id)
);
CREATE INDEX "ix_StixIntrusionSet_labels_StixIntrusionSet_id" ON "StixIntrusionSet_labels" ("StixIntrusionSet_id");
CREATE INDEX "ix_StixIntrusionSet_labels_labels" ON "StixIntrusionSet_labels" (labels);

CREATE TABLE "StixIntrusionSet_object_marking_refs" (
	"StixIntrusionSet_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixIntrusionSet_id", object_marking_refs_id),
	FOREIGN KEY("StixIntrusionSet_id") REFERENCES "StixIntrusionSet" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixIntrusionSet_object_marking_refs_object_marking_refs_id" ON "StixIntrusionSet_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixIntrusionSet_object_marking_refs_StixIntrusionSet_id" ON "StixIntrusionSet_object_marking_refs" ("StixIntrusionSet_id");

CREATE TABLE "StixLocation_labels" (
	"StixLocation_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixLocation_id", labels),
	FOREIGN KEY("StixLocation_id") REFERENCES "StixLocation" (id)
);
CREATE INDEX "ix_StixLocation_labels_labels" ON "StixLocation_labels" (labels);
CREATE INDEX "ix_StixLocation_labels_StixLocation_id" ON "StixLocation_labels" ("StixLocation_id");

CREATE TABLE "StixLocation_object_marking_refs" (
	"StixLocation_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixLocation_id", object_marking_refs_id),
	FOREIGN KEY("StixLocation_id") REFERENCES "StixLocation" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixLocation_object_marking_refs_StixLocation_id" ON "StixLocation_object_marking_refs" ("StixLocation_id");
CREATE INDEX "ix_StixLocation_object_marking_refs_object_marking_refs_id" ON "StixLocation_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixMalware_aliases" (
	"StixMalware_id" TEXT,
	aliases TEXT,
	PRIMARY KEY ("StixMalware_id", aliases),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id)
);
CREATE INDEX "ix_StixMalware_aliases_StixMalware_id" ON "StixMalware_aliases" ("StixMalware_id");
CREATE INDEX "ix_StixMalware_aliases_aliases" ON "StixMalware_aliases" (aliases);

CREATE TABLE "StixMalware_operating_system_refs" (
	"StixMalware_id" TEXT,
	operating_system_refs_id TEXT,
	PRIMARY KEY ("StixMalware_id", operating_system_refs_id),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id),
	FOREIGN KEY(operating_system_refs_id) REFERENCES "StixSoftware" (id)
);
CREATE INDEX "ix_StixMalware_operating_system_refs_StixMalware_id" ON "StixMalware_operating_system_refs" ("StixMalware_id");
CREATE INDEX "ix_StixMalware_operating_system_refs_operating_system_refs_id" ON "StixMalware_operating_system_refs" (operating_system_refs_id);

CREATE TABLE "StixMalware_architecture_execution_envs" (
	"StixMalware_id" TEXT,
	architecture_execution_envs TEXT,
	PRIMARY KEY ("StixMalware_id", architecture_execution_envs),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id)
);
CREATE INDEX "ix_StixMalware_architecture_execution_envs_architecture_execution_envs" ON "StixMalware_architecture_execution_envs" (architecture_execution_envs);
CREATE INDEX "ix_StixMalware_architecture_execution_envs_StixMalware_id" ON "StixMalware_architecture_execution_envs" ("StixMalware_id");

CREATE TABLE "StixMalware_implementation_languages" (
	"StixMalware_id" TEXT,
	implementation_languages TEXT,
	PRIMARY KEY ("StixMalware_id", implementation_languages),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id)
);
CREATE INDEX "ix_StixMalware_implementation_languages_StixMalware_id" ON "StixMalware_implementation_languages" ("StixMalware_id");
CREATE INDEX "ix_StixMalware_implementation_languages_implementation_languages" ON "StixMalware_implementation_languages" (implementation_languages);

CREATE TABLE "StixMalware_capabilities" (
	"StixMalware_id" TEXT,
	capabilities TEXT,
	PRIMARY KEY ("StixMalware_id", capabilities),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id)
);
CREATE INDEX "ix_StixMalware_capabilities_capabilities" ON "StixMalware_capabilities" (capabilities);
CREATE INDEX "ix_StixMalware_capabilities_StixMalware_id" ON "StixMalware_capabilities" ("StixMalware_id");

CREATE TABLE "StixMalware_sample_refs" (
	"StixMalware_id" TEXT,
	sample_refs_id TEXT,
	PRIMARY KEY ("StixMalware_id", sample_refs_id),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id),
	FOREIGN KEY(sample_refs_id) REFERENCES "StixCyberObservableObject" (id)
);
CREATE INDEX "ix_StixMalware_sample_refs_StixMalware_id" ON "StixMalware_sample_refs" ("StixMalware_id");
CREATE INDEX "ix_StixMalware_sample_refs_sample_refs_id" ON "StixMalware_sample_refs" (sample_refs_id);

CREATE TABLE "StixMalware_malware_types" (
	"StixMalware_id" TEXT,
	malware_types TEXT,
	PRIMARY KEY ("StixMalware_id", malware_types),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id)
);
CREATE INDEX "ix_StixMalware_malware_types_StixMalware_id" ON "StixMalware_malware_types" ("StixMalware_id");
CREATE INDEX "ix_StixMalware_malware_types_malware_types" ON "StixMalware_malware_types" (malware_types);

CREATE TABLE "StixMalware_labels" (
	"StixMalware_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixMalware_id", labels),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id)
);
CREATE INDEX "ix_StixMalware_labels_StixMalware_id" ON "StixMalware_labels" ("StixMalware_id");
CREATE INDEX "ix_StixMalware_labels_labels" ON "StixMalware_labels" (labels);

CREATE TABLE "StixMalware_object_marking_refs" (
	"StixMalware_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixMalware_id", object_marking_refs_id),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixMalware_object_marking_refs_object_marking_refs_id" ON "StixMalware_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixMalware_object_marking_refs_StixMalware_id" ON "StixMalware_object_marking_refs" ("StixMalware_id");

CREATE TABLE "StixMalwareAnalysis_modules" (
	"StixMalwareAnalysis_id" TEXT,
	modules TEXT,
	PRIMARY KEY ("StixMalwareAnalysis_id", modules),
	FOREIGN KEY("StixMalwareAnalysis_id") REFERENCES "StixMalwareAnalysis" (id)
);
CREATE INDEX "ix_StixMalwareAnalysis_modules_modules" ON "StixMalwareAnalysis_modules" (modules);
CREATE INDEX "ix_StixMalwareAnalysis_modules_StixMalwareAnalysis_id" ON "StixMalwareAnalysis_modules" ("StixMalwareAnalysis_id");

CREATE TABLE "StixMalwareAnalysis_installed_software_refs" (
	"StixMalwareAnalysis_id" TEXT,
	installed_software_refs_id TEXT,
	PRIMARY KEY ("StixMalwareAnalysis_id", installed_software_refs_id),
	FOREIGN KEY("StixMalwareAnalysis_id") REFERENCES "StixMalwareAnalysis" (id),
	FOREIGN KEY(installed_software_refs_id) REFERENCES "StixSoftware" (id)
);
CREATE INDEX "ix_StixMalwareAnalysis_installed_software_refs_StixMalwareAnalysis_id" ON "StixMalwareAnalysis_installed_software_refs" ("StixMalwareAnalysis_id");
CREATE INDEX "ix_StixMalwareAnalysis_installed_software_refs_installed_software_refs_id" ON "StixMalwareAnalysis_installed_software_refs" (installed_software_refs_id);

CREATE TABLE "StixMalwareAnalysis_analysis_sco_refs" (
	"StixMalwareAnalysis_id" TEXT,
	analysis_sco_refs_id TEXT,
	PRIMARY KEY ("StixMalwareAnalysis_id", analysis_sco_refs_id),
	FOREIGN KEY("StixMalwareAnalysis_id") REFERENCES "StixMalwareAnalysis" (id),
	FOREIGN KEY(analysis_sco_refs_id) REFERENCES "StixCyberObservableObject" (id)
);
CREATE INDEX "ix_StixMalwareAnalysis_analysis_sco_refs_StixMalwareAnalysis_id" ON "StixMalwareAnalysis_analysis_sco_refs" ("StixMalwareAnalysis_id");
CREATE INDEX "ix_StixMalwareAnalysis_analysis_sco_refs_analysis_sco_refs_id" ON "StixMalwareAnalysis_analysis_sco_refs" (analysis_sco_refs_id);

CREATE TABLE "StixMalwareAnalysis_labels" (
	"StixMalwareAnalysis_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixMalwareAnalysis_id", labels),
	FOREIGN KEY("StixMalwareAnalysis_id") REFERENCES "StixMalwareAnalysis" (id)
);
CREATE INDEX "ix_StixMalwareAnalysis_labels_labels" ON "StixMalwareAnalysis_labels" (labels);
CREATE INDEX "ix_StixMalwareAnalysis_labels_StixMalwareAnalysis_id" ON "StixMalwareAnalysis_labels" ("StixMalwareAnalysis_id");

CREATE TABLE "StixMalwareAnalysis_object_marking_refs" (
	"StixMalwareAnalysis_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixMalwareAnalysis_id", object_marking_refs_id),
	FOREIGN KEY("StixMalwareAnalysis_id") REFERENCES "StixMalwareAnalysis" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixMalwareAnalysis_object_marking_refs_object_marking_refs_id" ON "StixMalwareAnalysis_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixMalwareAnalysis_object_marking_refs_StixMalwareAnalysis_id" ON "StixMalwareAnalysis_object_marking_refs" ("StixMalwareAnalysis_id");

CREATE TABLE "StixNote_authors" (
	"StixNote_id" TEXT,
	authors TEXT,
	PRIMARY KEY ("StixNote_id", authors),
	FOREIGN KEY("StixNote_id") REFERENCES "StixNote" (id)
);
CREATE INDEX "ix_StixNote_authors_StixNote_id" ON "StixNote_authors" ("StixNote_id");
CREATE INDEX "ix_StixNote_authors_authors" ON "StixNote_authors" (authors);

CREATE TABLE "StixNote_object_refs" (
	"StixNote_id" TEXT,
	object_refs_id TEXT NOT NULL,
	PRIMARY KEY ("StixNote_id", object_refs_id),
	FOREIGN KEY("StixNote_id") REFERENCES "StixNote" (id),
	FOREIGN KEY(object_refs_id) REFERENCES "StixObject" (id)
);
CREATE INDEX "ix_StixNote_object_refs_StixNote_id" ON "StixNote_object_refs" ("StixNote_id");
CREATE INDEX "ix_StixNote_object_refs_object_refs_id" ON "StixNote_object_refs" (object_refs_id);

CREATE TABLE "StixNote_labels" (
	"StixNote_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixNote_id", labels),
	FOREIGN KEY("StixNote_id") REFERENCES "StixNote" (id)
);
CREATE INDEX "ix_StixNote_labels_labels" ON "StixNote_labels" (labels);
CREATE INDEX "ix_StixNote_labels_StixNote_id" ON "StixNote_labels" ("StixNote_id");

CREATE TABLE "StixNote_object_marking_refs" (
	"StixNote_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixNote_id", object_marking_refs_id),
	FOREIGN KEY("StixNote_id") REFERENCES "StixNote" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixNote_object_marking_refs_StixNote_id" ON "StixNote_object_marking_refs" ("StixNote_id");
CREATE INDEX "ix_StixNote_object_marking_refs_object_marking_refs_id" ON "StixNote_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixObservedData_object_refs" (
	"StixObservedData_id" TEXT,
	object_refs_id TEXT,
	PRIMARY KEY ("StixObservedData_id", object_refs_id),
	FOREIGN KEY("StixObservedData_id") REFERENCES "StixObservedData" (id),
	FOREIGN KEY(object_refs_id) REFERENCES "StixObject" (id)
);
CREATE INDEX "ix_StixObservedData_object_refs_StixObservedData_id" ON "StixObservedData_object_refs" ("StixObservedData_id");
CREATE INDEX "ix_StixObservedData_object_refs_object_refs_id" ON "StixObservedData_object_refs" (object_refs_id);

CREATE TABLE "StixObservedData_labels" (
	"StixObservedData_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixObservedData_id", labels),
	FOREIGN KEY("StixObservedData_id") REFERENCES "StixObservedData" (id)
);
CREATE INDEX "ix_StixObservedData_labels_StixObservedData_id" ON "StixObservedData_labels" ("StixObservedData_id");
CREATE INDEX "ix_StixObservedData_labels_labels" ON "StixObservedData_labels" (labels);

CREATE TABLE "StixObservedData_object_marking_refs" (
	"StixObservedData_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixObservedData_id", object_marking_refs_id),
	FOREIGN KEY("StixObservedData_id") REFERENCES "StixObservedData" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixObservedData_object_marking_refs_object_marking_refs_id" ON "StixObservedData_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixObservedData_object_marking_refs_StixObservedData_id" ON "StixObservedData_object_marking_refs" ("StixObservedData_id");

CREATE TABLE "StixOpinion_authors" (
	"StixOpinion_id" TEXT,
	authors TEXT,
	PRIMARY KEY ("StixOpinion_id", authors),
	FOREIGN KEY("StixOpinion_id") REFERENCES "StixOpinion" (id)
);
CREATE INDEX "ix_StixOpinion_authors_authors" ON "StixOpinion_authors" (authors);
CREATE INDEX "ix_StixOpinion_authors_StixOpinion_id" ON "StixOpinion_authors" ("StixOpinion_id");

CREATE TABLE "StixOpinion_object_refs" (
	"StixOpinion_id" TEXT,
	object_refs_id TEXT NOT NULL,
	PRIMARY KEY ("StixOpinion_id", object_refs_id),
	FOREIGN KEY("StixOpinion_id") REFERENCES "StixOpinion" (id),
	FOREIGN KEY(object_refs_id) REFERENCES "StixObject" (id)
);
CREATE INDEX "ix_StixOpinion_object_refs_StixOpinion_id" ON "StixOpinion_object_refs" ("StixOpinion_id");
CREATE INDEX "ix_StixOpinion_object_refs_object_refs_id" ON "StixOpinion_object_refs" (object_refs_id);

CREATE TABLE "StixOpinion_labels" (
	"StixOpinion_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixOpinion_id", labels),
	FOREIGN KEY("StixOpinion_id") REFERENCES "StixOpinion" (id)
);
CREATE INDEX "ix_StixOpinion_labels_labels" ON "StixOpinion_labels" (labels);
CREATE INDEX "ix_StixOpinion_labels_StixOpinion_id" ON "StixOpinion_labels" ("StixOpinion_id");

CREATE TABLE "StixOpinion_object_marking_refs" (
	"StixOpinion_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixOpinion_id", object_marking_refs_id),
	FOREIGN KEY("StixOpinion_id") REFERENCES "StixOpinion" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixOpinion_object_marking_refs_object_marking_refs_id" ON "StixOpinion_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixOpinion_object_marking_refs_StixOpinion_id" ON "StixOpinion_object_marking_refs" ("StixOpinion_id");

CREATE TABLE "StixReport_report_types" (
	"StixReport_id" TEXT,
	report_types TEXT,
	PRIMARY KEY ("StixReport_id", report_types),
	FOREIGN KEY("StixReport_id") REFERENCES "StixReport" (id)
);
CREATE INDEX "ix_StixReport_report_types_report_types" ON "StixReport_report_types" (report_types);
CREATE INDEX "ix_StixReport_report_types_StixReport_id" ON "StixReport_report_types" ("StixReport_id");

CREATE TABLE "StixReport_object_refs" (
	"StixReport_id" TEXT,
	object_refs_id TEXT NOT NULL,
	PRIMARY KEY ("StixReport_id", object_refs_id),
	FOREIGN KEY("StixReport_id") REFERENCES "StixReport" (id),
	FOREIGN KEY(object_refs_id) REFERENCES "StixObject" (id)
);
CREATE INDEX "ix_StixReport_object_refs_StixReport_id" ON "StixReport_object_refs" ("StixReport_id");
CREATE INDEX "ix_StixReport_object_refs_object_refs_id" ON "StixReport_object_refs" (object_refs_id);

CREATE TABLE "StixReport_labels" (
	"StixReport_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixReport_id", labels),
	FOREIGN KEY("StixReport_id") REFERENCES "StixReport" (id)
);
CREATE INDEX "ix_StixReport_labels_labels" ON "StixReport_labels" (labels);
CREATE INDEX "ix_StixReport_labels_StixReport_id" ON "StixReport_labels" ("StixReport_id");

CREATE TABLE "StixReport_object_marking_refs" (
	"StixReport_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixReport_id", object_marking_refs_id),
	FOREIGN KEY("StixReport_id") REFERENCES "StixReport" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixReport_object_marking_refs_object_marking_refs_id" ON "StixReport_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixReport_object_marking_refs_StixReport_id" ON "StixReport_object_marking_refs" ("StixReport_id");

CREATE TABLE "StixThreatActor_threat_actor_types" (
	"StixThreatActor_id" TEXT,
	threat_actor_types TEXT,
	PRIMARY KEY ("StixThreatActor_id", threat_actor_types),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id)
);
CREATE INDEX "ix_StixThreatActor_threat_actor_types_StixThreatActor_id" ON "StixThreatActor_threat_actor_types" ("StixThreatActor_id");
CREATE INDEX "ix_StixThreatActor_threat_actor_types_threat_actor_types" ON "StixThreatActor_threat_actor_types" (threat_actor_types);

CREATE TABLE "StixThreatActor_aliases" (
	"StixThreatActor_id" TEXT,
	aliases TEXT,
	PRIMARY KEY ("StixThreatActor_id", aliases),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id)
);
CREATE INDEX "ix_StixThreatActor_aliases_aliases" ON "StixThreatActor_aliases" (aliases);
CREATE INDEX "ix_StixThreatActor_aliases_StixThreatActor_id" ON "StixThreatActor_aliases" ("StixThreatActor_id");

CREATE TABLE "StixThreatActor_roles" (
	"StixThreatActor_id" TEXT,
	roles TEXT,
	PRIMARY KEY ("StixThreatActor_id", roles),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id)
);
CREATE INDEX "ix_StixThreatActor_roles_StixThreatActor_id" ON "StixThreatActor_roles" ("StixThreatActor_id");
CREATE INDEX "ix_StixThreatActor_roles_roles" ON "StixThreatActor_roles" (roles);

CREATE TABLE "StixThreatActor_goals" (
	"StixThreatActor_id" TEXT,
	goals TEXT,
	PRIMARY KEY ("StixThreatActor_id", goals),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id)
);
CREATE INDEX "ix_StixThreatActor_goals_goals" ON "StixThreatActor_goals" (goals);
CREATE INDEX "ix_StixThreatActor_goals_StixThreatActor_id" ON "StixThreatActor_goals" ("StixThreatActor_id");

CREATE TABLE "StixThreatActor_secondary_motivations" (
	"StixThreatActor_id" TEXT,
	secondary_motivations TEXT,
	PRIMARY KEY ("StixThreatActor_id", secondary_motivations),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id)
);
CREATE INDEX "ix_StixThreatActor_secondary_motivations_StixThreatActor_id" ON "StixThreatActor_secondary_motivations" ("StixThreatActor_id");
CREATE INDEX "ix_StixThreatActor_secondary_motivations_secondary_motivations" ON "StixThreatActor_secondary_motivations" (secondary_motivations);

CREATE TABLE "StixThreatActor_personal_motivations" (
	"StixThreatActor_id" TEXT,
	personal_motivations TEXT,
	PRIMARY KEY ("StixThreatActor_id", personal_motivations),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id)
);
CREATE INDEX "ix_StixThreatActor_personal_motivations_StixThreatActor_id" ON "StixThreatActor_personal_motivations" ("StixThreatActor_id");
CREATE INDEX "ix_StixThreatActor_personal_motivations_personal_motivations" ON "StixThreatActor_personal_motivations" (personal_motivations);

CREATE TABLE "StixThreatActor_labels" (
	"StixThreatActor_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixThreatActor_id", labels),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id)
);
CREATE INDEX "ix_StixThreatActor_labels_StixThreatActor_id" ON "StixThreatActor_labels" ("StixThreatActor_id");
CREATE INDEX "ix_StixThreatActor_labels_labels" ON "StixThreatActor_labels" (labels);

CREATE TABLE "StixThreatActor_object_marking_refs" (
	"StixThreatActor_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixThreatActor_id", object_marking_refs_id),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixThreatActor_object_marking_refs_object_marking_refs_id" ON "StixThreatActor_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixThreatActor_object_marking_refs_StixThreatActor_id" ON "StixThreatActor_object_marking_refs" ("StixThreatActor_id");

CREATE TABLE "StixTool_aliases" (
	"StixTool_id" TEXT,
	aliases TEXT,
	PRIMARY KEY ("StixTool_id", aliases),
	FOREIGN KEY("StixTool_id") REFERENCES "StixTool" (id)
);
CREATE INDEX "ix_StixTool_aliases_aliases" ON "StixTool_aliases" (aliases);
CREATE INDEX "ix_StixTool_aliases_StixTool_id" ON "StixTool_aliases" ("StixTool_id");

CREATE TABLE "StixTool_tool_types" (
	"StixTool_id" TEXT,
	tool_types TEXT,
	PRIMARY KEY ("StixTool_id", tool_types),
	FOREIGN KEY("StixTool_id") REFERENCES "StixTool" (id)
);
CREATE INDEX "ix_StixTool_tool_types_StixTool_id" ON "StixTool_tool_types" ("StixTool_id");
CREATE INDEX "ix_StixTool_tool_types_tool_types" ON "StixTool_tool_types" (tool_types);

CREATE TABLE "StixTool_labels" (
	"StixTool_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixTool_id", labels),
	FOREIGN KEY("StixTool_id") REFERENCES "StixTool" (id)
);
CREATE INDEX "ix_StixTool_labels_StixTool_id" ON "StixTool_labels" ("StixTool_id");
CREATE INDEX "ix_StixTool_labels_labels" ON "StixTool_labels" (labels);

CREATE TABLE "StixTool_object_marking_refs" (
	"StixTool_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixTool_id", object_marking_refs_id),
	FOREIGN KEY("StixTool_id") REFERENCES "StixTool" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixTool_object_marking_refs_object_marking_refs_id" ON "StixTool_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixTool_object_marking_refs_StixTool_id" ON "StixTool_object_marking_refs" ("StixTool_id");

CREATE TABLE "StixVulnerability_labels" (
	"StixVulnerability_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixVulnerability_id", labels),
	FOREIGN KEY("StixVulnerability_id") REFERENCES "StixVulnerability" (id)
);
CREATE INDEX "ix_StixVulnerability_labels_labels" ON "StixVulnerability_labels" (labels);
CREATE INDEX "ix_StixVulnerability_labels_StixVulnerability_id" ON "StixVulnerability_labels" ("StixVulnerability_id");

CREATE TABLE "StixVulnerability_object_marking_refs" (
	"StixVulnerability_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixVulnerability_id", object_marking_refs_id),
	FOREIGN KEY("StixVulnerability_id") REFERENCES "StixVulnerability" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixVulnerability_object_marking_refs_StixVulnerability_id" ON "StixVulnerability_object_marking_refs" ("StixVulnerability_id");
CREATE INDEX "ix_StixVulnerability_object_marking_refs_object_marking_refs_id" ON "StixVulnerability_object_marking_refs" (object_marking_refs_id);

CREATE TABLE "StixRelationship_labels" (
	"StixRelationship_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixRelationship_id", labels),
	FOREIGN KEY("StixRelationship_id") REFERENCES "StixRelationship" (id)
);
CREATE INDEX "ix_StixRelationship_labels_labels" ON "StixRelationship_labels" (labels);
CREATE INDEX "ix_StixRelationship_labels_StixRelationship_id" ON "StixRelationship_labels" ("StixRelationship_id");

CREATE TABLE "StixRelationship_object_marking_refs" (
	"StixRelationship_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixRelationship_id", object_marking_refs_id),
	FOREIGN KEY("StixRelationship_id") REFERENCES "StixRelationship" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixRelationship_object_marking_refs_object_marking_refs_id" ON "StixRelationship_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixRelationship_object_marking_refs_StixRelationship_id" ON "StixRelationship_object_marking_refs" ("StixRelationship_id");

CREATE TABLE "StixExternalReference" (
	id INTEGER NOT NULL,
	source_name TEXT NOT NULL,
	description TEXT,
	url TEXT,
	external_id TEXT,
	"StixCommonObject_id" TEXT,
	"StixDomainObject_id" TEXT,
	"StixRelationshipObject_id" TEXT,
	"StixIdentity_id" TEXT,
	"StixMarkingDefinition_id" TEXT,
	"StixLanguageContent_id" TEXT,
	"StixExtensionDefinition_id" TEXT,
	"StixAttackPattern_id" TEXT,
	"StixCampaign_id" TEXT,
	"StixCourseOfAction_id" TEXT,
	"StixGrouping_id" TEXT,
	"StixIncident_id" TEXT,
	"StixIndicator_id" TEXT,
	"StixInfrastructure_id" TEXT,
	"StixIntrusionSet_id" TEXT,
	"StixLocation_id" TEXT,
	"StixMalware_id" TEXT,
	"StixMalwareAnalysis_id" TEXT,
	"StixNote_id" TEXT,
	"StixObservedData_id" TEXT,
	"StixOpinion_id" TEXT,
	"StixReport_id" TEXT,
	"StixThreatActor_id" TEXT,
	"StixTool_id" TEXT,
	"StixVulnerability_id" TEXT,
	"StixRelationship_id" TEXT,
	"StixSighting_id" TEXT,
	hashes_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY("StixCommonObject_id") REFERENCES "StixCommonObject" (id),
	FOREIGN KEY("StixDomainObject_id") REFERENCES "StixDomainObject" (id),
	FOREIGN KEY("StixRelationshipObject_id") REFERENCES "StixRelationshipObject" (id),
	FOREIGN KEY("StixIdentity_id") REFERENCES "StixIdentity" (id),
	FOREIGN KEY("StixMarkingDefinition_id") REFERENCES "StixMarkingDefinition" (id),
	FOREIGN KEY("StixLanguageContent_id") REFERENCES "StixLanguageContent" (id),
	FOREIGN KEY("StixExtensionDefinition_id") REFERENCES "StixExtensionDefinition" (id),
	FOREIGN KEY("StixAttackPattern_id") REFERENCES "StixAttackPattern" (id),
	FOREIGN KEY("StixCampaign_id") REFERENCES "StixCampaign" (id),
	FOREIGN KEY("StixCourseOfAction_id") REFERENCES "StixCourseOfAction" (id),
	FOREIGN KEY("StixGrouping_id") REFERENCES "StixGrouping" (id),
	FOREIGN KEY("StixIncident_id") REFERENCES "StixIncident" (id),
	FOREIGN KEY("StixIndicator_id") REFERENCES "StixIndicator" (id),
	FOREIGN KEY("StixInfrastructure_id") REFERENCES "StixInfrastructure" (id),
	FOREIGN KEY("StixIntrusionSet_id") REFERENCES "StixIntrusionSet" (id),
	FOREIGN KEY("StixLocation_id") REFERENCES "StixLocation" (id),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id),
	FOREIGN KEY("StixMalwareAnalysis_id") REFERENCES "StixMalwareAnalysis" (id),
	FOREIGN KEY("StixNote_id") REFERENCES "StixNote" (id),
	FOREIGN KEY("StixObservedData_id") REFERENCES "StixObservedData" (id),
	FOREIGN KEY("StixOpinion_id") REFERENCES "StixOpinion" (id),
	FOREIGN KEY("StixReport_id") REFERENCES "StixReport" (id),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id),
	FOREIGN KEY("StixTool_id") REFERENCES "StixTool" (id),
	FOREIGN KEY("StixVulnerability_id") REFERENCES "StixVulnerability" (id),
	FOREIGN KEY("StixRelationship_id") REFERENCES "StixRelationship" (id),
	FOREIGN KEY("StixSighting_id") REFERENCES "StixSighting" (id),
	FOREIGN KEY(hashes_id) REFERENCES "StixHashes" (id)
);
CREATE INDEX "ix_StixExternalReference_id" ON "StixExternalReference" (id);

CREATE TABLE "StixGranularMarking" (
	id INTEGER NOT NULL,
	marking_ref TEXT NOT NULL,
	lang TEXT,
	"StixObject_id" TEXT,
	"StixCommonObject_id" TEXT,
	"StixDomainObject_id" TEXT,
	"StixRelationshipObject_id" TEXT,
	"StixCyberObservableObject_id" TEXT,
	"StixIdentity_id" TEXT,
	"StixMarkingDefinition_id" TEXT,
	"StixLanguageContent_id" TEXT,
	"StixExtensionDefinition_id" TEXT,
	"StixArtifact_id" TEXT,
	"StixAutonomousSystem_id" TEXT,
	"StixDirectory_id" TEXT,
	"StixDomainName_id" TEXT,
	"StixEmailAddress_id" TEXT,
	"StixEmailMessage_id" TEXT,
	"StixFile_id" TEXT,
	"StixIpv4Address_id" TEXT,
	"StixIpv6Address_id" TEXT,
	"StixMacAddress_id" TEXT,
	"StixMutex_id" TEXT,
	"StixNetworkTraffic_id" TEXT,
	"StixProcess_id" TEXT,
	"StixSoftware_id" TEXT,
	"StixUrl_id" TEXT,
	"StixUserAccount_id" TEXT,
	"StixWindowsRegistryKey_id" TEXT,
	"StixX509Certificate_id" TEXT,
	"StixAttackPattern_id" TEXT,
	"StixCampaign_id" TEXT,
	"StixCourseOfAction_id" TEXT,
	"StixGrouping_id" TEXT,
	"StixIncident_id" TEXT,
	"StixIndicator_id" TEXT,
	"StixInfrastructure_id" TEXT,
	"StixIntrusionSet_id" TEXT,
	"StixLocation_id" TEXT,
	"StixMalware_id" TEXT,
	"StixMalwareAnalysis_id" TEXT,
	"StixNote_id" TEXT,
	"StixObservedData_id" TEXT,
	"StixOpinion_id" TEXT,
	"StixReport_id" TEXT,
	"StixThreatActor_id" TEXT,
	"StixTool_id" TEXT,
	"StixVulnerability_id" TEXT,
	"StixRelationship_id" TEXT,
	"StixSighting_id" TEXT,
	PRIMARY KEY (id),
	FOREIGN KEY(marking_ref) REFERENCES "StixMarkingDefinition" (id),
	FOREIGN KEY("StixObject_id") REFERENCES "StixObject" (id),
	FOREIGN KEY("StixCommonObject_id") REFERENCES "StixCommonObject" (id),
	FOREIGN KEY("StixDomainObject_id") REFERENCES "StixDomainObject" (id),
	FOREIGN KEY("StixRelationshipObject_id") REFERENCES "StixRelationshipObject" (id),
	FOREIGN KEY("StixCyberObservableObject_id") REFERENCES "StixCyberObservableObject" (id),
	FOREIGN KEY("StixIdentity_id") REFERENCES "StixIdentity" (id),
	FOREIGN KEY("StixMarkingDefinition_id") REFERENCES "StixMarkingDefinition" (id),
	FOREIGN KEY("StixLanguageContent_id") REFERENCES "StixLanguageContent" (id),
	FOREIGN KEY("StixExtensionDefinition_id") REFERENCES "StixExtensionDefinition" (id),
	FOREIGN KEY("StixArtifact_id") REFERENCES "StixArtifact" (id),
	FOREIGN KEY("StixAutonomousSystem_id") REFERENCES "StixAutonomousSystem" (id),
	FOREIGN KEY("StixDirectory_id") REFERENCES "StixDirectory" (id),
	FOREIGN KEY("StixDomainName_id") REFERENCES "StixDomainName" (id),
	FOREIGN KEY("StixEmailAddress_id") REFERENCES "StixEmailAddress" (id),
	FOREIGN KEY("StixEmailMessage_id") REFERENCES "StixEmailMessage" (id),
	FOREIGN KEY("StixFile_id") REFERENCES "StixFile" (id),
	FOREIGN KEY("StixIpv4Address_id") REFERENCES "StixIpv4Address" (id),
	FOREIGN KEY("StixIpv6Address_id") REFERENCES "StixIpv6Address" (id),
	FOREIGN KEY("StixMacAddress_id") REFERENCES "StixMacAddress" (id),
	FOREIGN KEY("StixMutex_id") REFERENCES "StixMutex" (id),
	FOREIGN KEY("StixNetworkTraffic_id") REFERENCES "StixNetworkTraffic" (id),
	FOREIGN KEY("StixProcess_id") REFERENCES "StixProcess" (id),
	FOREIGN KEY("StixSoftware_id") REFERENCES "StixSoftware" (id),
	FOREIGN KEY("StixUrl_id") REFERENCES "StixUrl" (id),
	FOREIGN KEY("StixUserAccount_id") REFERENCES "StixUserAccount" (id),
	FOREIGN KEY("StixWindowsRegistryKey_id") REFERENCES "StixWindowsRegistryKey" (id),
	FOREIGN KEY("StixX509Certificate_id") REFERENCES "StixX509Certificate" (id),
	FOREIGN KEY("StixAttackPattern_id") REFERENCES "StixAttackPattern" (id),
	FOREIGN KEY("StixCampaign_id") REFERENCES "StixCampaign" (id),
	FOREIGN KEY("StixCourseOfAction_id") REFERENCES "StixCourseOfAction" (id),
	FOREIGN KEY("StixGrouping_id") REFERENCES "StixGrouping" (id),
	FOREIGN KEY("StixIncident_id") REFERENCES "StixIncident" (id),
	FOREIGN KEY("StixIndicator_id") REFERENCES "StixIndicator" (id),
	FOREIGN KEY("StixInfrastructure_id") REFERENCES "StixInfrastructure" (id),
	FOREIGN KEY("StixIntrusionSet_id") REFERENCES "StixIntrusionSet" (id),
	FOREIGN KEY("StixLocation_id") REFERENCES "StixLocation" (id),
	FOREIGN KEY("StixMalware_id") REFERENCES "StixMalware" (id),
	FOREIGN KEY("StixMalwareAnalysis_id") REFERENCES "StixMalwareAnalysis" (id),
	FOREIGN KEY("StixNote_id") REFERENCES "StixNote" (id),
	FOREIGN KEY("StixObservedData_id") REFERENCES "StixObservedData" (id),
	FOREIGN KEY("StixOpinion_id") REFERENCES "StixOpinion" (id),
	FOREIGN KEY("StixReport_id") REFERENCES "StixReport" (id),
	FOREIGN KEY("StixThreatActor_id") REFERENCES "StixThreatActor" (id),
	FOREIGN KEY("StixTool_id") REFERENCES "StixTool" (id),
	FOREIGN KEY("StixVulnerability_id") REFERENCES "StixVulnerability" (id),
	FOREIGN KEY("StixRelationship_id") REFERENCES "StixRelationship" (id),
	FOREIGN KEY("StixSighting_id") REFERENCES "StixSighting" (id)
);
CREATE INDEX "ix_StixGranularMarking_id" ON "StixGranularMarking" (id);

CREATE TABLE "StixMimePart" (
	id INTEGER NOT NULL,
	body TEXT,
	body_raw_ref TEXT,
	content_type TEXT,
	content_disposition TEXT,
	"StixEmailMessage_id" TEXT,
	PRIMARY KEY (id),
	FOREIGN KEY(body_raw_ref) REFERENCES "StixCyberObservableObject" (id),
	FOREIGN KEY("StixEmailMessage_id") REFERENCES "StixEmailMessage" (id)
);
CREATE INDEX "ix_StixMimePart_id" ON "StixMimePart" (id);

CREATE TABLE "StixEmailMessage_to_refs" (
	"StixEmailMessage_id" TEXT,
	to_refs_id TEXT,
	PRIMARY KEY ("StixEmailMessage_id", to_refs_id),
	FOREIGN KEY("StixEmailMessage_id") REFERENCES "StixEmailMessage" (id),
	FOREIGN KEY(to_refs_id) REFERENCES "StixEmailAddress" (id)
);
CREATE INDEX "ix_StixEmailMessage_to_refs_StixEmailMessage_id" ON "StixEmailMessage_to_refs" ("StixEmailMessage_id");
CREATE INDEX "ix_StixEmailMessage_to_refs_to_refs_id" ON "StixEmailMessage_to_refs" (to_refs_id);

CREATE TABLE "StixEmailMessage_cc_refs" (
	"StixEmailMessage_id" TEXT,
	cc_refs_id TEXT,
	PRIMARY KEY ("StixEmailMessage_id", cc_refs_id),
	FOREIGN KEY("StixEmailMessage_id") REFERENCES "StixEmailMessage" (id),
	FOREIGN KEY(cc_refs_id) REFERENCES "StixEmailAddress" (id)
);
CREATE INDEX "ix_StixEmailMessage_cc_refs_cc_refs_id" ON "StixEmailMessage_cc_refs" (cc_refs_id);
CREATE INDEX "ix_StixEmailMessage_cc_refs_StixEmailMessage_id" ON "StixEmailMessage_cc_refs" ("StixEmailMessage_id");

CREATE TABLE "StixEmailMessage_bcc_refs" (
	"StixEmailMessage_id" TEXT,
	bcc_refs_id TEXT,
	PRIMARY KEY ("StixEmailMessage_id", bcc_refs_id),
	FOREIGN KEY("StixEmailMessage_id") REFERENCES "StixEmailMessage" (id),
	FOREIGN KEY(bcc_refs_id) REFERENCES "StixEmailAddress" (id)
);
CREATE INDEX "ix_StixEmailMessage_bcc_refs_bcc_refs_id" ON "StixEmailMessage_bcc_refs" (bcc_refs_id);
CREATE INDEX "ix_StixEmailMessage_bcc_refs_StixEmailMessage_id" ON "StixEmailMessage_bcc_refs" ("StixEmailMessage_id");

CREATE TABLE "StixEmailMessage_received_lines" (
	"StixEmailMessage_id" TEXT,
	received_lines TEXT,
	PRIMARY KEY ("StixEmailMessage_id", received_lines),
	FOREIGN KEY("StixEmailMessage_id") REFERENCES "StixEmailMessage" (id)
);
CREATE INDEX "ix_StixEmailMessage_received_lines_StixEmailMessage_id" ON "StixEmailMessage_received_lines" ("StixEmailMessage_id");
CREATE INDEX "ix_StixEmailMessage_received_lines_received_lines" ON "StixEmailMessage_received_lines" (received_lines);

CREATE TABLE "StixEmailMessage_object_marking_refs" (
	"StixEmailMessage_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixEmailMessage_id", object_marking_refs_id),
	FOREIGN KEY("StixEmailMessage_id") REFERENCES "StixEmailMessage" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixEmailMessage_object_marking_refs_object_marking_refs_id" ON "StixEmailMessage_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixEmailMessage_object_marking_refs_StixEmailMessage_id" ON "StixEmailMessage_object_marking_refs" ("StixEmailMessage_id");

CREATE TABLE "StixProcess_opened_connection_refs" (
	"StixProcess_id" TEXT,
	opened_connection_refs_id TEXT,
	PRIMARY KEY ("StixProcess_id", opened_connection_refs_id),
	FOREIGN KEY("StixProcess_id") REFERENCES "StixProcess" (id),
	FOREIGN KEY(opened_connection_refs_id) REFERENCES "StixNetworkTraffic" (id)
);
CREATE INDEX "ix_StixProcess_opened_connection_refs_opened_connection_refs_id" ON "StixProcess_opened_connection_refs" (opened_connection_refs_id);
CREATE INDEX "ix_StixProcess_opened_connection_refs_StixProcess_id" ON "StixProcess_opened_connection_refs" ("StixProcess_id");

CREATE TABLE "StixProcess_child_refs" (
	"StixProcess_id" TEXT,
	child_refs_id TEXT,
	PRIMARY KEY ("StixProcess_id", child_refs_id),
	FOREIGN KEY("StixProcess_id") REFERENCES "StixProcess" (id),
	FOREIGN KEY(child_refs_id) REFERENCES "StixProcess" (id)
);
CREATE INDEX "ix_StixProcess_child_refs_child_refs_id" ON "StixProcess_child_refs" (child_refs_id);
CREATE INDEX "ix_StixProcess_child_refs_StixProcess_id" ON "StixProcess_child_refs" ("StixProcess_id");

CREATE TABLE "StixProcess_object_marking_refs" (
	"StixProcess_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixProcess_id", object_marking_refs_id),
	FOREIGN KEY("StixProcess_id") REFERENCES "StixProcess" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixProcess_object_marking_refs_object_marking_refs_id" ON "StixProcess_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixProcess_object_marking_refs_StixProcess_id" ON "StixProcess_object_marking_refs" ("StixProcess_id");

CREATE TABLE "StixSighting_observed_data_refs" (
	"StixSighting_id" TEXT,
	observed_data_refs_id TEXT,
	PRIMARY KEY ("StixSighting_id", observed_data_refs_id),
	FOREIGN KEY("StixSighting_id") REFERENCES "StixSighting" (id),
	FOREIGN KEY(observed_data_refs_id) REFERENCES "StixObservedData" (id)
);
CREATE INDEX "ix_StixSighting_observed_data_refs_StixSighting_id" ON "StixSighting_observed_data_refs" ("StixSighting_id");
CREATE INDEX "ix_StixSighting_observed_data_refs_observed_data_refs_id" ON "StixSighting_observed_data_refs" (observed_data_refs_id);

CREATE TABLE "StixSighting_where_sighted_refs" (
	"StixSighting_id" TEXT,
	where_sighted_refs_id TEXT,
	PRIMARY KEY ("StixSighting_id", where_sighted_refs_id),
	FOREIGN KEY("StixSighting_id") REFERENCES "StixSighting" (id),
	FOREIGN KEY(where_sighted_refs_id) REFERENCES "StixDomainObject" (id)
);
CREATE INDEX "ix_StixSighting_where_sighted_refs_StixSighting_id" ON "StixSighting_where_sighted_refs" ("StixSighting_id");
CREATE INDEX "ix_StixSighting_where_sighted_refs_where_sighted_refs_id" ON "StixSighting_where_sighted_refs" (where_sighted_refs_id);

CREATE TABLE "StixSighting_labels" (
	"StixSighting_id" TEXT,
	labels TEXT,
	PRIMARY KEY ("StixSighting_id", labels),
	FOREIGN KEY("StixSighting_id") REFERENCES "StixSighting" (id)
);
CREATE INDEX "ix_StixSighting_labels_StixSighting_id" ON "StixSighting_labels" ("StixSighting_id");
CREATE INDEX "ix_StixSighting_labels_labels" ON "StixSighting_labels" (labels);

CREATE TABLE "StixSighting_object_marking_refs" (
	"StixSighting_id" TEXT,
	object_marking_refs_id TEXT,
	PRIMARY KEY ("StixSighting_id", object_marking_refs_id),
	FOREIGN KEY("StixSighting_id") REFERENCES "StixSighting" (id),
	FOREIGN KEY(object_marking_refs_id) REFERENCES "StixMarkingDefinition" (id)
);
CREATE INDEX "ix_StixSighting_object_marking_refs_object_marking_refs_id" ON "StixSighting_object_marking_refs" (object_marking_refs_id);
CREATE INDEX "ix_StixSighting_object_marking_refs_StixSighting_id" ON "StixSighting_object_marking_refs" ("StixSighting_id");

CREATE TABLE "StixGranularMarking_selectors" (
	"StixGranularMarking_id" INTEGER,
	selectors TEXT NOT NULL,
	PRIMARY KEY ("StixGranularMarking_id", selectors),
	FOREIGN KEY("StixGranularMarking_id") REFERENCES "StixGranularMarking" (id)
);
CREATE INDEX "ix_StixGranularMarking_selectors_StixGranularMarking_id" ON "StixGranularMarking_selectors" ("StixGranularMarking_id");
CREATE INDEX "ix_StixGranularMarking_selectors_selectors" ON "StixGranularMarking_selectors" (selectors);
