
/// A [`LabelName`] uniquely names a specific token in an ASN.1 tree
#[rustfmt::skip]
#[derive(Clone, Debug, PartialEq, Eq, Copy, serde::Serialize, serde::Deserialize, Hash, PartialOrd, Ord)]
pub enum LabelName {
    /// Signed Object
    SignedObjectContentInfo,
    SignedObjectContentType,
    SignedObjectContent,
    SignedObjectSignedData,

    /// Version
    SignedObjectVersion,

    /// DigestAlgortihmIdentfiers
    SignedObjectDigestAlgorithms,
    SignedObjectDigestAlgorithmIdentifier,
    SignedObjectDigestAlgorithmIdentifierId,
    SignedObjectDigestAlgorithmIdentifierParameters,

    /// Outer eContentInfo
    SignedObjectEncapContentInfo,
    /// eContentType
    EContentType,
    /// eContent
    EContent,
    /// eContent OCTET STRING
    EContentString,
    /// eContent value, like RPKI-ROA
    EContentProfiled,

    /// Route Origin Attestation
    // RoaContent, -> EContentProfiled
    RoaAsid,
    RoaIpAddrBlocks,
    RoaIpAddressFamily,
    RoaIpAddressFamilyAfi,
    RoaIpAddressFamilyAddresses,
    RoaIpAddressSeq(u32),
    RoaIpAddress(u32),
    RoaIpAddressMl(u32),

    /// AS Provider Authorization
    // AspaContent, -> EContentProfiled
    AspaProviderAuthorization,
    AspaVersion,
    AspaVersionValue,
    AspaCustomerAsid,
    AspaProviderAsSeq,

    /// Ghostbuster Record
    // GbrContent,
    GbrVcard,

    /// Manifest
    // MftContent, -> EContentProfiled
    MftVersion,
    MftNumber,
    MftThisUpdate,
    MftNextUpdate,
    MftFileHashAlg,
    MftFileList,
    MftFileAndHash,
    MftFile,
    MftHash,
    /// iManifest
    IMftCrlEntries,
    IMftCrlEntriesSeq,

    SignedObjectCertificateSet,

    // Certificate for Certs / CertificateList for CRLs / CertificateChoices Certificate for SOs
    CertificateSeq,
    /// TBSCertificate for Certs / TBSCertList for CRLs
    Certificate,
    CertificateSignatureAlgorithm,
    CertificateSignatureAlgorithmId,
    CertificateSignatureAlgorithmParameters,
    CertificateSignature,

    /// Certificate Fields
    CertFldVersionSeq,
    CertFldVersion,
    CertFldSerialNumber,
    CertFldSignature,
    CertFldSignatureAlgorithm,
    CertFldSignatureParameters,
    CertFldIssuer,
    /// RelativeDistinguishedName SET
    CertFldIssuerRdnSet,
    CertFldIssuerAttributeTypeAndValue,
    CertFldIssuerAttributeType,
    CertFldIssuerAttributeValue,
    CertFldIssuerAttributeValueCN,
    CertFldIssuerAttributeValueSerial,
    CertFldExtensions,
    CertFldExtensionsSeq,
    CertFldValidity,
    CertFldValidityNotBefore,
    CertFldValidityNotAfter,
    CertFldSubject,
    /// RelativeDistinguishedName SET
    CertFldSubjectRdnSet,
    CertFldSubjectAttributeTypeAndValue,
    CertFldSubjectAttributeType,
    CertFldSubjectAttributeValue,
    CertFldSubjectPublicKeyInfo,
    CertFldSubjectPublicKeyInfoAlgorithm,
    CertFldSubjectPublicKeyInfoAlgorithmId,
    CertFldSubjectPublicKeyInfoAlgorithmParameters,
    CertFldSubjectPublicKeyInfoPublicKey,

    // revokedCertificates
    CrlFldEntries,

    /// Authority Key Identifier [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2
    CertExtAki,
    CertExtAkiOid,
    CertExtAkiValue,
    CertExtAkiSeq,
    CertExtAkiKeyIdentifier,

    /// Subject Key Identifier [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2
    CertExtSki,
    CertExtSkiOid,
    CertExtSkiValue,
    CertExtSkiKeyIdentifier,

    /// Key Usage [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3
    CertExtKu,
    CertExtKuOid,
    CertExtKuCritc,
    CertExtKuValue,
    CertExtKuBitstring,

    /// Certificate Policies [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4
    CertExtCp,
    CertExtCpOid,
    CertExtCpCritc,
    CertExtCpValue,
    CertExtCpSeq,
    CertExtCpPolicyInformation,
    CertExtCpPolicyIdentifierOid,
    CertExtCpPolicyQualifiers,
    CertExtCpPolicyQualifierInfo,
    CertExtCpPolicyQualifierOid, // TODO Certification Practice Statement (CPS) pointer qualifier type
    CertExtCpPolicyQualifier,

    /// Basic Constraints Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9
    CertExtBc,
    CertExtBcOid,
    CertExtBcCritc,
    CertExtBcValue,
    CertExtBcSeq,
    CertExtBcCa,

    /// CRL Distribution Points Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.13
    CertExtCrldp,
    CertExtCrldpOid,
    CertExtCrldpValue,
    CertExtCrldpSeq,
    CertExtCrldpDistributionPoint,
    CertExtCrldpDistributionPointName,
    CertExtCrldpFullName,
    CertExtCrldpUri,

    /// Authority Information Access Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.1
    CertExtAia,
    CertExtAiaOid,
    CertExtAiaValue,
    CertExtAiaSeq,
    CertExtAiaAccessDescription,
    CertExtAiaCaIssuersOid,
    CertExtAiaCaIssuersUri,

    /// Subject Information Access Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.2
    CertExtSia,
    CertExtSiaOid,
    CertExtSiaValue,
    CertExtSiaSeq,
    CertExtSiaAccessDescription,
    CertExtSiaCaRepositoryOid,
    CertExtSiaCaRepositoryUri,
    CertExtSiaRpkiManifestOid,
    CertExtSiaRpkiManifestUri,
    CertExtSiaNotificationOid,
    CertExtSiaNotificationUri,
    CertExtSiaSignedObjectOid,
    CertExtSiaSignedObjectUri,

    /// IP Address Delegation Extension [RFC3779]
    ///
    /// [RFC3779]: https://www.rfc-editor.org/rfc/rfc3779.html#section-2
    CertExtIp,
    CertExtIpOid,
    CertExtIpCritc,
    CertExtIpValue,
    CertExtIpSeq,
    CertExtIpAddressFamily,
    CertExtIpAddressFamilyId,
    CertExtIpAddressChoice,
    CertExtIpAddressPrefix(u32),
    CertExtIpAddressRange(u32),
    CertExtIpAddressRangeMin(u32),
    CertExtIpAddressRangeMax(u32),

    /// Autonomous System Identifier Delegation Extension [RFC3779]
    ///
    /// [RFC3779]: https://www.rfc-editor.org/rfc/rfc3779.html#section-3
    CertExtAsid,
    CertExtAsidOid,
    CertExtAsidCritc,
    CertExtAsidValue,
    CertExtAsidSeq,
    CertExtAsidAsnum,
    CertExtAsidAsnumIdOrRange,
    CertExtAsidAsnumRageMin,
    CertExtAsidAsnumRageMax,
    CertExtAsidRdi,
    CertExtAsidRdiIdOrRange,
    CertExtAsidRdiRangeMin,
    CertExtAsidRdiRangeMax,

    /// CRL Number Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3
    CrlExtCrln,
    CrlExtCrlnOid,
    CrlExtCrlnValue,
    /// CRLNumber ::= INTEGER (0..MAX)
    CrlExtCrlnCrlNumber,

    /// signerInfos
    SignedObjectSignerInfos,
    SignerInfo,
    SignerInfoVersion,
    SignerInfoSignerIdentifier,
    SignerInfoDigestAlgorithm,
    SignerInfoDigestAlgorithmIdentifierId,
    SignerInfoDigestAlgorithmIdentifierParameters,
    SignerInfoSignedAttributes,
    SignerInfoSignedAttributeContentType,
    SignerInfoSignedAttributeContentTypeOid,
    SignerInfoSignedAttributeContentTypeValues,
    SignerInfoSignedAttributeContentTypeAttributeValue,
    SignerInfoSignedAttributeMessageDigest,
    SignerInfoSignedAttributeMessageDigestOid,
    SignerInfoSignedAttributeMessageDigestValues,
    SignerInfoSignedAttributeMessageDigestAttributeValue,
    SignerInfoSignedAttributeSigningTime,
    SignerInfoSignedAttributeSigningTimeOid,
    SignerInfoSignedAttributeSigningTimeValues,
    SignerInfoSignedAttributeSigningTimeAttributeValue,
    SignerInfoSignedAttributeBinarySigningTime,
    SignerInfoSignedAttributeBinarySigningTimeOid,
    SignerInfoSignedAttributeBinarySigningTimeValues,
    SignerInfoSignedAttributeBinarySigningTimeAttributeValue,
    SignerInfoSignedAttributeSignature,
    SignerInfoSignedAttributeSignatureOid,
    SignerInfoSignedAttributeSignatureValues,
    SignerInfoSignedAttributeSignatureAttributeValue,
    SignerInfoSignatureAlgorithm,
    SignerInfoSignatureAlgorithmId,
    SignerInfoSignatureAlgorithmParameters,
    SignerInfoSignature,
}

impl LabelName {
    #[rustfmt::skip]
    pub fn short_label(&self) -> &'static str {
        use LabelName::*;
        match self {
            // Signed Object
            SignedObjectContentInfo => "contentInfo",
            SignedObjectContentType => "contentType",
            SignedObjectContent => "content",
            SignedObjectSignedData => "signedData",

            SignedObjectVersion => "version",

            SignedObjectDigestAlgorithms => "digestAlgorithms",
            SignedObjectDigestAlgorithmIdentifier => "digestAlgorithmIdentifier",
            SignedObjectDigestAlgorithmIdentifierId => "digestAlgorithmIdentifierId",
            SignedObjectDigestAlgorithmIdentifierParameters => "digestAlgorithmIdentifierParameters",

            SignedObjectEncapContentInfo => "eContentInfo",
            EContentType => "eContentType",
            EContent => "eContent",
            EContentString => "eContentString",
            EContentProfiled => "eContentProfiled",

            // Route Origin Authorization
            // RoaContent => "roaContent",
            RoaAsid => "roaAsId",
            RoaIpAddrBlocks => "roaIpAddrBlocks",
            RoaIpAddressFamily => "roaIpAddressFamily",
            RoaIpAddressFamilyAfi => "roaIpAddressFamilyAfi",
            RoaIpAddressFamilyAddresses => "roaAddresses",
            RoaIpAddressSeq(ipv) if *ipv == 1 => "roaIpAddressSeq_v4",
            RoaIpAddressSeq(ipv) if *ipv == 2 => "roaIpAddressSeq_v6",
            RoaIpAddressSeq(_ipv) => "roaIpAddressSeq",
            RoaIpAddress(ipv) if *ipv == 1 => "roaIpAddress_v4",
            RoaIpAddress(ipv) if *ipv == 2 => "roaIpAddress_v6",
            RoaIpAddress(_ipv) => "roaIpAddress",
            RoaIpAddressMl(ipv) if *ipv == 1 => "roaIpAddressMl_v4",
            RoaIpAddressMl(ipv) if *ipv == 2 => "roaIpAddressMl_v6",
            RoaIpAddressMl(_ipv) => "roaIpAddressMl",

            // AS Path Attestation
            // AspaContent => "aspaContent",
            AspaProviderAuthorization => "aspaProviderAuthorization",
            AspaVersion => "aspaVersion",
            AspaVersionValue => "aspaVersionValue",
            AspaCustomerAsid => "aspaCustomerAsid",
            AspaProviderAsSeq => "aspaProviderAsSeq",

            // Ghostbuster Record
            // GbrContent => "gbrContent",
            GbrVcard => "gbrVcard",

            // Manifest
            // MftContent => "mftContent",
            MftVersion => "mftVersion",
            MftNumber => "mftNumber",
            MftThisUpdate => "mftThisUpdate",
            MftNextUpdate => "mftNextUpdate",
            MftFileHashAlg => "mftFileHashAlg",
            MftFileList => "mftFileList",
            MftFileAndHash => "mftFileAndHash",
            MftFile => "mftFile",
            MftHash => "mftHash",
            // iManifest
            IMftCrlEntries => "imftCrlEntriesField",
            IMftCrlEntriesSeq => "imftCrlEntries",

            SignedObjectCertificateSet => "certificateSet",

            CertificateSeq => "certificateSeq",
            Certificate => "certificate",
            CertificateSignatureAlgorithm => "certificateSignatureAlgorithm",
            CertificateSignatureAlgorithmId => "certificateSignatureAlgorithmId",
            CertificateSignatureAlgorithmParameters => "certificateSignatureAlgorithmParameters",
            CertificateSignature => "certificateSignature",

            CertFldVersionSeq => "certVersionSeq",
            CertFldVersion => "certVersion",
            CertFldSerialNumber => "certSerialNumber",
            CertFldSignature => "certSignature",
            CertFldSignatureAlgorithm => "certSignatureAlgorithm",
            CertFldSignatureParameters => "certSignatureParameters",
            CertFldIssuer => "certIssuer",
            CertFldIssuerRdnSet => "certIssuerRdnSet",
            CertFldIssuerAttributeTypeAndValue => "certIssuerAttributeTypeAndValue",
            CertFldIssuerAttributeType => "certIssuerAttributeType",
            CertFldIssuerAttributeValue => "certIssuerAttributeValue",
            CertFldIssuerAttributeValueCN => "certIssuerAttributeValueCN",
            CertFldIssuerAttributeValueSerial => "certIssuerAttributeValueSerial",
            CertFldExtensions => "certExtensions",
            CertFldExtensionsSeq => "certExtensionsSeq",
            CertFldValidity => "certValidity",
            CertFldValidityNotBefore => "certNotBefore",
            CertFldValidityNotAfter => "certNotAfter",
            CertFldSubject => "certSubject",
            CertFldSubjectRdnSet => "certSubjectRdnSet",
            CertFldSubjectAttributeTypeAndValue => "certSubjectAttributeTypeAndValue",
            CertFldSubjectAttributeType => "certSubjectAttributeType",
            CertFldSubjectAttributeValue => "certSubjectAttributeValue",
            CertFldSubjectPublicKeyInfo => "certSubjectPublicKeyInfo",
            CertFldSubjectPublicKeyInfoAlgorithm => "certSubjectPublicKeyInfoAlgorithm",
            CertFldSubjectPublicKeyInfoAlgorithmId => "certSubjectPublicKeyInfoAlgorithmId",
            CertFldSubjectPublicKeyInfoAlgorithmParameters => "certSubjectPublicKeyInfoAlgorithmParameters",
            CertFldSubjectPublicKeyInfoPublicKey => "certSubjectPublicKeyInfoPublicKey",
            CrlFldEntries => "crlEntries",

            // Authority Key Identifier
            CertExtAki => "authorityKeyIdentifierExt",
            CertExtAkiOid => "authorityKeyIdentifierOid",
            CertExtAkiValue => "authorityKeyIdentifierValue",
            CertExtAkiSeq => "authorityKeyIdentifierSeq",
            CertExtAkiKeyIdentifier => "authorityKeyIdentifierKeyIdentifier",

            // Subject Key Identifier
            CertExtSki => "subjectKeyIdentifierExt",
            CertExtSkiOid => "subjectKeyIdentifierOid",
            CertExtSkiValue => "subjectKeyIdentifierValue",
            CertExtSkiKeyIdentifier => "subjectKeyIdentifierKeyIdentifier",

            // Key Usage
            CertExtKu => "keyUsageExt",
            CertExtKuOid => "keyUsageOid",
            CertExtKuCritc => "keyUsageValue",
            CertExtKuValue => "keyUsageValue",
            CertExtKuBitstring => "keyUsageBitstring",

            // Certificate Policies
            CertExtCp => "certificatePoliciesExt",
            CertExtCpOid => "certificatePoliciesOid",
            CertExtCpCritc => "certificatePoliciesCritc",
            CertExtCpValue => "certificatePoliciesValue",
            CertExtCpSeq => "certificatePoliciesSeq",
            CertExtCpPolicyInformation => "cpPolicyInformation",
            CertExtCpPolicyIdentifierOid => "cpPolicyIdentifierOid",
            CertExtCpPolicyQualifiers => "cpPolicyQualifiers",
            CertExtCpPolicyQualifierInfo => "cpPolicyQualifierInfo",
            CertExtCpPolicyQualifierOid => "cpPolicyQualifierOid",
            CertExtCpPolicyQualifier => "cpPolicyQualifier",

            // Basic Constraints
            CertExtBc => "basicConstraintsExt",
            CertExtBcOid => "basicConstraintsOid",
            CertExtBcCritc => "basicConstraintsCritc",
            CertExtBcValue => "basicConstraintsValue",
            CertExtBcSeq => "basicConstraintsSeq",
            CertExtBcCa => "basicConstraintsCa",

            // CRL Distribution Points
            CertExtCrldp => "crlDistributionPointsExt",
            CertExtCrldpOid => "crlDistributionPointsOid",
            CertExtCrldpValue => "crlDistributionPointsValue",
            CertExtCrldpSeq => "crlDistributionPointsSeq",
            CertExtCrldpDistributionPoint => "crlDistributionPointsDistributionPoint",
            CertExtCrldpDistributionPointName => "crlDistributionPointsDistributionPointName",
            CertExtCrldpFullName => "crlDistributionPointsFullName",
            CertExtCrldpUri => "crlDistributionPointsUri",

            // Authority Information Access
            CertExtAia => "authorityInformationAccessExt",
            CertExtAiaOid => "authorityInformationAccessOid",
            CertExtAiaValue => "authorityInformationAccessValue",
            CertExtAiaSeq => "authorityInformationAccessSeq",
            CertExtAiaAccessDescription => "aiaAccessDescription",
            CertExtAiaCaIssuersOid => "aiaCaIssuersOid",
            CertExtAiaCaIssuersUri => "aiaCaIssuersUri",

            // Subject Information Access
            CertExtSia => "subjectInformationAccessExt",
            CertExtSiaOid => "subjectInformationAccessOid",
            CertExtSiaValue => "subjectInformationAccessValue",
            CertExtSiaSeq => "subjectInformationAccessSeq",
            CertExtSiaAccessDescription => "siaAccessDescription",
            CertExtSiaCaRepositoryOid => "siaCaRepository",
            CertExtSiaCaRepositoryUri => "siaCaRepositoryURI",
            CertExtSiaRpkiManifestOid => "siaRpkiManifest",
            CertExtSiaRpkiManifestUri => "siaRpkiManifestURI",
            CertExtSiaNotificationOid => "siaNotification",
            CertExtSiaNotificationUri => "siaNotificationURI",
            CertExtSiaSignedObjectOid => "siaSignedObject",
            CertExtSiaSignedObjectUri => "siaSignedObjectURI",

            // IP Address Delegation Extension
            CertExtIp => "ipAddressDelegationExt",
            CertExtIpOid => "ipAddressDelegationOid",
            CertExtIpCritc => "ipAddressDelegationCritc",
            CertExtIpValue => "ipAddressDelegationValue",
            CertExtIpSeq => "ipAddressDelegationSeq",
            CertExtIpAddressFamily => "ipAddressDelegationFamily",
            CertExtIpAddressFamilyId => "ipAddressDelegationFamilyId",
            CertExtIpAddressChoice => "ipAddressDelegationIpAddrChoice",
            CertExtIpAddressPrefix(ipv) if *ipv == 1 => "ipAddressDelegation_v4_prefix",
            CertExtIpAddressPrefix(ipv) if *ipv == 2 => "ipAddressDelegation_v6_prefix",
            CertExtIpAddressPrefix(_ipv) => "ipAddressDelegation_prefix",
            CertExtIpAddressRange(ipv) if *ipv == 1 => "ipAddressDelegation_v4_range",
            CertExtIpAddressRange(ipv) if *ipv == 2 => "ipAddressDelegation_v6_range",
            CertExtIpAddressRange(_ipv) => "ipAddressDelegation_range",
            CertExtIpAddressRangeMin(ipv) if *ipv == 1 => "ipAddressDelegation_v4_rangeMin",
            CertExtIpAddressRangeMin(ipv) if *ipv == 2 => "ipAddressDelegation_v6_rangeMin",
            CertExtIpAddressRangeMin(_ipv) => "ipAddressDelegation_rangeMin",
            CertExtIpAddressRangeMax(ipv) if *ipv == 1 => "ipAddressDelegation_v4_rangeMax",
            CertExtIpAddressRangeMax(ipv) if *ipv == 2 => "ipAddressDelegation_v6_rangeMax",
            CertExtIpAddressRangeMax(_ipv) => "ipAddressDelegation_rangeMax",

            // Autonomous System Identifier Delegation Extension
            CertExtAsid => "asIdDelegationExt",
            CertExtAsidOid => "asIdDelegationOid",
            CertExtAsidCritc => "asIdDelegationCritc",
            CertExtAsidValue => "asIdDelegationValue",
            CertExtAsidSeq => "asIdDelegationSeq",
            CertExtAsidAsnum => "asIdDelegationAsnum",
            CertExtAsidAsnumIdOrRange => "asIdDelegationAsnumIdOrRange",
            CertExtAsidAsnumRageMin => "asIdDelegationAsnumRangeMin",
            CertExtAsidAsnumRageMax => "asIdDelegationAsnumRageMax",
            CertExtAsidRdi => "asIdDelegationRdi",
            CertExtAsidRdiIdOrRange => "asIdDelegationRdiOrRange",
            CertExtAsidRdiRangeMin => "asIdDelegationRdiRangeMin",
            CertExtAsidRdiRangeMax => "asIdDelegationRdiRangeMax",

            // CRL Number Extension
            CrlExtCrln => "crlNumberExt",
            CrlExtCrlnOid => "crlNumberOid",
            CrlExtCrlnValue => "crlNumberValue",
            CrlExtCrlnCrlNumber => "crlNumberCrlNumber",

            // signerInfos
            SignedObjectSignerInfos => "signerInfos",
            SignerInfo => "signerInfo",
            SignerInfoVersion => "signerInfoVersion",
            SignerInfoSignerIdentifier => "signerInfoSignerIdentifier",
            SignerInfoDigestAlgorithm => "signerInfoDigestAlgorithm",
            SignerInfoDigestAlgorithmIdentifierId => "signerInfoDigestAlgorithmId",
            SignerInfoDigestAlgorithmIdentifierParameters => "signerInfoDigestAlgorithmParameters",
            SignerInfoSignedAttributes => "signedAttributes",
            SignerInfoSignedAttributeContentType => "signedAttrContentType",
            SignerInfoSignedAttributeContentTypeOid => "signedAttrContentTypeOid",
            SignerInfoSignedAttributeContentTypeValues => "signedAttrContentTypeValues",
            SignerInfoSignedAttributeContentTypeAttributeValue => "signedAttrContentTypeAttributeValue",
            SignerInfoSignedAttributeMessageDigest => "signedAttrMessageDigest",
            SignerInfoSignedAttributeMessageDigestOid => "signedAttrMessageDigestOid",
            SignerInfoSignedAttributeMessageDigestValues => "signedAttrMessageDigestValues",
            SignerInfoSignedAttributeMessageDigestAttributeValue => "signedAttrMessageDigestAttributeValue",
            SignerInfoSignedAttributeSigningTime => "signedAttrSigningTime",
            SignerInfoSignedAttributeSigningTimeOid => "signedAttrSigningTimeOid",
            SignerInfoSignedAttributeSigningTimeValues => "signedAttrSigningTimeValues",
            SignerInfoSignedAttributeSigningTimeAttributeValue => "signedAttrSigningTimeAttributeValue",
            SignerInfoSignedAttributeBinarySigningTime => "signedAttrBinarySigningTime",
            SignerInfoSignedAttributeBinarySigningTimeOid => "signedAttrBinarySigningTimeOid",
            SignerInfoSignedAttributeBinarySigningTimeValues => "signedAttrBinarySigningTimeValues",
            SignerInfoSignedAttributeBinarySigningTimeAttributeValue => "signedAttrBinarySigningTimeAttributeValue",
            SignerInfoSignedAttributeSignature => "signedAttrSignature",
            SignerInfoSignedAttributeSignatureOid => "signedAttrSignatureOid",
            SignerInfoSignedAttributeSignatureValues => "signedAttrSignatureValues",
            SignerInfoSignedAttributeSignatureAttributeValue => "signedAttrSignatureAttributeValue",
            SignerInfoSignatureAlgorithm => "signerInfoSignatureAlgorithm",
            SignerInfoSignatureAlgorithmId => "signerInfoSignatureAlgorithmId",
            SignerInfoSignatureAlgorithmParameters => "signerInfoSignatureAlgorithmParameters",
            SignerInfoSignature => "signerInfoSignature",
        }
    }

    /// Returns the OID associated with a [`LabelName`] (indicated by ending with -Oid).
    ///
    /// Returns [`None`], if no OID is associated with this [`LabelName`].
    pub fn oid(&self) -> Option<&'static str> {
        use LabelName::*;
        match self {
            CertExtAkiOid => Some("2.5.29.35"),
            CertExtSkiOid => Some("2.5.29.14"),
            CertExtKuOid => Some("2.5.29.15"),
            CertExtCpOid => Some("2.5.29.32"),
            CertExtBcOid => Some("2.5.29.19"),
            CertExtCrldpOid => Some("2.5.29.31"),
            CertExtAiaOid => Some("1.3.6.1.5.5.7.1.1"),
            CertExtAiaCaIssuersOid => Some("1.3.6.1.5.5.7.48.2"),
            CertExtSiaOid => Some("1.3.6.1.5.5.7.1.11"),
            CertExtSiaCaRepositoryOid => Some("1.3.6.1.5.5.7.48.5"),
            CertExtSiaRpkiManifestOid => Some("1.3.6.1.5.5.7.48.10"),
            CertExtSiaNotificationOid => Some("1.3.6.1.5.5.7.48.13"),
            CertExtSiaSignedObjectOid => Some("1.3.6.1.5.5.7.48.11"),
            CertExtIpOid => Some("1.3.6.1.5.5.7.1.7"),
            CertExtAsidOid => Some("1.3.6.1.5.5.7.1.8"),
            CrlExtCrlnOid => Some("2.5.29.20"),
            SignerInfoSignedAttributeContentTypeOid => Some("1.2.840.113549.1.9.3"),
            SignerInfoSignedAttributeMessageDigestOid => Some("1.2.840.113549.1.9.4"),
            SignerInfoSignedAttributeSigningTimeOid => Some("1.2.840.113549.1.9.5"),
            SignerInfoSignedAttributeBinarySigningTimeOid => Some("1.2.840.113549.1.9.16.2.46"),
            SignerInfoSignedAttributeSignatureOid => Some("1.2.840.113549.1.9.6"),
            _ => None,
        }
    }
}