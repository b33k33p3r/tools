import asn1tools
import sys

# First, let's compile an ASN.1 specification for CRL based on RFC 5280 to parse the file.
asn1_spec = """

CRL DEFINITIONS ::= BEGIN

CertificateList  ::=  SEQUENCE  {
     tbsCertList          TBSCertList,
     signatureAlgorithm   AlgorithmIdentifier,
     signatureValue       BIT STRING
}

TBSCertList  ::=  SEQUENCE  {
     version                 Version OPTIONAL,
                             -- if present, MUST be v2
     signature               AlgorithmIdentifier,
     issuer                  Name,
     thisUpdate              Time,
     nextUpdate              Time OPTIONAL,
     revokedCertificates     SEQUENCE OF SEQUENCE  {
          userCertificate         CertificateSerialNumber,
          revocationDate          Time,
          crlEntryExtensions      Extensions OPTIONAL
                                        -- if present, version MUST be v2
     } OPTIONAL,
     crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                        -- if present, version MUST be v2
}

AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL
}

Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

CertificateSerialNumber  ::=  INTEGER

Name ::= CHOICE {
    -- only one possibility for now --
    rdnSequence  RDNSequence
}

RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::=
    SET SIZE (1..MAX) OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
    type     AttributeType,
    value    AttributeValue
}

AttributeType ::= OBJECT IDENTIFIER

AttributeValue ::= ANY -- DEFINED BY AttributeType

Time ::= CHOICE {
    utcTime        UTCTime,
    generalTime    GeneralizedTime
}

Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension

Extension ::= SEQUENCE {
    extnID      OBJECT IDENTIFIER,
    critical    BOOLEAN DEFAULT FALSE,
    extnValue   OCTET STRING
}
END
"""

# Compile the ASN.1 specification
compiler = asn1tools.compile_string(asn1_spec, 'der')

# Function to parse CRL
def parse_crl(file_path):
    # Read the CRL file
    with open(file_path, 'rb') as file:
        crl_data = file.read()
    # Parse the CRL using the compiled specification
    try:
        crl_parsed = compiler.decode('CertificateList', crl_data)
        print("CRL parsed successfully:")
        print(crl_parsed)
    except Exception as e:
        print("Failed to parse CRL:", str(e))

# Check if a file path is provided as a command-line argument
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parseasn1.py path_to_crl_file")
    else:
        # Get the file path from command-line arguments and parse the CRL
        file_path = sys.argv[1]
        parse_crl(file_path)
