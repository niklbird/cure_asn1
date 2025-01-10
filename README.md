## Overview

**cure_asn1** is a Rust library designed for parsing RPKI objects encoded in ASN.1 format, as well as handling RRDP (RPKI Repository Delta Protocol) objects. Whether you're building tools for RPKI validation, analyzing route security data, or experimenting with ASN.1 encoding, **cure_asn1** provides robust and efficient functionality.
The library is build to be easily understandable and extendable.

---

## Features

- 📜 **ASN.1 Parsing**: Decode and parse RPKI objects encoded in ASN.1.
- 🌐 **RRDP Support**: Handle RRDP objects for managing repositories and updates.
- ⚡ **High Performance**: Built in Rust for speed and reliability.
- 🛠️ **Customizable**: Extend and integrate the library into your own tools.

## Usage
Parse an RPKI object by calling cure_asn1::rpki::parse_rpki_object(). 
