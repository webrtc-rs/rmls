<h1 align="center">
 <a href="https://rmls.io"><img src="https://raw.githubusercontent.com/webrtc-rs/rmls/master/doc/logo.png" alt="rmls.io"></a>
 <br>
</h1>
<p align="center">
 <a href="https://github.com/webrtc-rs/rmls/actions">
  <img src="https://github.com/webrtc-rs/rmls/workflows/cargo/badge.svg">
 </a>
 <a href="https://codecov.io/gh/webrtc-rs/rmls"> 
  <img src="https://codecov.io/gh/webrtc-rs/rmls/branch/master/graph/badge.svg">
 </a>
 <a href="https://deps.rs/repo/github/webrtc-rs/rmls">
  <img src="https://deps.rs/repo/github/webrtc-rs/rmls/status.svg">
 </a>
 <a href="https://crates.io/crates/rmls">
  <img src="https://img.shields.io/crates/v/rmls.svg">
 </a>
 <a href="https://docs.rs/rmls">
  <img src="https://docs.rs/rmls/badge.svg">
 </a>
 <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
 </a>
 <a href="https://discord.gg/4Ju8UHdXMs">
  <img src="https://img.shields.io/discord/800204819540869120?logo=discord" alt="Discord">
 </a>
 <a href="https://twitter.com/WebRTCrs">
  <img src="https://img.shields.io/twitter/url/https/twitter.com/webrtcrs.svg?style=social&label=%40WebRTCrs" alt="Twitter">
 </a>
</p>
<p align="center">
 Messaging Layer Security in Rust
</p>


<details>
<summary><b>Table of Content</b></summary>

- [Overview](#overview)
- [Supported CipherSuites](#supported-ciphersuites)
- [Supported Platforms](#supported-platforms)
- [Cryptography Dependencies](#cryptography-dependencies)
- [Open Source License](#open-source-license)
- [Contributing](#contributing)

</details>


## Overview

*RMLS* is a Rust implementation of the Messaging Layer Security (MLS) protocol, as specified in [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420).
Messaging Layer Security (MLS) is a key establishment protocol that provides efficient asynchronous group key establishment with forward secrecy (FS) and 
post-compromise security (PCS) for groups in size ranging from two to thousands.

## Supported CipherSuites

- MLS_128_HPKEX25519_AES128GCM_SHA256_Ed25519
- MLS_128_DHKEMP256_AES128GCM_SHA256_P256
- MLS_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519

## Supported Platforms

*RMLS* is built and tested on the Github CI for the following rust targets:

- x86_64-unknown-linux-gnu 
- i686-unknown-linux-gnu
- x86_64-pc-windows-msvc
- i686-pc-windows-msvc
- x86_64-apple-darwin

The Github CI also builds (but doesn't test) the following rust targets:

- aarch64-apple-darwin
- aarch64-unknown-linux-gnu
- aarch64-linux-android
- aarch64-apple-ios
- aarch64-apple-ios-sim
- wasm32-unknown-unknown
- armv7-linux-androideabi
- x86_64-linux-android
- i686-linux-android

## Cryptography Dependencies

*RMLS* does not implement its own cryptographic primitives. Instead, it relies
on existing implementations of the cryptographic primitives, i.e., [ring](https://github.com/briansmith/ring) or [RustCrypto](https://github.com/RustCrypto). There
are two cryptography providers implemented right now:

- [ring](https://github.com/briansmith/ring) based crypto provider
- [RustCrypto](https://github.com/RustCrypto) based crypto provider 

Other cryptography providers, like [openssl](https://github.com/sfackler/rust-openssl) or
[boring](https://github.com/cloudflare/boring), are also possible, see [CryptoProvider Trait](https://docs.rs/rmls/latest/rmls/crypto/provider/trait.CryptoProvider.html) for more
details.

## Open Source License

Dual licensing under both MIT and Apache-2.0 is the currently accepted standard by the Rust language community and has been used for both the compiler and many public libraries since (see <https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license>). 
In order to match the community standards, *RMLS* is using the dual MIT+Apache-2.0 license.

## Contributing

Contributors or Pull Requests are Welcome!!!