This is my (Lennert Buijtenhek's) implementation of the Eiger-selected
node-handshake recruitment coding challenge as found here:

	https://github.com/eqlabs/recruitment-exercises/blob/master/node-handshake.md  


Protocol chosen
---------------
The challenge asks for an implementation of a peer-to-peer network
protocol handshake.  I decided to implement the libp2p TLS ("/tls/1.0.0")
handshake, as documented here:

	https://github.com/libp2p/specs/blob/master/tls/tls.md

This includes the generation and validation of the libp2p-specific
X.509 certificate extension that encodes the node's libp2p public key
plus a signature of the key referenced in the X.509 certificate (the
"TLS key") using the libp2p node key.

Ed25519 and ECDSA node keys are both supported, using the
secp256k1-specific compressed point encoding format for secp256k1 keys,
and the more generic DER encoding for keys on non-secp256k1 curves, as
per the libp2p TLS protocol documentation.

There is also a minimal implementation of the libp2p multistream-select
protocol, which is needed to negotiate "/tls/1.0.0" so that we can
initiate the libp2p TLS handshake with the peer, and we also use it to
negotiate "/yamux/1.0.0" inside the TLS session, even though we could
negotiate yamux using TLS ALPN -- the point of doing this was to show
that the multistream-select implementation can be used both on a raw
TCP connection as well as inside a TLS session.


Getting started
---------------
The demo app will:

- generate a libp2p node key (Ed25519 by default, but you can switch
  around an if statement in the first lines of the main() function to
  make it generate an ECDSA key instead if you want to test that);

- connect to TCP port 4001 on 127.0.0.1;

- perform multistream-select negotation for protocol "/tls/1.0.0";

- perform the libp2p TLS handshake using the libp2p node key, and an
  ephemeral TLS key and X.509 certificate which are generated on the
  fly, and checking the remote's presented X.509 certificate for the
  presence and validity of the X.509 libp2p node key extension;

- perform another multistream-select negotation inside the established
  TLS session for "/yamux/1.0.0".

If all of this is successful, it will print a message telling you so,
and if not, it should tell you what went wrong.

I set up the demo app this way to be able to test the libp2p TLS
handshake implementation against Kubo, an IPFS implementation, and the
easiest way to test the demo app would be to download Kubo (from
dist.ipfs.tech) and run it using "ipfs daemon", and then running the
demo app on the same machine.

Successful output should look something like this:

	$ cargo run
	   Compiling eiger-challenge v0.1.0 (/home/buytenh/eiger/neg)
	    Finished dev [unoptimized + debuginfo] target(s) in 0.87s
	     Running `target/debug/eiger-challenge`
	Connecting to 127.0.0.1:4001
	Connected to 127.0.0.1:4001
	Negotiating multistream protocol /tls/1.0.0 with remote
	Negotiated multistream protocol /tls/1.0.0 with remote
	Performing TLS handshake
	Performed TLS handshake
	Negotiating multistream protocol /yamux/1.0.0 with remote
	Negotiated multistream protocol /yamux/1.0.0 with remote
	Terminating successfully
	$


Protocol choice
---------------
Initially, I thought about submitting a Rust implementation of the
handshake protocol of dvpn, which is a peer-to-peer networking
application with its own built-in mesh routing protocol -- but then I
figured that since I wrote dvpn myself (in C), reimplementing part of
it in Rust would not demonstrate my ability to read protocol
documentation and turn it into a protocol implementation.  Also, dvpn
is a relatively obscure project that never gained much popularity, and
setting it up would be a bit of a hassle for the reviewer of my code.
(Also, I already started rewriting dvpn in Rust as a hobby project in
the background some time ago.)

The coding challenge instructions hinted at not picking Bitcoin, so I
then settled on implementing "ipfs", this being a peer-to-peer
protocol that I had heard about a while ago, but had never used, and
had never read any implementations or any protocol documentation or
other documentation for before I started this challenge, and I had
no idea exactly what sub-protocols or technologies it encompassed.

As part of this challenge, I spent a fair bit of time learning about
ipfs and what underlying protocols it uses and how those protocols
work, and in the end, I settled on focusing on doing the work necessary
to enable an implementation of ipfs's Bitswap protocol, which meant
that I would implement the multistream-select protocol and the libp2p
TLS handshake for this challenge, and would forgo the DHT (Kademlia)
side of ipfs for now.


Implementation process
----------------------
I referenced the libp2p TLS documentation:

	https://github.com/libp2p/specs/blob/master/tls/tls.md

As well as the multistream-select documentation:

	https://github.com/multiformats/multistream-select

Also, I used tcpdump/wireshark to inspect the traffic flowing in and
out of a locally running Kubo node, and I performed testing of my code
against this locally running Kubo node.

I have not looked at any other libp2p or ipfs implementations.  This
self-imposed restriction has probably made my life a little bit harder
than it otherwise would have been, and during the protocol implementation
process I have wanted to reference other implementations at times, to
help with debugging and when there were gaps in the available protocol
documentation, but I did not want to inadvertently derive (part of) my
submission from other implementations, and looking at other protocol
implementations would feel like cheating for the purpose of completing
this challenge, and I wanted to complete this challenge without cheating.


Implementation choices and dependencies
---------------------------------------
This project depends on the openssl crate, because we need a TLS
implementation to perform the libp2p-tls handshake, and I somewhat
arbitrarily picked OpenSSL as the TLS library, mostly because I have
used it before from C code (but not from Rust code).

We don't use the openssl crate's SslContext build wrappers.  The openssl
crate declares C OpenSSL's defaults to be insecure, and it nudges you
towards using its provided SslContext build wrappers that enable things
like SNI and hostname verification by default, which makes sense e.g. if
you need a TLS library for the reason that you want to speak https, but
the libp2p TLS handshake is "special", and doesn't use these TLS
features, and therefore, using the SslContext build wrappers is not
useful or appropriate.

We have particular requirements for the validation of the peer's X.509
certificate (specifically, that it contains a libp2p-specific X.509
certificate extension that encodes the libp2p node key as well as a
signature for the TLS key using the libp2p node key), and we automatically
set up our SslContext so that this validation is performed during the
TLS handshake, and this is what provides the security of our TLS
handshake, and not the reliance on SNI or hostname verification or
certificate chain validation like in the case of https.

To validate the libp2p X.509 extension in the peer's presented X.509
certificate, we need to be able to extract that extension's data from
the certificate, but, as I found out fairly late during the challenge
implementation process, the openssl crate does not seem to provide
access to C OpenSSL's X509_EXTENSION_get_data() and friends.  Therefore,
this project pulls in an external X.509 parser, for which I somewhat
arbitrarily picked the "x509-parser" crate, and uses that to extract
the libp2p X.509 extension from the peer certificate.

To validate the peer certificate's libp2p X.509 extension, which at
the top level is in ASN.1 DER format like the X.509 certificate itself
is, we need a DER parser, and for this I picked the "asn1-rs" crate,
since that is the parser that "x509-parser" uses, and so, we already
have it as a dependency.

To validate the peer certificate's libp2p X.509 extension, we also
need a protobuf parser, since the publicKey half of that extension is
in protobuf format.  (Why?  It's a mystery.)  For this I somewhat
arbitrarily picked the "protobuf" crate.  The publicKey field is
described in src/protos/publickey.proto, which is compiled to Rust code
at build time and pulled in.

The challenge description did not explicitly mention that async Rust
was to be used, but there is the hint that it should be non-blocking,
so I implemented this as async, and I (again somewhat arbitrarily)
picked tokio as the runtime, and "tokio-openssl" as the OpenSSL wrapper.

I developed and tested this code on Rust 1.74.0 as that is what comes
with my Linux distro.


Future work
-----------
I am fairly happy with this code, but since a fairly large chunk of time
allocated for this challenge got eaten up by figuring out libp2p protocol
intricacies, there is room for potential future improvements, and some of
those potential future improvements would include:

- Some additional libp2p-tls-openssl tests to generate bad certificates
  and signatures and validate that those fail.

  We do validate all the libp2p TLS X.509 certificate test vectors as
  part of our tests, and the "invalid" test vector is correctly rejected
  by my implementation, but it would be good to incorporate the generation
  of bad certificates into our tests as well.

- Adding a multistream-select responder implementation and adding tests
  to test the initiator against the responder, and to test the full
  libp2p TCP-level handshake as part of these tests.

- The user-facing APIs for the libp2p-tls-openssl and multistream modules
  need to be fleshed out more.

  For this, there really needs to be a "real" user of these APIs (i.e.
  a yamux implementation, and then possibly a Bitswap implementation on
  top of that), and not just the stub that we have now, and the needs
  of that "real" user would then drive the design of those APIs.

  (E.g. one obvious missing feature is a simple multihash implementation
  so that we can print the local and remote libp2p node IDs as part of the
  libp2p handshake process.)

- The code could use some more polish in some places.
