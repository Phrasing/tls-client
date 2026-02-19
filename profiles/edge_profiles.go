package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

var Edge_145 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Edge",
		RandomExtensionOrder: false,
		Version:              "145",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					// Edge 145 extension order (from captured JA4_ro fingerprint)
					&tls.UtlsGREASEExtension{},
					&tls.ExtendedMasterSecretExtension{},                               // 23
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},      // 16
					tls.BoringGREASEECH(),                                               // 65037
					&tls.SupportedVersionsExtension{Versions: []uint16{                  // 43
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{ // 27
						tls.CertCompressionBrotli,
					}},
					&tls.SessionTicketExtension{},                                        // 35
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{ // 13
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, // 17613
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{                        // 51
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.StatusRequestExtension{},                                           // 5
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{                    // 10
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SNIExtension{},                                                     // 0
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},       // 45
					&tls.SCTExtension{},                                                     // 18
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, // 65281
					&tls.SupportedPointsExtension{SupportedPoints: []byte{                   // 11
						tls.PointFormatUncompressed,
					}},
					&tls.UtlsGREASEExtension{},
					// Note: No TrustAnchors extension (0xca34) — Edge 145 does not include it
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
