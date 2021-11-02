//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fulcio

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	"golang.org/x/term"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/pkg/cosign"
	fulcioClient "github.com/sigstore/fulcio/pkg/generated/client"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	FlowNormal = "normal"
	FlowDevice = "device"
	FlowToken  = "token"
)

type Resp struct {
	CertPEM  []byte
	ChainPEM []byte
	SCT      []byte
}

type oidcConnector interface {
	OIDConnect(string, string, string) (*oauthflow.OIDCIDToken, error)
}

type realConnector struct {
	flow oauthflow.TokenGetter
}

func (rf *realConnector) OIDConnect(url, clientID, secret string) (*oauthflow.OIDCIDToken, error) {
	return oauthflow.OIDConnect(url, clientID, secret, rf.flow)
}

type signingCertProvider interface {
	SigningCert(params *operations.SigningCertParams, authInfo runtime.ClientAuthInfoWriter, opts ...operations.ClientOption) (*operations.SigningCertCreated, error)
}

func getPublicBytes(public crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch public.(type) {
	case *ecdsa.PublicKey:
		ecdsaPub := public.(*ecdsa.PublicKey)
		pubBytes, err = x509.MarshalPKIXPublicKey(ecdsaPub)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Unsupported key type")
	}

	return pubBytes, nil
}

func getCertForOauthID(internalSigner signature.SignerVerifier, scp signingCertProvider, connector oidcConnector, oidcIssuer string, oidcClientID string) (Resp, error) {
	public, err := internalSigner.PublicKey()
	if err != nil {
		return Resp{}, errors.New("reading public")
	}

	pubBytes, err := getPublicBytes(public)
	if err != nil {
		return Resp{}, err
	}

	tok, err := connector.OIDConnect(oidcIssuer, oidcClientID, "")
	if err != nil {
		return Resp{}, err
	}

	// Sign the email address as part of the request
	proof, err := internalSigner.SignMessage(bytes.NewReader([]byte(tok.Subject)))
	if err != nil {
		return Resp{}, err
	}

	bearerAuth := httptransport.BearerToken(tok.RawString)

	content := strfmt.Base64(pubBytes)
	signedChallenge := strfmt.Base64(proof)
	params := operations.NewSigningCertParams()
	params.SetCertificateRequest(
		&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Algorithm: models.CertificateRequestPublicKeyAlgorithmEcdsa,
				Content:   &content,
			},
			SignedEmailAddress: &signedChallenge,
		},
	)

	resp, err := scp.SigningCert(params, bearerAuth)
	if err != nil {
		return Resp{}, err
	}
	sct, err := base64.StdEncoding.DecodeString(resp.SCT.String())
	if err != nil {
		return Resp{}, err
	}

	// split the cert and the chain
	certBlock, chainPem := pem.Decode([]byte(resp.Payload))
	certPem := pem.EncodeToMemory(certBlock)
	fr := Resp{
		CertPEM:  certPem,
		ChainPEM: chainPem,
		SCT:      sct,
	}

	return fr, nil
}

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(ctx context.Context, internalSigner signature.SignerVerifier, idToken, flow, oidcIssuer, oidcClientID string, fClient *fulcioClient.Fulcio) (Resp, error) {
	c := &realConnector{}
	switch flow {
	case FlowDevice:
		c.flow = oauthflow.NewDeviceFlowTokenGetter(
			oidcIssuer, oauthflow.SigstoreDeviceURL, oauthflow.SigstoreTokenURL)
	case FlowNormal:
		c.flow = oauthflow.DefaultIDTokenGetter
	case FlowToken:
		c.flow = &oauthflow.StaticTokenGetter{RawToken: idToken}
	default:
		return Resp{}, fmt.Errorf("unsupported oauth flow: %s", flow)
	}

	return getCertForOauthID(internalSigner, fClient.Operations, c, oidcIssuer, oidcClientID)
}

type Signer struct {
	Cert  []byte
	Chain []byte
	SCT   []byte
	pub   crypto.PublicKey
	signature.SignerVerifier
}

func NewSigner(ctx context.Context, idToken, oidcIssuer, oidcClientID string, fClient *fulcioClient.Fulcio, internalSigner signature.SignerVerifier) (*Signer, error) {
	if internalSigner == nil {
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		priv, err := cosign.GeneratePrivateKey()
		if err != nil {
			return nil, errors.Wrap(err, "generating cert")
		}
		internalSigner, err = signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
		if err != nil {
			return nil, err
		}
	}

	public, err := internalSigner.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "reading public")
	}

	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	var flow string
	switch {
	case idToken != "":
		flow = FlowToken
	case !term.IsTerminal(0):
		fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")
		flow = FlowDevice
	default:
		flow = FlowNormal
	}
	Resp, err := GetCert(ctx, internalSigner, idToken, flow, oidcIssuer, oidcClientID, fClient) // TODO, use the chain.
	if err != nil {
		return nil, errors.Wrap(err, "retrieving cert")
	}

	f := &Signer{
		pub:            &public,
		SignerVerifier: internalSigner,
		Cert:           Resp.CertPEM,
		Chain:          Resp.ChainPEM,
		SCT:            Resp.SCT,
	}

	return f, nil
}

func (f *Signer) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return &f.pub, nil
}

var _ signature.Signer = &Signer{}

func GetRoots() *x509.CertPool {
	return fulcioroots.Get()
}
