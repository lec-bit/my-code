/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: lec-bit
 * Create: 2024-02-27
 */

package kmeshsecurity

import (
	"fmt"
	"time"

	"google.golang.org/grpc"
	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"

	"istio.io/istio/security/pkg/monitoring"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	"kmesh.net/kmesh/pkg/nets"
)

var tlsOpts *TLSOptions
var 	PilotCertProvider = env.Register("PILOT_CERT_PROVIDER", "istiod",
"The provider of Pilot DNS certificate.").Get()


type CitadelClient struct {
	// It means enable tls connection to Citadel if this is not nil.
	tlsOpts  *TLSOptions
	client   pb.IstioCertificateServiceClient
	conn     *grpc.ClientConn
	provider *TokenProvider
	opts     *security.Options
}

// NewCitadelClient create a CA client for Citadel.
func NewCitadelClient(opts *security.Options, tlsOpts *TLSOptions) (*CitadelClient, error) {
	var err error;

	c := &CitadelClient{
		tlsOpts:  tlsOpts,
		opts:     opts,
		provider: NewCATokenProvider(opts),
	}
	CSRSignAddress := env.Register("MESH_CONTROLLER", "istiod.istio-system.svc:15012", "").Get()
	conn, err = nets.GrpcConnect(CSRSignAddress);
	if err != nil {
		log.Errorf("Failed to connect to endpoint %s: %v", opts.CAEndpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", opts.CAEndpoint)
	}

	c.conn = conn
	c.client = pb.NewIstioCertificateServiceClient(conn)
	return c, nil
}

func NewCATokenProvider(opts *security.Options) *TokenProvider {
	return &TokenProvider{opts, true}
}

// TokenProvider is a grpc PerRPCCredentials that can be used to attach a JWT token to each gRPC call.
// TokenProvider can be used for XDS, which may involve token exchange through STS.
type TokenProvider struct {
	opts *security.Options
	// TokenProvider can be used for XDS. Because CA is often used with
	// external systems and XDS is not often (yet?), many of the security options only apply to CA
	// communication. A more proper solution would be to have separate options for CA and XDS, but
	// this requires API changes.
	forCA bool
}

//grpc连接建立位置，建立一次？
  func (c *CitadelClient) fetch_cert(resourceName string) (secret *security.SecretItem, err error) {
	log.Infof("------------------fetch_cert---------- %#v ----------\n", resourceName);

	trustBundlePEM := []string{}
	 var rootCertPEM []byte

	 
//生成構造CSR,
// TODO: ns和domain都不對，這裡獲取的是kmesh的，需要調整成pod的，原因是抄的istio代碼這裡是為自己生成證書，kmesh需要為pod生成證書
	csrHostName := &spiffe.Identity{
		TrustDomain:    Cache.TrustDomain, // TODO
		Namespace:      Cache.Namespace, //TODO
		ServiceAccount: resourceName,
	}
	log.Infof("constructed host name for CSR: %s", csrHostName.String())

	options := pkiutil.CertOptions{
		Host:       csrHostName.String(),
		RSAKeySize: c.opts.WorkloadRSAKeySize,
		PKCS8Key:   c.opts.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(c.opts.ECCSigAlg),
		ECCCurve:   pkiutil.SupportedEllipticCurves(c.opts.ECCCurve),
	}
	logPrefix := cacheLogPrefix(resourceName)
	log.Infof("------------------GenCSR---------- %#v ----------\n", resourceName);
	// Generate the cert/key, send CSR to CA.
	csrPEM, keyPEM, err := pkiutil.GenCSR(options)
	if err != nil {
		log.Errorf("%s failed to generate key and certificate for CSR: %v", logPrefix, err)
		return nil, err
	}
	
	//申请证书签名
	numOutgoingRequests.With(RequestType.Value(monitoring.CSR)).Increment()
	certChainPEM, err := c.CSRSign(csrPEM, int64(c.opts.SecretTTL.Seconds()))
	if err == nil {
		trustBundlePEM, err = c.GetRootCertBundle()
	}

	certChain := concatCerts(certChainPEM)

	var expireTime time.Time
	// Cert expire time by default is createTime + sc.configOptions.SecretTTL.
	// Istiod respects SecretTTL that passed to it and use it decide TTL of cert it issued.
	// Some customer CA may override TTL param that's passed to it.
	if expireTime, err = nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain); err != nil {
		log.Errorf("%s failed to extract expire time from server certificate in CSR response %+v: %v",
			logPrefix, certChainPEM, err)
		return nil, fmt.Errorf("failed to extract expire time from server certificate in CSR response: %v", err)
	}

	if len(trustBundlePEM) > 0 {
		rootCertPEM = concatCerts(trustBundlePEM)
	} else {
		// If CA Client has no explicit mechanism to retrieve CA root, infer it from the root of the certChain
		rootCertPEM = []byte(certChainPEM[len(certChainPEM)-1])
	}
	log.Infof("------------------rootCertPEM---------- %v\n", rootCertPEM);
	log.Infof("------------------expireTime---------- %v\n", expireTime);
	log.Infof("------------------keyPEM---------- %v\n", keyPEM);
	log.Infof("------------------certChain---------- %v\n", certChain);
	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     resourceName,
		CreatedTime:      time.Now(),
		ExpireTime:       expireTime,
		RootCert:         rootCertPEM,
	}, nil
}
