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
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/security"
)
   


type TLSOptions struct {
	RootCert string
	Key      string
	Cert     string
}



// CSRSign calls Citadel to sign a CSR.
func (c *CitadelClient) CSRSign(csrPEM []byte, certValidTTLInSec int64) (res []string, err error) {
	crMetaStruct := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			security.CertSigner: {
				Kind: &structpb.Value_StringValue{StringValue: c.opts.CertSigner},
			},
		},
	}
	req := &pb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidTTLInSec,
		Metadata:         crMetaStruct,
	}
	// TODO(hzxuzhonghu): notify caclient rebuilding only when root cert is updated.
	// It can happen when the istiod dns certs is resigned after root cert is updated,
	// in this case, the ca grpc client can not automatically connect to istiod after the underlying network connection closed.
	// Becase that the grpc client still use the old tls configuration to reconnect to istiod.
	// So here we need to rebuild the caClient in order to use the new root cert.
	defer func() {
		if err != nil {
			log.Errorf("failed to sign CSR: %v", err)
			// if err := c.reconnect(); err != nil {
			// 	log.Errorf("failed reconnect: %v", err)
			// }
		}
	}()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %v", err)
	}

	if len(resp.CertChain) <= 1 {
		return nil, errors.New("invalid empty CertChain")
	}

	return resp.CertChain, nil
}

// GetRootCertBundle: Citadel (Istiod) CA doesn't publish any endpoint to retrieve CA certs
func (c *CitadelClient) GetRootCertBundle() ([]string, error) {
	return []string{}, nil
}
