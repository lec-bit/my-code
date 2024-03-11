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
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	"istio.io/istio/pkg/security"
	"kmesh.net/kmesh/pkg/logger"
)
   
   var certs_maps sync.Map
  
   var log = logger.NewLoggerField("kmeshsecurity")
  
   var CACertFilePath = ""

   type SecretManagerClient struct {
	caClient *CitadelClient

	// configOptions includes all configurable params for the cache.
	configOptions *security.Options

	// callback function to invoke when detecting secret change.
	secretHandler func(resourceName string)

	// 
	cache sync.Map

	// Dynamically configured Trust Bundle
	configTrustBundle []byte

	caRootPath string
}

  // concatCerts concatenates PEM certificates, making sure each one starts on a new line
 func concatCerts(certsPEM []string) []byte {
	 if len(certsPEM) == 0 {
		 return []byte{}
	 }
	 var certChain bytes.Buffer
	 for i, c := range certsPEM {
		 certChain.WriteString(c)
		 if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			 certChain.WriteString("\n")
		 }
	 }
	 return certChain.Bytes()
 }
   
   // ProxyArgs provides all of the configuration parameters for the Pilot proxy.
  type ProxyArgs struct {
	  DNSDomain          string
	  StsPort            int
	  TokenManagerPlugin string
  
	  MeshConfigFile string
  
	  // proxy config flags (named identically)
	  ServiceCluster         string
	  ProxyLogLevel          string
	  ProxyComponentLogLevel string
	  Concurrency            int
	  TemplateFile           string
	  OutlierLogPath         string
  
	  PodName      string
	  PodNamespace string
  
	  // enableProfiling enables profiling via web interface host:port/debug/pprof/
	  EnableProfiling bool
  }
  
  
  const (
	  DefaultPurgeInterval         = 1 * time.Hour
	  DefaultModuleExpiry          = 24 * time.Hour
	  DefaultHTTPRequestTimeout    = 15 * time.Second
	  DefaultHTTPRequestMaxRetries = 5
  )
  

   type entry struct {
	  value interface{}
	  mu    sync.Mutex
  }
   
  var (
	  proxyArgs      ProxyArgs
  )
  
  const (
	  // MaxRetryInterval retry interval time when reconnect
	  MaxRetryInterval = time.Second * 30
  
	  // MaxRetryCount retry max count when reconnect
	  MaxRetryCount = 3
  
  //	credFetcherTypeEnv = "JWT"
  //	trustDomainEnv     = "cluster.local"
	  jwtPath            = "/var/run/secrets/tokens/istio-token"
	  rootCertPath       = "/var/run/secrets/istio/root-cert.pem"
  
	  KubeAppProberEnvName = "ISTIO_KUBE_APP_PROBERS"
  
	  ConfigPathDir = "./etc/istio/proxy"
	  
  )
  
 // cacheLogPrefix returns a unified log prefix.
 func cacheLogPrefix(resourceName string) string {
	 lPrefix := fmt.Sprintf("resource:%s", resourceName)
	 return lPrefix
 }
 
//有效期到期，提前30s检查并自动刷新
func (sc *SecretManagerClient) delayedTask(delaytime time.Time, resourceName string ) {
	var new_certs *security.SecretItem
	var err error
	log.Infof("------------------delayedTask--------------------\n");
	//找慕阳看一下，包含在删除workload，证书的逻辑中
	for {
		<-time.After(time.Until(delaytime.Add(-30 * time.Second)))

		if _, ok := certs_maps.Load(resourceName); !ok {
			return
		} else {
			new_certs, err = fetch_cert(resourceName);
			if err != nil {
				//重新获取
			}
		}
		// 检查 key 是否存在workload中，如果存在则刷新，否则放弃，如果本轮出现多线程误刷新，会在下一轮workload检查中将证书删除，所以无需加锁
		_, ok := certs_maps.Load(resourceName);//需要修改成从cache中读取workload并判断
		if ok {
			certs_maps.Store(resourceName, *new_certs)
			delaytime = new_certs.ExpireTime;
		}
	}
}

// NewSecretManagerClient creates a new SecretManagerClient.
func NewSecretManagerClient() (*SecretManagerClient, error) {

	tlsOpts = &TLSOptions{
		RootCert:      rootCertPath,
	}

	options:= NewSecurityOptions()
	caClient, err := NewCitadelClient(options, tlsOpts)
	if err != nil {
		return nil, err
	}

	ret := &SecretManagerClient{
		caClient:      caClient,
		configOptions: options,
		caRootPath:  options.CARootPath,
	}
	return ret, nil
}

   
   /*从通道中获取
	   hashmap中检查
	   检查有效期
	   调用fetch_cert
	   创建delay任务，到点自动执行
   */
   func Update_certs(resourceName string) {
	   var new_certs *security.SecretItem
	   var err error
 
		 log.Infof("------------------Update_certs--------------------\n");
 
	   //检查hashmap中是否存在
	   if certs, ok := certs_maps.Load(resourceName); ok {
  
		  _certs := certs.(*security.SecretItem);
		  //_certs需要判空
		  if _certs == nil {
			  return
		  }
		  //检查有效期
		   if _certs.ExpireTime.After(time.Now()) {
			   return
		   } else {
			   new_certs, err = fetch_cert(resourceName);
			   if err != nil {
				   //重新获取
			   }
		   }
   
	   } else {
		   new_certs, err = fetch_cert(resourceName);
		   if err != nil {
			   //重新获取
		   }
	   }
	   //获取逻辑判空
	   if new_certs != nil{
		  certs_maps.Store(resourceName, *new_certs)
		  delaytime := new_certs.ExpireTime;
		  go delayedTask(delaytime, resourceName);
	   }
  
   }
   
   
   func Delete_certs(resourceName string) {
	   if _, ok := certs_maps.Load(resourceName); ok {
		  certs_maps.Delete(resourceName)
	   }
   }
