/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/obsernetics/pahlevan/pkg/cli"
)

// Package-level Kubernetes clients shared across CLI commands. They are
// populated by InitializeClients (invoked from the root command's
// PersistentPreRunE) and read back via GetClients.
var (
	k8sClient       client.Client
	kubeClient      kubernetes.Interface
	restConfig      *rest.Config
	globalNamespace string
	clientsReady    bool
)

// InitializeClients loads the Kubernetes REST configuration and constructs the
// controller-runtime client (for typed CRD access) and the client-go clientset
// (for core/apps/admissionregistration APIs) used by the CLI commands.
func InitializeClients(kubeconfig, namespace string, verbose bool) error {
	globalNamespace = namespace

	var err error
	if kubeconfig != "" {
		restConfig, err = config.GetConfigWithContext(kubeconfig)
	} else {
		restConfig, err = config.GetConfig()
	}
	if err != nil {
		return fmt.Errorf("failed to get Kubernetes config: %w", err)
	}

	scheme := cli.GetScheme()

	k8sClient, err = client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	kubeClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	if globalNamespace == "" {
		globalNamespace = "default"
	}

	clientsReady = true
	return nil
}

// GetClients returns the initialized clients. The final boolean reports whether
// the clients were successfully initialized and are ready for use.
func GetClients() (client.Client, kubernetes.Interface, *rest.Config, string, bool) {
	return k8sClient, kubeClient, restConfig, globalNamespace, clientsReady
}

// getRESTConfig exposes the loaded REST config for commands (e.g. watch) that
// need to build additional clients such as a controller-runtime WithWatch client.
func getRESTConfig() *rest.Config {
	return restConfig
}
