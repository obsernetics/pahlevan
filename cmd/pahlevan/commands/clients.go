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
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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
func InitializeClients(kubeconfig, kubeContext, namespace string, verbose bool) error {
	globalNamespace = namespace

	var err error
	switch {
	case kubeconfig != "" || kubeContext != "":
		// --kubeconfig names a file and --context names a context inside it.
		// Both used to be collapsed into config.GetConfigWithContext, whose
		// argument is a context name, so `--kubeconfig ~/.kube/staging.yaml`
		// failed with `context "~/.kube/staging.yaml" does not exist` - and
		// --context was dropped on the floor entirely, which is worse: the
		// command then runs happily against whatever the current context is,
		// while the user believes they are pointed at staging.
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		if kubeconfig != "" {
			rules.ExplicitPath = kubeconfig
		}
		overrides := &clientcmd.ConfigOverrides{}
		if kubeContext != "" {
			overrides.CurrentContext = kubeContext
		}
		restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	default:
		restConfig, err = config.GetConfig()
	}
	if err != nil {
		// client-go's own message for a laptop with no kubeconfig is
		// "invalid configuration: no configuration has been provided", which
		// names no file, no flag and no next step. The first thing anybody
		// runs against a new binary must not read as a bug in the binary.
		return fmt.Errorf("cannot reach a Kubernetes cluster: %w\n%s", err, ClusterHint())
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

// ClusterHint is the "what do I do now" half of every missing-cluster error.
//
// It is one string rather than a sentence repeated per command so the advice
// cannot go stale in some commands and not others, and it ends by naming the
// commands that work anyway: a reader whose kubeconfig is genuinely missing
// still has something to run.
func ClusterHint() string {
	return strings.Join([]string{
		"Point the CLI at a cluster with one of:",
		"  pahlevan <command> --kubeconfig /path/to/kubeconfig",
		"  export KUBECONFIG=/path/to/kubeconfig",
		"Check what you have with: kubectl config current-context",
		"These commands need no cluster: version, coverage, events, ui, policy explain.",
	}, "\n")
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
