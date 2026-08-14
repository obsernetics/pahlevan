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
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Component identifiers accepted by --component on the logs, metrics and debug
// commands.
const (
	componentAgent    = "agent"
	componentOperator = "operator"
	componentAll      = "all"
)

// Workload identity of the two Pahlevan components. Both the DaemonSet/
// Deployment and their pods carry these as app.kubernetes.io/name.
const (
	agentAppName    = "pahlevan-agent"
	operatorAppName = "pahlevan-operator"

	componentLabelKey = "app.kubernetes.io/name"
)

// defaultComponentNamespace is where the shipped manifests install both
// components. It is only a hint: namespace resolution falls back to a
// cluster-wide search so a non-default install is still found.
const defaultComponentNamespace = "pahlevan-system"

// defaultMetricsPort is the container port both components serve /metrics on.
const defaultMetricsPort = "8080"

// componentAppNames maps a --component value to the app.kubernetes.io/name
// label values it selects.
func componentAppNames(component string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(component)) {
	case "", componentAll:
		return []string{agentAppName, operatorAppName}, nil
	case componentAgent, agentAppName:
		return []string{agentAppName}, nil
	case componentOperator, operatorAppName:
		return []string{operatorAppName}, nil
	default:
		return nil, fmt.Errorf("invalid --component %q: expected one of agent, operator, all", component)
	}
}

// componentForAppName turns an app.kubernetes.io/name label back into the short
// component name used in output.
func componentForAppName(appName string) string {
	switch appName {
	case agentAppName:
		return componentAgent
	case operatorAppName:
		return componentOperator
	default:
		return appName
	}
}

// resolveComponentNamespace picks the namespace to search for component pods.
//
// An explicit --namespace always wins. Otherwise the global namespace from the
// kubeconfig context is used when it names something other than "default",
// because the components are never installed into "default" by the shipped
// manifests. Failing that an empty string is returned, which means "search
// every namespace" so a custom install namespace is still discovered.
func resolveComponentNamespace(explicit string) string {
	if ns := strings.TrimSpace(explicit); ns != "" {
		return ns
	}
	_, _, _, globalNs, _ := GetClients()
	if globalNs != "" && globalNs != "default" {
		return globalNs
	}
	return ""
}

// componentPod pairs a discovered pod with the short component name it belongs
// to, so multiplexed output can label each line.
type componentPod struct {
	Component string
	Pod       corev1.Pod
}

// Node returns the node the pod is scheduled on, or "<unscheduled>".
func (c componentPod) Node() string {
	if c.Pod.Spec.NodeName == "" {
		return "<unscheduled>"
	}
	return c.Pod.Spec.NodeName
}

// Container returns the name of the pod's first container, which is the one
// carrying the component process in both shipped manifests.
func (c componentPod) Container() string {
	if len(c.Pod.Spec.Containers) > 0 {
		return c.Pod.Spec.Containers[0].Name
	}
	return ""
}

// Restarts sums container restart counts for the pod.
func (c componentPod) Restarts() int32 {
	var total int32
	for _, cs := range c.Pod.Status.ContainerStatuses {
		total += cs.RestartCount
	}
	return total
}

// Ready reports whether every container in the pod is ready.
func (c componentPod) Ready() bool {
	if len(c.Pod.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, cs := range c.Pod.Status.ContainerStatuses {
		if !cs.Ready {
			return false
		}
	}
	return true
}

// ReadyString renders readiness as the familiar "n/m" of kubectl get pods.
func (c componentPod) ReadyString() string {
	ready := 0
	for _, cs := range c.Pod.Status.ContainerStatuses {
		if cs.Ready {
			ready++
		}
	}
	return fmt.Sprintf("%d/%d", ready, len(c.Pod.Status.ContainerStatuses))
}

// Image returns the image of the pod's first container.
func (c componentPod) Image() string {
	if len(c.Pod.Spec.Containers) > 0 {
		return c.Pod.Spec.Containers[0].Image
	}
	return "<unknown>"
}

// findComponentPods lists the pods belonging to the requested component(s).
//
// An empty namespace searches every namespace. An empty node matches every
// node. The result is sorted by component, namespace and name so output is
// stable across invocations.
func findComponentPods(ctx context.Context, kube kubernetes.Interface, namespace, component, node string) ([]componentPod, error) {
	if kube == nil {
		return nil, fmt.Errorf("kubernetes clientset is not initialized; check your kubeconfig and cluster connectivity")
	}
	appNames, err := componentAppNames(component)
	if err != nil {
		return nil, err
	}

	var out []componentPod
	for _, appName := range appNames {
		list, err := kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: componentLabelKey + "=" + appName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list %s pods: %w", appName, err)
		}
		for i := range list.Items {
			pod := list.Items[i]
			if node != "" && pod.Spec.NodeName != node {
				continue
			}
			out = append(out, componentPod{Component: componentForAppName(appName), Pod: pod})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
		}
		if out[i].Pod.Namespace != out[j].Pod.Namespace {
			return out[i].Pod.Namespace < out[j].Pod.Namespace
		}
		return out[i].Pod.Name < out[j].Pod.Name
	})
	return out, nil
}

// noComponentPodsError explains an empty discovery result in terms an operator
// can act on rather than returning a bare "not found".
func noComponentPodsError(namespace, component, node string) error {
	scope := "any namespace"
	if namespace != "" {
		scope = fmt.Sprintf("namespace %q", namespace)
	}
	msg := fmt.Sprintf("no Pahlevan %s pods found in %s", componentDescription(component), scope)
	if node != "" {
		msg += fmt.Sprintf(" on node %q", node)
	}
	return fmt.Errorf("%s.\n"+
		"Pahlevan installs the agent as the %q DaemonSet and the operator as the %q Deployment, "+
		"labelled %s=<name>, in the %q namespace by default. "+
		"Pass --namespace if you installed elsewhere",
		msg, agentAppName, operatorAppName, componentLabelKey, defaultComponentNamespace)
}

// componentDescription renders a --component value for use in a sentence.
func componentDescription(component string) string {
	switch strings.ToLower(strings.TrimSpace(component)) {
	case componentAgent:
		return "agent"
	case componentOperator:
		return "operator"
	default:
		return "component"
	}
}

// validateOutputFormat checks a --output value against the formats a command
// actually implements, so an unsupported value fails fast with the valid set
// instead of producing empty output.
func validateOutputFormat(format string, allowed ...string) error {
	for _, a := range allowed {
		if format == a {
			return nil
		}
	}
	return fmt.Errorf("invalid --output %q: expected one of %s", format, strings.Join(allowed, ", "))
}
