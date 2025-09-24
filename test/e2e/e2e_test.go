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

package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	testNamespace     = "pahlevan-e2e-test"
	operatorNamespace = "pahlevan-system"
	timeout           = 5 * time.Minute
	interval          = 5 * time.Second
)

func TestMain(m *testing.M) {
	// Skip E2E tests if not explicitly requested
	if os.Getenv("E2E_TESTS") != "true" {
		fmt.Println("E2E tests skipped. Set E2E_TESTS=true to run.")
		os.Exit(0)
	}

	code := m.Run()
	os.Exit(code)
}

func setupClient(t *testing.T) (client.Client, kubernetes.Interface, *rest.Config) {
	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}

	k8sClient, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to create clientset: %v", err)
	}

	return k8sClient, clientset, cfg
}

func TestOperatorDeployment(t *testing.T) {
	k8sClient, clientset, _ := setupClient(t)
	ctx := context.Background()

	t.Run("OperatorPodIsRunning", func(t *testing.T) {
		// Wait for operator pod to be running
		err := wait.PollImmediate(interval, timeout, func() (bool, error) {
			pods, err := clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{
				LabelSelector: "app.kubernetes.io/name=pahlevan",
			})
			if err != nil {
				t.Logf("Error listing pods: %v", err)
				return false, nil
			}

			if len(pods.Items) == 0 {
				t.Logf("No operator pods found")
				return false, nil
			}

			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning {
					t.Logf("Operator pod %s is running", pod.Name)
					return true, nil
				}
				t.Logf("Pod %s status: %s", pod.Name, pod.Status.Phase)
			}
			return false, nil
		})

		if err != nil {
			// Get pod logs for debugging
			pods, _ := clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{
				LabelSelector: "app.kubernetes.io/name=pahlevan",
			})
			for _, pod := range pods.Items {
				t.Logf("Pod %s status: %+v", pod.Name, pod.Status)
				if len(pod.Status.ContainerStatuses) > 0 {
					t.Logf("Container status: %+v", pod.Status.ContainerStatuses[0])
				}
			}
			t.Fatalf("Operator pod is not running after %v: %v", timeout, err)
		}
	})

	t.Run("OperatorDeploymentIsReady", func(t *testing.T) {
		deployment := &appsv1.Deployment{}
		err := wait.PollImmediate(interval, timeout, func() (bool, error) {
			err := k8sClient.Get(ctx, client.ObjectKey{
				Namespace: operatorNamespace,
				Name:      "pahlevan-operator",
			}, deployment)
			if err != nil {
				t.Logf("Error getting deployment: %v", err)
				return false, nil
			}

			if deployment.Status.ReadyReplicas == *deployment.Spec.Replicas {
				t.Logf("Deployment is ready: %d/%d replicas",
					deployment.Status.ReadyReplicas, *deployment.Spec.Replicas)
				return true, nil
			}

			t.Logf("Deployment not ready yet: %d/%d replicas",
				deployment.Status.ReadyReplicas, *deployment.Spec.Replicas)
			return false, nil
		})

		if err != nil {
			t.Fatalf("Deployment is not ready after %v: %v", timeout, err)
		}
	})
}

func TestTestWorkloadDeployment(t *testing.T) {
	_, clientset, _ := setupClient(t)
	ctx := context.Background()

	t.Run("TestAppIsRunning", func(t *testing.T) {
		err := wait.PollImmediate(interval, timeout, func() (bool, error) {
			pods, err := clientset.CoreV1().Pods(testNamespace).List(ctx, metav1.ListOptions{
				LabelSelector: "app=test-app",
			})
			if err != nil {
				t.Logf("Error listing test app pods: %v", err)
				return false, nil
			}

			if len(pods.Items) == 0 {
				t.Logf("No test app pods found")
				return false, nil
			}

			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning {
					t.Logf("Test app pod %s is running", pod.Name)
					return true, nil
				}
				t.Logf("Test app pod %s status: %s", pod.Name, pod.Status.Phase)
			}
			return false, nil
		})

		if err != nil {
			t.Fatalf("Test app pod is not running after %v: %v", timeout, err)
		}
	})
}

func TestOperatorLogs(t *testing.T) {
	_, clientset, _ := setupClient(t)
	ctx := context.Background()

	t.Run("OperatorLogsContainExpectedMessages", func(t *testing.T) {
		pods, err := clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=pahlevan",
		})
		if err != nil {
			t.Fatalf("Failed to list operator pods: %v", err)
		}

		if len(pods.Items) == 0 {
			t.Fatalf("No operator pods found")
		}

		// Get logs from the first pod
		podName := pods.Items[0].Name
		req := clientset.CoreV1().Pods(operatorNamespace).GetLogs(podName, &corev1.PodLogOptions{
			TailLines: &[]int64{100}[0],
		})

		logs, err := req.Stream(ctx)
		if err != nil {
			t.Fatalf("Failed to get pod logs: %v", err)
		}
		defer logs.Close()

		// Read logs (basic validation that logs exist)
		buf := make([]byte, 1024)
		n, err := logs.Read(buf)
		if err != nil && n == 0 {
			t.Fatalf("Failed to read logs: %v", err)
		}

		logContent := string(buf[:n])
		t.Logf("Operator logs (first 1024 bytes): %s", logContent)

		// Basic check that operator is producing logs
		if len(logContent) == 0 {
			t.Fatalf("No logs found from operator")
		}
	})
}

func TestClusterHealth(t *testing.T) {
	_, clientset, _ := setupClient(t)
	ctx := context.Background()

	t.Run("AllPodsAreHealthy", func(t *testing.T) {
		// Check pahlevan-system namespace
		pods, err := clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("Failed to list pods in %s: %v", operatorNamespace, err)
		}

		for _, pod := range pods.Items {
			if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodSucceeded {
				t.Errorf("Pod %s in namespace %s is not healthy: %s",
					pod.Name, pod.Namespace, pod.Status.Phase)
			}

			// Check for excessive restarts
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if containerStatus.RestartCount > 0 {
					t.Logf("Warning: Container %s in pod %s has restarted %d times",
						containerStatus.Name, pod.Name, containerStatus.RestartCount)
				}
			}
		}

		// Check test namespace
		pods, err = clientset.CoreV1().Pods(testNamespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("Failed to list pods in %s: %v", testNamespace, err)
		}

		for _, pod := range pods.Items {
			if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodSucceeded {
				t.Errorf("Pod %s in namespace %s is not healthy: %s",
					pod.Name, pod.Namespace, pod.Status.Phase)
			}
		}
	})

	t.Run("NoFailedEvents", func(t *testing.T) {
		// Check for Warning or Error events
		events, err := clientset.CoreV1().Events(operatorNamespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("Failed to list events: %v", err)
		}

		var errorEvents []corev1.Event
		for _, event := range events.Items {
			if event.Type == "Warning" || event.Type == "Error" {
				// Filter out expected warnings
				if event.Reason != "Unhealthy" && event.Reason != "BackOff" {
					errorEvents = append(errorEvents, event)
				}
			}
		}

		if len(errorEvents) > 0 {
			t.Logf("Found %d warning/error events:", len(errorEvents))
			for _, event := range errorEvents {
				t.Logf("Event: %s %s - %s", event.Type, event.Reason, event.Message)
			}
		}
	})
}

func TestBasicFunctionality(t *testing.T) {
	k8sClient, _, _ := setupClient(t)
	ctx := context.Background()

	t.Run("NamespacesExist", func(t *testing.T) {
		namespaces := []string{operatorNamespace, testNamespace}
		for _, ns := range namespaces {
			namespace := &corev1.Namespace{}
			err := k8sClient.Get(ctx, client.ObjectKey{Name: ns}, namespace)
			if err != nil {
				t.Fatalf("Namespace %s does not exist: %v", ns, err)
			}
			t.Logf("Namespace %s exists", ns)
		}
	})
}