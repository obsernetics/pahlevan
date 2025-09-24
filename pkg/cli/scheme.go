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

package cli

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	// Add client-go schemes
	_ = clientgoscheme.AddToScheme(scheme) //nolint:errcheck // Safe to ignore during init
	// Add Pahlevan schemes
	_ = policyv1alpha1.AddToScheme(scheme) //nolint:errcheck // Safe to ignore during init
}

// GetScheme returns the runtime scheme with all necessary types registered
func GetScheme() *runtime.Scheme {
	return scheme
}

// GetCodecs returns the codec factory
func GetCodecs() serializer.CodecFactory {
	return codecs
}
