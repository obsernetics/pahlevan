package main

import (
	"context"
	"errors"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/obsernetics/pahlevan/internal/admission"
)

// ensureAdmissionOnce ensures the CEL ValidatingAdmissionPolicy hardening
// baseline exists and logs the outcome. Extracted from the manager runnable
// closure so the decision logic (what to log for which admission.Ensure
// result) is testable without a running controller-runtime manager.
//
// Errors are deliberately swallowed rather than propagated: an admission
// problem must not crash the operator's other responsibilities.
func ensureAdmissionOnce(ctx context.Context, log logr.Logger, c client.Client) {
	if err := admission.Ensure(ctx, c); err != nil {
		if errors.Is(err, admission.ErrUnsupported) {
			log.Info("CEL admission policy skipped", "reason", err.Error())
			return
		}
		log.Error(err, "failed to ensure CEL admission policy")
		return
	}
	log.Info("CEL ValidatingAdmissionPolicy ensured (pahlevan-pod-hardening)")
}

// reconcileDerivedAdmissionOnce re-derives admission rules from learned
// baselines and logs the outcome. Extracted for the same reason as
// ensureAdmissionOnce.
func reconcileDerivedAdmissionOnce(ctx context.Context, log logr.Logger, c client.Client) {
	n, err := admission.EnsureDerived(ctx, c)
	if errors.Is(err, admission.ErrUnsupported) {
		return
	}
	if err != nil {
		log.V(1).Info("derived admission reconcile failed", "error", err.Error())
		return
	}
	if n > 0 {
		log.Info("derived admission policies reconciled", "policies", n)
	}
}
