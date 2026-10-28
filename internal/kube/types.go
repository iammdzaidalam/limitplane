package kube

import (
	"encoding/json"
	"time"
)

// ObjectMeta holds the metadata fields LimitPlane reads or writes.
type ObjectMeta struct {
	Name            string            `json:"name,omitempty"`
	GenerateName    string            `json:"generateName,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Generation      int64             `json:"generation,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	OwnerReferences []OwnerReference  `json:"ownerReferences,omitempty"`
}

type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"` // "True" or "False"
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
}

// RateLimitPolicy's spec is kept raw: it is the policy file format minus keys, and policy.Parse validates it.
type RateLimitPolicy struct {
	Metadata ObjectMeta      `json:"metadata"`
	Spec     json.RawMessage `json:"spec"`
	Status   PolicyStatus    `json:"status"`
}

type PolicyStatus struct {
	ObservedGeneration int64       `json:"observedGeneration"`
	Conditions         []Condition `json:"conditions"`
	ActiveReplicas     int         `json:"activeReplicas"`
}

type Tenant struct {
	Metadata ObjectMeta   `json:"metadata"`
	Spec     TenantSpec   `json:"spec"`
	Status   TenantStatus `json:"status"`
}

type TenantSpec struct {
	ID           string `json:"id"`
	Tier         string `json:"tier"`
	KeySecretRef struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"keySecretRef"`
}

type TenantStatus struct {
	ObservedGeneration int64       `json:"observedGeneration"`
	Conditions         []Condition `json:"conditions"`
	MonthlyUsed        int64       `json:"monthlyUsed"`
}

// Secret data is base64 in JSON, which encoding/json decodes into []byte for us.
type Secret struct {
	Metadata ObjectMeta        `json:"metadata"`
	Data     map[string][]byte `json:"data"`
}

type Lease struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     LeaseSpec  `json:"spec"`
}

type LeaseSpec struct {
	HolderIdentity       string    `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds int       `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          MicroTime `json:"acquireTime,omitzero"`
	RenewTime            MicroTime `json:"renewTime,omitzero"`
	LeaseTransitions     int       `json:"leaseTransitions,omitempty"`
}

// MicroTime is the API's microsecond timestamp used by Leases.
type MicroTime struct{ time.Time }

func (t MicroTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format("2006-01-02T15:04:05.000000Z07:00"))
}

func (t *MicroTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || s == "" {
		return err
	}
	v, err := time.Parse(time.RFC3339Nano, s)
	t.Time = v
	return err
}
