package vkcloud

import (
	core "k8s.io/api/core/v1"
)

type Config struct {
	OSAuthURLSecretRef    core.SecretKeySelector `json:"osAuthUrlSecretRef"`
	OSUsernameSecretRef   core.SecretKeySelector `json:"osUsernameSecretRef"`
	OSPasswordSecretRef   core.SecretKeySelector `json:"osPasswordSecretRef"`
	OSProjectIDSecretRef  core.SecretKeySelector `json:"osProjectIDSecretRef"`
	OSDomainNameSecretRef core.SecretKeySelector `json:"osDomainNameSecretRef"`
}
