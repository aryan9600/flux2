# RFC-0001 Memorandum on Flux Authorisation and Multi-tenancy

## Summary

This RFC describes in detail, for [Flux version 0.24][] (Nov 2021),

 - the authorisation model for Flux (how it determines which operations can proceed);
 - two models for multi-tenancy (safely sharing cluster resources)
 - reference implementations of the two multi-tenancy models

[Flux version 0.24]: https://github.com/fluxcd/flux2/releases/tag/v0.24.0

## Motivation

To this point, the Flux project has provided [examples of how to make a multi-tenant
system](https://github.com/fluxcd/flux2-multi-tenancy/tree/v0.1.0), but not explained exactly how
they relate to Flux's authorisation model; nor has the authorisation model itself been
documented. Further work on support for multi-tenancy requires a full account of Flux's
authorisation model as a baseline. Similarly, it will help to have assumptions about multi-tenancy
described, for reference.

### Goals

- Give a comprehensive account of Flux's authorisation model
- Define two models for multi-tenancy, "soft multi-tenancy" and "hard multi-tenancy".
- Explain when each model is appropriate.
- Give a reference implementation of each model with Flux.

### Non-Goals

- Give an exhaustive account of multi-tenancy implementations in general.
- Provide an [end-to-end workflow](](https://github.com/fluxcd/flux2-multi-tenancy/tree/v0.1.0)) of
  how to set up multi-tenancy with Flux.

## Flux's authorisation model

The Flux controllers undertake operations as specified by custom resources from the kinds defined in
the [Flux API][]. Most of the operations are through the Kubernetes API. Authorisation for
operations on external systems is not accounted for here.

Flux defers to [Kubernetes' native RBAC][k8s-rbac] and [namespace isolation][k8s-ns] to determine
which operations are authorised when processing the custom resources in the Flux API.

This means Kubernetes API operations are constrained by the service account under which each
controller runs. In the [default deployment of Flux][flux-rbac] these have the [`cluster-admin`
cluster role][k8s-cluster-admin] bound to them.

[Flux API]: https://fluxcd.io/docs/components/
[flux-rbac]: https://github.com/fluxcd/flux2/tree/v0.24.0/manifests/rbac
[k8s-ns]: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
[k8s-rbac]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
[k8s-cluster-admin]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles

### Impersonation

The Kustomize controller and Helm controller both apply arbitrary sets of Kubernetes configuration
("_synced configuration_") to a cluster. These controllers use the service account named in the
field `.spec.serviceAccountName` in the `Kustomization` and `HelmRelease` objects respectively,
while applying the synced configuration. This mechanism is called "impersonation".

The `.spec.serviceAccountName` field is optional. If empty, the controller's service account is
used.

Aside from creating, updating and deleting resources according to a synced configuration, the
"apply" step may involve accessing resources referenced by the Flux API object, using the
impersonated service account if given. All other accesses use the controller's service account.

**`kustomizations.kustomize.toolkit.fluxcd.io/v1beta2`**

Object referenced in `healthChecks` have their status assessed after a synced configuration has been
applied.

**`helmreleases.helm.toolkit.fluxcd/v2beta1`**

The fields `targetNamespace` and `storageNamespace` can refer to other namespaces, and affect where
the Helm chart is created or updated, and the record of its deployment is kept. The creation or
update, and the recording, are done with impersonation.

### Exceptions to namespace isolation

Some Flux API kinds have fields which can refer to objects in another namespace. The Flux
controllers do not require these to be in the same namespace as the referring object. The following
are fields that are not restricted to the same namespace, listed by API kind.

**`kustomizations.kustomize.toolkit.fluxcd.io/v1beta2`**

 - `.spec.dependsOn`
 - `.spec.healthChecks`
 - `.spec.sourceRef`

These three fields can have references that include a namespace.

**`helmreleases.helm.toolkit.fluxcd/v2beta1`**

 - `.spec.dependsOn`
 - `.spec.targetNamespace`
 - `.spec.storageNamespace`
 - `.spec.chart.spec.sourceRef`

The items in `.spec.dependsOn` can have references that include a namespace.

The fields `targetNamespace` and `storageNamespace` are mentioned here because they may refer to a
namespace other than the one containing the `HelmRelease` object in question.

 - `.spec.chart.sourceRef`

This field can refer to an object in another namespace. The `.spec.chart` field as a whole gives a
template for a `HelmChart` object, which is created in the same namespace as the source object.

**`alerts.notification.toolkit.fluxcd.io/v1beta1`**

 - `.spec.eventSources`

Items in this field are references that can include a namespace.

**`receivers.notification.toolkit.fluxcd.io/v1beta1`**

 - `.spec.resources`

Items in this field are references that can include a namespace.

**`imagepolicies.image.toolkit.fluxcd.io/v1beta1`**

 - `.spec.imageRepositoryRef`

This field can include a namespace.

**`imageupdateautomation.image.toolkit.fluxcd.io`**

Note that the field `.spec.sourceRef` does _not_ allow a namespace.

### Remote apply

The Kustomize controller and Helm controller are able to apply a set of configuration to a cluster
other than the cluster in which they run. If the `Kustomization` or `HelmRelease` object [refers to
a secret containing a "kubeconfig" file][kubeconfig], the controller will construct a client using
that kubeconfig, and the client is used to apply the prepared set of configuration. The effect of
this is that the configuration will be applied as the user given in the kubeconfig; often this is a
user with the `cluster-admin` role bound to it, but not necessarily so.

[serviceAccountName]: https://fluxcd.io/docs/components/kustomize/api/#kustomize.toolkit.fluxcd.io/v1beta2.KustomizationSpec
[kubeconfig]: https://fluxcd.io/docs/components/kustomize/api/#kustomize.toolkit.fluxcd.io/v1beta2.KubeConfig

## Assumptions made by the multi-tenancy models

### User Roles

The tenancy models assume two types of user: platform admins and tenants.
Besides installing Flux, all the other operations (deploy applications, configure ingress, policies, etc)
do not require users to have direct access to the Kubernetes API. Flux acts as a proxy between users and
the Kubernetes API, using Git as source of truth for the cluster desired state. Changes to the clusters
and workloads configuration can be made in a collaborative manner, where the various teams responsible for
the delivery process propose, review and approve changes via pull request workflows.

#### Platform Admins

The platform admins have unrestricted access to Kubernetes API.
They are responsible for installing Flux and granting Flux
access to the sources (Git, Helm, OCI repositories) that make up the cluster(s) control plane desired state.
The repository(s) owned by the platform admins are reconciled on the cluster(s) by Flux, under
the [cluster-admin](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)
Kubernetes cluster role.

Example of operations performed by platform admins:

- Bootstrap Flux onto cluster(s).
- Extend the Kubernetes API with custom resource definitions and validation webhooks.
- Configure various controllers for ingress, storage, logging, monitoring, progressive delivery, etc.
- Set up namespaces for tenants and define their level of access with Kubernetes RBAC.
- Onboard tenants by registering their Git repositories with Flux.

#### Tenants

The tenants have restricted access to the cluster(s) according to the Kubernetes RBAC configured
by the platform admins. The repositories owned by tenants are reconciled on the cluster(s) by Flux,
under the Kubernetes account(s) assigned by platform admins.

Example of operations performed by tenants:

- Register their sources with Flux (`GitRepositories`, `HelmRepositories` and `Buckets`).
- Deploy workload(s) into their namespace(s) using Flux custom resources (`Kustomizations` and `HelmReleases`).
- Automate application updates using Flux custom resources (`ImageRepositories`, `ImagePolicies` and `ImageUpdateAutomations`).
- Configure the release pipeline(s) using Flagger custom resources (`Canaries` and `MetricsTemplates`).
- Setup webhooks and alerting for their release pipeline(s) using Flux custom resources (`Receivers` and `Alerts`).

## Tenancy Models

The Kubernetes tenancy models supported by Flux are: soft multi-tenancy and hard multi-tenancy.

For an overview of the Kubernetes multi-tenant architecture please consult the following documentation:

- [Three Tenancy Models For Kubernetes](https://kubernetes.io/blog/2021/04/15/three-tenancy-models-for-kubernetes/)
- [GKE multi-tenancy overview](https://cloud.google.com/kubernetes-engine/docs/concepts/multitenancy-overview)
- [EKS multi-tenancy best practices](https://aws.github.io/aws-eks-best-practices/security/docs/multitenancy/)

### Soft Multi-Tenancy

With soft multi-tenancy, the platform admins use Kubernetes constructs such as namespaces, accounts,
roles and role bindings to create a logical separation between tenants.

When Flux deploys workloads from a repository belonging to a tenant, it uses the Kubernetes account assigned to that
tenant to perform the git-to-cluster reconciliation. By leveraging Kubernetes RBAC, Flux can ensure
that the operations performed by tenants are restricted to their namespaces.

Note that with this model, tenants share cluster-wide resources such as
`ClusterRoles`, `CustomResourceDefinitions`, `IngressClasses`, `StorageClasses`,
and they cannot create or alter these resources.
If a tenant adds a cluster-scoped resource definition to their repository,
Flux will fail the git-to-cluster reconciliation due to Kubernetes RBAC restrictions.

To restrict the reconciliation of tenant's sources, a Kubernetes service account name can be specified 
in Flux `Kustomizations` and `HelmReleases` under `.spec.serviceAccountName`. Please consult the Flux  
documentation for more details:

- [Kustomization API: Role-based access control](https://fluxcd.io/docs/components/kustomize/kustomization/#role-based-access-control)
- [HelmRelease API: Role-based access control](https://fluxcd.io/docs/components/helm/helmreleases/#role-based-access-control)
- [Flux multi-tenancy example repository](https://github.com/fluxcd/flux2-multi-tenancy)

Note that with soft multi-tenancy, true tenant isolation requires security measures beyond Kubernetes RBAC.
Please refer to the Kubernetes [security considerations documentation](https://kubernetes.io/blog/2021/04/15/three-tenancy-models-for-kubernetes/#security-considerations)
for more details on how to harden shared clusters.

#### Tenants Onboarding

When onboarding tenants, platform admins have the option to assign namespaces, set
permissions and register the tenants main repositories onto clusters.

The Flux CLI offers an easy way of generating all the Kubernetes manifests needed to onboard tenants:

- `flux create tenant` command generates namespaces, service accounts and Kubernetes RBAC
  with restricted access to the cluster resources, given tenants access only to their namespaces.
- `flux create secret git` command generates SSH keys used by Flux to clone the tenants repositories.
- `flux create source git` command generates the configuration that tells Flux which repositories belong to tenants.
- `flux create kustomization` command generates the configuration that tells Flux how to reconcile the manifests found in the tenants repositories.

All the above commands have an `--export` flag for generating the Kubernetes resources in YAML format.
The platform admins should place the generated manifests in the repository that defines the cluster(s) desired state.

Here is an example of the generated manifests:

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: tenant1
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: flux
  namespace: tenant1
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: flux
  namespace: tenant1
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: flux
    namespace: tenant1
---
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: tenant1
  namespace: tenant1
spec:
  interval: 5m0s
  ref:
    branch: main
  secretRef:
    name: tenant1-git-auth
  url: ssh://git@github.com/org/tenant1
---
apiVersion: kustomize.toolkit.fluxcd.io/v1beta2
kind: Kustomization
metadata:
  name: tenant1
  namespace: tenant1
spec:
  interval: 10m0s
  path: ./
  prune: true
  serviceAccountName: flux
  sourceRef:
    kind: GitRepository
    name: tenant1
```

Note that the [cluster-admin](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)
role is used in a `RoleBinding`; this only gives full control over every resource in the role binding's namespace.

Once the tenants main repositories are registered on the cluster(s), the tenants can configure their app delivery
in Git using Kubernetes namespace-scoped resources such as `Deployments`, `Services`, Flagger `Canaries`,
Flux `GitRepositories`, `Kustomizations`, `HelmRepositories`, `HelmReleases`, `ImageUpdateAutomations`,
`Alerts`, `Receivers`, etc.

#### Caveats

As of v0.23.0, Flux does not enforce a service account to be specified on Flux `Kustomizations` and `HelmReleases`.
When a service account is not specified, Flux defaults to cluster-admin.
In order to enforce the tenant isolation, an admission controller such as Kyverno or OPA Gatekeeper must be used
to make the `.spec.serviceAccountName` a required field for the Flux custom resources created by tenants.

We provide an [example](https://github.com/fluxcd/flux2-multi-tenancy/blob/main/infrastructure/kyverno-policies/flux-multi-tenancy.yaml) 
for enforcing service accounts using a Kyverno cluster policy.

As of v0.23.0, Flux allows for `Kustomizations` and `HelmReleases` to reference sources
(`GitRepositories`, `HelmRepositories` and `Buckets`) across namespaces.
In order to prevent tenants from accessing each other sources, an admission controller such as Kyverno or OPA Gatekeeper
must be used to block cross-namespace references.

We provide an [example](https://github.com/fluxcd/flux2-multi-tenancy/blob/main/infrastructure/kyverno-policies/flux-multi-tenancy.yaml)
for blocking source cross-namespace references using a Kyverno cluster policy.

### Hard Multi-Tenancy

With hard multi-tenancy, the platform admins use Kubernetes Cluster API to create dedicated clusters for each tenant.
The Flux instance installed on the management cluster is responsible
for reconciling the cluster definitions belonging to tenants.

To enable GitOps for the tenant's clusters, the platform admins can configure the Flux instance running on the
management cluster to connect to the tenant's cluster using the `kubeConfig` generated by the Cluster API provider.

To configure Flux reconciliation of remote clusters, a Kubernetes secret containing a `kubeConfig` can be specified
in Flux `Kustomizations` and `HelmReleases` under `.spec.kubeConfig.secretRef`. Please consult the Flux API
documentation for more details:

- [Kustomization API: Remote Clusters](https://fluxcd.io/docs/components/kustomize/kustomization/#remote-clusters--cluster-api)
- [HelmRelease API: Remote Clusters](https://fluxcd.io/docs/components/helm/helmreleases/#remote-clusters--cluster-api)

Note that with hard multi-tenancy, tenants have full access to cluster-wide resources, so they have the option
to manage Flux independently of platform admins, by deploying a Flux instance on each cluster.

#### Caveats

When using a Kubernetes Cluster API provider, the `kubeConfig` secret is automatically generated and Flux can
make use of it without any manual actions. For clusters created by other means than Cluster API, the
platform team has to create the `kubeConfig` secrets to allow Flux access to the remote clusters.

As of Flux v0.23.0, we don't provide any guidance for cluster admins on how to generate the `kubeConfig` secrets.

## Implementation History

- Soft multi-tenancy based on service account impersonation was first released in flux2 **v0.0.1**.
- Generating namespaces and RBAC for defining tenants with `flux create tenant` was first released in flux2 **v0.1.0**.
- Hard multi-tenancy based on remote cluster reconciliation was first released in flux2 **v0.2.0**.
- Soft multi-tenancy end-to-end workflow example was first published on 27 Nov 2020 at
  [fluxcd/flux2-multi-tenancy](https://github.com/fluxcd/flux2-multi-tenancy).
- Soft multi-tenancy [CVE-2021-41254](https://github.com/fluxcd/kustomize-controller/security/advisories/GHSA-35rf-v2jv-gfg7)
  "Privilege escalation to cluster admin on multi-tenant environments" was fixed in flux2 **v0.15.0**.
