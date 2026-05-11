How to mitigate the "Dirty Frag" CVE-2026-43284 in OpenShift 4

Mitigation
Red Hat is publishing a solution to block access to the vulnerable kernel functions in advance of fully patched kernels by using kernel module blacklisting.
Node reboots will not be required for this mitigation. The mitigation can be removed after updating to the resolved z-stream release of OpenShift.

Note: this mitigation works by blacklisting the esp4, esp6, and rxrpc kernel modules. This will impact workloads that rely on those kernel modules. IPsec is a known workload that relies on related codepaths and will be impacted. There are currently no other known side-effects of this mitigation strategy, although there is the possibility it triggers false positives and inadvertently impacts valid workloads. Customers are advised to test this mitigation in a non-production cluster.

IMPORTANT: do not apply this mitigation if IPsec is in use (it is required to check not only the cluster but also the workloads).

How to check if IPsec is in use?
Validate that the cluster is not using IPsec by checking the OpenShift OVN IPsec config:
# oc get network.operator cluster -o jsonpath='{.spec.defaultNetwork.ovnKubernetesConfig.ipsecConfig}{"\n"}'; 

Validate that networking pods are not leveraging IPsec:
# oc get pods -n openshift-ovn-kubernetes -l app=ovn-ipsec

Validate the worker nodes for IPsec transforms. Firstly, select a node from the list of worker nodes:
# oc get -o name nodes -l node-role.kubernetes.io/worker

Then check the selected worker node $NODE for the presence :
# oc debug node/"${NODE}" -- chroot /host sh -c 'ip xfrm state && ip xfrm policy && echo done'

Check if IPsec packages/processes are running on nodes
# sudo systemctl status ipsec
# sudo systemctl status strongswan
# sudo systemctl status libreswan

# ps -ef | egrep "ipsec|strongswan|charon|libreswan"

Check for IPsec tunnels/interfaces
# ip xfrm state
# ip xfrm policy

Search workload manifests/configurations
# oc get cm,secrets,deployments,daemonsets -A | egrep -i "ipsec|vpn|strongswan|libreswan"

Mitigation steps
Create a YAML file disable-dirtyfrag.yaml containing the following:
```
apiVersion: v1
kind: Namespace
metadata:
  name: disable-dirtyfrag
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: disable-dirtyfrag
  namespace: disable-dirtyfrag
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: disable-dirtyfrag-privileged
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:privileged
subjects:
  - kind: ServiceAccount
    name: disable-dirtyfrag
    namespace: disable-dirtyfrag
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: disable-dirtyfrag
  namespace: disable-dirtyfrag
  labels:
    app: disable-dirtyfrag
spec:
  selector:
    matchLabels:
      app: disable-dirtyfrag
  template:
    metadata:
      labels:
        app: disable-dirtyfrag
    spec:
      serviceAccountName: disable-dirtyfrag
      nodeSelector:
        kubernetes.io/os: linux
        node-role.kubernetes.io/worker: ""
      tolerations:
        - operator: Exists
      terminationGracePeriodSeconds: 1
      containers:
        - name: disable-modules
          image: image-registry.openshift-image-registry.svc:5000/openshift/cli:latest
          command:
            - /bin/sh
            - "-c"
            - |
              if grep -qs "esp4" /host/etc/modprobe.d/dirtyfrag.conf 2>/dev/null; then
                echo "Modprobe config already present, skipping"
              else
                printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /host/etc/modprobe.d/dirtyfrag.conf
                echo "Created /etc/modprobe.d/dirtyfrag.conf"
              fi
              for mod in esp4 esp6 rxrpc; do
                if chroot /host grep -q "^${mod} " /proc/modules 2>/dev/null; then
                  if chroot /host modprobe -r "${mod}" 2>/dev/null; then
                    echo "Unloaded ${mod}"
                  else
                    echo "WARNING: could not unload ${mod} (may be in use, reboot required)"
                  fi
                else
                  echo "OK: ${mod} was not loaded"
                fi
              done
              echo "=== result ==="
              PROTECTED=true
              for mod in esp4 esp6 rxrpc; do
                if chroot /host grep -q "^${mod} " /proc/modules 2>/dev/null; then
                  echo "WARNING: ${mod} is still loaded, reboot node to complete mitigation"
                  PROTECTED=false
                fi
              done
              if [ "${PROTECTED}" = "true" ]; then
                echo "Node is protected"
              fi
              sleep infinity
          securityContext:
            privileged: true
          volumeMounts:
            - name: host-root
              mountPath: /host
      volumes:
        - name: host-root
          hostPath:
            path: /
```

Apply the YAML file to cluster
# oc apply -f disable-dirtyfrag.yaml

Check the pod logs to confirm that the kernel modules were unloaded
# oc logs -n disable-dirtyfrag -l app=disable-dirtyfrag

Roll-back 
# # oc delete -f disable-dirtyfrag.yaml
