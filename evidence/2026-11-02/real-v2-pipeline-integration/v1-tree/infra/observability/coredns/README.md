# Internal DNS during a LAN outage

The existing pods inherit a Tailnet search suffix and ndots:5. A service FQDN with four dots can therefore be tried with the Tailnet suffix before its absolute form. When upstream DNS has no route, libc returns EAI_AGAIN before reaching the valid internal name. Direct Service IPs and absolute service DNS queries can still work.

`cluster-search.override` returns NXDOMAIN only for invalid names formed by appending a `*.ts.net` search suffix to a `*.cluster.local` name. The existing Kubernetes DNS, genuine Tailnet names, external forwarding, and other custom CoreDNS files remain unchanged. It does not restore external connectivity or change host routing.

Install this fragment as one data key in the existing `kube-system/coredns-custom` ConfigMap. Back up that ConfigMap, compare UID/resourceVersion before patching, and retain all existing data keys. The existing Corefile already imports `/etc/coredns/custom/*.override`; allow the projected file and reload plugin to update. Verify an absolute service query, an invalid suffixed query (NXDOMAIN), and ordinary libc service resolution. Roll back only this key if verification fails.

Source: [CoreDNS template plugin and invalid search domain example](https://coredns.io/plugins/template/).
