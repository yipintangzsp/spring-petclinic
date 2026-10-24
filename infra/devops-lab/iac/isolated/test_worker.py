import copy
import unittest
from worker import inspect_preview, inspect_plan, ADDRESS, PROBE

class PlanGuards(unittest.TestCase):
    def fixture(self):
        def resource(address, after):
            return {'address': address, 'change': {'actions': ['create'], 'after': after}}
        return {'resource_changes': [
            resource('kubernetes_namespace_v1.lab', {'metadata': [{'name': 'tf-devops-lab', 'labels': {'petclinic.devops.local/owner': 'terraform-iac-lab'}}]}),
            resource('kubernetes_resource_quota_v1.budget', {'metadata': [{'name': 'lab-budget', 'namespace': 'tf-devops-lab'}], 'spec': [{'hard': {'pods': '0', 'persistentvolumeclaims': '0', 'secrets': '0', 'services': '0', 'requests.storage': '0', 'configmaps': '4'}}]}),
            resource(ADDRESS, {'metadata': [{'name': 'environment-manifest', 'namespace': 'tf-devops-lab'}], 'data': {'config_revision': 'v1', 'managed_by': 'terraform', 'scenario': 'petclinic-devops-study'}})]}

    def test_preview_accepts_bounded_creates(self):
        self.assertEqual(len(inspect_preview(self.fixture())), 3)

    def test_foreign_namespace_rejected(self):
        v=self.fixture();v['resource_changes'][2]['change']['after']['metadata'][0]['namespace']='petclinic'
        with self.assertRaises(RuntimeError): inspect_preview(v)

    def test_compute_quota_rejected(self):
        v=self.fixture();v['resource_changes'][1]['change']['after']['spec'][0]['hard']['pods']='1'
        with self.assertRaises(RuntimeError): inspect_preview(v)

    def test_replacement_rejected(self):
        v=self.fixture();v['resource_changes'][2]['change']['actions']=['delete','create']
        with self.assertRaises(RuntimeError): inspect_preview(v)

    def test_shared_cleanup_never_removes_real_resource(self):
        v=self.fixture();real=v['resource_changes'][2];real['change']['after']['metadata'][0].update(namespace='tf-remote-lab',labels={'petclinic.devops.local/owner':'terraform-remote-lab'});real['change']['actions']=['delete']
        v['resource_changes']=[real,{'address':PROBE,'change':{'actions':['delete'],'after':None}}]
        with self.assertRaises(RuntimeError): inspect_plan(v,True)

import errno
import socket
import struct
from worker import icmp_rejection

class KernelRejectionProof(unittest.TestCase):
    def entry(self, origin=2, kind=3, code=3):
        return [(socket.SOL_IP, 11, struct.pack('=IBBBBII', errno.ECONNREFUSED, origin, kind, code, 0, 0, 0))]

    def test_kernel_icmp_policy_reject(self):
        self.assertEqual(icmp_rejection(self.entry())['origin'], 'kernel-ICMP')

    def test_local_refusal_is_not_network_policy_proof(self):
        with self.assertRaises(RuntimeError): icmp_rejection(self.entry(origin=1))

    def test_plain_tcp_reset_has_no_icmp_proof(self):
        with self.assertRaises(RuntimeError): icmp_rejection([])

    def test_unrelated_icmp_cannot_pass(self):
        with self.assertRaises(RuntimeError): icmp_rejection(self.entry(code=1))
