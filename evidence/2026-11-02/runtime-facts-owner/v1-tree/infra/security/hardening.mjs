export function hardenManifest(original){
 let s=original;
 if(!s.includes('        fsGroup: 10001\n'))s=s.replace('        runAsGroup: 10001\n','        runAsGroup: 10001\n        fsGroup: 10001\n        seccompProfile:\n          type: RuntimeDefault\n');
 if(!s.includes('            readOnlyRootFilesystem: true\n'))s=s.replace('            allowPrivilegeEscalation: false\n','            readOnlyRootFilesystem: true\n            allowPrivilegeEscalation: false\n');
 if(!s.includes('            - name: runtime-tmp\n'))s=s.replace('          volumeMounts:\n','          volumeMounts:\n            - name: runtime-tmp\n              mountPath: /tmp\n');
 if(!s.includes('\n        - name: runtime-tmp\n'))s=s.replace('      volumes:\n','      volumes:\n        - name: runtime-tmp\n          emptyDir:\n            sizeLimit: 128Mi\n');
 for(const expected of ['        fsGroup: 10001\n        seccompProfile:\n          type: RuntimeDefault\n','            readOnlyRootFilesystem: true\n            allowPrivilegeEscalation: false\n','            - name: runtime-tmp\n              mountPath: /tmp\n','        - name: runtime-tmp\n          emptyDir:\n            sizeLimit: 128Mi\n'])if(!s.includes(expected))throw Error('Production hardening layout changed; review required');
 return s;
}
