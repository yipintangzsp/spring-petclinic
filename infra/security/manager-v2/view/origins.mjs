// Exact loopback-facing names only; never wildcard *.devops.local.
export const LOCAL_HOSTS=Object.freeze(['127.0.0.1:17862','localhost:17862','security.devops.local:17862']);
export const localHost=host=>LOCAL_HOSTS.includes(host);
export const localOrigin=origin=>LOCAL_HOSTS.some(host=>origin==='http://'+host);
