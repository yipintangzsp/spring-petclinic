"""Publish fresh host/VM measurements for the existing Airflow resource guard."""
import argparse
import json
import time

from controlled import http_bad, kube, sample

NAME = 'platform-host-resources'


def run(interval=15, once=False):
    consecutive = 0
    while True:
        try:
            value = sample()
            consecutive = consecutive + 1 if http_bad(value) else 0
            value['consecutiveBadHttp'] = consecutive
            resource = {'apiVersion': 'v1', 'kind': 'ConfigMap',
                        'metadata': {'name': NAME, 'namespace': 'data-infra',
                                     'labels': {'app': 'platform-resource-guard'}},
                        'data': {'sample.json': json.dumps(value)}}
            kube(['apply', '-f', '-'], resource)
            print(json.dumps({'sampledAt': value['at'], 'availableMiB': value['availableMiB'],
                              'macDiskFreeMiB': value['mac']['diskFreeMiB'],
                              'consecutiveBadHttp': consecutive}), flush=True)
        except Exception as problem:
            # Never publish a made-up healthy value after a failed probe. Tasks
            # reject the previous measurement once it becomes stale.
            print(json.dumps({'error': str(problem), 'at': time.time()}), flush=True)
            if once:
                raise
        if once:
            return
        time.sleep(interval)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--interval', type=int, choices=range(15, 61), default=15)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    run(args.interval, args.once)
