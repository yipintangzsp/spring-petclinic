"""Run in a temporary bounded Job with a verified Pika wheel and Secret mount.
Phase publish persists three confirmed messages; phase consume runs after Pod replacement.
"""
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, '/test/pika.whl')
import pika
batch = os.environ['BATCH_ID']
assert batch.startswith('rabbitmq-check-') and batch.replace('-', '').isalnum()
queue, dead = batch, batch + '-dead'
credentials = pika.PlainCredentials(Path('/auth/username').read_text(), Path('/auth/password').read_text())
connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq.data-infra.svc.cluster.local', 5672, 'petclinic', credentials, heartbeat=30, blocked_connection_timeout=15, socket_timeout=10, stack_timeout=20, connection_attempts=3, retry_delay=3))
channel = connection.channel(); channel.basic_qos(prefetch_count=1)
phase = os.environ['PHASE']
if phase == 'publish':
    channel.queue_declare(queue=dead, durable=True, arguments={'x-queue-type':'classic'})
    channel.queue_declare(queue=queue, durable=True, arguments={'x-queue-type':'classic','x-dead-letter-exchange':'','x-dead-letter-routing-key':dead})
    channel.confirm_delivery()
    for i in range(3):
        channel.basic_publish(exchange='', routing_key=queue, body=json.dumps({'batch_id':batch,'sequence':i,'kind':'platform-acceptance'}), mandatory=True, properties=pika.BasicProperties(content_type='application/json',delivery_mode=2,message_id=f'{batch}-{i}'))
    declared=channel.queue_declare(queue=queue, passive=True)
    assert declared.method.message_count == 3
    result={'phase':phase,'batch_id':batch,'publisher_confirms':3,'durable_queue':True,'persistent_messages':3}
else:
    assert phase == 'consume'
    assert channel.queue_declare(queue=queue, passive=True).method.message_count == 3
    method, properties, body=channel.basic_get(queue=queue, auto_ack=False)
    assert method and properties.delivery_mode == 2 and json.loads(body)['batch_id']==batch
    first=json.loads(body)['sequence']; channel.basic_nack(method.delivery_tag, requeue=True)
    seen=set(); redelivered=False
    for i in range(3):
        method, properties, body=channel.basic_get(queue=queue, auto_ack=False)
        assert method and properties.delivery_mode==2
        item=json.loads(body);assert item['batch_id']==batch and item['sequence'] not in seen;seen.add(item['sequence'])
        redelivered |= bool(method.redelivered and item['sequence']==first)
        if item['sequence']==2:channel.basic_nack(method.delivery_tag, requeue=False)
        else:channel.basic_ack(method.delivery_tag)
    assert seen=={0,1,2} and redelivered
    method=None
    for i in range(20):
        method, properties, body=channel.basic_get(queue=dead, auto_ack=False)
        if method:break
        time.sleep(.25)
    assert method and json.loads(body)['sequence']==2 and properties.headers['x-death'][0]['reason']=='rejected'
    channel.basic_ack(method.delivery_tag)
    assert channel.queue_declare(queue=queue, passive=True).method.message_count==0
    assert channel.queue_declare(queue=dead, passive=True).method.message_count==0
    channel.queue_delete(queue=queue, if_empty=True, if_unused=True)
    channel.queue_delete(queue=dead, if_empty=True, if_unused=True)
    result={'phase':phase,'batch_id':batch,'persisted_after_pod_replacement':3,'acked':2,'nack_requeue_redelivered':True,'dead_letter_received_and_acked':1,'owned_test_queues_removed':True}
connection.close();print(json.dumps(result),flush=True)
