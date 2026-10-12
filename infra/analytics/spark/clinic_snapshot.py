"""Reconcile a bounded, non-PII business snapshot using the actual Spark engine."""
import datetime,json,time
from pathlib import Path
from pyspark.sql import SparkSession,functions as F,types as T

def process_resources(partition):
    rows=sum(1 for _ in partition)
    root=Path('/sys/fs/cgroup')
    peak=int((root/'memory.peak').read_text())
    current=int((root/'memory.current').read_text())
    cpu=dict(line.split() for line in (root/'cpu.stat').read_text().splitlines())
    return iter([{'records':rows,'memoryPeakBytes':peak,'memoryCurrentBytes':current,'cpuUsageMicroseconds':int(cpu['usage_usec'])}])

start=time.monotonic();spark=SparkSession.builder.appName('Petclinic bounded visit snapshot').getOrCreate()
spark.sparkContext.setJobGroup('petclinic-snapshot','Bounded existing Petclinic visit statistics')
try:
    schema=T.StructType([T.StructField('visit_id',T.LongType(),False),T.StructField('visit_date',T.DateType(),False)])
    data=spark.read.option('header','true').schema(schema).csv('/opt/clinic/visits.csv').cache()
    rows=data.count()
    if not 0<rows<=5000:raise ValueError('Snapshot exceeds the approved nonempty 5000-row budget')
    if data.filter(F.col('visit_id').isNull()|F.col('visit_date').isNull()).count():raise ValueError('Invalid input ID/date')
    if data.select('visit_id').distinct().count()!=rows:raise ValueError('Duplicate snapshot visit IDs')
    window=data.filter((F.col('visit_date')>=F.lit('2026-01-01').cast('date'))&(F.col('visit_date')<=F.lit('2026-12-31').cast('date')))
    daily=[{'date':str(r.visit_date),'visits':r.visits} for r in window.groupBy('visit_date').agg(F.count('*').alias('visits')).orderBy('visit_date').collect()]
    executor_resources=data.rdd.mapPartitions(process_resources).collect()
    if sum(r['records'] for r in executor_resources)!=rows:raise ValueError('Executor resource probe did not cover the real snapshot')
    driver_peak=int(Path('/sys/fs/cgroup/memory.peak').read_text())
    result={'event':'petclinic_spark_success','source_kind':'demo','source':'existing Petclinic snapshot',
            'sparkVersion':spark.version,'applicationId':spark.sparkContext.applicationId,
            'jobIds':sorted(spark.sparkContext.statusTracker().getJobIdsForGroup('petclinic-snapshot')),
            'driverMemoryPeakBytes':driver_peak,'executorResources':executor_resources,
            'inputRows':rows,'windowStart':'2026-01-01','windowEnd':'2026-12-31',
            'windowVisits':sum(r['visits'] for r in daily),'daily':daily,
            'generatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'durationSeconds':round(time.monotonic()-start,3)}
    print('CLINIC_RESULT:'+json.dumps(result,sort_keys=True),flush=True)
finally:
    spark.stop()
