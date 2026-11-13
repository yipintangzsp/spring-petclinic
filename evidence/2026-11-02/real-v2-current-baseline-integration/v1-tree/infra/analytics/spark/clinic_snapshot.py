"""Reconcile a bounded, non-PII Petclinic snapshot with the actual Spark engine."""
import argparse
import datetime
import json
import time
from pathlib import Path

from pyspark.sql import SparkSession, functions as F, types as T


def process_resources(partition):
    rows = sum(1 for _ in partition)
    root = Path('/sys/fs/cgroup')
    cpu = dict(line.split() for line in (root / 'cpu.stat').read_text().splitlines())
    return iter([{
        'records': rows,
        'memoryPeakBytes': int((root / 'memory.peak').read_text()),
        'memoryCurrentBytes': int((root / 'memory.current').read_text()),
        'cpuUsageMicroseconds': int(cpu['usage_usec']),
    }])


def main(args):
    started_at = datetime.datetime.now(datetime.timezone.utc)
    started = time.monotonic()
    first = datetime.date.fromisoformat(args.start)
    last = datetime.date.fromisoformat(args.end)
    if not 0 <= (last - first).days <= 365:
        raise ValueError('The inclusive Spark window must be 1..366 days')

    spark = SparkSession.builder.appName('Petclinic bounded visit snapshot').getOrCreate()
    spark.sparkContext.setJobGroup('petclinic-snapshot', 'Bounded existing Petclinic visit statistics')
    try:
        schema = T.StructType([
            T.StructField('visit_id', T.LongType(), False),
            T.StructField('visit_date', T.DateType(), False),
            T.StructField('pet_id', T.LongType(), False),
            T.StructField('pet_type', T.StringType(), False),
        ])
        data = spark.read.option('header', 'true').schema(schema).csv('/opt/clinic/visits.csv').cache()
        rows = data.count()
        if not 0 < rows <= 5000:
            raise ValueError('Snapshot exceeds the approved nonempty 5000-row budget')
        invalid = data.filter(
            F.col('visit_id').isNull() | F.col('visit_date').isNull()
            | F.col('pet_id').isNull() | F.col('pet_type').isNull()
        ).count()
        unique_rows = data.select('visit_id').distinct().count()
        if invalid or unique_rows != rows:
            raise ValueError('Snapshot has null fields or duplicate visit IDs')

        extent = data.agg(F.min('visit_date').alias('minimum'), F.max('visit_date').alias('maximum')).first()
        window = data.filter((F.col('visit_date') >= F.lit(args.start).cast('date'))
                             & (F.col('visit_date') <= F.lit(args.end).cast('date')))
        daily = [{'date': str(r.visit_date), 'visits': r.visits}
                 for r in window.groupBy('visit_date').agg(F.count('*').alias('visits'))
                 .orderBy('visit_date').collect()]
        by_type = [{'type': r.pet_type, 'visits': r.visits}
                   for r in window.groupBy('pet_type').agg(F.count('*').alias('visits'))
                   .orderBy('pet_type').collect()]
        executor_resources = data.rdd.mapPartitions(process_resources).collect()
        if sum(r['records'] for r in executor_resources) != rows:
            raise ValueError('Executor resource probe did not cover the real snapshot')

        result = {
            'event': 'petclinic_spark_success',
            'batchId': args.batch_id,
            'sourceKind': 'demo',
            'source': 'existing Petclinic PostgreSQL snapshot',
            'sparkVersion': spark.version,
            'applicationId': spark.sparkContext.applicationId,
            'jobIds': sorted(spark.sparkContext.statusTracker().getJobIdsForGroup('petclinic-snapshot')),
            'driverMemoryPeakBytes': int(Path('/sys/fs/cgroup/memory.peak').read_text()),
            'executorResources': executor_resources,
            'inputRows': rows,
            'uniqueVisitIds': unique_rows,
            'sourceMinimumDate': str(extent.minimum),
            'sourceMaximumDate': str(extent.maximum),
            'windowStart': args.start,
            'windowEnd': args.end,
            'windowVisits': sum(r['visits'] for r in daily),
            'daily': daily,
            'visitsByPetType': by_type,
            'startedAt': started_at.isoformat(),
            'finishedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'durationSeconds': round(time.monotonic() - started, 3),
        }
        print('CLINIC_RESULT:' + json.dumps(result, sort_keys=True), flush=True)
        time.sleep(args.ui_hold_seconds)
    finally:
        spark.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--from', dest='start', required=True)
    parser.add_argument('--to', dest='end', required=True)
    parser.add_argument('--batch-id', required=True)
    parser.add_argument('--ui-hold-seconds', type=int, default=45)
    main(parser.parse_args())
