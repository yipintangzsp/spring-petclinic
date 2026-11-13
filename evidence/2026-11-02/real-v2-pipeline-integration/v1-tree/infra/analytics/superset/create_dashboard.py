"""Create private, synchronous charts over the latest successful analysis run."""
import json,os
from superset.app import create_app
from superset import db,appbuilder

app=create_app()
from superset.models.core import Database
from superset.models.dashboard import Dashboard
from superset.connectors.sqla.models import SqlaTable,SqlMetric
from superset.models.slice import Slice

with app.app_context():
    admin=appbuilder.sm.find_user(username='admin')
    if admin is None:raise RuntimeError('Existing Superset admin account was not found')
    name='Petclinic analytics through Trino'
    database=db.session.query(Database).filter_by(database_name=name).one_or_none()
    if database is None:database=Database(database_name=name);db.session.add(database)
    database.sqlalchemy_uri=os.environ['CLINIC_TRINO_URI'];database.allow_run_async=False
    database.allow_dml=False;database.allow_ctas=False;database.allow_cvas=False;database.expose_in_sqllab=True
    database.extra=json.dumps({'engine_params':{'connect_args':{'request_timeout':15,'max_attempts':2,'session_properties':{'query_max_execution_time':'60s','query_max_run_time':'90s'}}}})
    db.session.flush()
    latest="(SELECT run_id FROM clinic.petclinic_analytics.runs WHERE status='success' ORDER BY generated_at DESC LIMIT 1)"
    definitions={
        'daily':('Petclinic daily visits · latest successful run',f'SELECT stat_date,visits FROM clinic.petclinic_analytics.daily_visits WHERE run_id={latest}','visits'),
        'types':('Petclinic pet types · latest successful run',f'SELECT type,pets FROM clinic.petclinic_analytics.pet_types WHERE run_id={latest}','pets'),
        'provenance':('Petclinic analysis provenance · latest successful run',f'SELECT generated_at,source_kind,window_start,window_end,owners,pets,vets,visits,watermark,input_rows FROM clinic.petclinic_analytics.runs WHERE run_id={latest}',None)
    }
    datasets={}
    for key,(title,sql,value) in definitions.items():
        dataset=db.session.query(SqlaTable).filter_by(database_id=database.id,table_name=title).one_or_none()
        if dataset is None:dataset=SqlaTable(table_name=title,database=database,owners=[admin]);db.session.add(dataset)
        dataset.sql=sql;dataset.schema='petclinic_analytics';db.session.flush();dataset.fetch_metadata()
        if key=='daily':dataset.main_dttm_col='stat_date'
        if value and not any(m.metric_name=='total_'+value for m in dataset.metrics):
            dataset.metrics.append(SqlMetric(metric_name='total_'+value,expression='SUM('+value+')',metric_type='sum',verbose_name='Total '+value))
        datasets[key]=dataset
    db.session.flush();charts=[]
    specs=[
        ('每日就诊记录 · 年度分析窗口','echarts_timeseries_line','daily',{'metrics':['total_visits'],'x_axis':'stat_date','granularity_sqla':'stat_date','time_grain_sqla':'P1D','time_range':'No filter','groupby':[],'row_limit':367,'truncate_metric':True,'show_legend':False}),
        ('宠物类型分布 · 快照时点','pie','types',{'metric':'total_pets','groupby':['type'],'row_limit':64,'show_labels':True,'show_legend':True,'label_type':'key_value_percent'}),
        ('年度窗口就诊记录总数','big_number_total','daily',{'metric':'total_visits','time_range':'No filter','subheader':'既有演示数据；记录数不代表已完成治疗'}),
        ('最近成功分析 · 来源与更新时间','table','provenance',{'query_mode':'raw','all_columns':['generated_at','source_kind','window_start','window_end','owners','pets','vets','visits','watermark','input_rows'],'row_limit':1,'time_range':'No filter'})
    ]
    for title,viz,key,options in specs:
        title='20261011 · '+title;chart=db.session.query(Slice).filter_by(slice_name=title).one_or_none()
        if chart is None:chart=Slice(slice_name=title,owners=[admin]);db.session.add(chart)
        dataset=datasets[key];chart.viz_type=viz;chart.datasource_type='table';chart.datasource_id=dataset.id
        chart.params=json.dumps({'viz_type':viz,'datasource':str(dataset.id)+'__table',**options},ensure_ascii=False);charts.append(chart)
    db.session.flush()
    dashboard=db.session.query(Dashboard).filter_by(slug='petclinic-analytics-20261011').one_or_none()
    if dashboard is None:dashboard=Dashboard(slug='petclinic-analytics-20261011',owners=[admin]);db.session.add(dashboard)
    dashboard.dashboard_title='Petclinic 业务统计 · 既有演示数据';dashboard.published=True;dashboard.slices=charts
    layout={'DASHBOARD_VERSION_KEY':'v2','ROOT_ID':{'type':'ROOT','id':'ROOT_ID','children':['GRID_ID']},'GRID_ID':{'type':'GRID','id':'GRID_ID','children':['ROW-0','ROW-1'],'parents':['ROOT_ID']},'HEADER_ID':{'type':'HEADER','id':'HEADER_ID','meta':{'text':dashboard.dashboard_title}}}
    for row in range(2):
        rid='ROW-'+str(row);ids=['CHART-'+str(c.id) for c in charts[row*2:row*2+2]]
        layout[rid]={'type':'ROW','id':rid,'children':ids,'parents':['ROOT_ID','GRID_ID'],'meta':{'background':'BACKGROUND_TRANSPARENT'}}
        for chart,cid in zip(charts[row*2:row*2+2],ids):
            layout[cid]={'type':'CHART','id':cid,'children':[],'parents':['ROOT_ID','GRID_ID',rid],'meta':{'chartId':chart.id,'width':6,'height':50,'sliceName':chart.slice_name}}
    dashboard.position_json=json.dumps(layout,ensure_ascii=False);dashboard.json_metadata=json.dumps({'cross_filters_enabled':False,'native_filter_configuration':[],'refresh_frequency':60,'timed_refresh_immune_slices':[]});db.session.commit()
    print('RESULT:'+json.dumps({'dashboardId':dashboard.id,'slug':dashboard.slug,'databaseId':database.id,'datasets':{k:v.id for k,v in datasets.items()},'charts':[{'id':c.id,'viz':c.viz_type} for c in charts],'publishedForAuthenticatedUsers':True}))
