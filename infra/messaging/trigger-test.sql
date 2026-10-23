-- Exercise Hibernate's actual two-step persistence without retaining any test row.
BEGIN;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
DO $$
DECLARE v integer; p integer;
BEGIN
 SELECT id INTO STRICT p FROM public.pets ORDER BY id LIMIT 1;
 INSERT INTO public.visits (visit_date,description)
 VALUES (CURRENT_DATE+1,'transactional RabbitMQ trigger check') RETURNING id INTO v;
 IF EXISTS (SELECT 1 FROM clinic_messaging.jobs WHERE event_id='visit-'||v) THEN
  RAISE EXCEPTION 'Unlinked visit must not create a follow-up';
 END IF;
 UPDATE public.visits SET pet_id=p WHERE id=v;
 IF (SELECT count(*) FROM clinic_messaging.jobs WHERE event_id='visit-'||v AND kind='visit_followup')<>1 THEN
  RAISE EXCEPTION 'Pet link must create exactly one outbox record';
 END IF;
 UPDATE public.visits SET pet_id=p WHERE id=v;
 IF (SELECT count(*) FROM clinic_messaging.jobs WHERE event_id='visit-'||v)<>1 THEN
  RAISE EXCEPTION 'Repeated pet link created duplicate outbox records';
 END IF;
END;
$$;
ROLLBACK;
