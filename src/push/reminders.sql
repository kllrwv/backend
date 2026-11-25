WITH due AS MATERIALIZED (
    SELECT pref.account_id,pref.reminder_variant
    FROM web_push_preferences pref JOIN accounts a ON a.id=pref.account_id
    WHERE pref.reminders AND a.deleted_at IS NULL
      AND coalesce((a.notice_preferences->>'all')::boolean,true)
      AND coalesce(a.last_seen,a.created_at)<=now()-interval '4 days'
      AND coalesce(pref.last_reminder,'-infinity')<=now()-interval '7 days'
      AND EXISTS (SELECT 1 FROM web_push_subscriptions sub JOIN sessions s ON s.id=sub.session_id
                  WHERE sub.account_id=a.id AND s.expires_at>now())
    ORDER BY pref.last_reminder NULLS FIRST,pref.account_id LIMIT 80
), marked AS (
    UPDATE web_push_preferences pref SET last_reminder=now(),reminder_variant=CASE
      WHEN due.reminder_variant IS NULL THEN floor(random()*$1::integer)::smallint
      ELSE ((due.reminder_variant+1+floor(random()*($1::integer-1))::integer)%$1::integer)::smallint END
    FROM due WHERE pref.account_id=due.account_id RETURNING pref.account_id,pref.reminder_variant
)
INSERT INTO web_push_jobs(session_id,kind,variant)
SELECT sub.session_id,'reminders',marked.reminder_variant FROM marked
JOIN web_push_subscriptions sub USING(account_id)
JOIN sessions s ON s.id=sub.session_id AND s.expires_at>now()
