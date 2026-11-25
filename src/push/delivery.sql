SELECT j.id,j.kind,j.variant,j.attempts,j.session_id,sub.endpoint,sub.p256dh,sub.auth,sub.lang,
       n.kind AS event_kind,coalesce(actor.display_name,actor.username) AS actor_name,
       actor.username AS actor_username,author.username AS post_username,coalesce(parent.id,p.id) AS post_id,
       left(p.body,140) AS excerpt,extract(epoch FROM coalesce(n.created_at,p.created_at,j.created_at))::bigint AS timestamp,
       coalesce((a.notice_preferences->>'sound')::boolean,false) AS sound
FROM web_push_jobs j
JOIN web_push_subscriptions sub ON sub.session_id=j.session_id
JOIN sessions s ON s.id=sub.session_id AND s.account_id=sub.account_id AND s.expires_at>now()
JOIN accounts a ON a.id=sub.account_id AND a.deleted_at IS NULL
JOIN web_push_preferences pref ON pref.account_id=a.id
LEFT JOIN notifications n ON n.id=j.notification_id
LEFT JOIN posts p ON p.id=coalesce(n.post_id,j.post_id)
LEFT JOIN posts parent ON parent.id=p.reply_to
LEFT JOIN accounts actor ON actor.id=coalesce(n.actor,p.author_id)
LEFT JOIN accounts author ON author.id=coalesce(parent.author_id,p.author_id)
WHERE j.id=$1 AND (j.kind='test' OR (
    coalesce((a.notice_preferences->>'all')::boolean,true)
    AND CASE j.kind
        WHEN 'activity' THEN pref.activity AND n.recipient=a.id AND n.read_at IS NULL
            AND coalesce((a.notice_preferences->>n.kind)::boolean,true)
        WHEN 'following' THEN pref.following AND EXISTS (
            SELECT 1 FROM follows WHERE follower_id=a.id AND followed_id=p.author_id)
        WHEN 'recommendations' THEN pref.recommendations AND NOT EXISTS (
            SELECT 1 FROM post_views WHERE post_id=p.id AND account_id=a.id)
        WHEN 'reminders' THEN pref.reminders AND coalesce(a.last_seen,a.created_at)<=now()-interval '4 days'
    END
    AND (actor.id IS NULL OR (actor.deleted_at IS NULL AND NOT accounts_blocked(a.id,actor.id)))
    AND (p.id IS NULL OR visible_post(p.id,a.id))
))
