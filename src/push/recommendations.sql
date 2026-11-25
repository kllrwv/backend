WITH recent AS MATERIALIZED (
    SELECT id,author_id,created_at FROM posts
    WHERE created_at>now()-interval '36 hours' AND reply_to IS NULL
      AND (wall_owner_id IS NULL OR wall_owner_id=author_id) AND deleted_at IS NULL
    ORDER BY created_at DESC,id DESC LIMIT 250
), due AS MATERIALIZED (
    SELECT pref.account_id,pref.following
    FROM web_push_preferences pref JOIN accounts a ON a.id=pref.account_id
    WHERE pref.recommendations AND a.deleted_at IS NULL
      AND coalesce((a.notice_preferences->>'all')::boolean,true)
      AND coalesce(a.last_seen,a.created_at)>now()-interval '4 days'
      AND coalesce(pref.last_recommendation,'-infinity')<=now()-interval '2 days'
      AND EXISTS (SELECT 1 FROM web_push_subscriptions sub JOIN sessions s ON s.id=sub.session_id
                  WHERE sub.account_id=a.id AND s.expires_at>now())
), picked AS MATERIALIZED (
    SELECT due.account_id,candidate.id AS post_id
    FROM due CROSS JOIN LATERAL (
        SELECT r.id FROM recent r
        WHERE r.author_id<>due.account_id AND visible_post(r.id,due.account_id)
          AND NOT EXISTS (SELECT 1 FROM post_views WHERE post_id=r.id AND account_id=due.account_id)
          AND NOT EXISTS (SELECT 1 FROM post_likes WHERE post_id=r.id AND account_id=due.account_id)
          AND (NOT due.following OR NOT EXISTS (
                SELECT 1 FROM follows WHERE follower_id=due.account_id AND followed_id=r.author_id))
          AND (EXISTS (SELECT 1 FROM follows WHERE follower_id=due.account_id AND followed_id=r.author_id)
            OR EXISTS (
                SELECT 1 FROM post_likes liked JOIN posts earlier ON earlier.id=liked.post_id
                WHERE liked.account_id=due.account_id AND liked.created_at>now()-interval '30 days'
                  AND earlier.author_id=r.author_id AND visible_post(earlier.id,due.account_id))
            OR EXISTS (
                SELECT 1 FROM post_hashtags tag JOIN post_hashtags seen ON seen.tag=tag.tag
                JOIN post_likes liked ON liked.post_id=seen.post_id AND liked.account_id=due.account_id
                WHERE tag.post_id=r.id AND liked.created_at>now()-interval '30 days'
                  AND visible_post(seen.post_id,due.account_id)))
        ORDER BY (SELECT count(*) FROM post_likes WHERE post_id=r.id) DESC,r.created_at DESC,r.id DESC
        LIMIT 1
    ) candidate
    ORDER BY due.account_id LIMIT 80
), marked AS (
    UPDATE web_push_preferences pref SET last_recommendation=now() FROM picked
    WHERE pref.account_id=picked.account_id RETURNING pref.account_id,picked.post_id
)
INSERT INTO web_push_jobs(session_id,kind,post_id)
SELECT sub.session_id,'recommendations',marked.post_id FROM marked
JOIN web_push_subscriptions sub USING(account_id)
JOIN sessions s ON s.id=sub.session_id AND s.expires_at>now()
