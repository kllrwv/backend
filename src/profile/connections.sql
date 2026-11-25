SELECT coalesce((
    SELECT jsonb_agg(to_jsonb(entry) ORDER BY entry.followers DESC, entry.id DESC)
    FROM (
        SELECT a.id, a.username, a.display_name AS name, a.verified, a.id = $2 AS mine,
               NOT a.avatar_hidden AND (a.avatar IS NOT NULL OR a.avatar_object_id IS NOT NULL) AS avatar,
               EXISTS (SELECT 1 FROM follows WHERE follower_id = $2 AND followed_id = a.id) AS followed,
               popularity.followers
        FROM (
            SELECT follower_id AS account_id FROM follows WHERE $3 AND followed_id = target.id
            UNION ALL
            SELECT followed_id AS account_id FROM follows WHERE NOT $3 AND follower_id = target.id
        ) connections
        JOIN accounts a ON a.id = connections.account_id
        CROSS JOIN LATERAL (
            SELECT count(*) AS followers FROM follows WHERE followed_id = a.id
        ) popularity
        WHERE a.deleted_at IS NULL AND a.username IS NOT NULL AND a.display_name IS NOT NULL
          AND NOT accounts_blocked(a.id, $2)
          AND ($4::bigint IS NULL OR (popularity.followers, a.id) < ($4, $5::uuid))
        ORDER BY popularity.followers DESC, a.id DESC
        LIMIT $6
    ) entry
), '[]'::jsonb)
FROM accounts target
WHERE target.id = $1 AND target.username IS NOT NULL AND target.deleted_at IS NULL
  AND NOT accounts_blocked(target.id, $2)
