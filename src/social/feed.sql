WITH candidates AS MATERIALIZED (
    SELECT p.*
    FROM posts p JOIN accounts a ON a.id = p.author_id
    WHERE ($3::uuid IS NULL AND p.reply_to IS NULL OR p.reply_to = $3)
      AND ($9::uuid IS NULL OR p.id = $9)
      AND (NOT post_removed(p.id) OR admin_can($1,'content.moderate'))
      AND NOT accounts_blocked(p.author_id, $1)
      AND NOT coalesce(accounts_blocked(p.wall_owner_id, $1), false)
      AND CASE
          WHEN $9 IS NOT NULL THEN readable_post(p.id, $1)
          WHEN $3 IS NOT NULL THEN readable_post($3, $1)
          WHEN $7::uuid IS NULL THEN p.wall_owner_id IS NULL
          WHEN $8::boolean THEN p.wall_owner_id IS NULL AND EXISTS (
              SELECT 1 FROM accounts WHERE id=$7 AND audience_allows(id,$1,like_access)
          ) AND EXISTS (
              SELECT 1 FROM post_likes WHERE post_id = p.id AND account_id = $7)
          ELSE p.wall_owner_id = $7 OR (p.wall_owner_id IS NULL AND p.author_id = $7)
      END
      AND ($2 <> 'following' OR p.author_id = $1 OR EXISTS (
          SELECT 1 FROM follows WHERE follower_id = $1 AND followed_id = p.author_id))
      AND ($6 = '' OR EXISTS (
          SELECT 1 FROM post_hashtags WHERE post_id = p.id AND tag = $6))
      AND ($4 = '' OR strpos(lower(p.body), lower($4)) > 0
          OR strpos(lower(a.username), lower($4)) > 0 OR strpos(lower(a.display_name), lower($4)) > 0
          OR EXISTS (SELECT 1 FROM account_usernames h WHERE h.account_id=a.id AND h.slot>0 AND h.enabled
              AND a.deleted_at IS NULL AND strpos(h.username,lower(nullif(ltrim($4,'@'),'')))>0))
    ORDER BY p.created_at DESC, p.id DESC
    LIMIT CASE WHEN $3 IS NULL THEN 400 END
),
signals AS (
    SELECT p.*,
           (SELECT count(*) FROM post_likes WHERE post_id = p.id) AS likes,
           (SELECT count(*) FROM posts r WHERE r.reply_to = p.id AND visible_post(r.id,$1)) AS replies,
           (SELECT count(*) FROM posts WHERE repost_of = p.id AND deleted_at IS NULL) AS reposts,
           (SELECT count(*) FROM post_views WHERE post_id = p.id) AS views,
           EXISTS (SELECT 1 FROM post_likes WHERE post_id = p.id AND account_id = $1) AS liked,
           EXISTS (SELECT 1 FROM posts WHERE repost_of = p.id AND author_id = $1 AND deleted_at IS NULL) AS reposted,
           EXISTS (SELECT 1 FROM follows WHERE follower_id = $1 AND followed_id = p.author_id) AS followed
    FROM candidates p
),
ranked AS (
    SELECT *,
      CASE WHEN $2 = 'recommended' AND $3 IS NULL AND $4 = '' AND $6 = '' AND $7 IS NULL AND $9 IS NULL THEN
          ln(1.0 + likes + 1.8 * replies + 2.4 * reposts)
              + CASE WHEN followed THEN 1.4 ELSE 0 END
              + CASE WHEN EXISTS (
                  SELECT 1 FROM post_likes l JOIN posts history ON history.id = l.post_id
                  WHERE l.account_id = $1 AND history.author_id = signals.author_id
                    AND l.created_at > now() - interval '90 days'
              ) THEN 1.0 ELSE 0 END
              - ln(1.0 + greatest(extract(epoch FROM now() - created_at), 0) / 129600.0)
              + 1.15 * ((hashtextextended(id::text, hashtextextended($1::text, 0)) & 65535) / 65536.0)
       END AS interest
    FROM signals
),
page AS (
    SELECT *,
           CASE WHEN interest IS NOT NULL THEN interest - 0.55 * ln(row_number() OVER (
               PARTITION BY author_id ORDER BY interest DESC, created_at DESC, id DESC
           )) ELSE 0 END AS score
    FROM ranked
    ORDER BY score DESC,
             CASE WHEN $3 IS NOT NULL AND $10 = 'popular' THEN likes END DESC,
             CASE WHEN $3 IS NOT NULL AND $10 = 'oldest' THEN created_at END ASC,
             created_at DESC, id DESC
    LIMIT 21 OFFSET $5
)
SELECT ARRAY(
    SELECT jsonb_build_object(
        'id', p.id, 'deleted',post_removed(p.id),'can_moderate',admin_can($1,'content.moderate'),'body', p.body, 'created_at', extract(epoch FROM p.created_at)::bigint,
        'author', jsonb_build_object('id', a.id, 'name', a.display_name, 'username', a.username, 'verified',a.verified, 'avatar', NOT a.avatar_hidden AND (a.avatar IS NOT NULL OR a.avatar_object_id IS NOT NULL)),
        'image', EXISTS (SELECT 1 FROM post_images WHERE post_id = p.id),
        'media', moderated_attachments(p.id,$1), 'poll', CASE WHEN admin_can($1,'content.moderate') OR NOT EXISTS(SELECT 1 FROM polls WHERE post_id=p.id AND deleted_at IS NOT NULL) THEN poll_view(p.id,$1) END,
        'poll_deleted',admin_can($1,'content.moderate') AND EXISTS(SELECT 1 FROM polls WHERE post_id=p.id AND deleted_at IS NOT NULL),
        'likes', p.likes, 'replies', p.replies, 'reposts', p.reposts, 'views', p.views,
        'liked', p.liked, 'reposted', p.reposted, 'followed', p.followed, 'mine', p.author_id = $1,
        'can_delete', p.author_id = $1 OR coalesce(p.wall_owner_id = $1, false), 'wall', p.wall_owner_id IS NOT NULL,
        'is_repost', p.is_repost,
        'original', CASE WHEN original.id IS NOT NULL THEN jsonb_build_object(
            'id', original.id, 'body', original.body,
            'image', EXISTS (SELECT 1 FROM post_images WHERE post_id = original.id),
            'media', moderated_attachments(original.id,$1), 'poll', CASE WHEN NOT EXISTS(SELECT 1 FROM polls WHERE post_id=original.id AND deleted_at IS NOT NULL) THEN poll_view(original.id,$1) END,
            'author', jsonb_build_object('id', oa.id, 'name', oa.display_name, 'username', oa.username, 'verified',oa.verified, 'avatar', NOT oa.avatar_hidden AND (oa.avatar IS NOT NULL OR oa.avatar_object_id IS NOT NULL))
        ) END
    )
    FROM page p JOIN accounts a ON a.id = p.author_id
    LEFT JOIN posts original ON original.id = p.repost_of AND visible_post(original.id, $1)
    LEFT JOIN accounts oa ON oa.id = original.author_id
    ORDER BY p.score DESC,
             CASE WHEN $3 IS NOT NULL AND $10 = 'popular' THEN p.likes END DESC,
             CASE WHEN $3 IS NOT NULL AND $10 = 'oldest' THEN p.created_at END ASC,
             p.created_at DESC, p.id DESC
) AS posts,
CASE WHEN $3::uuid IS NULL AND $7 IS NULL AND $9 IS NULL AND $5 = 0 THEN EXISTS (
    SELECT 1
    FROM follows f
    JOIN posts p ON p.author_id = f.followed_id
    WHERE f.follower_id = $1 AND p.reply_to IS NULL AND p.wall_owner_id IS NULL
      AND visible_post(p.id,$1)
) END AS has_following_posts
