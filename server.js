import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { supabase } from './supabaseClient.js';

const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// middleware
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const COOKIE_NAME = process.env.COOKIE_NAME || 'ysid';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';

// --- helpers ---
function setAuthCookie(res, payload) {
  const { exp, iat, nbf, ...clean } = payload || {};
  const token = jwt.sign(clean, JWT_SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

//관리자
function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ message: '로그인이 필요합니다.' });
  if (req.user.role !== 'admin') return res.status(403).json({ message: '관리자만 접근 가능합니다.' });
  next();
}

// 공개 URL → 파일 경로 추출
function pathFromPublicUrl(publicUrl) {
  const REVIEW_BUCKET = 'review-images';
  if (!publicUrl) return null;
  const marker = `/object/public/${REVIEW_BUCKET}/`;
  const idx = publicUrl.indexOf(marker);
  if (idx === -1) return null;
  return publicUrl.slice(idx + marker.length); 
}


function authMiddleware(req, _res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) { req.user = null; return next(); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, nickname }
  } catch {
    req.user = null;
  }
  next();
}
app.use(authMiddleware);

function requireLogin(req, res, next) {
  if (!req.user) return res.status(401).json({ message: '로그인이 필요합니다.' });
  next();
}

app.post('/signup', async (req, res) => {
  try {
    const { email, nickname, password } = req.body || {};

    // 1) 이메일 형식
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({ message: '유효한 이메일을 입력하세요.' });
    }

    // 2) 비밀번호 제한(최소 8자, 영문+숫자 포함, 특수문자 허용)
    const pwRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*]{8,}$/;
    if (!password || !pwRegex.test(password)) {
      return res.status(400).json({
        message: '비밀번호는 최소 8자, 영문+숫자를 포함해야 합니다.'
      });
    }

    // 3) 닉네임 길이/문자 제한(선택)
    if (!nickname || nickname.length < 2 || nickname.length > 16) {
      return res.status(400).json({ message: '닉네임은 2~16자여야 합니다.' });
    }

    // 4) 중복 검사 (DB unique와 이중 방어)
    const [{ data: byEmail }, { data: byNick }] = await Promise.all([
      supabase.from('users').select('id').eq('email', email).maybeSingle(),
      supabase.from('users').select('id').eq('nickname', nickname).maybeSingle(),
    ]);
    if (byEmail) return res.status(409).json({ message: '이미 가입된 이메일입니다.' });
    if (byNick)  return res.status(409).json({ message: '이미 사용 중인 닉네임입니다.' });

    // 5) 저장
    const password_hash = await bcrypt.hash(password, 10);

    const { data: user, error } = await supabase.from('users')
      .insert([{ email, nickname, password_hash }])
      .select('id, email, nickname').single();
    if (error) throw error;

    res.json({ ok: true, user });
  } catch (err) {
    res.status(500).json({ message: '회원가입 실패', detail: String(err.message || err) });
  }
});

// 닉네임 + 이메일로 직접 비밀번호 변경 (비로그인 상태에서도 가능)
app.post('/password/reset-direct', async (req, res) => {
  try {
    const { email, nickname, new_password } = (req.body || {});
    if (!email || !nickname || !new_password) {
      return res.status(400).json({ message: '이메일/닉네임/새 비밀번호가 필요합니다.' });
    }

    // 1) 사용자 조회 (닉네임 + 이메일 모두 일치해야)
    const { data: user, error: e1 } = await supabase
      .from('users')
      .select('id, email, nickname')
      .eq('email', email)
      .eq('nickname', nickname)
      .maybeSingle();

    // 보안상 계정 존재 유무를 굳이 드러내지 않으려면 동일 응답 사용 가능
    if (e1) throw e1;
    if (!user) {
      return res.status(200).json({ ok: true }); // 존재 여부 숨김(권장)
      // 또는 아래처럼 명확히 에러를 띄우고 싶다면:
      // return res.status(404).json({ message: '일치하는 계정을 찾을 수 없습니다.' });
    }

    // 2) 비밀번호 해시 후 저장
    const password_hash = await bcrypt.hash(new_password, 10);
    const { error: e2 } = await supabase
      .from('users')
      .update({ password_hash })
      .eq('id', user.id);
    if (e2) throw e2;

    // 3) 응답
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ message: '비밀번호 변경 실패', detail: String(err.message || err) });
  }
});


app.get('/logout', (req, res) => {
  const name = COOKIE_NAME || 'ysid';
  const opts = {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/', // 설정 때 기본값과 동일하게
  };

  // 1) 정상 삭제
  res.clearCookie(name, opts);
  // 2) 혹시 남는 경우 대비: 만료 쿠키 재설정
  res.cookie(name, '', { ...opts, maxAge: 0 });

  // 3) 과거 기본 이름(ysid)도 함께 제거 (혹시 이름 바꾼 적 있을 때)
  if (name !== 'ysid') {
    res.clearCookie('ysid', opts);
    res.cookie('ysid', '', { ...opts, maxAge: 0 });
  }

  res.json({ ok: true });
});

app.get('/check-auth', (req, res) => {
  res.json({ loggedIn: !!req.user });
});

app.get('/api/me', requireLogin, async (req, res) => {
  const { data, error } = await supabase.from('users')
    .select('id, email, nickname, role').eq('id', req.user.id).single();
  if (error) return res.status(500).json({ message: '조회 실패' });
  res.json(data);
});

app.put('/api/me', requireLogin, async (req, res) => {
  const { nickname } = req.body || {};
  const { error } = await supabase.from('users').update({ nickname }).eq('id', req.user.id);
  if (error) return res.status(500).json({ message: '수정 실패' });
  // 필요한 필드만 재서명
  setAuthCookie(res, { id: req.user.id, email: req.user.email, nickname, role: req.user.role || 'user' });
  res.json({ ok: true });
});

// 내가 작성한 리뷰 목록
// GET /api/reviews/mine?sort=latest|oldest|ratingDesc|ratingAsc
app.get('/api/reviews/mine', requireLogin, async (req, res) => {
  try {
    const raw = String(req.query.sort || 'latest').toLowerCase();
    const sort =
      raw === 'oldest'     ? 'oldest'     :
      raw === 'ratingdesc' ? 'ratingdesc' :
      raw === 'ratingasc'  ? 'ratingasc'  : 'latest';

    const { data, error } = await supabase
      .from('reviews')
      .select('id, title, rating, restaurant_name, created_at')  // 필요한 것만
      .eq('user_id', req.user.id);

    if (error) return res.status(500).json({ message: '조회 실패', detail: String(error.message || error) });

    const list = Array.isArray(data) ? data.slice() : [];

    // 정렬(안전하게 프런트에서 하지 않고 서버에서 결정)
    if (sort === 'oldest') {
      list.sort((a,b)=> new Date(a.created_at) - new Date(b.created_at));
    } else if (sort === 'ratingdesc') {
      list.sort((a,b)=> (b.rating||0)-(a.rating||0) || (new Date(b.created_at)-new Date(a.created_at)));
    } else if (sort === 'ratingasc') {
      list.sort((a,b)=> (a.rating||0)-(b.rating||0) || (new Date(b.created_at)-new Date(a.created_at)));
    } else {
      list.sort((a,b)=> new Date(b.created_at) - new Date(a.created_at)); // latest
    }

    res.json(list);
  } catch (e) {
    res.status(500).json({ message: '조회 실패', detail: String(e.message || e) });
  }
});

// 최근 리뷰 3개 + 북마크 수 (안정화)
app.get('/api/reviews/recent', async (req, res) => {
  try {
    let q = supabase
      .from('reviews')
      .select('id, title, rating, foodcategory, restaurant_name, created_at')
      .order('created_at', { ascending: false })
      .limit(3);

    // 관리자만 숨김글 포함 (관리자 아닌 경우 hidden !== true 만)
    if (!req.user || req.user.role !== 'admin') {
      q = q.not('hidden', 'is', true);
    }

    const { data: rows, error: e1 } = await q;
    if (e1) {
      console.error('[recent] step1 reviews error:', e1);
      throw e1;
    }

    const reviews = Array.isArray(rows) ? rows : [];
    if (reviews.length === 0) return res.json([]);

    // --- 북마크 집계는 "부분 실패 허용" ---
    let countMap = {};
    try {
      const ids = reviews.map(r => r.id);
      const { data: bmRows, error: e2 } = await supabase
        .from('bookmarks')
        .select('review_id')
        .in('review_id', ids);

      if (e2) throw e2;

      (bmRows || []).forEach(r => {
        countMap[r.review_id] = (countMap[r.review_id] || 0) + 1;
      });
    } catch (e) {
      console.error('[recent] step2 bookmarks error (continue with zeros):', e);
      // 북마크 집계 실패해도 리뷰 자체는 반환
      countMap = {};
    }

    const withCounts = reviews.map(r => ({
      ...r,
      bookmark_count: countMap[r.id] || 0,
    }));

    return res.json(withCounts);
  } catch (err) {
    // 여기서 환경변수 유무까지 같이 로깅
    console.error('[recent] fatal:', err, {
      SUPABASE_URL: !!process.env.SUPABASE_URL,
      SUPABASE_ANON_KEY: !!process.env.SUPABASE_ANON_KEY,
      NODE_ENV: process.env.NODE_ENV
    });
    return res.status(500).json({ message: '조회 실패', detail: String(err?.message || err) });
  }
});

app.get('/api/reviews', async (req, res) => {
  const { region, foodcategory, sub, sort = 'latest' } = req.query;

  let q = supabase.from('reviews')
    .select('id, title, rating, foodcategory, subcategory, regionnames, subregion, restaurant_name, created_at');

  if (!req.user || req.user.role !== 'admin') {
    q = q.not('hidden', 'is', true);
  }

  // 대분류 필터
  if (region) q = q.eq('regionnames', region);
  if (foodcategory) q = q.eq('foodcategory', foodcategory);

  // 소분류 필터
  if (sub) {
    if (region)      q = q.eq('subregion', sub);
    if (foodcategory) q = q.eq('subcategory', sub);
  }

  // 기본 정렬(최신/오래된) — 북마크 정렬은 아래에서 JS로 처리할 예정
  const sortKey = String(sort || 'latest').toLowerCase();
  if (sortKey === 'oldest') {
    q = q.order('created_at', { ascending: true });
  } else {
    q = q.order('created_at', { ascending: false });
  }

  const { data: list, error } = await q;
  if (error) return res.status(500).json({ message: '조회 실패', detail: String(error.message || error) });

  const reviews = Array.isArray(list) ? list.slice() : [];
  if (reviews.length === 0) return res.json([]);

  // 🔢 이 목록에 해당하는 리뷰들의 북마크 카운트 조회
  const ids = reviews.map(r => r.id);
  const { data: bmRows, error: e2 } = await supabase
    .from('bookmarks')
    .select('review_id')
    .in('review_id', ids);

  if (e2) return res.status(500).json({ message: '조회 실패', detail: String(e2.message || e2) });

  // count 집계 (JS에서 그룹핑)
  const countMap = {};
  (bmRows || []).forEach(row => {
    const k = row.review_id;
    countMap[k] = (countMap[k] || 0) + 1;
  });

  // 각 리뷰에 bookmark_count 부착
  reviews.forEach(r => { r.bookmark_count = countMap[r.id] || 0; });

  // ⭐ 북마크 정렬 처리
  if (sortKey === 'bookmarkdesc') {
    reviews.sort((a, b) =>
      (b.bookmark_count - a.bookmark_count) ||
      (new Date(b.created_at) - new Date(a.created_at))
    );
  } else if (sortKey === 'bookmarkasc') {
    reviews.sort((a, b) =>
      (a.bookmark_count - b.bookmark_count) ||
      (new Date(b.created_at) - new Date(a.created_at))
    );
  }
  // latest/oldest는 위에서 이미 정렬됨

  return res.json(reviews);
});

// ===== Bookmarks =====
// GET /api/bookmarks/mine?sort=latest|oldest|ratingDesc|ratingAsc
app.get('/api/bookmarks/mine', requireLogin, async (req, res) => {
  try {
    const sort = (req.query.sort || 'latest').toLowerCase();

    // 1) 내 북마크 행
    const { data: rows, error: e1 } = await supabase
      .from('bookmarks')
      .select('review_id, created_at')
      .eq('user_id', req.user.id);
    if (e1) return res.status(500).json({ message: '조회 실패(1)', detail: String(e1.message || e1) });

    const ids = (rows || []).map(r => r.review_id).filter(Boolean);
    if (ids.length === 0) return res.json([]);

    // 2) 리뷰들
    const { data: reviews, error: e2 } = await supabase
      .from('reviews')
      .select('id, title, rating, restaurant_name, image_url, created_at')
      .in('id', ids);
    if (e2) return res.status(500).json({ message: '조회 실패(2)', detail: String(e2.message || e2) });

    // 3) 정렬
    const list = (reviews || []).slice();
    if (sort === 'oldest') {
      list.sort((a,b)=> new Date(a.created_at) - new Date(b.created_at));
    } else if (sort === 'ratingdesc') {
      list.sort((a,b)=> (b.rating||0) - (a.rating||0) || (new Date(b.created_at)-new Date(a.created_at)));
    } else if (sort === 'ratingasc') {
      list.sort((a,b)=> (a.rating||0) - (b.rating||0) || (new Date(b.created_at)-new Date(a.created_at)));
    } else {
      list.sort((a,b)=> new Date(b.created_at) - new Date(a.created_at)); // latest
    }

    res.json(list);
  } catch (e) {
    res.status(500).json({ message: '조회 실패', detail: String(e.message || e) });
  }
});

// 상태/카운트 조회 (공개)  GET /api/bookmarks/:reviewId
app.get('/api/bookmarks/:reviewId', async (req, res) => {
  try {
    const reviewId = req.params.reviewId;

    const { count, error: eCount } = await supabase
      .from('bookmarks')
      .select('*', { count: 'exact', head: true })
      .eq('review_id', reviewId);
    if (eCount) throw eCount;

    let bookmarked = false;
    if (req.user) {
      const { data: mine, error: eMine } = await supabase
        .from('bookmarks')
        .select('id')
        .eq('user_id', req.user.id)
        .eq('review_id', reviewId)
        .maybeSingle();
      if (eMine) throw eMine;
      bookmarked = !!mine;
    }

    res.json({ count: count || 0, bookmarked });
  } catch (err) {
    res.status(500).json({ message: '북마크 상태 조회 실패', detail: String(err.message || err) });
  }
});

// 추가  POST /api/bookmarks/:reviewId
app.post('/api/bookmarks/:reviewId', requireLogin, async (req, res) => {
  try {
    const reviewId = req.params.reviewId;

    // 삽입(중복은 성공으로 간주)
    const { error: insErr } = await supabase
      .from('bookmarks')
      .insert([{ user_id: req.user.id, review_id: reviewId }]);
    if (insErr && !String(insErr.message||'').toLowerCase().includes('duplicate')) {
      throw insErr;
    }

    // 최신 카운트 반환
    const { count } = await supabase
      .from('bookmarks')
      .select('*', { count: 'exact', head: true })
      .eq('review_id', reviewId);

    res.json({ ok: true, bookmarked: true, count: count || 0 });
  } catch (err) {
    res.status(500).json({ message: '북마크 추가 실패', detail: String(err.message || err) });
  }
});

// POST /api/reports/:reviewId  (신고 제출)
app.post('/api/reports/:reviewId', requireLogin, async (req, res) => {
  try {
    const reviewId = req.params.reviewId;
    const reason = (req.body?.reason || '').slice(0, 500);

    // 중복 신고 방지 (unique index가 있지만 서버에서도 확인)
    const { data: exists, error: e1 } = await supabase
      .from('reports')
      .select('id')
      .eq('reporter_id', req.user.id)
      .eq('review_id', reviewId)
      .maybeSingle();
    if (e1) throw e1;
    if (exists) return res.json({ ok: true, duplicated: true });

    const { error: e2 } = await supabase
      .from('reports')
      .insert([{ review_id: reviewId, reporter_id: req.user.id, reason }]);
    if (e2) throw e2;

    res.json({ ok: true, duplicated: false });
  } catch (err) {
    res.status(500).json({ message: '신고 실패', detail: String(err.message || err) });
  }
});

// GET /api/admin/reports  (신고 목록)
app.get('/api/admin/reports', requireAdmin, async (req, res) => {
  try {
    // 1) 신고 원본 리스트
    const { data: reports, error: e1 } = await supabase
      .from('reports')
      .select('id, review_id, reporter_id, reason, created_at')
      .order('created_at', { ascending: false });
    if (e1) throw e1;

    if (!reports || reports.length === 0) return res.json([]);

    // 2) 관련 리뷰/유저 한번에 조회
    const reviewIds = [...new Set(reports.map(r => r.review_id).filter(Boolean))];
    const userIds   = [...new Set(reports.map(r => r.reporter_id).filter(Boolean))];

    const [{ data: reviews, error: e2 }, { data: users, error: e3 }] = await Promise.all([
      supabase.from('reviews')
        .select('id, title, restaurant_name, hidden')
        .in('id', reviewIds),
      supabase.from('users')
        .select('id, email, nickname')
        .in('id', userIds),
    ]);
    if (e2) throw e2;
    if (e3) throw e3;

    // 3) 매핑
    const reviewMap = new Map((reviews || []).map(r => [r.id, r]));
    const userMap   = new Map((users   || []).map(u => [u.id, u]));

    const rows = reports.map(r => ({
      id: r.id,
      review_id: r.review_id,
      reporter_id: r.reporter_id,
      reason: r.reason,
      created_at: r.created_at,
      reviews: reviewMap.get(r.review_id) || null,
      users: userMap.get(r.reporter_id) || null,
    }));

    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: '신고 목록 조회 실패', detail: String(e.message || e) });
  }
});

// GET /api/reports/:reviewId/status  (신고 상태/카운트 조회)
app.get('/api/reports/:reviewId/status', async (req, res) => {
  try {
    const reviewId = req.params.reviewId;

    // 총 신고 수
    const { count, error: e1 } = await supabase
      .from('reports')
      .select('*', { count: 'exact', head: true })
      .eq('review_id', reviewId);
    if (e1) throw e1;

    // 내가 이미 신고했는지
    let reported = false;
    if (req.user) {
      const { data: me, error: e2 } = await supabase
        .from('reports')
        .select('id')
        .eq('review_id', reviewId)
        .eq('reporter_id', req.user.id) // ← reporter_id 쓰고 있으므로 여기도 동일
        .maybeSingle();
      if (e2) throw e2;
      reported = !!me;
    }

    return res.json({ count: count || 0, reported });
  } catch (err) {
    return res.status(500).json({ message: '신고 상태 조회 실패', detail: String(err.message || err) });
  }
});

// POST /api/admin/reviews/:id/hide  { hidden: true|false }
app.post('/api/admin/reviews/:id/hide', requireAdmin, async (req, res) => {
  try {
    const hidden = !!req.body?.hidden;
    const { error } = await supabase
      .from('reviews')
      .update({ hidden })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: '숨김 처리 실패', detail: String(e.message || e) });
  }
});

// (옵션) 신고 해제/삭제
app.delete('/api/admin/reports/:id', requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('reports').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: '신고 삭제 실패', detail: String(e.message || e) });
  }
});

// 해제  DELETE /api/bookmarks/:reviewId
app.delete('/api/bookmarks/:reviewId', requireLogin, async (req, res) => {
  try {
    const reviewId = req.params.reviewId;

    const { error: delErr } = await supabase
      .from('bookmarks')
      .delete()
      .eq('user_id', req.user.id)
      .eq('review_id', reviewId);
    if (delErr) throw delErr;

    // 최신 카운트 반환
    const { count } = await supabase
      .from('bookmarks')
      .select('*', { count: 'exact', head: true })
      .eq('review_id', reviewId);

    res.json({ ok: true, bookmarked: false, count: count || 0 });
  } catch (err) {
    res.status(500).json({ message: '북마크 해제 실패', detail: String(err.message || err) });
  }
});

// 리뷰 상세 (소유자 여부 포함, 불필요한 노출 최소화)
app.get('/api/reviews/:id', async (req, res) => {
  try {
    // 필요한 컬럼만 명시적으로 선택 (lat/lng, subcategory/subregion 포함)
    const { data: review, error } = await supabase
      .from('reviews')
      .select(`
        id, user_id,
        title, restaurant_name, address,
        rating, content, image_url, image_urls,
        foodcategory, subcategory,
        regionnames, subregion,
        created_at, hidden,
        place_id, lat, lng
      `)
      .eq('id', req.params.id)
      .maybeSingle();

    if (error) throw error;
    if (review.hidden && (!req.user || (req.user.role !== 'admin' && req.user.id !== review.user_id))) {
      return res.status(404).json({ message: '없음' });
    }

    // 소유자 판별
    const isOwner = !!(req.user && req.user.id === review.user_id);

    // 응답 페이로드 구성 (소유자가 아니면 user_id 숨김)
    const payload = { ...review, isOwner };
    if (!isOwner) delete payload.user_id;

    return res.json(payload);
  } catch (e) {
    return res.status(500).json({ message: '조회 실패', detail: String(e.message || e) });
  }
});

// server.js (/login)
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: '필수 항목 누락' });

    const { data: user, error } = await supabase
      .from('users').select('id, email, nickname, password_hash, role').eq('email', email).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(401).json({ message: '이메일 또는 비밀번호가 틀립니다.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: '이메일 또는 비밀번호가 틀립니다.' });

    setAuthCookie(res, { id: user.id, email: user.email, nickname: user.nickname, role: user.role || 'user' });

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ message: '로그인 실패', detail: String(err.message || err) });
  }
});


app.post('/api/reviews', requireLogin, async (req, res) => {
  const payload = req.body || {};
  const row = {
    user_id: req.user.id,
    title: payload.title,
    restaurant_name: payload.restaurant_name,
    address: payload.address,
    rating: payload.rating,
    content: payload.content,
    image_url: payload.image_url ?? null,
    image_urls: Array.isArray(payload.image_urls) ? payload.image_urls : [],
    foodcategory: payload.foodcategory,
    regionnames: payload.regionnames,
    subcategory: payload.subcategory || null,
    subregion: payload.subregion || null,
    place_id: payload.place_id || null,
    lat: payload.lat ?? null,
    lng: payload.lng ?? null,
  };
  const { data, error } = await supabase.from('reviews').insert([row]).select('id').single();
  if (error) return res.status(500).json({ message: '등록 실패' });
  res.json({ ok: true, id: data.id });
});

app.put('/api/reviews/:id', requireLogin, async (req, res) => {
  const id = req.params.id;

  // 소유자 확인 + 기존 데이터 조회(이전 이미지 URL 비교 위해)
  const { data: review, error: e1 } = await supabase
    .from('reviews')
    .select('user_id, image_url, image_urls')
    .eq('id', id)
    .maybeSingle();
  if (e1 || !review) return res.status(404).json({ message: '없음' });
  if (review.user_id !== req.user.id) return res.status(403).json({ message: '권한 없음' });

  const payload = req.body || {};
  const update = {
    title: payload.title,
    restaurant_name: payload.restaurant_name,
    address: payload.address,
    rating: payload.rating,
    content: payload.content,
    image_url: payload.image_url ?? null,
    image_urls: Array.isArray(payload.image_urls) ? payload.image_urls : [],
    foodcategory: payload.foodcategory,
    regionnames: payload.regionnames,
    subcategory: payload.subcategory || null,
    subregion: payload.subregion || null,
    place_id: payload.place_id || null,
    lat: payload.lat ?? null,
    lng: payload.lng ?? null,
  };

  const prevUrl = review.image_url || null;
  const nextUrl = update.image_url || null;

  const { error } = await supabase.from('reviews').update(update).eq('id', id);
  if (error) return res.status(500).json({ message: '수정 실패' });

  res.json({ ok: true });
});

app.delete('/api/reviews/:id', requireLogin, async (req, res) => {
  const id = req.params.id;

  const { data: review, error: e1 } = await supabase
    .from('reviews')
    .select('user_id, image_url')
    .eq('id', id)
    .maybeSingle();
  if (e1 || !review) return res.status(404).json({ message: '없음' });
  if (review.user_id !== req.user.id) return res.status(403).json({ message: '권한 없음' });

  const { error } = await supabase.from('reviews').delete().eq('id', id);
  if (error) return res.status(500).json({ message: '삭제 실패' });

  res.json({ ok: true });
});


app.listen(PORT, () => console.log(`Server running http://localhost:${PORT}`));

app.get('/healthz', (_req, res) => res.type('text').send('ok'));
