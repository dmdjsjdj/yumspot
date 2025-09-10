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
import { createClient as createSbClient } from '@supabase/supabase-js';

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

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // 필수(비공개)
export const supabaseAdmin = createSbClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const REVIEW_BUCKET = 'review-images';

// --- helpers ---
function setAuthCookie(res, payload) {
  const { exp, iat, nbf, ...clean } = payload || {};
  const token = jwt.sign(clean, JWT_SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

// 공개 URL → 파일 경로 추출
function pathFromPublicUrl(publicUrl) {
  if (!publicUrl) return null;
  const marker = `/object/public/${REVIEW_BUCKET}/`;
  const idx = publicUrl.indexOf(marker);
  if (idx === -1) return null;
  return publicUrl.slice(idx + marker.length); 
}

async function deleteImageByPublicUrl(publicUrl) {
  const path = pathFromPublicUrl(publicUrl);
  if (!path) return;
  const { error } = await supabaseAdmin.storage.from(REVIEW_BUCKET).remove([path]);
  if (error) console.error('Storage remove error:', error);
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

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: '필수 항목 누락' });

    const { data: user, error } = await supabase
      .from('users').select('id, email, nickname, password_hash').eq('email', email).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(401).json({ message: '이메일 또는 비밀번호가 틀립니다.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: '이메일 또는 비밀번호가 틀립니다.' });

    //setAuthCookie(res, { id: user.id, email: user.email, nickname: user.nickname });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ message: '로그인 실패', detail: String(err.message || err) });
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
    .select('id, email, nickname').eq('id', req.user.id).single();
  if (error) return res.status(500).json({ message: '조회 실패' });
  res.json(data);
});

app.put('/api/me', requireLogin, async (req, res) => {
  const { nickname } = req.body || {};
  const { error } = await supabase.from('users').update({ nickname }).eq('id', req.user.id);
  if (error) return res.status(500).json({ message: '수정 실패' });
  // 필요한 필드만 재서명
  setAuthCookie(res, { id: req.user.id, email: req.user.email, nickname });
  res.json({ ok: true });
});

// --- Reviews ---
app.get('/api/reviews/recent', async (_req, res) => {
  const { data, error } = await supabase.from('reviews')
    .select('id, title, rating, foodcategory, restaurant_name, created_at')
    .order('created_at', { ascending: false })
    .limit(3);
  if (error) return res.status(500).json({ message: '조회 실패' });
  res.json(data);
});

app.get('/api/reviews', async (req, res) => {
  const { region, foodcategory, sub, sort = 'latest' } = req.query;

  let q = supabase.from('reviews')
    .select('id, title, rating, foodcategory, subcategory, regionnames, subregion, restaurant_name, created_at');

  // 정렬
  if (sort === 'latest') {
    q = q.order('created_at', { ascending: false });
  }
  // TODO: 북마크순은 북마크 컬럼/테이블 추가 후 여기서 정렬

  // 대분류 필터
  if (region) q = q.eq('regionnames', region);
  if (foodcategory) q = q.eq('foodcategory', foodcategory);

  // 소분류 필터 (둘 중 하나만 올 수 있음)
  if (sub) {
    if (region) q = q.eq('subregion', sub);
    if (foodcategory) q = q.eq('subcategory', sub);
  }

  const { data, error } = await q;
  if (error) return res.status(500).json({ message: '조회 실패' });
  res.json(data);
});

// 리뷰 상세 (소유자 여부 포함, 불필요한 노출 최소화)
app.get('/api/reviews/:id', async (req, res) => {
  try {
    // 필요한 컬럼만 명시적으로 선택 (lat/lng, subcategory/subregion 포함)
    const { data: rv, error } = await supabase
      .from('reviews')
      .select(`
        id, user_id,
        title, restaurant_name, address,
        rating, content, image_url,
        foodcategory, subcategory,
        regionnames, subregion,
        lat, lng,
        created_at, updated_at
      `)
      .eq('id', req.params.id)
      .maybeSingle();

    if (error) throw error;
    if (!rv) return res.status(404).json({ message: '없음' });

    // 소유자 판별
    const isOwner = !!(req.user && req.user.id === rv.user_id);

    // 응답 페이로드 구성 (소유자가 아니면 user_id 숨김)
    const payload = { ...rv, isOwner };
    if (!isOwner) delete payload.user_id;

    return res.json(payload);
  } catch (e) {
    return res.status(500).json({ message: '조회 실패', detail: String(e.message || e) });
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
    image_url: payload.image_url,
    foodcategory: payload.foodcategory,
    regionnames: payload.regionnames,
    subcategory: payload.subcategory || null,
    subregion: payload.subregion || null
  };
  const { data, error } = await supabase.from('reviews').insert([row]).select('id').single();
  if (error) return res.status(500).json({ message: '등록 실패' });
  res.json({ ok: true, id: data.id });
});

app.put('/api/reviews/:id', requireLogin, async (req, res) => {
  const id = req.params.id;

  // 소유자 확인 + 기존 데이터 조회(이전 이미지 URL 비교 위해)
  const { data: rv, error: e1 } = await supabase
    .from('reviews')
    .select('user_id, image_url')
    .eq('id', id)
    .maybeSingle();
  if (e1 || !rv) return res.status(404).json({ message: '없음' });
  if (rv.user_id !== req.user.id) return res.status(403).json({ message: '권한 없음' });

  const payload = req.body || {};
  const update = {
    title: payload.title,
    restaurant_name: payload.restaurant_name,
    address: payload.address,
    rating: payload.rating,
    content: payload.content,
    image_url: payload.image_url ?? null,
    foodcategory: payload.foodcategory,
    regionnames: payload.regionnames,
    subcategory: payload.subcategory || null,
    subregion: payload.subregion || null,
    lat: payload.lat ?? null,
    lng: payload.lng ?? null,
  };

  const prevUrl = rv.image_url || null;
  const nextUrl = update.image_url || null;

  const { error } = await supabase.from('reviews').update(update).eq('id', id);
  if (error) return res.status(500).json({ message: '수정 실패' });

  // 이미지가 교체되었으면 이전 파일 삭제(서버에서 수행)
  if (prevUrl && nextUrl && prevUrl !== nextUrl) {
    deleteImageByPublicUrl(prevUrl).catch(console.error);
  }
  // (선택) 새 URL이 null인데 이전이 존재 → 사용자 요청으로 삭제한 상황이라면 이전 것 삭제
  if (!nextUrl && prevUrl) {
    deleteImageByPublicUrl(prevUrl).catch(console.error);
  }

  res.json({ ok: true });
});

app.delete('/api/reviews/:id', requireLogin, async (req, res) => {
  const id = req.params.id;

  const { data: rv, error: e1 } = await supabase
    .from('reviews')
    .select('user_id, image_url')
    .eq('id', id)
    .maybeSingle();
  if (e1 || !rv) return res.status(404).json({ message: '없음' });
  if (rv.user_id !== req.user.id) return res.status(403).json({ message: '권한 없음' });

  // 1) 이미지가 있으면 스토리지에서 삭제 시도
  if (rv.image_url) {
    try { await deleteImageByPublicUrl(rv.image_url); } catch (e) { console.error(e); }
  }

  // 2) 리뷰 삭제
  const { error } = await supabase.from('reviews').delete().eq('id', id);
  if (error) return res.status(500).json({ message: '삭제 실패' });

  res.json({ ok: true });
});


app.listen(PORT, () => console.log(`Server running http://localhost:${PORT}`));
