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
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
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

// --- Auth ---
app.post('/signup', async (req, res) => {
  try {
    const { email, nickname, password } = req.body || {};
    if (!email || !nickname || !password) return res.status(400).json({ message: '필수 항목 누락' });

    const { data: exists, error: e1 } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
    if (e1) throw e1;
    if (exists) return res.status(409).json({ message: '이미 가입된 이메일' });

    const password_hash = await bcrypt.hash(password, 10);
    const { data: user, error: e2 } = await supabase.from('users')
      .insert([{ email, nickname, password_hash }])
      .select('id, email, nickname').single();
    if (e2) throw e2;

    res.json({ ok: true });
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

    setAuthCookie(res, { id: user.id, email: user.email, nickname: user.nickname });
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

app.get('/api/reviews/:id', async (req, res) => {
  const { data: rv, error } = await supabase.from('reviews').select('*')
    .eq('id', req.params.id).maybeSingle();
  if (error || !rv) return res.status(404).json({ message: '없음' });

  const isOwner = !!(req.user && req.user.id === rv.user_id);
  res.json({ ...rv, isOwner });
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

  // 소유자 확인
  const { data: rv, error: e1 } = await supabase.from('reviews').select('user_id').eq('id', id).maybeSingle();
  if (e1 || !rv) return res.status(404).json({ message: '없음' });
  if (rv.user_id !== req.user.id) return res.status(403).json({ message: '권한 없음' });

  const payload = req.body || {};
  const update = {
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
  const { error } = await supabase.from('reviews').update(update).eq('id', id);
  if (error) return res.status(500).json({ message: '수정 실패' });
  res.json({ ok: true });
});

app.delete('/api/reviews/:id', requireLogin, async (req, res) => {
  const id = req.params.id;

  const { data: rv, error: e1 } = await supabase.from('reviews').select('user_id').eq('id', id).maybeSingle();
  if (e1 || !rv) return res.status(404).json({ message: '없음' });
  if (rv.user_id !== req.user.id) return res.status(403).json({ message: '권한 없음' });

  const { error } = await supabase.from('reviews').delete().eq('id', id);
  if (error) return res.status(500).json({ message: '삭제 실패' });
  res.json({ ok: true });
});

// SPA 라우팅 필요시 아래 주석 해제
// app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));

app.listen(PORT, () => console.log(`Server running http://localhost:${PORT}`));
