import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import multer from 'multer';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { createClient } from '@supabase/supabase-js';
import cloudinaryModule from 'cloudinary';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pkg from 'pg';
import { Readable } from 'stream';
import { v2 as cloudinary } from 'cloudinary';

const { Pool } = pkg;

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const storage = multer.memoryStorage();
const upload = multer({ storage });


const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const jwtSecret = process.env.JWT_SECRET;

// 클라우디너리 설정
const cloudinary = cloudinaryModule.v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// 정적 파일
app.use(express.static(path.join(__dirname, 'public')));

const pgPool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  ssl: {
    rejectUnauthorized: false,
  },
});


// JWT 인증 미들웨어
function verifyToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send("로그인 필요");

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) return res.status(403).send("토큰 오류");
    req.user = decoded;
    next();
  });
}

// 기본 페이지
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// 회원가입
app.post('/signup', async (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username || !password || !nickname) return res.status(400).send("모든 필드를 입력해주세요");

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { error } = await supabase
      .from('users')
      .insert([{ username, password: hashedPassword, nickname }]);

    if (error) throw error;
    res.send('회원가입 완료!');
  } catch (err) {
    console.error('회원가입 오류:', err);
    res.status(500).send('서버 오류');
  }
});

// 로그인
app.post('/login', async (req, res) => {
  const { username, password, remember } = req.body;

  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !data) return res.status(400).json({ success: false, message: "아이디 없음" });

    const isMatch = await bcrypt.compare(password, data.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "비밀번호 틀림" });

    const token = jwt.sign({ id: data.id, username: data.username }, jwtSecret, { expiresIn: remember ? '7d' : '1h' });

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000, // 7일 or 1시간
    });

    res.json({ success: true, message: "로그인 성공" });
  } catch (err) {
    console.error('로그인 오류:', err);
    res.status(500).json({ success: false, message: "서버 오류" });
  }
});

// 로그아웃
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.send("로그아웃 성공");
});

// 사용자 인증 상태 확인
app.get('/check-auth', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ loggedIn: false });

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, user: decoded });
  });
});

// 비밀번호 찾기
app.post('/find-password', async (req, res) => {
  const { username, nickname } = req.body;
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .eq('nickname', nickname)
      .single();

    if (error || !data) return res.status(404).send("일치하는 사용자가 없습니다.");

    const tempPassword = Math.random().toString(36).slice(2, 10); // 임시 비번
    const hashed = await bcrypt.hash(tempPassword, 10);

    const { error: updateError } = await supabase
      .from('users')
      .update({ password: hashed })
      .eq('username', username);

    if (updateError) throw updateError;

    // 사용자에게 임시 비밀번호 전달
    res.json({
      message: "임시 비밀번호가 발급되었습니다. 로그인 후 반드시 비밀번호를 변경해주세요.",
      tempPassword // 프론트에서만 1회 노출
    });
  } catch (err) {
    console.error("비밀번호 찾기 오류:", err);
    res.status(500).send("서버 오류");
  }
});

// 프로필 수정
app.post('/edit-profile', verifyToken, async (req, res) => {
  const { newPassword, nickname } = req.body;
  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    const { error } = await supabase
      .from('users')
      .update({ password: hashed, nickname })
      .eq('id', req.user.id);

    if (error) throw error;

    res.send("정보 수정 완료");
  } catch (err) {
    console.error("프로필 수정 오류:", err);
    res.status(500).send("업데이트 실패");
  }
});

// 리뷰 저장
app.post('/submit-review', upload.single('reviewImage'), verifyToken, async (req, res) => {
  const {
    reviewtitle, reviewdate, restaurantname,
    restaurantaddress, rating, reviewcontent,
    foodcategory, regioncategory
  } = req.body;

  let image_url = null;

  if (req.file) {
    try {
      // 클라우디너리 스트림 업로드 함수
      const streamUpload = (buffer) => {
        return new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'reviews' },
            (error, result) => {
              if (result) resolve(result);
              else reject(error);
            }
          );

          const readable = new Readable();
          readable._read = () => {};
          readable.push(buffer);
          readable.push(null);
          readable.pipe(stream);
        });
      };

      const result = await streamUpload(req.file.buffer);
      image_url = result.secure_url;

    } catch (err) {
      console.error("이미지 업로드 실패:", err);
      return res.status(500).send("이미지 업로드 실패");
    }
  }

  try {
    const { error } = await supabase
      .from('reviews')
      .insert([{
        user_id: req.user.id,
        title: reviewtitle,
        date: reviewdate,
        restaurant_name: restaurantname,
        address: restaurantaddress,
        rating,
        content: reviewcontent,
        image_url: image_url,
        foodcategory: foodcategory,
        regionNames: regioncategory
      }]);

    if (error) throw error;

    res.send("리뷰 저장 완료!");
  } catch (err) {
    console.error("리뷰 저장 오류:", err);
    res.status(500).send("저장 실패");
  }
});

// 최근 리뷰 3개
app.get('/api/reviews/recent', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('reviews')
      .select('id, title, rating, foodcategory, regionnames')
      .order('date', { ascending: false })
      .limit(3);

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("리뷰 가져오기 실패:", err);
    res.status(500).send("서버 오류");
  }
});

// 리뷰 단일 조회
app.get('/get-review/:id', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('reviews')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error || !data) return res.status(404).send("리뷰를 찾을 수 없음");
    res.json(data);
  } catch (err) {
    console.error("리뷰 조회 오류:", err);
    res.status(500).send("서버 오류");
  }
});

// 내 리뷰 조회
app.get('/my-reviews', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('reviews')
      .select('*')
      .eq('user_id', req.user.id);

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("내 리뷰 조회 오류:", err);
    res.status(500).send("서버 오류");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 서버 실행 중: http://localhost:${PORT}`);
});
