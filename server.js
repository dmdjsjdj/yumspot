require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const path = require('path');
const multer = require('multer');

const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
const jwtSecret = process.env.JWT_SECRET || 'default_secret';
const cookieParser = require('cookie-parser');
app.use(cookieParser());

const cloudinary = require('cloudinary').v2;
const fs = require('fs');

console.log('DB_HOST:', process.env.DB_HOST);

// 정적 파일 제공 (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// 기본 페이지 설정 (루트 URL로 접근 시 `home.html` 제공)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
//리뷰 받아오기기
app.get('/get-reviews', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM reviews');
        if (results.length === 0) {
            return res.status(404).send('리뷰를 찾을 수 없습니다.');
        }
        res.json(results[0]); // 하나만 반환
    } catch (error) {
        console.error('리뷰 불러오기 오류:', error);
        res.status(500).send('서버 오류');
    }
});

app.get('/get-review/:id', async (req, res) => {
    const reviewId = req.params.id;
    try {
        const [results] = await db.query('SELECT * FROM reviews WHERE id = ?', [reviewId]);
        if (results.length === 0) return res.status(404).send('리뷰를 찾을 수 없음');
        res.json(results[0]);
    } catch (err) {
        console.error('리뷰 조회 오류:', err);
        res.status(500).send('서버 오류');
    }
});
//최근 리뷰 3개 불러오기
app.get('/api/reviews/recent', async (req, res) => {
    try {
        const [results] = await db.query("SELECT id, title, rating, foodcategory, regionNames FROM reviews ORDER BY date DESC LIMIT 3");
        res.json(results);
    } catch (err) {
        console.error("리뷰 가져오기 실패:", err);
        res.status(500).send("서버 오류");
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, nickname } = req.body;
    if (!username || !password || !nickname) return res.status(400).send("모든 필드를 입력해주세요");

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)', [username, hashedPassword, nickname]);
        res.send('회원가입 완료!');
    } catch (err) {
        console.error('회원가입 오류:', err);
        res.status(500).send('서버 오류');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [results] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) return res.status(400).send("아이디 없음");

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send("비밀번호 틀림");

        const token = jwt.sign({ id: user.id, username: user.username }, jwtSecret, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.send("로그인 성공");
    } catch (err) {
        console.error('로그인 오류:', err);
        res.status(500).send("서버 오류");
    }
});

// 비밀번호 찾기
app.post('/find-password', async (req, res) => {
    const { username, nickname } = req.body;
    try {
        const [results] = await db.query('SELECT * FROM users WHERE username = ? AND nickname = ?', [username, nickname]);
        if (results.length === 0) return res.status(404).send("일치하는 사용자가 없습니다.");

        const tempPassword = Math.random().toString(36).slice(2, 10);
        const hashedPassword = await bcrypt.hash(tempPassword, 10);

        await db.query('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username]);
        res.send(tempPassword);
    } catch (err) {
        console.error("비밀번호 찾기 오류:", err);
        res.status(500).send("서버 오류");
    }
});


function verifyToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send("로그인 필요");

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) return res.status(403).send("토큰 오류");
    req.user = decoded;
    next();
  });
}
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.send("로그아웃 성공");
});

//사용자확인&토큰확인
app.get('/check-auth', (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.json({ loggedIn: false });

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) return res.json({ loggedIn: false });
        res.json({ loggedIn: true, user: decoded });
    });
});

app.post('/edit-profile', verifyToken, async (req, res) => {
    const { newPassword, nickname } = req.body;
    try {
        const hashed = await bcrypt.hash(newPassword, 10);
        await db.query("UPDATE users SET password = ?, nickname = ? WHERE id = ?", [hashed, nickname, req.user.id]);
        res.send("정보 수정 완료");
    } catch (err) {
        console.error("프로필 수정 오류:", err);
        res.status(500).send("업데이트 실패");
    }
});


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/');  // 이미지 저장 폴더
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);  // 파일명 변경
    }
});

const upload = multer({ storage });

// MariaDB 연결 설정
import mysql from 'mysql2/promise'

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
})


// 데이터베이스 연결 확인
db.getConnection((err, connection) => {
    // 개발 환경에서는 DB 연결 스킵 (로컬 테스트를 위해)
    if (process.env.NODE_ENV !== 'development') {
        db.getConnection((err, connection) => {
            if (err) {
                console.error('MariaDB 연결 실패:', err);
                return;
            }
            console.log('MariaDB 연결 성공');
            connection.release();
        });
    } else {
        console.log('개발 환경 - DB 연결 건너뜀');
    }
});
module.exports = db;
// 리뷰 저장 API 엔드포인트
app.post('/submit-review', upload.single('reviewImage'), verifyToken, async (req, res) => {
    const {
        reviewTitle, reviewDate, restaurantName,
        restaurantAddress, rating, reviewContent,
        foodCategory, regionCategory
    } = req.body;

    let imageUrl = null;

    if (req.file) {
        try {
            const result = await cloudinary.uploader.upload(req.file.path);
            imageUrl = result.secure_url;

            // 업로드 후 서버에서 임시 파일 삭제
            fs.unlinkSync(req.file.path);
        } catch (err) {
            console.error("Cloudinary 업로드 오류:", err);
            return res.status(500).send("이미지 업로드 실패");
        }
    }

    const sql = `INSERT INTO reviews 
        (user_id, title, date, restaurant_name, address, rating, content, image_url, foodcategory, regionNames)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    try {
        await db.query(sql, [
            req.user.id, reviewTitle, reviewDate, restaurantName,
            restaurantAddress, rating, reviewContent, imageUrl,
            foodCategory, regionCategory
        ]);
        res.send("리뷰 저장 완료!");
    } catch (err) {
        console.error('리뷰 저장 오류:', err);
        res.status(500).send("저장 실패");
    }
});

//클라우디네리 이미지 저장
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

//리뷰 불러오기
app.get('/review/:id', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM reviews WHERE id = ?', [req.params.id]);
        if (results.length === 0) return res.status(404).send('리뷰 없음');
        res.json(results[0]);
    } catch (err) {
        console.error('리뷰 조회 오류:', err);
        res.status(500).send('서버 오류');
    }
});
//내 리뷰 불러오기
app.get("/my-reviews", verifyToken, async (req, res) => {
    try {
        const [results] = await db.query("SELECT * FROM reviews WHERE user_id = ?", [req.user.id]);
        res.json(results);
    } catch (err) {
        console.error("리뷰 조회 오류:", err);
        res.status(500).send("서버 오류");
    }
});

// 서버 실행
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`서버 실행 중: http://localhost:${PORT}`);
});

// 연결 유지를 위한 ping + 재연결 로직
setInterval(async () => {
  try {
    const [rows] = await db.query('SELECT 1');
    // console.log('DB keep-alive success');
  } catch (err) {
    console.error('DB 연결 끊김! 재연결 시도 중...');

    try {
      // 새로운 커넥션 강제로 생성해서 pool 내부 복구 유도
      const connection = await db.getConnection();
      console.log('DB 재연결 성공');
      connection.release();
    } catch (reconnectErr) {
      console.error('DB 재연결 실패:', reconnectErr);
    }
  }
}, 20000); // 30초마다 확인 (너무 자주하면 부하 생김)