const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const path = require('path');
const multer = require('multer');

const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
app.use(cookieParser());

const cloudinary = require('cloudinary').v2;
const fs = require('fs');

// 정적 파일 제공 (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// 기본 페이지 설정 (루트 URL로 접근 시 `home.html` 제공)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/get-reviews', (req, res) => {
    db.query('SELECT * FROM reviews', (error, results) => {  // ✅ db 사용
        if (error) {
            console.error('리뷰 불러오기 오류:', error);
            res.status(500).send('서버 오류');
        } if (results.length === 0) {
            res.status(404).send('리뷰를 찾을 수 없습니다.');
        } else {
            res.json(results[0]); // 하나만 반환
        }
    });
});
app.get('/get-review/:id', (req, res) => {
    const reviewId = req.params.id;
    const sql = 'SELECT * FROM reviews WHERE id = ?';
    db.query(sql, [reviewId], (err, results) => {
        if (err) {
            console.error('리뷰 조회 오류:', err);
            return res.status(500).send('서버 오류');
        }
        if (results.length === 0) {
            return res.status(404).send('리뷰를 찾을 수 없음');
        }
        res.json(results[0]);
    });
});


app.get('/api/reviews/recent', (req, res) => {
    const sql = "SELECT id, title, rating, foodcategory, regionNames FROM reviews ORDER BY date DESC LIMIT 3";

    db.query(sql, (err, results) => {
        if (err) {
            console.error("리뷰 가져오기 실패:", err);
            return res.status(500).send("서버 오류");
        }
        res.json(results);
    });
});

app.post('/signup', async (req, res) => {
    const { username, password, nickname } = req.body;
    if (!username || !password || !nickname) {
        return res.status(400).send("모든 필드를 입력해주세요");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // saltRounds = 10
        const sql = 'INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)';
        db.query(sql, [username, hashedPassword, nickname], (err, result) => {
            if (err) {
                console.error('회원가입 오류:', err);
                return res.status(500).send('서버 오류');
            }
            res.send('회원가입 완료!');
        });
    } catch (err) {
        console.error('비밀번호 암호화 오류:', err);
        res.status(500).send('암호화 오류');
    }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
    if (err) return res.status(500).send("서버 오류");

    if (results.length === 0) return res.status(400).send("아이디 없음");

    const user = results[0];
    const bcrypt = require('bcrypt');
    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(400).send("비밀번호 틀림");

      const token = jwt.sign({ id: user.id, username: user.username }, 'your_jwt_secret', { expiresIn: '1h' });
      res.cookie('token', token, { httpOnly: true });
      res.send("로그인 성공");
    });
  });
});

// 비밀번호 찾기: 아이디 + 닉네임 → 임시 비밀번호 발급
app.post('/find-password', async (req, res) => {
  const { username, nickname } = req.body;
  const findUserQuery = 'SELECT * FROM users WHERE username = ? AND nickname = ?';

  db.query(findUserQuery, [username, nickname], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).send("일치하는 사용자가 없습니다.");
    }

    // 임시 비밀번호 생성
    const tempPassword = Math.random().toString(36).slice(2, 10); // 예: "af8x4k9z"

    // 해싱
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    // 업데이트
    const updateQuery = 'UPDATE users SET password = ? WHERE username = ?';
    db.query(updateQuery, [hashedPassword, username], (err) => {
      if (err) {
        console.error("비밀번호 업데이트 오류:", err);
        return res.status(500).send("비밀번호 갱신 실패");
      }

      res.send(tempPassword);

    });
  });
});


function verifyToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send("로그인 필요");

  jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
    if (err) return res.status(403).send("토큰 오류");
    req.user = decoded;
    next();
  });
}
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.send("로그아웃 성공");
});
app.get('/check-auth', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ loggedIn: false });

  jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
    if (err) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, user: decoded });
  });
});
app.post('/edit-profile', verifyToken, (req, res) => {
  const { newPassword, nickname } = req.body;
  const hashed = bcrypt.hashSync(newPassword, 10);

  db.query("UPDATE users SET password = ?, nickname = ? WHERE id = ?", [hashed, nickname, req.user.id], err => {
    if (err) return res.status(500).send("업데이트 실패");
    res.send("정보 수정 완료");
  });
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
const db = mysql.createConnection({
    host: '127.0.0.1',  // MariaDB 서버 주소 (로컬)
    user: 'root',    // DB 사용자명
    password: 'jinor1128',  // DB 비밀번호
    database: 'yumspot_db' // 사용할 데이터베이스
});

// 데이터베이스 연결 확인
db.connect(err => {
    if (err) {
        console.error('MariaDB 연결 실패:', err);
        return;
    }
    console.log('MariaDB 연결 성공');
});

// 리뷰 저장 API 엔드포인트
app.post('/submit-review', upload.single('reviewImage'), async (req, res) => {
    if (!req.session.userId) return res.status(401).send("로그인 필요");

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

    db.query(sql, [
        req.session.userId, reviewTitle, reviewDate, restaurantName,
        restaurantAddress, rating, reviewContent, imageUrl,
        foodCategory, regionCategory
    ], (err, result) => {
        if (err) {
            console.error('리뷰 저장 오류:', err);
            return res.status(500).send("저장 실패");
        }
        res.send("리뷰 저장 완료!");
    });
});
//클라우디네리 이미지 저장
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

//리뷰 불러오기
app.get('/review/:id', (req, res) => {
    const reviewId = req.params.id;
    const sql = 'SELECT * FROM reviews WHERE id = ?';

    db.query(sql, [reviewId], (err, results) => {
        if (err) {
            console.error('리뷰 조회 오류:', err);
            res.status(500).send('서버 오류');
        } else if (results.length === 0) {
            res.status(404).send('리뷰 없음');
        } else {
            res.json(results[0]);
        }
    });
});
//내 리뷰 불러오기
app.get("/my-reviews", (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ message: "로그인이 필요합니다" });
    }

    const userId = req.session.user.userId;
    const sql = "SELECT * FROM reviews WHERE user_id = ?";
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error("리뷰 조회 오류:", err);
            return res.status(500).send("서버 오류");
        }
        res.json(results);
    });
});

// 서버 실행
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`서버 실행 중: http://localhost:${PORT}`);
});

setInterval(() => {
    db.ping((err) => {
        if (err) {
            console.error('MariaDB 연결이 끊어졌습니다. 다시 연결 시도 중...');
            db.connect();
        }
    });
}, 60000); // 60초마다 연결 확인

