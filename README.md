# 🍽️ YumSpot

> 사용자가 직접 맛집을 탐색하고 리뷰를 공유할 수 있는 맛집 리뷰 커뮤니티 웹 서비스

YumSpot은 지역과 음식 카테고리를 기준으로 맛집 리뷰를 탐색하고,
사용자가 직접 리뷰를 작성하고 북마크하거나 신고할 수 있는 웹 서비스입니다.

**Node.js + Express**를 기반으로 REST API 서버를 구축하고,
**JWT + HttpOnly Cookie**를 이용한 인증과 사용자/관리자 권한 분리를 구현했습니다.

데이터는 **Supabase의 PostgreSQL 데이터베이스**를 사용하며,
리뷰 이미지 URL은 Supabase Storage와 연동하여 관리할 수 있도록 구성했습니다.

또한 **Render를 이용해 실제 서비스 환경에 배포**하여 로컬 개발부터 Production 환경 배포까지 전체 과정을 경험했습니다.

---

## 🌐 Service

**[YumSpot 바로가기](https://yumspot-n7af.onrender.com)**

> Render의 배포 환경 특성상 일정 시간 요청이 없으면 서버가 비활성화될 수 있으며,
> 최초 요청 시 서버가 다시 활성화되면서 응답까지 시간이 걸릴 수 있습니다.

## 💻 Repository

**[GitHub Repository](https://github.com/dmdjsjdj/yumspot)**

---

# 📌 Project Overview

| 항목             | 내용                                |
| -------------- | --------------------------------- |
| 프로젝트명          | YumSpot                           |
| 프로젝트 유형        | 맛집 리뷰 커뮤니티 웹 서비스                  |
| 개발 목적          | 웹 서비스의 Backend 및 Full-Stack 개발 경험 |
| Backend        | Node.js, Express                  |
| Frontend       | HTML5, CSS3, JavaScript           |
| Database       | PostgreSQL (Supabase)             |
| Authentication | JWT + HttpOnly Cookie             |
| Password       | bcrypt                            |
| Storage        | Supabase Storage                  |
| Deployment     | Render                            |
| Repository     | GitHub                            |

---

# 🎯 프로젝트 목표

YumSpot은 단순히 맛집 정보를 조회하는 서비스를 넘어,
사용자가 직접 맛집 정보를 작성하고 다른 사용자와 공유할 수 있는 **커뮤니티형 웹 서비스**를 목표로 개발했습니다.

특히 다음과 같은 웹 서비스의 기본적인 Backend 구조를 직접 구현하는 데 중점을 두었습니다.

* REST API 설계 및 구현
* 사용자 인증 및 권한 관리
* 데이터베이스 연동
* 리뷰 CRUD
* 리뷰 이미지 관리
* 북마크 기능
* 리뷰 신고 기능
* 관리자 기능
* 실제 서비스 환경 배포

---

# ✨ 주요 기능

## 1. 회원가입 / 로그인

사용자가 계정을 생성하고 로그인하여 서비스를 이용할 수 있도록 인증 기능을 구현했습니다.

### 주요 기능

* 회원가입
* 이메일 중복 확인
* 닉네임 중복 확인
* 이메일 형식 검증
* 비밀번호 유효성 검사
* 비밀번호 bcrypt 해싱
* 로그인
* 로그아웃
* 로그인 상태 확인
* 회원정보 조회
* 회원정보 수정
* 비밀번호 변경

### 인증 방식

로그인 성공 시 서버에서 JWT를 생성하고
이를 **HttpOnly Cookie**에 저장하여 이후 API 요청에서 인증 상태를 확인합니다.

```text
사용자 로그인
      ↓
이메일 / 비밀번호 확인
      ↓
bcrypt 비밀번호 검증
      ↓
JWT 생성
      ↓
HttpOnly Cookie 저장
      ↓
이후 API 요청
      ↓
JWT 검증
      ↓
사용자 인증
```

비밀번호는 평문으로 저장하지 않고 `bcrypt`를 이용하여 해싱한 값을 데이터베이스에 저장합니다.

---

# 2. 리뷰 CRUD

로그인한 사용자가 직접 맛집 리뷰를 작성하고 관리할 수 있도록 구현했습니다.

### 주요 기능

* 리뷰 등록
* 리뷰 목록 조회
* 최근 리뷰 조회
* 리뷰 상세 조회
* 내가 작성한 리뷰 조회
* 리뷰 수정
* 리뷰 삭제
* 평점 등록
* 음식 카테고리 등록
* 지역 정보 등록
* 리뷰 이미지 URL 저장
* 장소 정보 저장

리뷰에는 다음과 같은 데이터를 관리합니다.

```text
Review
 ├── title
 ├── restaurant_name
 ├── address
 ├── rating
 ├── content
 ├── image_url
 ├── image_urls
 ├── foodcategory
 ├── subcategory
 ├── regionnames
 ├── subregion
 ├── place_id
 ├── lat
 ├── lng
 ├── user_id
 └── created_at
```

---

# 3. 지역 / 음식 카테고리별 리뷰 탐색

리뷰를 쉽게 탐색할 수 있도록 지역과 음식 카테고리를 기준으로 필터링할 수 있도록 구현했습니다.

### 지역 필터

```text
지역
 ├── 서울
 ├── 부산
 ├── 대구
 ├── 인천
 ├── 광주
 ├── 대전
 ├── 울산
 ├── 경기도
 └── 강원도
```

### 음식 카테고리

```text
음식
 ├── 한식
 ├── 일식
 ├── 중식
 ├── 양식
 ├── 분식
 ├── 디저트
 └── 패스트푸드
```

대분류뿐만 아니라 `subcategory`, `subregion` 데이터를 이용해 세부적인 분류도 처리할 수 있도록 구성했습니다.

---

# 4. 리뷰 정렬

리뷰 목록을 다양한 기준으로 확인할 수 있도록 정렬 기능을 구현했습니다.

### 지원 정렬

* 최신순
* 오래된순
* 북마크 많은순
* 북마크 적은순

내 리뷰 및 북마크한 리뷰에서는 평점을 기준으로도 정렬할 수 있습니다.

* 평점 높은순
* 평점 낮은순

---

# 5. 북마크

관심 있는 리뷰를 저장해두고 다시 확인할 수 있도록 북마크 기능을 구현했습니다.

### 주요 기능

* 북마크 추가
* 북마크 삭제
* 북마크 상태 확인
* 내가 북마크한 리뷰 조회
* 리뷰별 북마크 수 조회
* 북마크 수 기준 리뷰 정렬

### 북마크 데이터 처리

리뷰 목록을 조회한 뒤 해당 리뷰들의 ID를 기준으로 북마크 데이터를 한 번에 조회하고, 서버에서 리뷰별 북마크 수를 집계하도록 구현했습니다.

```text
리뷰 목록 조회
      ↓
리뷰 ID 목록 생성
      ↓
해당 ID의 Bookmark 조회
      ↓
Review ID 기준 집계
      ↓
각 리뷰에 bookmark_count 추가
      ↓
클라이언트에 응답
```

이를 통해 각 리뷰마다 별도의 북마크 조회 요청을 보내는 대신, 목록에 필요한 북마크 데이터를 묶어서 처리했습니다.

---

# 6. 리뷰 신고

부적절한 리뷰를 신고할 수 있도록 신고 기능을 구현했습니다.

### 신고 기능

* 리뷰 신고
* 신고 상태 확인
* 리뷰별 신고 수 조회
* 동일 사용자의 중복 신고 방지

신고 요청 시 서버에서 로그인한 사용자의 ID와 리뷰 ID를 기준으로 기존 신고 여부를 확인합니다.

```text
신고 요청
    ↓
로그인 여부 확인
    ↓
기존 신고 여부 확인
    ↓
이미 신고한 경우
    → 중복 신고 처리
    ↓
신고하지 않은 경우
    → 신고 데이터 저장
```

---

# 7. 관리자 기능

일반 사용자와 관리자의 권한을 구분하여
관리자만 신고된 리뷰를 관리할 수 있도록 구현했습니다.

### 관리자 기능

* 신고 목록 조회
* 신고된 리뷰 정보 확인
* 신고자 정보 확인
* 리뷰 숨김 처리
* 숨겨진 리뷰 해제
* 신고 데이터 삭제

관리자 API에는 별도의 `requireAdmin` Middleware를 적용하여
관리자 권한이 없는 사용자의 접근을 제한했습니다.

### 권한 구조

```text
USER
 ├── 리뷰 조회
 ├── 리뷰 작성
 ├── 리뷰 수정
 ├── 리뷰 삭제
 ├── 북마크
 └── 리뷰 신고

ADMIN
 ├── USER 기능
 ├── 신고 목록 조회
 ├── 신고 관리
 └── 리뷰 숨김 / 해제
```

---

# 🔐 Authentication & Authorization

## JWT 기반 인증

로그인 성공 시 서버에서 JWT를 생성하고
HttpOnly Cookie에 저장합니다.

이후 서버의 인증 Middleware에서 Cookie의 JWT를 검증하여
현재 로그인한 사용자를 확인합니다.

```text
Client
  │
  │ POST /login
  ▼
Express Server
  │
  │ 사용자 확인
  │ bcrypt 검증
  ▼
JWT 생성
  │
  ▼
HttpOnly Cookie
  │
  │ API Request
  ▼
authMiddleware
  │
  ├── JWT 검증
  │
  └── req.user 설정
```

### 인증 Middleware

서버에서는 요청마다 Cookie에 포함된 JWT를 확인하고
정상적인 토큰인 경우 `req.user`에 사용자 정보를 저장합니다.

이후 로그인 여부가 필요한 API에서는 `requireLogin` Middleware를 사용합니다.

```text
authMiddleware
      ↓
JWT 검증
      ↓
req.user 생성
      ↓
requireLogin
      ↓
로그인 사용자만 접근
```

관리자 기능에는 추가적으로 `requireAdmin` Middleware를 적용합니다.

```text
authMiddleware
      ↓
requireAdmin
      ↓
role === "admin"
      ↓
관리자 API 접근
```

---

# 🔑 비밀번호 보안

회원가입 시 사용자가 입력한 비밀번호를 그대로 데이터베이스에 저장하지 않고 `bcrypt`를 이용하여 해싱합니다.

```text
사용자 비밀번호
      ↓
bcrypt.hash()
      ↓
password_hash
      ↓
Database
```

로그인 시에는 사용자가 입력한 비밀번호와 저장된 해시를 `bcrypt.compare()`로 비교하여 인증합니다.

---

# 🗄️ Database

YumSpot은 **Supabase에서 제공하는 PostgreSQL 데이터베이스**를 사용합니다.

Node.js 서버에서는 `@supabase/supabase-js`를 이용해 데이터베이스에 접근합니다.

```text
Node.js / Express
        │
        │ Supabase Client
        ▼
     Supabase
        │
        ▼
   PostgreSQL
```

서버의 `supabaseClient.js`에서는 환경변수에 저장된 Supabase 정보를 이용해 Client를 생성합니다.

```text
SUPABASE_URL
      +
SUPABASE_ANON_KEY
      ↓
Supabase Client
```

### 주요 데이터

YumSpot에서는 다음과 같은 데이터를 사용합니다.

```text
users
 ├── 사용자 정보
 ├── 로그인 정보
 └── role

reviews
 ├── 리뷰 정보
 ├── 작성자
 ├── 평점
 ├── 카테고리
 ├── 지역
 └── 이미지 URL

bookmarks
 ├── 사용자
 └── 리뷰

reports
 ├── 신고자
 ├── 리뷰
 └── 신고 사유
```

---

# ☁️ Image Storage

리뷰 이미지 데이터는 Supabase Storage와 연동하여 관리합니다.

리뷰 데이터에는 이미지 파일 자체를 저장하기보다는
Storage에 저장된 이미지의 URL을 저장하는 방식으로 구성했습니다.

```text
이미지
  ↓
Supabase Storage
  ↓
Public Image URL
  ↓
reviews.image_url
reviews.image_urls
```

리뷰 데이터에서는 `image_url` 및 `image_urls` 필드를 이용해 이미지 정보를 관리합니다.

---

# 🔌 REST API

## Authentication

| Method | Endpoint                 | Description |
| ------ | ------------------------ | ----------- |
| POST   | `/signup`                | 회원가입        |
| POST   | `/login`                 | 로그인         |
| GET    | `/logout`                | 로그아웃        |
| GET    | `/check-auth`            | 로그인 상태 확인   |
| GET    | `/api/me`                | 회원정보 조회     |
| PUT    | `/api/me`                | 회원정보 수정     |
| POST   | `/password/reset-direct` | 비밀번호 변경     |

---

## Review

| Method | Endpoint              | Description  |
| ------ | --------------------- | ------------ |
| GET    | `/api/reviews`        | 리뷰 목록 조회     |
| GET    | `/api/reviews/recent` | 최근 리뷰 조회     |
| GET    | `/api/reviews/mine`   | 내가 작성한 리뷰 조회 |
| GET    | `/api/reviews/:id`    | 리뷰 상세 조회     |
| POST   | `/api/reviews`        | 리뷰 작성        |
| PUT    | `/api/reviews/:id`    | 리뷰 수정        |
| DELETE | `/api/reviews/:id`    | 리뷰 삭제        |

---

## Bookmark

| Method | Endpoint                   | Description   |
| ------ | -------------------------- | ------------- |
| GET    | `/api/bookmarks/:reviewId` | 북마크 상태 및 수 조회 |
| POST   | `/api/bookmarks/:reviewId` | 북마크 추가        |
| DELETE | `/api/bookmarks/:reviewId` | 북마크 삭제        |
| GET    | `/api/bookmarks/mine`      | 내 북마크 조회      |

---

## Report

| Method | Endpoint                        | Description  |
| ------ | ------------------------------- | ------------ |
| POST   | `/api/reports/:reviewId`        | 리뷰 신고        |
| GET    | `/api/reports/:reviewId/status` | 신고 상태 및 수 조회 |

---

## Admin

| Method | Endpoint                      | Description |
| ------ | ----------------------------- | ----------- |
| GET    | `/api/admin/reports`          | 신고 목록 조회    |
| POST   | `/api/admin/reviews/:id/hide` | 리뷰 숨김 / 해제  |
| DELETE | `/api/admin/reports/:id`      | 신고 삭제       |

관리자 API는 `requireAdmin` Middleware를 통해 관리자 권한을 확인합니다.

---

# 🏗️ Server Structure

현재 Backend는 하나의 Express 서버를 중심으로 구성되어 있습니다.

```text
yumspot/
│
├── public/
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── reviewdetail.html
│   ├── regionreview.html
│   ├── foodreview.html
│   ├── myreview.html
│   ├── mypage.html
│   ├── admin-reports.html
│   └── ...
│
├── server.js
├── supabaseClient.js
├── package.json
├── .env
└── .gitignore
```

### 서버 구성

`server.js`에서 다음과 같은 역할을 담당합니다.

```text
Express
 ├── Static File Serving
 ├── CORS
 ├── Cookie Parser
 ├── Body Parser
 │
 ├── Authentication Middleware
 │
 ├── User API
 ├── Review API
 ├── Bookmark API
 ├── Report API
 └── Admin API
```

---

# 🧩 Middleware

인증 및 권한 처리를 Middleware로 분리했습니다.

### `authMiddleware`

Cookie에 저장된 JWT를 검증하고
정상적인 토큰인 경우 `req.user`에 사용자 정보를 저장합니다.

### `requireLogin`

로그인이 필요한 API에서 사용자의 로그인 여부를 확인합니다.

```text
req.user 없음
     ↓
401 Unauthorized
```

### `requireAdmin`

관리자 전용 API에서 사용자 Role을 확인합니다.

```text
req.user.role !== "admin"
     ↓
403 Forbidden
```

이와 같이 인증과 권한 검사를 Middleware 단계에서 처리하여
각 API에서 동일한 검증 코드를 반복하지 않도록 구성했습니다.

---

# 💡 기술적으로 고민한 부분

## 1. 인증(Authentication)과 권한(Authorization) 분리

단순히 로그인 여부만 확인하는 것과
관리자처럼 특정 기능에 접근할 수 있는 권한을 확인하는 것은 별도의 문제라고 판단했습니다.

```text
Authentication
      ↓
"로그인한 사용자인가?"

Authorization
      ↓
"이 사용자가 이 기능을 사용할 권한이 있는가?"
```

따라서

* `authMiddleware`
* `requireLogin`
* `requireAdmin`

을 분리하여 각각의 역할을 담당하도록 구성했습니다.

---

## 2. JWT를 HttpOnly Cookie에 저장

JWT를 브라우저의 일반적인 저장 공간에 직접 저장하는 대신
HttpOnly Cookie를 이용하여 인증 토큰을 관리했습니다.

```text
Login
  ↓
JWT 생성
  ↓
HttpOnly Cookie
  ↓
Browser
  ↓
API Request
  ↓
Server JWT 검증
```

이를 통해 클라이언트 JavaScript에서 인증 Cookie에 직접 접근하지 않도록 구성했습니다.

---

## 3. 리뷰 작성자 권한 확인

리뷰 수정 및 삭제 요청 시
단순히 로그인 여부만 확인하지 않고 해당 리뷰의 `user_id`와 현재 로그인한 사용자의 ID를 비교합니다.

```text
리뷰 수정 / 삭제
       ↓
로그인 확인
       ↓
리뷰 조회
       ↓
review.user_id
       ↓
req.user.id와 비교
       ↓
일치 → 요청 처리
불일치 → 403
```

이를 통해 다른 사용자의 리뷰를 임의로 수정하거나 삭제하지 못하도록 처리했습니다.

---

## 4. 리뷰 숨김 처리

관리자가 신고된 리뷰를 검토한 후 숨길 수 있도록 `hidden` 값을 이용한 상태 관리 방식을 적용했습니다.

일반적인 리뷰 조회에서는 숨겨진 리뷰를 제외하고,
관리자는 숨겨진 리뷰까지 확인할 수 있도록 조회 조건을 다르게 적용했습니다.

```text
Review
  │
  ├── hidden = false
  │      ↓
  │   일반 사용자에게 노출
  │
  └── hidden = true
         ↓
      일반 사용자에게 비노출
         ↓
      관리자 확인 가능
```

리뷰 상세 조회에서도 리뷰의 작성자와 관리자 여부를 확인하여
숨겨진 리뷰에 대한 접근을 제한했습니다.

---

## 5. 북마크 데이터 집계

리뷰 목록에서 북마크 수를 함께 보여주기 위해
리뷰 ID 목록을 먼저 가져온 뒤 해당 ID에 대한 북마크 데이터를 조회하고 서버에서 집계했습니다.

```text
Reviews
   ↓
[id1, id2, id3]
   ↓
Bookmarks 조회
   ↓
review_id 기준 집계
   ↓
bookmark_count
```

이를 통해 리뷰 목록을 구성할 때 필요한 데이터를 서버에서 함께 가공하여 클라이언트에 전달하도록 했습니다.

---

# 🐛 Troubleshooting

## Render Production 환경에서 서버 비활성화

### 문제

Render의 배포 환경에서는 일정 시간 요청이 없는 경우 서비스가 비활성화될 수 있어, 오랜 시간 접속하지 않은 이후 첫 요청에서 응답까지 시간이 걸릴 수 있었습니다.

### 대응

서비스 상태를 확인할 수 있도록 Health Check용 API를 추가했습니다.

```http
GET /healthz
```

정상적으로 서버가 실행되고 있는 경우 다음과 같이 응답합니다.

```text
ok
```

또한 Supabase 데이터베이스 연결 상태를 확인하기 위한 별도의 API도 구성했습니다.

```http
GET /__db_ping
```

정상적으로 데이터베이스에 접근할 수 있는 경우 데이터베이스 조회 결과를 반환하도록 구성했습니다.

이를 통해

```text
Server 상태
    ↓
/healthz

Database 연결 상태
    ↓
/__db_ping
```

를 각각 확인할 수 있도록 했습니다.

---

# 🌐 Deployment

YumSpot은 **Render**를 이용하여 실제 서비스 환경에 배포했습니다.

### 배포 환경

| 구분             | 사용 기술                 |
| -------------- | --------------------- |
| Hosting        | Render                |
| Server         | Node.js + Express     |
| Database       | PostgreSQL (Supabase) |
| Storage        | Supabase Storage      |
| Authentication | JWT + HttpOnly Cookie |
| Repository     | GitHub                |

### 배포 구조

```text
GitHub
   │
   │ Push
   ▼
Render
   │
   ├── Node.js
   ├── Express
   │
   └── Environment Variables
          │
          ├── PORT
          ├── JWT_SECRET
          ├── COOKIE_NAME
          ├── SUPABASE_URL
          └── SUPABASE_ANON_KEY
```

민감한 인증 정보와 외부 서비스 연결 정보는 소스 코드에 직접 작성하지 않고 환경변수를 통해 관리했습니다.

---

# 🔒 Environment Variables

로컬 환경에서는 `.env` 파일을 이용해 환경변수를 관리합니다.

```env
PORT=3000

SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_key

JWT_SECRET=your_jwt_secret

COOKIE_NAME=ysid

NODE_ENV=development
```

실제 인증 정보와 Secret 값은 Repository에 포함하지 않습니다.

---

# 🛠️ Tech Stack

### Backend

![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat-square\&logo=node.js\&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=flat-square\&logo=express\&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=flat-square\&logo=jsonwebtokens\&logoColor=white)

`Node.js` `Express` `JWT` `bcrypt`

### Frontend

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square\&logo=html5\&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square\&logo=css3\&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square\&logo=javascript\&logoColor=black)

`HTML5` `CSS3` `JavaScript` `Fetch API`

### Database / Storage

![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square\&logo=postgresql\&logoColor=white)

`PostgreSQL` `Supabase` `Supabase Storage`

### Deployment / Development

`Render` `Git` `GitHub`

---

# 🚀 Getting Started

## 1. Clone Repository

```bash
git clone https://github.com/dmdjsjdj/yumspot.git

cd yumspot
```

## 2. Install Dependencies

```bash
npm install
```

## 3. Environment Variables

프로젝트 루트에 `.env` 파일을 생성하고 필요한 환경변수를 설정합니다.

```env
PORT=3000

SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_key

JWT_SECRET=your_jwt_secret

COOKIE_NAME=ysid

NODE_ENV=development
```

## 4. Run Server

```bash
node server.js
```

서버가 정상적으로 실행되면 다음과 같은 형태로 표시됩니다.

```text
Server running http://localhost:3000
```

---

# 📚 프로젝트를 통해 경험한 것

## Backend

* Node.js / Express 기반 서버 구축
* REST API 설계 및 구현
* JWT 기반 인증
* HttpOnly Cookie 인증
* bcrypt 비밀번호 해싱
* Express Middleware 구성
* 사용자 / 관리자 권한 분리
* HTTP Status Code를 이용한 예외 처리

## Database

* PostgreSQL 기반 데이터 관리
* Supabase를 이용한 데이터베이스 연동
* 사용자 / 리뷰 / 북마크 / 신고 데이터 처리
* 관계 데이터를 이용한 리뷰 및 북마크 관리

## Full-Stack

* HTML / CSS / JavaScript 기반 Frontend 구현
* Fetch API를 이용한 Backend API 연동
* 로그인 상태에 따른 화면 처리
* 리뷰 CRUD
* 북마크
* 신고 및 관리자 기능
* 이미지 Storage 연동

## Deployment

* GitHub Repository 관리
* Render를 이용한 Production 배포
* 환경변수를 이용한 Secret 관리
* Supabase와 Render 환경 연동
* 실제 배포 환경에서 API 및 인증 기능 확인

---

# 📝 Retrospective

YumSpot을 개발하면서 단순히 화면을 만드는 것보다
**사용자의 요청이 Frontend에서 Backend를 거쳐 데이터베이스에 저장되고, 다시 결과가 화면에 전달되는 전체 흐름**을 이해하는 데 집중했습니다.

특히 로그인 기능을 구현하면서 JWT를 이용한 인증과 HttpOnly Cookie를 이용한 인증 상태 유지 방식을 경험했고, 관리자 기능을 추가하면서 인증과 권한 검사를 별도로 처리하는 구조를 구성했습니다.

또한 리뷰 CRUD뿐만 아니라 북마크와 신고 기능을 구현하면서 여러 데이터 간의 관계를 고려하여 API를 설계하고 데이터를 조회하는 경험을 할 수 있었습니다.

개발 과정에서는 로컬 환경에서 정상적으로 동작하는 코드가 실제 Production 환경에서는 환경변수, 외부 데이터베이스, Storage, 서버 상태 등의 영향을 받을 수 있다는 점도 경험했습니다.

마지막으로 Render에 실제 서비스를 배포하면서 단순한 로컬 프로젝트를 넘어 **실제 사용자가 접근할 수 있는 웹 서비스의 개발 및 배포 과정**을 경험할 수 있었습니다.

---

# 👤 Developer

### 손예진 · Son Yejin

**Full-Stack Developer**

* GitHub: [dmdjsjdj](https://github.com/dmdjsjdj)
* Project: [YumSpot Repository](https://github.com/dmdjsjdj/yumspot)
* Live: [YumSpot](https://yumspot-n7af.onrender.com)

---

# 📎 Links

### 🌐 Live Service

https://yumspot-n7af.onrender.com

### 💻 GitHub Repository

https://github.com/dmdjsjdj/yumspot
