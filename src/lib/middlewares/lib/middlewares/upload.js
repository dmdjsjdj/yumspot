import multer from 'multer';
const storage = multer.memoryStorage(); // 디스크 대신 메모리 → 곧바로 클라우드 업로드
export const upload = multer({ storage });
