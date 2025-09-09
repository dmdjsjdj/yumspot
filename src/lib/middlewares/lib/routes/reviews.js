import express from 'express';
import prisma from '../lib/prisma.js';
import { upload } from '../middlewares/upload.js';
import { uploadToStorage, getPublicUrl } from '../lib/storage.js';
import { v4 as uuidv4 } from 'uuid';

const router = express.Router();

// 라우터 헬스
router.get('/health', async (req, res) => {
  try { await prisma.$queryRaw`SELECT 1`; res.json({ ok: true }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/reviews?region=서울&food=한식&sort=recent|rating_desc|rating_asc
router.get('/', async (req, res) => {
  const { region, food, sort } = req.query;

  const where = {};
  if (region) where.regionnames = region;
  if (food) where.foodcategory = food;

  let orderBy = [{ created_at: 'desc' }];
  if (sort === 'rating_desc') orderBy = [{ rating: 'desc' }, { created_at: 'desc' }];
  if (sort === 'rating_asc')  orderBy = [{ rating: 'asc' }, { created_at: 'desc' }];

  try {
    const rows = await prisma.reviews.findMany({ where, orderBy, take: 50 });
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/reviews (multipart/form-data)
router.post('/', upload.single('image'), async (req, res) => {
  try {
    let image_url = null;

    if (req.file) {
      const id  = uuidv4();
      const ext = (req.file.mimetype?.split('/')[1]) || 'jpg';
      const storagePath = `reviews/${id}.${ext}`;
      await uploadToStorage(req.file, { path: storagePath });
      image_url = getPublicUrl(storagePath);
    }

    const data = {
      username: req.body.username,
      title: req.body.title,
      restaurant_name: req.body.restaurant_name,
      address: req.body.address || null,
      rating: req.body.rating ? Number(req.body.rating) : null,
      content: req.body.content || null,
      foodcategory: req.body.foodcategory || null,
      regionnames: req.body.regionnames || null,
      image_url
    };

    const row = await prisma.reviews.create({ data });
    res.status(201).json(row);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

export default router;
