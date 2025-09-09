import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // 서버 전용 키 (절대 프론트에 노출 금지)
);

export async function uploadToStorage(file, { bucket = 'reviews', path }) {
  const { data, error } = await supabase.storage
    .from(bucket)
    .upload(path, file.buffer, { contentType: file.mimetype, upsert: false });
  if (error) throw error;
  return data; // { path }
}

export function getPublicUrl(path, bucket = 'reviews') {
  const { data } = supabase.storage.from(bucket).getPublicUrl(path);
  return data.publicUrl;
}
