<script type="module">
  import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
  const SUPABASE_URL = 'https://syklxwvuubivgunkyrfa.supabase.co';
  const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN5a2x4d3Z1dWJpdmd1bmt5cmZhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDkzMDg5MDQsImV4cCI6MjA2NDg4NDkwNH0.2EL5V5QCOZcBVDuuFc5yOWTt23WfThDYWqfAeL50qxg'; // anon key는 공개 가능

  window.sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
</script>
