-- =============================================
-- RLS & Security — Connect Inglês VIP
-- Execute APÓS o migration.sql
-- =============================================

-- 1. HABILITAR RLS EM TODAS AS TABELAS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE schools ENABLE ROW LEVEL SECURITY;
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE classes ENABLE ROW LEVEL SECURITY;
ALTER TABLE boletos ENABLE ROW LEVEL SECURITY;
ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;

-- 2. POLICIES — acesso via anon key (sem auth do Supabase)
-- Como o sistema usa login por tabela (sem Supabase Auth),
-- o RLS com anon key precisa permitir acesso para o app funcionar.
-- A proteção real de roles é feita no frontend.
-- Para segurança máxima, migrar para Supabase Auth no futuro.

-- USERS: leitura sem password_hash, escrita apenas para admins
-- NOTA: Para bloquear password_hash via RLS seria necessário usar
-- uma view ou function. Recomendação abaixo.

-- View segura para consulta de usuários (sem password_hash)
CREATE OR REPLACE VIEW users_safe AS
SELECT id, name, email, role, status, address, created_at
FROM users;

-- Policies permissivas (necessário enquanto usar anon key sem auth)
DO $$ BEGIN
  -- Drop existing policies to avoid conflicts
  DROP POLICY IF EXISTS "anon_all_users" ON users;
  DROP POLICY IF EXISTS "anon_all_schools" ON schools;
  DROP POLICY IF EXISTS "anon_all_teachers" ON teachers;
  DROP POLICY IF EXISTS "anon_all_students" ON students;
  DROP POLICY IF EXISTS "anon_all_classes" ON classes;
  DROP POLICY IF EXISTS "anon_all_boletos" ON boletos;
  DROP POLICY IF EXISTS "anon_all_student_contacts" ON student_contacts;
  DROP POLICY IF EXISTS "anon_all_attendance" ON attendance;
  DROP POLICY IF EXISTS "Allow all for authenticated" ON student_contacts;
  DROP POLICY IF EXISTS "Allow all for authenticated" ON attendance;
END $$;

CREATE POLICY "anon_all_users" ON users FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_all_schools" ON schools FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_all_teachers" ON teachers FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_all_students" ON students FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_all_classes" ON classes FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_all_boletos" ON boletos FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_all_student_contacts" ON student_contacts FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_all_attendance" ON attendance FOR ALL USING (true) WITH CHECK (true);

-- 3. CONSTRAINTS DE INTEGRIDADE

-- Boleto único por aluno/mês/ano (se ainda não existir)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'boletos_unique_student_mes_ano'
  ) THEN
    ALTER TABLE boletos ADD CONSTRAINT boletos_unique_student_mes_ano
      UNIQUE (student_id, mes_referencia, ano_referencia);
  END IF;
END $$;

-- Status de boleto válido
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'boletos_status_check'
  ) THEN
    ALTER TABLE boletos ADD CONSTRAINT boletos_status_check
      CHECK (status IN ('aberto', 'pago'));
  END IF;
END $$;

-- Role de usuário válido
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_role_check
      CHECK (role IN ('super_admin', 'admin', 'direcao', 'financeiro', 'secretaria', 'escola', 'escola_admin', 'professor'));
  END IF;
END $$;

-- Student type válido
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'students_type_check'
  ) THEN
    ALTER TABLE students ADD CONSTRAINT students_type_check
      CHECK (student_type IN ('Regular', 'VIP Online', 'VIP Presencial'));
  END IF;
END $$;

-- VIP status válido
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'students_vip_status_check'
  ) THEN
    ALTER TABLE students ADD CONSTRAINT students_vip_status_check
      CHECK (vip_status IS NULL OR vip_status IN ('Ativo', 'Pausado', 'Em risco', 'Cancelado'));
  END IF;
END $$;

-- Attendance status válido
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'attendance_status_check'
  ) THEN
    ALTER TABLE attendance ADD CONSTRAINT attendance_status_check
      CHECK (status IN ('pendente', 'presente', 'ausente', 'justificado'));
  END IF;
END $$;

-- 4. STORAGE — bucket comprovantes
-- Criar bucket se não existir (executar manualmente no dashboard se falhar):
-- INSERT INTO storage.buckets (id, name, public) VALUES ('comprovantes', 'comprovantes', true)
-- ON CONFLICT (id) DO NOTHING;

-- Policy de storage para comprovantes (acesso público leitura)
-- Executar no SQL Editor:
-- CREATE POLICY "Public read comprovantes" ON storage.objects
--   FOR SELECT USING (bucket_id = 'comprovantes');
-- CREATE POLICY "Anon upload comprovantes" ON storage.objects
--   FOR INSERT WITH CHECK (bucket_id = 'comprovantes');

-- =============================================
-- RECOMENDAÇÕES DE SEGURANÇA FUTURA:
-- 1. Migrar para Supabase Auth (email/password)
-- 2. Usar RLS baseado em auth.uid() e auth.jwt()
-- 3. Criar Edge Function para login que valide senha com bcrypt
-- 4. Remover password_hash das queries do frontend
-- 5. Usar a view users_safe no lugar de select direto na tabela users
-- =============================================
