-- =====================================================================
-- Connect Inglês VIP — SQL de Segurança
-- =====================================================================
--
-- DIAGNÓSTICO DE SEGURANÇA (leia antes de executar):
--
-- O sistema atual NÃO TEM segurança real no banco de dados.
--
-- Motivo: o login é feito por consulta direta na tabela `users`,
-- sem usar Supabase Auth. O frontend usa a anon key (pública).
-- Qualquer pessoa que inspecionar o HTML do site consegue:
--   1. Copiar a SUPABASE_URL e SUPABASE_KEY do código-fonte
--   2. Abrir o Supabase JS client no console do navegador
--   3. Executar sb.from('users').select('*') e ver TODOS os dados
--   4. Executar sb.from('boletos').select('*') e ver TODO o financeiro
--   5. Inserir, atualizar ou deletar qualquer registro
--
-- Esconder botões no frontend NÃO protege dados.
-- Policies com USING(true) são o mesmo que não ter RLS.
--
-- Para dados financeiros e pessoais de alunos de uma escola real,
-- isso é INACEITÁVEL em produção.
--
-- Este arquivo está dividido em:
--   PARTE A: Solução segura com Supabase Auth (RECOMENDADA)
--   PARTE B: Paliativo temporário para desenvolvimento (INSEGURO)
--   PARTE C: Constraints de integridade (sempre executar)
--
-- =====================================================================


-- #####################################################################
-- PARTE A — SOLUÇÃO SEGURA COM SUPABASE AUTH
-- #####################################################################
--
-- COMO FUNCIONA:
-- 1. Cada usuário do sistema é criado no Supabase Auth (email+senha)
-- 2. Uma tabela `profiles` vincula auth.users ao role do sistema
-- 3. Helpers SQL (is_admin, get_role, etc.) leem o role do usuário logado
-- 4. Policies usam auth.uid() — só funcionam para usuários autenticados
-- 5. A anon key NÃO consegue ler nenhuma tabela sensível
-- 6. O frontend usa supabase.auth.signInWithPassword() no login
--
-- PARA ATIVAR:
-- 1. Execute este SQL no Supabase
-- 2. Crie os usuários via Supabase Dashboard > Authentication > Users
-- 3. Insira os profiles com o role correto
-- 4. Altere o frontend para usar supabase.auth.signInWithPassword()
-- 5. Remova o login por tabela `users`
-- #####################################################################

-- ========== TABELA PROFILES ==========

CREATE TABLE IF NOT EXISTS profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  email text NOT NULL,
  role text NOT NULL DEFAULT 'secretaria',
  status boolean NOT NULL DEFAULT true,
  address text,
  created_at timestamptz DEFAULT now(),

  CONSTRAINT profiles_role_check CHECK (
    role IN ('super_admin', 'direcao', 'financeiro', 'secretaria', 'professor')
  )
);

CREATE INDEX IF NOT EXISTS idx_profiles_role ON profiles(role);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Trigger: criar profile automaticamente ao criar user no Auth
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO profiles (id, name, email, role)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'role', 'secretaria')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();


-- ========== HELPERS SQL ==========

-- Retorna o role do usuário logado
CREATE OR REPLACE FUNCTION get_my_role()
RETURNS text AS $$
  SELECT role FROM profiles WHERE id = auth.uid();
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- Verifica se é admin (super_admin ou direcao)
CREATE OR REPLACE FUNCTION is_admin()
RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE id = auth.uid()
    AND role IN ('super_admin', 'direcao')
    AND status = true
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- Verifica se pode ver financeiro global
CREATE OR REPLACE FUNCTION can_view_finance()
RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE id = auth.uid()
    AND role IN ('super_admin', 'direcao', 'financeiro')
    AND status = true
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- Verifica se tem determinado role
CREATE OR REPLACE FUNCTION has_role(allowed_roles text[])
RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE id = auth.uid()
    AND role = ANY(allowed_roles)
    AND status = true
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER;


-- ========== POLICIES COM auth.uid() ==========

-- ---------- profiles ----------
CREATE POLICY "profiles_select_own"
  ON profiles FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "profiles_update_own"
  ON profiles FOR UPDATE
  USING (id = auth.uid() OR is_admin());

CREATE POLICY "profiles_insert_admin"
  ON profiles FOR INSERT
  WITH CHECK (is_admin());

CREATE POLICY "profiles_delete_admin"
  ON profiles FOR DELETE
  USING (is_admin());

-- ---------- schools ----------
ALTER TABLE schools ENABLE ROW LEVEL SECURITY;

CREATE POLICY "schools_select"
  ON schools FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "schools_insert"
  ON schools FOR INSERT
  WITH CHECK (is_admin());

CREATE POLICY "schools_update"
  ON schools FOR UPDATE
  USING (is_admin());

CREATE POLICY "schools_delete"
  ON schools FOR DELETE
  USING (is_admin());

-- ---------- teachers ----------
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;

CREATE POLICY "teachers_select"
  ON teachers FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "teachers_insert"
  ON teachers FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','secretaria']));

CREATE POLICY "teachers_update"
  ON teachers FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','secretaria']));

CREATE POLICY "teachers_delete"
  ON teachers FOR DELETE
  USING (is_admin());

-- ---------- students ----------
ALTER TABLE students ENABLE ROW LEVEL SECURITY;

CREATE POLICY "students_select"
  ON students FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "students_insert"
  ON students FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "students_update"
  ON students FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "students_delete"
  ON students FOR DELETE
  USING (is_admin());

-- ---------- classes ----------
ALTER TABLE classes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "classes_select"
  ON classes FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "classes_insert"
  ON classes FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','secretaria']));

CREATE POLICY "classes_update"
  ON classes FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','secretaria']));

CREATE POLICY "classes_delete"
  ON classes FOR DELETE
  USING (is_admin());

-- ---------- boletos ----------
ALTER TABLE boletos ENABLE ROW LEVEL SECURITY;

-- Secretaria pode ver boletos (precisa para operar cobranças por aluno),
-- mas NÃO pode ver views/queries agregadas de faturamento global.
-- A proteção de totais globais é feita via view restrita (abaixo).
CREATE POLICY "boletos_select"
  ON boletos FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "boletos_insert"
  ON boletos FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "boletos_update"
  ON boletos FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "boletos_delete"
  ON boletos FOR DELETE
  USING (has_role(ARRAY['super_admin','direcao','financeiro']));

-- ---------- student_contacts ----------
ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "contacts_select"
  ON student_contacts FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "contacts_insert"
  ON student_contacts FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "contacts_update"
  ON student_contacts FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "contacts_delete"
  ON student_contacts FOR DELETE
  USING (is_admin());

-- ---------- attendance ----------
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;

CREATE POLICY "attendance_select"
  ON attendance FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "attendance_insert"
  ON attendance FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','secretaria','professor']));

CREATE POLICY "attendance_update"
  ON attendance FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','secretaria','professor']));

CREATE POLICY "attendance_delete"
  ON attendance FOR DELETE
  USING (is_admin());


-- ========== BLOQUEIO DE FATURAMENTO GLOBAL PARA SECRETARIA ==========

-- View que só retorna dados para quem pode ver financeiro global.
-- Secretaria recebe zero linhas.
-- O frontend deve usar esta view no lugar de resumo_financeiro_aluno
-- para os cards de faturamento total.
CREATE OR REPLACE VIEW resumo_financeiro_global AS
SELECT *
FROM resumo_financeiro_aluno
WHERE can_view_finance();

-- Revogar acesso direto à view existente de resumo se possível:
-- REVOKE SELECT ON resumo_financeiro_aluno FROM anon;
-- REVOKE SELECT ON resumo_financeiro_aluno FROM authenticated;
-- GRANT SELECT ON resumo_financeiro_global TO authenticated;


-- ========== STORAGE — BUCKET COMPROVANTES ==========

INSERT INTO storage.buckets (id, name, public)
VALUES ('comprovantes', 'comprovantes', false)
ON CONFLICT (id) DO NOTHING;

-- Leitura: apenas usuários autenticados
CREATE POLICY "comprovantes_select"
  ON storage.objects FOR SELECT
  USING (bucket_id = 'comprovantes' AND auth.uid() IS NOT NULL);

-- Upload: apenas roles que operam financeiro
CREATE POLICY "comprovantes_insert"
  ON storage.objects FOR INSERT
  WITH CHECK (
    bucket_id = 'comprovantes'
    AND has_role(ARRAY['super_admin','direcao','financeiro','secretaria'])
  );

-- Delete: apenas admin
CREATE POLICY "comprovantes_delete"
  ON storage.objects FOR DELETE
  USING (bucket_id = 'comprovantes' AND is_admin());


-- ========== TABELA USERS LEGADA ==========

-- Se for migrar para Supabase Auth, a tabela `users` atual vira legado.
-- Durante a migração, manter ambas.
-- Após migração completa, remover `users` e usar `profiles`.

-- Enquanto `users` existir, bloquear acesso anon:
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Nenhuma policy para anon = anon não lê nada.
-- Apenas o service_role (backend) acessa.
-- Se o frontend ainda precisar da tabela `users` para login,
-- a migração para Auth ainda não está completa.



-- #####################################################################
-- PARTE B — PALIATIVO TEMPORÁRIO PARA DESENVOLVIMENTO
-- #####################################################################
--
-- ⚠️  ATENÇÃO: ISTO NÃO É SEGURANÇA ⚠️
--
-- Use APENAS durante o desenvolvimento local enquanto migra para Auth.
-- NÃO use em produção com dados reais de alunos.
--
-- O que isto faz:
-- - Habilita RLS mas permite tudo via anon (para o app funcionar)
-- - Bloqueia password_hash via view (proteção mínima)
-- - O frontend continua usando login por tabela
--
-- O que isto NÃO protege:
-- - Qualquer pessoa com a anon key acessa todos os dados
-- - Não há distinção de role no banco — tudo é frontend
-- - Dados financeiros e pessoais ficam expostos
--
-- PARA USAR (em vez da Parte A):
-- Comente a Parte A inteira e descomente o bloco abaixo.
-- #####################################################################

/*
-- === INÍCIO DO BLOCO TEMPORÁRIO (descomentar para usar) ===

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE schools ENABLE ROW LEVEL SECURITY;
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE classes ENABLE ROW LEVEL SECURITY;
ALTER TABLE boletos ENABLE ROW LEVEL SECURITY;
ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;

-- View sem password_hash (proteção mínima)
CREATE OR REPLACE VIEW users_safe AS
SELECT id, name, email, role, status, address, created_at
FROM users;

-- ⚠️ Policies abertas — INSEGURO, apenas para desenvolvimento
DO $$ BEGIN
  DROP POLICY IF EXISTS "temp_dev_users" ON users;
  DROP POLICY IF EXISTS "temp_dev_schools" ON schools;
  DROP POLICY IF EXISTS "temp_dev_teachers" ON teachers;
  DROP POLICY IF EXISTS "temp_dev_students" ON students;
  DROP POLICY IF EXISTS "temp_dev_classes" ON classes;
  DROP POLICY IF EXISTS "temp_dev_boletos" ON boletos;
  DROP POLICY IF EXISTS "temp_dev_contacts" ON student_contacts;
  DROP POLICY IF EXISTS "temp_dev_attendance" ON attendance;
END $$;

-- Leitura: permitir para anon (necessário para o app funcionar)
-- Escrita: permitir para anon (o app faz insert/update/delete direto)
-- ISTO É INSEGURO. Todo mundo com a key pode ler e escrever tudo.
CREATE POLICY "temp_dev_users" ON users
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_schools" ON schools
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_teachers" ON teachers
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_students" ON students
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_classes" ON classes
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_boletos" ON boletos
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_contacts" ON student_contacts
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_attendance" ON attendance
  FOR ALL USING (true) WITH CHECK (true);

-- === FIM DO BLOCO TEMPORÁRIO ===
*/



-- #####################################################################
-- PARTE C — CONSTRAINTS DE INTEGRIDADE (SEMPRE EXECUTAR)
-- #####################################################################
-- Estas constraints protegem dados independente de RLS.
-- Execute esta parte em qualquer cenário.
-- #####################################################################

-- Boleto único por aluno/mês/ano
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

-- Role de usuário válido (tabela legada)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_role_check
      CHECK (role IN (
        'super_admin', 'admin', 'direcao', 'financeiro',
        'secretaria', 'escola', 'escola_admin', 'professor'
      ));
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
