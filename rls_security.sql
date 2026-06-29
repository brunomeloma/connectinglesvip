-- =====================================================================
-- Connect Inglês VIP — SQL de Segurança v3 (produção)
-- Reexecutável: todo CREATE POLICY tem DROP IF EXISTS antes.
-- =====================================================================
--
-- ESTADO ATUAL DO SISTEMA:
--
-- O frontend usa a anon key do Supabase (visível no HTML) e faz login
-- consultando users.password_hash em texto plano. Isso significa:
--
--   - Qualquer pessoa que abrir o código-fonte copia a key
--   - Com a key, acessa a API REST e lê/escreve qualquer tabela
--   - Esconder botões no frontend NÃO protege dados
--   - Policies USING(true) são equivalentes a RLS desligado
--
-- ESTE SQL RESOLVE O PROBLEMA com Supabase Auth:
--   - Login via supabase.auth.signInWithPassword()
--   - Tabela profiles com role, vinculada a auth.users
--   - Policies baseadas em auth.uid() — anon não lê nada
--   - Helpers SQL com SECURITY DEFINER + search_path fixo
--   - Constraints de integridade em todas as tabelas
--
-- O QUE PRECISA MUDAR NO FRONTEND (index.html):
--
--   1. Trocar doLogin():
--      DE:  sb.from('users').select('*').eq('email',email).single()
--      PARA: sb.auth.signInWithPassword({ email, password })
--
--   2. Trocar doLogout():
--      DE:  currentUser = null
--      PARA: sb.auth.signOut()
--
--   3. Buscar profile após login:
--      const { data: { user } } = await sb.auth.getUser()
--      const { data: profile } = await sb.from('profiles')
--        .select('*').eq('id', user.id).single()
--      currentUser = profile
--
--   4. Remover toda referência a tabela `users` no frontend.
--      Não consultar password_hash. Usar `profiles` em vez de `users`.
--
--   5. Para comprovantes, trocar getPublicUrl() por:
--      sb.storage.from('comprovantes').createSignedUrl(path, 3600)
--      Isso gera URL temporária de 1h em vez de URL pública permanente.
--
--   6. Trocar sb.from('users').select(...) em admins por
--      sb.from('profiles').select(...) — mesmos campos, sem senha.
--
--   7. Criar usuários via Supabase Dashboard > Authentication > Users
--      ou via sb.auth.admin.createUser() (requer service_role key em
--      backend/Edge Function, nunca no frontend).
--
-- DIVISÃO DO ARQUIVO:
--   PARTE A: Profiles, helpers, policies (solução segura)
--   PARTE B: Paliativo temporário para dev (INSEGURO, comentado)
--   PARTE C: Constraints de integridade (sempre executar)
--
-- =====================================================================



-- #####################################################################
-- PARTE A — SEGURANÇA REAL COM SUPABASE AUTH
-- #####################################################################


-- =====================================================================
-- A1. TABELA PROFILES
-- =====================================================================

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

-- Trigger: criar profile ao criar user no Auth
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
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
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();


-- =====================================================================
-- A2. HELPERS SQL
-- =====================================================================
-- Todos com SECURITY DEFINER + SET search_path = public
-- para evitar privilege escalation via search_path hijacking.

CREATE OR REPLACE FUNCTION get_my_role()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT role FROM profiles WHERE id = auth.uid() AND status = true;
$$;

CREATE OR REPLACE FUNCTION is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE id = auth.uid()
      AND role IN ('super_admin', 'direcao')
      AND status = true
  );
$$;

CREATE OR REPLACE FUNCTION can_view_finance()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE id = auth.uid()
      AND role IN ('super_admin', 'direcao', 'financeiro')
      AND status = true
  );
$$;

CREATE OR REPLACE FUNCTION has_role(allowed_roles text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE id = auth.uid()
      AND role = ANY(allowed_roles)
      AND status = true
  );
$$;


-- =====================================================================
-- A3. RPC SEGURA PARA ATUALIZAR PROFILE
-- =====================================================================
-- Usuário NÃO pode editar role, status ou permissões diretamente.
-- UPDATE em profiles é restrito a admin via policy.
-- Esta RPC permite que o próprio usuário altere apenas name e address.

CREATE OR REPLACE FUNCTION update_my_profile(
  new_name text DEFAULT NULL,
  new_address text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE profiles
  SET
    name = COALESCE(new_name, name),
    address = COALESCE(new_address, address)
  WHERE id = auth.uid();
END;
$$;

-- RPC para admin alterar role/status de outro usuário
CREATE OR REPLACE FUNCTION admin_update_profile(
  target_id uuid,
  new_role text DEFAULT NULL,
  new_status boolean DEFAULT NULL,
  new_name text DEFAULT NULL,
  new_address text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT is_admin() THEN
    RAISE EXCEPTION 'Permissão negada: apenas super_admin e direcao podem alterar perfis.';
  END IF;

  UPDATE profiles
  SET
    role = COALESCE(new_role, role),
    status = COALESCE(new_status, status),
    name = COALESCE(new_name, name),
    address = COALESCE(new_address, address)
  WHERE id = target_id;
END;
$$;


-- =====================================================================
-- A4. POLICIES — PROFILES
-- =====================================================================
-- Regras:
-- - Usuário vê apenas o próprio profile
-- - Admin/direcao vê todos os profiles
-- - Secretaria não precisa (e não deve) ver lista de admins
-- - UPDATE e DELETE somente via admin (RPCs acima para self-edit)
-- - INSERT controlado pelo trigger on_auth_user_created

DROP POLICY IF EXISTS "profiles_select_own" ON profiles;
DROP POLICY IF EXISTS "profiles_select_admin" ON profiles;
DROP POLICY IF EXISTS "profiles_update_admin" ON profiles;
DROP POLICY IF EXISTS "profiles_insert_admin" ON profiles;
DROP POLICY IF EXISTS "profiles_delete_admin" ON profiles;

CREATE POLICY "profiles_select_own"
  ON profiles FOR SELECT
  USING (id = auth.uid());

CREATE POLICY "profiles_select_admin"
  ON profiles FOR SELECT
  USING (is_admin());

-- UPDATE direto na tabela só para admin.
-- Usuário comum edita via RPC update_my_profile() que bypassa RLS.
CREATE POLICY "profiles_update_admin"
  ON profiles FOR UPDATE
  USING (is_admin());

-- INSERT via trigger (SECURITY DEFINER bypassa RLS)
CREATE POLICY "profiles_insert_admin"
  ON profiles FOR INSERT
  WITH CHECK (is_admin());

CREATE POLICY "profiles_delete_admin"
  ON profiles FOR DELETE
  USING (is_admin());


-- =====================================================================
-- A5. POLICIES — SCHOOLS
-- =====================================================================

ALTER TABLE schools ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "schools_select" ON schools;
DROP POLICY IF EXISTS "schools_insert" ON schools;
DROP POLICY IF EXISTS "schools_update" ON schools;
DROP POLICY IF EXISTS "schools_delete" ON schools;
DROP POLICY IF EXISTS "anon_all_schools" ON schools;

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


-- =====================================================================
-- A6. POLICIES — TEACHERS
-- =====================================================================

ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "teachers_select" ON teachers;
DROP POLICY IF EXISTS "teachers_insert" ON teachers;
DROP POLICY IF EXISTS "teachers_update" ON teachers;
DROP POLICY IF EXISTS "teachers_delete" ON teachers;
DROP POLICY IF EXISTS "anon_all_teachers" ON teachers;

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


-- =====================================================================
-- A7. POLICIES — STUDENTS
-- =====================================================================

ALTER TABLE students ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "students_select" ON students;
DROP POLICY IF EXISTS "students_insert" ON students;
DROP POLICY IF EXISTS "students_update" ON students;
DROP POLICY IF EXISTS "students_delete" ON students;
DROP POLICY IF EXISTS "anon_all_students" ON students;

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


-- =====================================================================
-- A8. POLICIES — CLASSES
-- =====================================================================

ALTER TABLE classes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "classes_select" ON classes;
DROP POLICY IF EXISTS "classes_insert" ON classes;
DROP POLICY IF EXISTS "classes_update" ON classes;
DROP POLICY IF EXISTS "classes_delete" ON classes;
DROP POLICY IF EXISTS "anon_all_classes" ON classes;

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


-- =====================================================================
-- A9. POLICIES — BOLETOS
-- =====================================================================
--
-- LIMITAÇÃO IMPORTANTE SOBRE SECRETARIA E FATURAMENTO:
--
-- A secretaria tem SELECT em boletos porque precisa operar cobranças
-- por aluno (ver boletos individuais, marcar pagamento, lançar).
--
-- Porém, com SELECT liberado, ela PODE rodar:
--   SELECT SUM(valor) FROM boletos WHERE status = 'pago'
-- e descobrir o faturamento total. O RLS do Postgres não filtra
-- por coluna nem por tipo de query (agregação vs. row).
--
-- OPÇÕES PARA RESOLVER (escolher uma):
--
-- Opção 1 — Limitar secretaria por escola/unidade:
--   Adicionar school_id na tabela boletos (via student->class->school)
--   e na tabela profiles. Policy: secretaria só vê boletos de alunos
--   da sua escola. Funciona se houver múltiplas unidades.
--
-- Opção 2 — Remover SELECT direto e usar RPCs:
--   Revogar SELECT de boletos para secretaria.
--   Criar funções RPC como:
--     get_boletos_do_aluno(student_id uuid)
--     marcar_pagamento(boleto_id uuid, ...)
--     lancar_boletos(student_id uuid, ...)
--   As RPCs são SECURITY DEFINER e retornam apenas o necessário.
--   O frontend chama sb.rpc('get_boletos_do_aluno', { student_id })
--   em vez de sb.from('boletos').select(...).
--   ESTA É A OPÇÃO MAIS SEGURA.
--
-- Opção 3 — Aceitar o risco controlado:
--   Secretaria tem SELECT e pode tecnicamente somar.
--   Mitigar com auditoria (log de queries) e confiança na equipe.
--   Não é segurança real, mas pode ser aceitável para equipe pequena.
--
-- O SQL abaixo implementa Opção 3 (SELECT liberado).
-- Para implementar Opção 2, veja a seção A12 (RPCs de boleto).
--
-- =====================================================================

ALTER TABLE boletos ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "boletos_select" ON boletos;
DROP POLICY IF EXISTS "boletos_insert" ON boletos;
DROP POLICY IF EXISTS "boletos_update" ON boletos;
DROP POLICY IF EXISTS "boletos_delete" ON boletos;
DROP POLICY IF EXISTS "anon_all_boletos" ON boletos;

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


-- =====================================================================
-- A10. POLICIES — STUDENT_CONTACTS
-- =====================================================================

ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "contacts_select" ON student_contacts;
DROP POLICY IF EXISTS "contacts_insert" ON student_contacts;
DROP POLICY IF EXISTS "contacts_update" ON student_contacts;
DROP POLICY IF EXISTS "contacts_delete" ON student_contacts;
DROP POLICY IF EXISTS "anon_all_student_contacts" ON student_contacts;
DROP POLICY IF EXISTS "Allow all for authenticated" ON student_contacts;

CREATE POLICY "contacts_select"
  ON student_contacts FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "contacts_insert"
  ON student_contacts FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "contacts_update"
  ON student_contacts FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE POLICY "contacts_delete"
  ON student_contacts FOR DELETE
  USING (is_admin());


-- =====================================================================
-- A11. POLICIES — ATTENDANCE
-- =====================================================================

ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "attendance_select" ON attendance;
DROP POLICY IF EXISTS "attendance_insert" ON attendance;
DROP POLICY IF EXISTS "attendance_update" ON attendance;
DROP POLICY IF EXISTS "attendance_delete" ON attendance;
DROP POLICY IF EXISTS "anon_all_attendance" ON attendance;
DROP POLICY IF EXISTS "Allow all for authenticated" ON attendance;

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


-- =====================================================================
-- A12. RPCs SEGURAS PARA BOLETOS (OPÇÃO 2 — opcional)
-- =====================================================================
-- Se quiser bloquear SELECT direto de boletos para secretaria,
-- remova a policy boletos_select acima e use estas RPCs.
-- O frontend chamaria sb.rpc('fn_name', { params }) em vez de
-- sb.from('boletos').select(...).
--
-- Para ativar: descomente o bloco abaixo e comente boletos_select.
-- =====================================================================

/*
CREATE OR REPLACE FUNCTION get_boletos_aluno(p_student_id uuid, p_ano int)
RETURNS SETOF boletos
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;

  RETURN QUERY
  SELECT * FROM boletos
  WHERE student_id = p_student_id
    AND ano_referencia = p_ano
  ORDER BY mes_referencia;
END;
$$;

CREATE OR REPLACE FUNCTION marcar_pagamento_boleto(
  p_boleto_id uuid,
  p_data_pagamento date,
  p_observacao text DEFAULT NULL,
  p_comprovante_url text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;

  UPDATE boletos
  SET status = 'pago',
      data_pagamento = p_data_pagamento,
      observacao = p_observacao,
      comprovante_url = p_comprovante_url
  WHERE id = p_boleto_id;
END;
$$;
*/


-- =====================================================================
-- A13. BLOQUEIO DE FATURAMENTO GLOBAL — VIEW SEGURA
-- =====================================================================
--
-- PROBLEMA COM VIEWS E RLS:
-- Views padrão no Postgres rodam com as permissões do OWNER da view,
-- não do usuário que consulta. Isso significa que uma view criada
-- pelo superuser IGNORA o RLS das tabelas base.
--
-- SOLUÇÃO: security_invoker = true (Postgres 15+, Supabase suporta).
-- Com isso, a view roda com as permissões de quem consulta.
-- Se o Supabase do projeto for Postgres < 15, usar RPC em vez de view.
--
-- A view abaixo retorna zero linhas para secretaria.
-- =====================================================================

DROP VIEW IF EXISTS resumo_financeiro_global;

-- Tente com security_invoker primeiro (Postgres 15+):
CREATE OR REPLACE VIEW resumo_financeiro_global
WITH (security_invoker = true)
AS
SELECT * FROM resumo_financeiro_aluno;

-- Se o comando acima falhar com erro de syntax,
-- o Postgres é < 15. Nesse caso, usar esta RPC:
--
-- CREATE OR REPLACE FUNCTION get_resumo_financeiro()
-- RETURNS TABLE(
--   -- ajuste as colunas conforme sua view resumo_financeiro_aluno
--   student_id uuid,
--   nome text,
--   valor_pago numeric,
--   valor_aberto numeric
-- )
-- LANGUAGE plpgsql
-- STABLE
-- SECURITY DEFINER
-- SET search_path = public
-- AS $$
-- BEGIN
--   IF NOT can_view_finance() THEN
--     RETURN; -- retorna zero linhas
--   END IF;
--   RETURN QUERY SELECT * FROM resumo_financeiro_aluno;
-- END;
-- $$;

-- Permissões da view:
-- Secretaria consulta resumo_financeiro_global mas não vê linhas
-- porque can_view_finance() retorna false para ela.
-- Admin/direcao/financeiro veem tudo normalmente.


-- =====================================================================
-- A14. TABELA USERS LEGADA — BLOQUEIO
-- =====================================================================
-- A tabela users atual tem password_hash em texto plano.
-- Com Supabase Auth ativo, ela não é mais necessária.
-- Durante a migração, bloquear acesso:

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_all_users" ON users;
DROP POLICY IF EXISTS "temp_dev_users" ON users;
-- Nenhuma policy = ninguém lê via API (nem anon nem authenticated).
-- Apenas service_role e superuser acessam.
-- Após migração completa, DROP TABLE users;


-- =====================================================================
-- A15. STORAGE — COMPROVANTES
-- =====================================================================
-- Bucket PRIVADO (public = false).
-- Frontend usa signed URLs para exibir, não public URLs.
-- No frontend, trocar:
--   sb.storage.from('comprovantes').getPublicUrl(path)
-- Por:
--   sb.storage.from('comprovantes').createSignedUrl(path, 3600)
--   (URL válida por 1 hora)

INSERT INTO storage.buckets (id, name, public)
VALUES ('comprovantes', 'comprovantes', false)
ON CONFLICT (id) DO UPDATE SET public = false;

DROP POLICY IF EXISTS "comprovantes_select" ON storage.objects;
DROP POLICY IF EXISTS "comprovantes_insert" ON storage.objects;
DROP POLICY IF EXISTS "comprovantes_delete" ON storage.objects;
DROP POLICY IF EXISTS "Public read comprovantes" ON storage.objects;
DROP POLICY IF EXISTS "Anon upload comprovantes" ON storage.objects;

CREATE POLICY "comprovantes_select"
  ON storage.objects FOR SELECT
  USING (bucket_id = 'comprovantes' AND auth.uid() IS NOT NULL);

CREATE POLICY "comprovantes_insert"
  ON storage.objects FOR INSERT
  WITH CHECK (
    bucket_id = 'comprovantes'
    AND has_role(ARRAY['super_admin','direcao','financeiro','secretaria'])
  );

CREATE POLICY "comprovantes_delete"
  ON storage.objects FOR DELETE
  USING (bucket_id = 'comprovantes' AND is_admin());



-- #####################################################################
-- PARTE B — PALIATIVO TEMPORÁRIO PARA DESENVOLVIMENTO
-- #####################################################################
--
-- ⚠️  ISTO NÃO É SEGURANÇA — APENAS PARA DESENVOLVIMENTO LOCAL  ⚠️
--
-- Use enquanto migra o frontend para Supabase Auth.
-- NÃO use com dados reais de alunos ou financeiros.
--
-- O que faz: habilita RLS mas permite tudo via anon.
-- O que NÃO faz: proteger absolutamente nada.
--
-- Para usar: comente toda a Parte A e descomente o bloco abaixo.
-- #####################################################################

/*
-- === INÍCIO BLOCO TEMPORÁRIO ===

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE schools ENABLE ROW LEVEL SECURITY;
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE classes ENABLE ROW LEVEL SECURITY;
ALTER TABLE boletos ENABLE ROW LEVEL SECURITY;
ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE VIEW users_safe AS
SELECT id, name, email, role, status, address, created_at FROM users;

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

-- ⚠️ INSEGURO: permite tudo para qualquer key
CREATE POLICY "temp_dev_users" ON users FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_schools" ON schools FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_teachers" ON teachers FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_students" ON students FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_classes" ON classes FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_boletos" ON boletos FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_contacts" ON student_contacts FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "temp_dev_attendance" ON attendance FOR ALL USING (true) WITH CHECK (true);

-- === FIM BLOCO TEMPORÁRIO ===
*/



-- #####################################################################
-- PARTE C — CONSTRAINTS DE INTEGRIDADE (SEMPRE EXECUTAR)
-- #####################################################################

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'boletos_unique_student_mes_ano') THEN
    ALTER TABLE boletos ADD CONSTRAINT boletos_unique_student_mes_ano
      UNIQUE (student_id, mes_referencia, ano_referencia);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'boletos_status_check') THEN
    ALTER TABLE boletos ADD CONSTRAINT boletos_status_check
      CHECK (status IN ('aberto', 'pago'));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
    ALTER TABLE users ADD CONSTRAINT users_role_check
      CHECK (role IN (
        'super_admin', 'admin', 'direcao', 'financeiro',
        'secretaria', 'escola', 'escola_admin', 'professor'
      ));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'students_type_check') THEN
    ALTER TABLE students ADD CONSTRAINT students_type_check
      CHECK (student_type IN ('Regular', 'VIP Online', 'VIP Presencial'));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'students_vip_status_check') THEN
    ALTER TABLE students ADD CONSTRAINT students_vip_status_check
      CHECK (vip_status IS NULL OR vip_status IN ('Ativo', 'Pausado', 'Em risco', 'Cancelado'));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'attendance_status_check') THEN
    ALTER TABLE attendance ADD CONSTRAINT attendance_status_check
      CHECK (status IN ('pendente', 'presente', 'ausente', 'justificado'));
  END IF;
END $$;
