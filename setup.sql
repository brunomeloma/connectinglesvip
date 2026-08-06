-- =====================================================================
-- Connect Inglês VIP — setup.sql
-- ESTE É O ÚNICO SQL QUE DEVE SER EXECUTADO para configurar
-- segurança e banco. Não execute outros arquivos .sql.
-- Reexecutável: usa IF NOT EXISTS e DROP IF EXISTS em tudo.
-- Ordem: profiles > campos > constraints > helpers > RPCs > RLS > storage
-- =====================================================================


-- #####################################################################
-- 1. PROFILES (vinculada a auth.users)
-- #####################################################################

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

CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  INSERT INTO profiles (id, name, email, role)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email,'@',1)), NEW.email, COALESCE(NEW.raw_user_meta_data->>'role','secretaria'));
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION handle_new_user();


-- #####################################################################
-- 2. CAMPOS E TABELAS ADICIONAIS
-- #####################################################################

ALTER TABLE students ADD COLUMN IF NOT EXISTS student_type text DEFAULT 'Regular';
ALTER TABLE students ADD COLUMN IF NOT EXISTS contact_preference text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS whatsapp text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_status text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_notes text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_class_days text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_start_time text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_end_time text;

ALTER TABLE classes ADD COLUMN IF NOT EXISTS class_days text;
ALTER TABLE classes ADD COLUMN IF NOT EXISTS start_time text;
ALTER TABLE classes ADD COLUMN IF NOT EXISTS end_time text;

ALTER TABLE boletos ADD COLUMN IF NOT EXISTS comprovante_path text;

CREATE TABLE IF NOT EXISTS student_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid REFERENCES students(id) ON DELETE CASCADE,
  user_id uuid REFERENCES profiles(id) ON DELETE SET NULL,
  contact_type text, message text, channel text DEFAULT 'whatsapp',
  notes text, created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attendance (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id uuid REFERENCES classes(id) ON DELETE CASCADE,
  student_id uuid REFERENCES students(id) ON DELETE CASCADE,
  date date NOT NULL, status text DEFAULT 'pendente',
  confirmed boolean DEFAULT false,
  marked_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  UNIQUE(class_id, student_id, date)
);

CREATE INDEX IF NOT EXISTS idx_student_contacts_student_id ON student_contacts(student_id);
CREATE INDEX IF NOT EXISTS idx_student_contacts_created_at ON student_contacts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_students_student_type ON students(student_type);
CREATE INDEX IF NOT EXISTS idx_attendance_class_date ON attendance(class_id, date);
CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance(student_id);


-- #####################################################################
-- 3. CONSTRAINTS
-- #####################################################################

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='boletos_unique_student_mes_ano') THEN
    ALTER TABLE boletos ADD CONSTRAINT boletos_unique_student_mes_ano UNIQUE (student_id, mes_referencia, ano_referencia);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='boletos_status_check') THEN
    ALTER TABLE boletos ADD CONSTRAINT boletos_status_check CHECK (status IN ('aberto','pago'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='students_type_check') THEN
    ALTER TABLE students ADD CONSTRAINT students_type_check CHECK (student_type IN ('Regular','VIP Online','VIP Presencial'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='students_vip_status_check') THEN
    ALTER TABLE students ADD CONSTRAINT students_vip_status_check CHECK (vip_status IS NULL OR vip_status IN ('Ativo','Pausado','Em risco','Cancelado'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='attendance_status_check') THEN
    ALTER TABLE attendance ADD CONSTRAINT attendance_status_check CHECK (status IN ('pendente','presente','ausente','justificado'));
  END IF;
END $$;


-- #####################################################################
-- 4. HELPERS SQL
-- #####################################################################

CREATE OR REPLACE FUNCTION get_my_role()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT role FROM profiles WHERE id = auth.uid() AND status = true; $$;

CREATE OR REPLACE FUNCTION is_admin()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('super_admin','direcao') AND status = true); $$;

CREATE OR REPLACE FUNCTION can_view_finance()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('super_admin','direcao','financeiro','secretaria') AND status = true); $$;

CREATE OR REPLACE FUNCTION has_role(allowed_roles text[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = ANY(allowed_roles) AND status = true); $$;


-- #####################################################################
-- 5. RPCs ADMIN
-- #####################################################################

CREATE OR REPLACE FUNCTION update_my_profile(new_name text DEFAULT NULL, new_address text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN UPDATE profiles SET name=COALESCE(new_name,name), address=COALESCE(new_address,address) WHERE id=auth.uid(); END; $$;

CREATE OR REPLACE FUNCTION admin_update_profile(target_id uuid, new_role text DEFAULT NULL, new_status boolean DEFAULT NULL, new_name text DEFAULT NULL, new_address text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE profiles SET role=COALESCE(new_role,role), status=COALESCE(new_status,status), name=COALESCE(new_name,name), address=COALESCE(new_address,address) WHERE id=target_id;
END; $$;


-- #####################################################################
-- 6. RPCs FINANCEIRO
-- #####################################################################

-- Boletos de UM aluno — direção/financeiro vê tudo
CREATE OR REPLACE FUNCTION get_boletos_aluno(p_student_id uuid, p_ano int)
RETURNS SETOF boletos LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY SELECT * FROM boletos WHERE student_id=p_student_id AND ano_referencia=p_ano ORDER BY mes_referencia;
END; $$;

-- Boletos de UM aluno — secretaria: acesso financeiro completo, igual
-- financeiro/direção (ela faz caixa e cobrança e precisa dos mesmos
-- dados: valor, status, comprovante) para lançar, reeditar, marcar pago
-- e conferir comprovantes sem nada escondido.
DROP FUNCTION IF EXISTS get_boletos_aluno_secretaria(uuid, int);
CREATE OR REPLACE FUNCTION get_boletos_aluno_secretaria(p_student_id uuid, p_ano int)
RETURNS TABLE(
  id uuid, mes_referencia int, ano_referencia int,
  data_vencimento date, valor numeric, status text, data_pagamento date,
  observacao text, url_boleto text, codigo_boleto text,
  comprovante_path text, comprovante_url text, tem_comprovante boolean
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT b.id, b.mes_referencia, b.ano_referencia,
      b.data_vencimento, b.valor, b.status, b.data_pagamento,
      b.observacao, b.url_boleto, b.codigo_boleto,
      b.comprovante_path, b.comprovante_url,
      (b.comprovante_path IS NOT NULL OR b.comprovante_url IS NOT NULL)
    FROM boletos b WHERE b.student_id=p_student_id AND b.ano_referencia=p_ano
    ORDER BY b.mes_referencia;
END; $$;

-- Listagem com nome do aluno, valores e totais — direção/financeiro/secretaria
-- (a secretaria faz caixa e cobrança, precisa ver os mesmos dados)
CREATE OR REPLACE FUNCTION get_boletos_com_aluno(p_ano int, p_status text DEFAULT NULL)
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  mes_referencia int, ano_referencia int, data_vencimento date,
  valor numeric, status text, data_pagamento date, observacao text,
  comprovante_url text, comprovante_path text, url_boleto text, codigo_boleto text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  RETURN QUERY
    SELECT b.id, b.student_id, s.first_name, s.last_name,
      b.mes_referencia, b.ano_referencia, b.data_vencimento,
      b.valor, b.status, b.data_pagamento, b.observacao,
      b.comprovante_url, b.comprovante_path, b.url_boleto, b.codigo_boleto
    FROM boletos b JOIN students s ON s.id=b.student_id
    WHERE b.ano_referencia=p_ano AND (p_status IS NULL OR b.status=p_status)
    ORDER BY b.data_vencimento;
END; $$;

-- Listagem para secretaria: apenas aluno, situação e contagem, SEM valores
CREATE OR REPLACE FUNCTION get_alunos_com_boletos_status(p_ano int)
RETURNS TABLE(
  student_id uuid, first_name text, last_name text,
  tem_aberto boolean, total_boletos bigint
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  RETURN QUERY
    SELECT b.student_id, s.first_name, s.last_name,
      bool_or(b.status='aberto'),
      count(*)::bigint
    FROM boletos b JOIN students s ON s.id=b.student_id
    WHERE b.ano_referencia=p_ano
    GROUP BY b.student_id, s.first_name, s.last_name
    ORDER BY s.first_name;
END; $$;

-- Resumo financeiro global — só direção/financeiro
CREATE OR REPLACE FUNCTION get_resumo_financeiro()
RETURNS TABLE(student_id uuid, nome text, valor_pago numeric, valor_aberto numeric)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT can_view_finance() THEN RETURN; END IF;
  RETURN QUERY SELECT s.id, (s.first_name||' '||s.last_name)::text,
    COALESCE(SUM(CASE WHEN b.status='pago' THEN b.valor ELSE 0 END),0),
    COALESCE(SUM(CASE WHEN b.status='aberto' THEN b.valor ELSE 0 END),0)
  FROM students s LEFT JOIN boletos b ON b.student_id=s.id
  WHERE s.status=true GROUP BY s.id,s.first_name,s.last_name HAVING SUM(b.valor)>0;
END; $$;

-- Marcar pagamento
CREATE OR REPLACE FUNCTION marcar_pagamento_boleto(
  p_boleto_id uuid, p_status text,
  p_data_pagamento date DEFAULT NULL, p_observacao text DEFAULT NULL,
  p_comprovante_path text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  IF p_status NOT IN ('pago','aberto') THEN RAISE EXCEPTION 'Status inválido'; END IF;
  IF p_status='pago' THEN
    UPDATE boletos SET status='pago',
      data_pagamento=COALESCE(p_data_pagamento,CURRENT_DATE),
      observacao=p_observacao,
      comprovante_path=CASE WHEN p_comprovante_path IS NOT NULL AND NOT p_comprovante_path LIKE 'http%' THEN p_comprovante_path ELSE comprovante_path END,
      comprovante_url=CASE WHEN p_comprovante_path IS NOT NULL AND p_comprovante_path LIKE 'http%' THEN p_comprovante_path ELSE comprovante_url END
    WHERE id=p_boleto_id;
  ELSE
    UPDATE boletos SET status='aberto', data_pagamento=NULL, observacao=NULL, comprovante_path=NULL, comprovante_url=NULL WHERE id=p_boleto_id;
  END IF;
END; $$;

-- Marcar vencidos
CREATE OR REPLACE FUNCTION marcar_vencidos_pago(p_boleto_ids uuid[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE boletos SET status='pago', data_pagamento=CURRENT_DATE WHERE id=ANY(p_boleto_ids);
END; $$;

-- Lançar boletos
CREATE OR REPLACE FUNCTION lancar_boletos_aluno(p_rows jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE r jsonb; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  FOR r IN SELECT * FROM jsonb_array_elements(p_rows) LOOP
    INSERT INTO boletos (student_id,mes_referencia,ano_referencia,data_vencimento,valor,url_boleto,codigo_boleto)
    VALUES ((r->>'student_id')::uuid,(r->>'mes_referencia')::int,(r->>'ano_referencia')::int,(r->>'data_vencimento')::date,(r->>'valor')::numeric,r->>'url_boleto',r->>'codigo_boleto')
    ON CONFLICT (student_id,mes_referencia,ano_referencia) DO UPDATE SET
      data_vencimento=EXCLUDED.data_vencimento, valor=EXCLUDED.valor, url_boleto=EXCLUDED.url_boleto, codigo_boleto=EXCLUDED.codigo_boleto;
  END LOOP;
END; $$;

-- Deletar boleto (só direção/financeiro)
CREATE OR REPLACE FUNCTION deletar_boleto(p_boleto_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  DELETE FROM boletos WHERE id=p_boleto_id;
END; $$;

-- Boletos que vencem hoje (com dados do aluno, para aba Cobranças)
CREATE OR REPLACE FUNCTION get_boletos_vencem_hoje()
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text, whatsapp text, mobile_number text,
  mes_referencia int, ano_referencia int, data_vencimento date, valor numeric,
  status text, url_boleto text, codigo_boleto text, observacao text,
  comprovante_path text, comprovante_url text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT b.id, b.student_id, s.first_name, s.last_name, s.whatsapp, s.mobile_number,
      b.mes_referencia, b.ano_referencia, b.data_vencimento, b.valor,
      b.status, b.url_boleto, b.codigo_boleto, b.observacao,
      b.comprovante_path, b.comprovante_url
    FROM boletos b JOIN students s ON s.id=b.student_id
    WHERE b.data_vencimento=CURRENT_DATE AND b.status='aberto'
    ORDER BY s.first_name;
END; $$;

-- Boletos vencidos (não pagos, data < hoje)
CREATE OR REPLACE FUNCTION get_boletos_vencidos()
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text, whatsapp text, mobile_number text,
  mes_referencia int, ano_referencia int, data_vencimento date, valor numeric,
  status text, url_boleto text, codigo_boleto text, observacao text,
  dias_atraso int, comprovante_path text, comprovante_url text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT b.id, b.student_id, s.first_name, s.last_name, s.whatsapp, s.mobile_number,
      b.mes_referencia, b.ano_referencia, b.data_vencimento, b.valor,
      b.status, b.url_boleto, b.codigo_boleto, b.observacao,
      (CURRENT_DATE - b.data_vencimento)::int,
      b.comprovante_path, b.comprovante_url
    FROM boletos b JOIN students s ON s.id=b.student_id
    WHERE b.data_vencimento<CURRENT_DATE AND b.status='aberto'
    ORDER BY b.data_vencimento;
END; $$;

-- Boletos pagos hoje
CREATE OR REPLACE FUNCTION get_boletos_pagos_hoje()
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  mes_referencia int, ano_referencia int, valor numeric, data_pagamento date, observacao text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT b.id, b.student_id, s.first_name, s.last_name,
      b.mes_referencia, b.ano_referencia, b.valor, b.data_pagamento, b.observacao
    FROM boletos b JOIN students s ON s.id=b.student_id
    WHERE b.data_pagamento=CURRENT_DATE AND b.status='pago'
    ORDER BY s.first_name;
END; $$;

-- Registrar cobrança (usa student_contacts)
CREATE OR REPLACE FUNCTION registrar_cobranca_boleto(
  p_student_id uuid, p_contact_type text, p_message text,
  p_channel text DEFAULT 'whatsapp', p_notes text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  INSERT INTO student_contacts (student_id, user_id, contact_type, message, channel, notes)
  VALUES (p_student_id, auth.uid(), p_contact_type, p_message, p_channel, p_notes);
END; $$;

-- Última cobrança por aluno
CREATE OR REPLACE FUNCTION get_ultima_cobranca(p_student_id uuid)
RETURNS TABLE(created_at timestamptz, contact_type text, message text, channel text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT sc.created_at, sc.contact_type, sc.message, sc.channel
    FROM student_contacts sc
    WHERE sc.student_id=p_student_id AND sc.contact_type IN ('cobranca','boleto_vencido','confirmacao_pagamento')
    ORDER BY sc.created_at DESC LIMIT 1;
END; $$;


-- #####################################################################
-- 7. RLS POLICIES
-- #####################################################################

-- Limpar todas as policies antigas
DO $$ DECLARE pol record; BEGIN
  FOR pol IN
    SELECT policyname, tablename FROM pg_policies
    WHERE schemaname='public' AND (policyname LIKE 'anon_%' OR policyname LIKE 'temp_dev_%' OR policyname='Allow all for authenticated')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', pol.policyname, pol.tablename);
  END LOOP;
END $$;

-- profiles
DROP POLICY IF EXISTS "profiles_select_own" ON profiles;
DROP POLICY IF EXISTS "profiles_select_admin" ON profiles;
DROP POLICY IF EXISTS "profiles_update_admin" ON profiles;
DROP POLICY IF EXISTS "profiles_insert_admin" ON profiles;
DROP POLICY IF EXISTS "profiles_delete_admin" ON profiles;
CREATE POLICY "profiles_select_own" ON profiles FOR SELECT USING (id=auth.uid());
CREATE POLICY "profiles_select_admin" ON profiles FOR SELECT USING (is_admin());
CREATE POLICY "profiles_update_admin" ON profiles FOR UPDATE USING (is_admin());
CREATE POLICY "profiles_insert_admin" ON profiles FOR INSERT WITH CHECK (is_admin());
CREATE POLICY "profiles_delete_admin" ON profiles FOR DELETE USING (is_admin());

-- schools
ALTER TABLE schools ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "schools_select" ON schools;
DROP POLICY IF EXISTS "schools_insert" ON schools;
DROP POLICY IF EXISTS "schools_update" ON schools;
DROP POLICY IF EXISTS "schools_delete" ON schools;
CREATE POLICY "schools_select" ON schools FOR SELECT USING (auth.uid() IS NOT NULL);
CREATE POLICY "schools_insert" ON schools FOR INSERT WITH CHECK (is_admin());
CREATE POLICY "schools_update" ON schools FOR UPDATE USING (is_admin());
CREATE POLICY "schools_delete" ON schools FOR DELETE USING (is_admin());

-- teachers
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "teachers_select" ON teachers;
DROP POLICY IF EXISTS "teachers_insert" ON teachers;
DROP POLICY IF EXISTS "teachers_update" ON teachers;
DROP POLICY IF EXISTS "teachers_delete" ON teachers;
CREATE POLICY "teachers_select" ON teachers FOR SELECT USING (auth.uid() IS NOT NULL);
CREATE POLICY "teachers_insert" ON teachers FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','secretaria']));
CREATE POLICY "teachers_update" ON teachers FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','secretaria']));
CREATE POLICY "teachers_delete" ON teachers FOR DELETE USING (is_admin());

-- students
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "students_select" ON students;
DROP POLICY IF EXISTS "students_insert" ON students;
DROP POLICY IF EXISTS "students_update" ON students;
DROP POLICY IF EXISTS "students_delete" ON students;
CREATE POLICY "students_select" ON students FOR SELECT USING (auth.uid() IS NOT NULL);
CREATE POLICY "students_insert" ON students FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "students_update" ON students FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "students_delete" ON students FOR DELETE USING (is_admin());

-- classes
ALTER TABLE classes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "classes_select" ON classes;
DROP POLICY IF EXISTS "classes_insert" ON classes;
DROP POLICY IF EXISTS "classes_update" ON classes;
DROP POLICY IF EXISTS "classes_delete" ON classes;
CREATE POLICY "classes_select" ON classes FOR SELECT USING (auth.uid() IS NOT NULL);
CREATE POLICY "classes_insert" ON classes FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','secretaria']));
CREATE POLICY "classes_update" ON classes FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','secretaria']));
CREATE POLICY "classes_delete" ON classes FOR DELETE USING (is_admin());

-- boletos (secretaria SEM SELECT direto — usa RPCs)
ALTER TABLE boletos ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "boletos_select" ON boletos;
DROP POLICY IF EXISTS "boletos_insert" ON boletos;
DROP POLICY IF EXISTS "boletos_update" ON boletos;
DROP POLICY IF EXISTS "boletos_delete" ON boletos;
CREATE POLICY "boletos_select" ON boletos FOR SELECT USING (has_role(ARRAY['super_admin','direcao','financeiro']));
CREATE POLICY "boletos_insert" ON boletos FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro']));
CREATE POLICY "boletos_update" ON boletos FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','financeiro']));
CREATE POLICY "boletos_delete" ON boletos FOR DELETE USING (has_role(ARRAY['super_admin','direcao','financeiro']));

-- student_contacts
ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "contacts_select" ON student_contacts;
DROP POLICY IF EXISTS "contacts_insert" ON student_contacts;
DROP POLICY IF EXISTS "contacts_update" ON student_contacts;
DROP POLICY IF EXISTS "contacts_delete" ON student_contacts;
CREATE POLICY "contacts_select" ON student_contacts FOR SELECT USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "contacts_insert" ON student_contacts FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "contacts_update" ON student_contacts FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "contacts_delete" ON student_contacts FOR DELETE USING (is_admin());

-- attendance
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "attendance_select" ON attendance;
DROP POLICY IF EXISTS "attendance_insert" ON attendance;
DROP POLICY IF EXISTS "attendance_update" ON attendance;
DROP POLICY IF EXISTS "attendance_delete" ON attendance;
CREATE POLICY "attendance_select" ON attendance FOR SELECT USING (auth.uid() IS NOT NULL);
CREATE POLICY "attendance_insert" ON attendance FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','secretaria','professor']));
CREATE POLICY "attendance_update" ON attendance FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','secretaria','professor']));
CREATE POLICY "attendance_delete" ON attendance FOR DELETE USING (is_admin());

-- users (legada — bloquear, só se existir)
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='users') THEN
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
    EXECUTE 'DROP POLICY IF EXISTS "anon_all_users" ON users';
  END IF;
END $$;

-- #####################################################################
-- 8. CONTROLE DE PROFESSORES — teacher_lessons
-- #####################################################################

ALTER TABLE teachers ADD COLUMN IF NOT EXISTS valor_hora numeric(8,2) DEFAULT 0;

CREATE TABLE IF NOT EXISTS teacher_lessons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id uuid REFERENCES classes(id) ON DELETE SET NULL,
  teacher_id uuid REFERENCES teachers(id) ON DELETE CASCADE,
  actual_teacher_id uuid REFERENCES teachers(id) ON DELETE CASCADE,
  lesson_date date NOT NULL,
  lesson_type text NOT NULL DEFAULT 'aula_normal',
  status text NOT NULL DEFAULT 'realizada',
  hours numeric(4,2) NOT NULL DEFAULT 1,
  notes text,
  counts_for_payment boolean DEFAULT true,
  paid boolean DEFAULT false,
  paid_at date,
  paid_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE teacher_lessons ADD COLUMN IF NOT EXISTS counts_for_payment boolean DEFAULT true;

-- Recriar constraints para garantir tipos atualizados (incluindo treinamento)
ALTER TABLE teacher_lessons DROP CONSTRAINT IF EXISTS tl_type_check;
ALTER TABLE teacher_lessons ADD CONSTRAINT tl_type_check CHECK (lesson_type IN ('aula_normal','substituicao','reuniao','evento','treinamento','outro'));

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='tl_status_check') THEN
    ALTER TABLE teacher_lessons ADD CONSTRAINT tl_status_check CHECK (status IN ('realizada','nao_realizada','cancelada','falta','justificada'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='tl_hours_check') THEN
    ALTER TABLE teacher_lessons ADD CONSTRAINT tl_hours_check CHECK (hours > 0 AND hours <= 24);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_tl_date ON teacher_lessons(lesson_date DESC);
CREATE INDEX IF NOT EXISTS idx_tl_actual_teacher ON teacher_lessons(actual_teacher_id);
CREATE INDEX IF NOT EXISTS idx_tl_class ON teacher_lessons(class_id);

ALTER TABLE teacher_lessons ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "tl_select" ON teacher_lessons;
DROP POLICY IF EXISTS "tl_insert" ON teacher_lessons;
DROP POLICY IF EXISTS "tl_update" ON teacher_lessons;
DROP POLICY IF EXISTS "tl_delete" ON teacher_lessons;
CREATE POLICY "tl_select" ON teacher_lessons FOR SELECT USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "tl_insert" ON teacher_lessons FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "tl_update" ON teacher_lessons FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "tl_delete" ON teacher_lessons FOR DELETE USING (is_admin());

-- Lançar aula (secretaria + admin)
CREATE OR REPLACE FUNCTION lancar_aula_professor(
  p_class_id uuid DEFAULT NULL,
  p_teacher_id uuid DEFAULT NULL,
  p_actual_teacher_id uuid DEFAULT NULL,
  p_lesson_date date DEFAULT CURRENT_DATE,
  p_lesson_type text DEFAULT 'aula_normal',
  p_status text DEFAULT 'realizada',
  p_hours numeric DEFAULT 1,
  p_notes text DEFAULT NULL,
  p_counts_for_payment boolean DEFAULT true
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_id uuid; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  INSERT INTO teacher_lessons(class_id, teacher_id, actual_teacher_id, lesson_date, lesson_type, status, hours, notes, counts_for_payment, created_by)
  VALUES (p_class_id, p_teacher_id, COALESCE(p_actual_teacher_id, p_teacher_id), p_lesson_date, p_lesson_type, p_status, p_hours, p_notes, p_counts_for_payment, auth.uid())
  RETURNING id INTO v_id;
  RETURN v_id;
END; $$;

-- Atualizar aula (secretaria + admin)
CREATE OR REPLACE FUNCTION atualizar_aula_professor(
  p_id uuid,
  p_class_id uuid DEFAULT NULL,
  p_teacher_id uuid DEFAULT NULL,
  p_actual_teacher_id uuid DEFAULT NULL,
  p_lesson_date date DEFAULT NULL,
  p_lesson_type text DEFAULT NULL,
  p_status text DEFAULT NULL,
  p_hours numeric DEFAULT NULL,
  p_notes text DEFAULT NULL,
  p_counts_for_payment boolean DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE teacher_lessons SET
    class_id = COALESCE(p_class_id, class_id),
    teacher_id = COALESCE(p_teacher_id, teacher_id),
    actual_teacher_id = COALESCE(p_actual_teacher_id, actual_teacher_id),
    lesson_date = COALESCE(p_lesson_date, lesson_date),
    lesson_type = COALESCE(p_lesson_type, lesson_type),
    status = COALESCE(p_status, status),
    hours = COALESCE(p_hours, hours),
    notes = COALESCE(p_notes, notes),
    counts_for_payment = COALESCE(p_counts_for_payment, counts_for_payment)
  WHERE id = p_id;
END; $$;

-- Deletar aula (só admin)
CREATE OR REPLACE FUNCTION deletar_aula_professor(p_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  DELETE FROM teacher_lessons WHERE id = p_id;
END; $$;

-- Listar aulas — admin/financeiro (com valor_hora e counts_for_payment)
CREATE OR REPLACE FUNCTION get_aulas_mes(p_mes int, p_ano int, p_teacher_id uuid DEFAULT NULL)
RETURNS TABLE(
  id uuid, class_id uuid, class_name text,
  teacher_id uuid, teacher_name text,
  actual_teacher_id uuid, actual_teacher_name text,
  lesson_date date, lesson_type text, status text,
  hours numeric, valor_hora numeric, notes text,
  counts_for_payment boolean, paid boolean, paid_at date, created_at timestamptz
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT tl.id,
      tl.class_id, c.name::text,
      tl.teacher_id, (tr.first_name||' '||tr.last_name)::text,
      tl.actual_teacher_id, (at2.first_name||' '||at2.last_name)::text,
      tl.lesson_date, tl.lesson_type, tl.status,
      tl.hours, COALESCE(at2.valor_hora, 0)::numeric, tl.notes,
      tl.counts_for_payment, tl.paid, tl.paid_at, tl.created_at
    FROM teacher_lessons tl
    LEFT JOIN classes c ON c.id = tl.class_id
    LEFT JOIN teachers tr ON tr.id = tl.teacher_id
    LEFT JOIN teachers at2 ON at2.id = tl.actual_teacher_id
    WHERE EXTRACT(MONTH FROM tl.lesson_date)::int = p_mes
      AND EXTRACT(YEAR FROM tl.lesson_date)::int = p_ano
      AND (p_teacher_id IS NULL OR tl.actual_teacher_id = p_teacher_id)
    ORDER BY tl.lesson_date DESC;
END; $$;

-- Listar aulas — secretaria (SEM valor_hora, COM counts_for_payment)
CREATE OR REPLACE FUNCTION get_aulas_mes_secretaria(p_mes int, p_ano int, p_teacher_id uuid DEFAULT NULL)
RETURNS TABLE(
  id uuid, class_id uuid, class_name text,
  teacher_id uuid, teacher_name text,
  actual_teacher_id uuid, actual_teacher_name text,
  lesson_date date, lesson_type text, status text,
  hours numeric, notes text, counts_for_payment boolean, paid boolean, created_at timestamptz
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT tl.id,
      tl.class_id, c.name::text,
      tl.teacher_id, (tr.first_name||' '||tr.last_name)::text,
      tl.actual_teacher_id, (at2.first_name||' '||at2.last_name)::text,
      tl.lesson_date, tl.lesson_type, tl.status,
      tl.hours, tl.notes, tl.counts_for_payment, tl.paid, tl.created_at
    FROM teacher_lessons tl
    LEFT JOIN classes c ON c.id = tl.class_id
    LEFT JOIN teachers tr ON tr.id = tl.teacher_id
    LEFT JOIN teachers at2 ON at2.id = tl.actual_teacher_id
    WHERE EXTRACT(MONTH FROM tl.lesson_date)::int = p_mes
      AND EXTRACT(YEAR FROM tl.lesson_date)::int = p_ano
      AND (p_teacher_id IS NULL OR tl.actual_teacher_id = p_teacher_id)
    ORDER BY tl.lesson_date DESC;
END; $$;

-- Relatório financeiro de professores — só admin/direção
-- Pagamento baseado em: actual_teacher_id + counts_for_payment=true + status=realizada
CREATE OR REPLACE FUNCTION get_relatorio_pagamento_professor(p_mes int, p_ano int)
RETURNS TABLE(
  teacher_id uuid, teacher_name text, valor_hora numeric,
  total_atividades bigint, total_horas_pagas numeric, total_horas_registradas numeric,
  total_substituicoes bigint, atividades_nao_pagas bigint,
  total_a_pagar numeric, todos_pagos boolean
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT
      t.id,
      (t.first_name||' '||t.last_name)::text,
      COALESCE(t.valor_hora, 0)::numeric,
      -- total de atividades lançadas (qualquer status)
      COUNT(tl.id),
      -- horas que contam para pagamento (realizada + counts_for_payment)
      COALESCE(SUM(tl.hours) FILTER (WHERE tl.status='realizada' AND tl.counts_for_payment=true), 0)::numeric,
      -- horas totais realizadas (incluindo não pagas)
      COALESCE(SUM(tl.hours) FILTER (WHERE tl.status='realizada'), 0)::numeric,
      -- substituições realizadas que contam
      COUNT(tl.id) FILTER (WHERE tl.lesson_type='substituicao' AND tl.status='realizada' AND tl.counts_for_payment=true),
      -- atividades que não geram pagamento
      COUNT(tl.id) FILTER (WHERE tl.counts_for_payment=false OR tl.status IN ('cancelada','nao_realizada','falta')),
      -- valor a pagar = horas pagas × valor/hora do professor que realizou
      COALESCE(SUM(tl.hours) FILTER (WHERE tl.status='realizada' AND tl.counts_for_payment=true), 0) * COALESCE(t.valor_hora, 0),
      -- todos pagos = todas as atividades que contam já foram marcadas como pagas
      COALESCE(bool_and(tl.paid) FILTER (WHERE tl.status='realizada' AND tl.counts_for_payment=true), false)
    FROM teachers t
    LEFT JOIN teacher_lessons tl ON tl.actual_teacher_id = t.id
      AND EXTRACT(MONTH FROM tl.lesson_date)::int = p_mes
      AND EXTRACT(YEAR FROM tl.lesson_date)::int = p_ano
    WHERE t.status = true
    GROUP BY t.id, t.first_name, t.last_name, t.valor_hora
    HAVING COUNT(tl.id) > 0
    ORDER BY t.first_name;
END; $$;

-- Marcar aulas do professor como pagas (admin/direção)
CREATE OR REPLACE FUNCTION marcar_pago_professor(p_teacher_id uuid, p_mes int, p_ano int)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE teacher_lessons SET paid=true, paid_at=CURRENT_DATE, paid_by=auth.uid()
  WHERE actual_teacher_id=p_teacher_id
    AND EXTRACT(MONTH FROM lesson_date)::int=p_mes
    AND EXTRACT(YEAR FROM lesson_date)::int=p_ano
    AND status='realizada'
    AND counts_for_payment=true;
END; $$;

-- Atualizar valor_hora de um professor específico (admin/direção)
CREATE OR REPLACE FUNCTION atualizar_valor_hora(p_teacher_id uuid, p_valor_hora numeric)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE teachers SET valor_hora = p_valor_hora WHERE id = p_teacher_id;
END; $$;

-- Aplicar valor_hora global para todos os professores ativos (admin/direção)
CREATE OR REPLACE FUNCTION aplicar_valor_hora_global(p_valor_hora numeric)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_count int; BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  IF p_valor_hora < 0 THEN RAISE EXCEPTION 'Valor não pode ser negativo'; END IF;
  UPDATE teachers SET valor_hora = p_valor_hora WHERE status = true;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END; $$;


-- storage comprovantes
INSERT INTO storage.buckets (id, name, public) VALUES ('comprovantes', 'comprovantes', false)
ON CONFLICT (id) DO UPDATE SET public = false;
DROP POLICY IF EXISTS "comprovantes_select" ON storage.objects;
DROP POLICY IF EXISTS "comprovantes_insert" ON storage.objects;
DROP POLICY IF EXISTS "comprovantes_delete" ON storage.objects;
DROP POLICY IF EXISTS "Public read comprovantes" ON storage.objects;
DROP POLICY IF EXISTS "Anon upload comprovantes" ON storage.objects;
CREATE POLICY "comprovantes_select" ON storage.objects FOR SELECT USING (bucket_id='comprovantes' AND auth.uid() IS NOT NULL);
CREATE POLICY "comprovantes_insert" ON storage.objects FOR INSERT WITH CHECK (bucket_id='comprovantes' AND has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "comprovantes_delete" ON storage.objects FOR DELETE USING (bucket_id='comprovantes' AND is_admin());


-- #####################################################################
-- 9. DOCUMENTOS — LEITURA E ASSINATURA ELETRÔNICA (link público por token)
-- #####################################################################
-- Fluxo: a secretaria gera um link com token para um aluno; o responsável
-- abre o link (sem login), lê o documento até o fim, marca ciência e
-- assina digitando nome/CPF. Tudo fica registrado para auditoria.
-- O responsável NUNCA acessa a tabela diretamente — só via as 3 RPCs
-- marcadas como "PÚBLICA" abaixo, validadas por token.

CREATE TABLE IF NOT EXISTS document_signatures (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid REFERENCES students(id) ON DELETE CASCADE,
  document_type text NOT NULL,
  token text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pendente',
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '30 days'),
  opened_at timestamptz,
  reading_completed_at timestamptz,
  signed_at timestamptz,
  signer_name text,
  signer_cpf text,
  ip_address text,
  user_agent text,
  revoked_at timestamptz,
  revoked_by uuid REFERENCES profiles(id) ON DELETE SET NULL
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ds_document_type_check') THEN
    ALTER TABLE document_signatures ADD CONSTRAINT ds_document_type_check CHECK (document_type IN ('turma_infantil','adulto','vip','vip_premium'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ds_status_check') THEN
    ALTER TABLE document_signatures ADD CONSTRAINT ds_status_check CHECK (status IN ('pendente','aberto','lido','assinado','revogado'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ds_student ON document_signatures(student_id);
CREATE INDEX IF NOT EXISTS idx_ds_status ON document_signatures(status);
CREATE INDEX IF NOT EXISTS idx_ds_created_at ON document_signatures(created_at DESC);

ALTER TABLE document_signatures ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "ds_select" ON document_signatures;
DROP POLICY IF EXISTS "ds_insert" ON document_signatures;
DROP POLICY IF EXISTS "ds_update" ON document_signatures;
DROP POLICY IF EXISTS "ds_delete" ON document_signatures;
CREATE POLICY "ds_select" ON document_signatures FOR SELECT USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "ds_insert" ON document_signatures FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "ds_update" ON document_signatures FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','secretaria']));
CREATE POLICY "ds_delete" ON document_signatures FOR DELETE USING (is_admin());
-- Nenhuma policy de anon: o público só entra pelas RPCs SECURITY DEFINER abaixo.

-- Gerar link de assinatura para um aluno (staff)
CREATE OR REPLACE FUNCTION gerar_link_assinatura(p_student_id uuid, p_document_type text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_token text; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  IF p_document_type NOT IN ('turma_infantil','adulto','vip','vip_premium') THEN RAISE EXCEPTION 'Tipo de documento inválido'; END IF;
  v_token := replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','');
  INSERT INTO document_signatures (student_id, document_type, token, created_by)
  VALUES (p_student_id, p_document_type, v_token, auth.uid());
  RETURN v_token;
END; $$;

-- Revogar um link ainda não assinado (staff)
CREATE OR REPLACE FUNCTION revogar_link_assinatura(p_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE document_signatures SET status='revogado', revoked_at=now(), revoked_by=auth.uid()
  WHERE id=p_id AND status<>'assinado';
END; $$;

-- Histórico de auditoria (staff)
-- DROP antes do CREATE: seções mais abaixo neste arquivo mudam as
-- colunas de retorno dessa função (cpf_confere, manual_signature_*),
-- e Postgres não permite "CREATE OR REPLACE" mudar o tipo de retorno.
DROP FUNCTION IF EXISTS listar_documentos_assinatura(uuid);
CREATE FUNCTION listar_documentos_assinatura(p_student_id uuid DEFAULT NULL)
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  document_type text, status text, created_at timestamptz, expires_at timestamptz,
  opened_at timestamptz, reading_completed_at timestamptz, signed_at timestamptz,
  signer_name text, signer_cpf text, ip_address text, user_agent text,
  created_by_name text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT d.id, d.student_id, s.first_name, s.last_name,
      d.document_type, d.status, d.created_at, d.expires_at,
      d.opened_at, d.reading_completed_at, d.signed_at,
      d.signer_name, d.signer_cpf, d.ip_address, d.user_agent,
      p.name
    FROM document_signatures d
    JOIN students s ON s.id = d.student_id
    LEFT JOIN profiles p ON p.id = d.created_by
    WHERE p_student_id IS NULL OR d.student_id = p_student_id
    ORDER BY d.created_at DESC;
END; $$;

-- PÚBLICA — abrir documento pelo token (sem login). Marca abertura.
CREATE OR REPLACE FUNCTION abrir_documento_assinatura(p_token text)
RETURNS TABLE(
  first_name text, last_name text, document_type text, status text,
  opened_at timestamptz, reading_completed_at timestamptz, signed_at timestamptz,
  signer_name text, expires_at timestamptz
) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row document_signatures%ROWTYPE; BEGIN
  SELECT * INTO v_row FROM document_signatures WHERE token = p_token;
  IF NOT FOUND THEN RAISE EXCEPTION 'Link inválido.'; END IF;
  IF v_row.status <> 'assinado' AND v_row.status <> 'revogado' AND v_row.expires_at < now() THEN
    UPDATE document_signatures SET status='revogado' WHERE id=v_row.id AND status NOT IN ('assinado','revogado');
    v_row.status := 'revogado';
  ELSIF v_row.status = 'pendente' THEN
    UPDATE document_signatures SET status='aberto', opened_at=now() WHERE id=v_row.id;
    v_row.status := 'aberto'; v_row.opened_at := now();
  END IF;
  RETURN QUERY
    SELECT s.first_name, s.last_name, v_row.document_type, v_row.status,
      v_row.opened_at, v_row.reading_completed_at, v_row.signed_at,
      v_row.signer_name, v_row.expires_at
    FROM students s WHERE s.id = v_row.student_id;
END; $$;

-- PÚBLICA — marcar que o responsável rolou o documento até o final
CREATE OR REPLACE FUNCTION confirmar_leitura_assinatura(p_token text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row document_signatures%ROWTYPE; BEGIN
  SELECT * INTO v_row FROM document_signatures WHERE token = p_token;
  IF NOT FOUND THEN RAISE EXCEPTION 'Link inválido.'; END IF;
  IF v_row.status IN ('assinado','revogado') THEN RAISE EXCEPTION 'Este documento não pode mais ser lido.'; END IF;
  IF v_row.reading_completed_at IS NULL THEN
    UPDATE document_signatures SET reading_completed_at=now(), status='lido' WHERE id=v_row.id;
  END IF;
END; $$;

-- PÚBLICA — assinar (exige leitura completa registrada no servidor)
CREATE OR REPLACE FUNCTION assinar_documento(
  p_token text, p_signer_name text, p_signer_cpf text,
  p_ip text DEFAULT NULL, p_user_agent text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row document_signatures%ROWTYPE; BEGIN
  SELECT * INTO v_row FROM document_signatures WHERE token = p_token;
  IF NOT FOUND THEN RAISE EXCEPTION 'Link inválido.'; END IF;
  IF v_row.status = 'assinado' THEN RAISE EXCEPTION 'Este documento já foi assinado.'; END IF;
  IF v_row.status = 'revogado' OR v_row.expires_at < now() THEN RAISE EXCEPTION 'Este link expirou ou foi revogado.'; END IF;
  IF v_row.reading_completed_at IS NULL THEN RAISE EXCEPTION 'É necessário ler o documento até o final antes de assinar.'; END IF;
  IF coalesce(trim(p_signer_name),'')='' OR coalesce(trim(p_signer_cpf),'')='' THEN RAISE EXCEPTION 'Nome completo e CPF são obrigatórios.'; END IF;
  UPDATE document_signatures SET
    status='assinado', signed_at=now(),
    signer_name=trim(p_signer_name), signer_cpf=trim(p_signer_cpf),
    ip_address=p_ip, user_agent=p_user_agent
  WHERE id=v_row.id;
END; $$;

GRANT EXECUTE ON FUNCTION abrir_documento_assinatura(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION confirmar_leitura_assinatura(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION assinar_documento(text, text, text, text, text) TO anon, authenticated;


-- #####################################################################
-- 10. FREQUÊNCIA — REGISTRO DE AULAS E CONTROLE DE PRESENÇA
-- #####################################################################
-- Cada encontro de uma turma gera um registro em class_lessons (data,
-- professor que ministrou — permite substituição —, status, conteúdo
-- ministrado e observações). A presença de cada aluno matriculado fica
-- em attendance, vinculada à aula via lesson_id.

CREATE TABLE IF NOT EXISTS class_lessons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id uuid REFERENCES classes(id) ON DELETE CASCADE,
  lesson_date date NOT NULL,
  teacher_id uuid REFERENCES teachers(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'realizada',
  content text,
  notes text,
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  UNIQUE(class_id, lesson_date)
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='cl_status_check') THEN
    ALTER TABLE class_lessons ADD CONSTRAINT cl_status_check CHECK (status IN ('realizada','cancelada','remarcada'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_cl_class ON class_lessons(class_id);
CREATE INDEX IF NOT EXISTS idx_cl_date ON class_lessons(lesson_date DESC);
CREATE INDEX IF NOT EXISTS idx_cl_teacher ON class_lessons(teacher_id);

ALTER TABLE attendance ADD COLUMN IF NOT EXISTS lesson_id uuid REFERENCES class_lessons(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_attendance_lesson ON attendance(lesson_id);

ALTER TABLE class_lessons ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "cl_select" ON class_lessons;
DROP POLICY IF EXISTS "cl_insert" ON class_lessons;
DROP POLICY IF EXISTS "cl_update" ON class_lessons;
DROP POLICY IF EXISTS "cl_delete" ON class_lessons;
CREATE POLICY "cl_select" ON class_lessons FOR SELECT USING (auth.uid() IS NOT NULL);
CREATE POLICY "cl_insert" ON class_lessons FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','secretaria','professor']));
CREATE POLICY "cl_update" ON class_lessons FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','secretaria','professor']));
CREATE POLICY "cl_delete" ON class_lessons FOR DELETE USING (is_admin());

-- Criar/atualizar o registro de aula de uma turma numa data (1 por dia por turma)
CREATE OR REPLACE FUNCTION registrar_aula_turma(
  p_class_id uuid, p_lesson_date date, p_teacher_id uuid DEFAULT NULL,
  p_status text DEFAULT 'realizada', p_content text DEFAULT NULL, p_notes text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_id uuid; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','secretaria','professor']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  IF p_status NOT IN ('realizada','cancelada','remarcada') THEN RAISE EXCEPTION 'Status de aula inválido'; END IF;
  INSERT INTO class_lessons (class_id, lesson_date, teacher_id, status, content, notes, created_by)
  VALUES (p_class_id, p_lesson_date, p_teacher_id, p_status, p_content, p_notes, auth.uid())
  ON CONFLICT (class_id, lesson_date) DO UPDATE SET
    teacher_id=EXCLUDED.teacher_id, status=EXCLUDED.status, content=EXCLUDED.content,
    notes=EXCLUDED.notes, updated_at=now()
  RETURNING id INTO v_id;
  RETURN v_id;
END; $$;

-- Salvar frequência de uma aula em lote (p_rows = [{student_id, status}, ...])
CREATE OR REPLACE FUNCTION salvar_frequencia_aula(p_lesson_id uuid, p_rows jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_lesson class_lessons%ROWTYPE; r jsonb; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','secretaria','professor']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  SELECT * INTO v_lesson FROM class_lessons WHERE id=p_lesson_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Aula não encontrada'; END IF;
  FOR r IN SELECT * FROM jsonb_array_elements(p_rows) LOOP
    INSERT INTO attendance (class_id, student_id, date, status, lesson_id, confirmed, marked_by)
    VALUES (v_lesson.class_id, (r->>'student_id')::uuid, v_lesson.lesson_date, r->>'status', p_lesson_id, true, auth.uid())
    ON CONFLICT (class_id, student_id, date) DO UPDATE SET
      status=EXCLUDED.status, lesson_id=EXCLUDED.lesson_id, confirmed=true, marked_by=auth.uid();
  END LOOP;
END; $$;

-- Aulas de uma turma com resumo de presença (para o histórico da turma)
CREATE OR REPLACE FUNCTION get_aulas_turma(p_class_id uuid)
RETURNS TABLE(
  id uuid, lesson_date date, teacher_id uuid, teacher_name text,
  status text, content text, notes text,
  total_presentes bigint, total_ausentes bigint, total_justificados bigint, total_alunos bigint
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Não autenticado'; END IF;
  RETURN QUERY
    SELECT cl.id, cl.lesson_date, cl.teacher_id, (t.first_name||' '||t.last_name)::text,
      cl.status, cl.content, cl.notes,
      COUNT(a.id) FILTER (WHERE a.status='presente'),
      COUNT(a.id) FILTER (WHERE a.status='ausente'),
      COUNT(a.id) FILTER (WHERE a.status='justificado'),
      COUNT(a.id)
    FROM class_lessons cl
    LEFT JOIN teachers t ON t.id = cl.teacher_id
    LEFT JOIN attendance a ON a.lesson_id = cl.id
    WHERE cl.class_id = p_class_id
    GROUP BY cl.id, cl.lesson_date, cl.teacher_id, t.first_name, t.last_name, cl.status, cl.content, cl.notes
    ORDER BY cl.lesson_date DESC;
END; $$;

-- Histórico de frequência de um aluno
CREATE OR REPLACE FUNCTION get_frequencia_aluno(p_student_id uuid)
RETURNS TABLE(
  attendance_id uuid, lesson_date date, class_name text, teacher_name text,
  content text, status text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Não autenticado'; END IF;
  RETURN QUERY
    SELECT a.id, a.date, c.name::text, (t.first_name||' '||t.last_name)::text,
      cl.content, a.status
    FROM attendance a
    JOIN classes c ON c.id = a.class_id
    LEFT JOIN class_lessons cl ON cl.id = a.lesson_id
    LEFT JOIN teachers t ON t.id = cl.teacher_id
    WHERE a.student_id = p_student_id AND a.status <> 'pendente'
    ORDER BY a.date DESC;
END; $$;

-- Relatório de frequência flexível (turma/aluno/professor/período combináveis)
CREATE OR REPLACE FUNCTION get_relatorio_frequencia(
  p_class_id uuid DEFAULT NULL, p_student_id uuid DEFAULT NULL,
  p_teacher_id uuid DEFAULT NULL, p_data_ini date DEFAULT NULL, p_data_fim date DEFAULT NULL
) RETURNS TABLE(
  lesson_date date, class_id uuid, class_name text, teacher_name text,
  content text, student_id uuid, student_name text, status text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT a.date, c.id, c.name::text, (t.first_name||' '||t.last_name)::text,
      cl.content, s.id, (s.first_name||' '||s.last_name)::text, a.status
    FROM attendance a
    JOIN classes c ON c.id = a.class_id
    JOIN students s ON s.id = a.student_id
    LEFT JOIN class_lessons cl ON cl.id = a.lesson_id
    LEFT JOIN teachers t ON t.id = cl.teacher_id
    WHERE a.status <> 'pendente'
      AND (p_class_id IS NULL OR a.class_id = p_class_id)
      AND (p_student_id IS NULL OR a.student_id = p_student_id)
      AND (p_teacher_id IS NULL OR cl.teacher_id = p_teacher_id)
      AND (p_data_ini IS NULL OR a.date >= p_data_ini)
      AND (p_data_fim IS NULL OR a.date <= p_data_fim)
    ORDER BY a.date DESC;
END; $$;


-- #####################################################################
-- 11. CORREÇÃO DE INTEGRIDADE — excluir aluno/professor/turma não pode
-- apagar em cascata histórico financeiro, jurídico e acadêmico
-- #####################################################################
-- Antes: ON DELETE CASCADE em attendance, document_signatures,
-- teacher_lessons e class_lessons apagava para sempre presenças, contratos
-- já assinados e lançamentos de pagamento junto com o registro pai.
-- Agora: ON DELETE SET NULL preserva a linha (e seus dados), apenas
-- desvinculando a referência ao registro excluído.

ALTER TABLE attendance DROP CONSTRAINT IF EXISTS attendance_class_id_fkey;
ALTER TABLE attendance ADD CONSTRAINT attendance_class_id_fkey
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE SET NULL;

ALTER TABLE attendance DROP CONSTRAINT IF EXISTS attendance_student_id_fkey;
ALTER TABLE attendance ADD CONSTRAINT attendance_student_id_fkey
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL;

ALTER TABLE student_contacts DROP CONSTRAINT IF EXISTS student_contacts_student_id_fkey;
ALTER TABLE student_contacts ADD CONSTRAINT student_contacts_student_id_fkey
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL;

ALTER TABLE document_signatures DROP CONSTRAINT IF EXISTS document_signatures_student_id_fkey;
ALTER TABLE document_signatures ADD CONSTRAINT document_signatures_student_id_fkey
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL;

ALTER TABLE teacher_lessons DROP CONSTRAINT IF EXISTS teacher_lessons_teacher_id_fkey;
ALTER TABLE teacher_lessons ADD CONSTRAINT teacher_lessons_teacher_id_fkey
  FOREIGN KEY (teacher_id) REFERENCES teachers(id) ON DELETE SET NULL;

ALTER TABLE teacher_lessons DROP CONSTRAINT IF EXISTS teacher_lessons_actual_teacher_id_fkey;
ALTER TABLE teacher_lessons ADD CONSTRAINT teacher_lessons_actual_teacher_id_fkey
  FOREIGN KEY (actual_teacher_id) REFERENCES teachers(id) ON DELETE SET NULL;

ALTER TABLE class_lessons DROP CONSTRAINT IF EXISTS class_lessons_class_id_fkey;
ALTER TABLE class_lessons ADD CONSTRAINT class_lessons_class_id_fkey
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE SET NULL;

-- boletos é definida fora deste arquivo (schema-base), então procura o nome
-- real da constraint em vez de arriscar um nome adivinhado
DO $$ DECLARE v_conname text; BEGIN
  SELECT con.conname INTO v_conname
  FROM pg_constraint con
  JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY(con.conkey)
  WHERE con.contype = 'f'
    AND con.conrelid = 'boletos'::regclass
    AND con.confrelid = 'students'::regclass
    AND att.attname = 'student_id'
  LIMIT 1;

  IF v_conname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE boletos DROP CONSTRAINT %I', v_conname);
    EXECUTE 'ALTER TABLE boletos ADD CONSTRAINT boletos_student_id_fkey FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL';
  END IF;
END $$;


-- #####################################################################
-- 12. CADASTRO DE ALUNO — Modalidade e Dados do Responsável
-- #####################################################################
-- Reorganização do cadastro: matrícula passa a ter Escola/Turma/
-- Modalidade/Nível, e a antiga seção "Dados VIP / Acompanhamento" é
-- substituída por "Dados do Responsável" (para alunos menores de idade).
-- Colunas antigas (student_type, vip_status, vip_notes, vip_class_days,
-- vip_start_time, vip_end_time, contact_preference, whatsapp) são
-- mantidas no banco para não perder histórico, apenas deixam de ser
-- editadas pelo formulário.

ALTER TABLE students ADD COLUMN IF NOT EXISTS modalidade text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_cpf text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_rg text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_email text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_address text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_notes text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_comprovante_path text;

ALTER TABLE students DROP CONSTRAINT IF EXISTS students_modalidade_check;
ALTER TABLE students ADD CONSTRAINT students_modalidade_check
  CHECK (modalidade IS NULL OR modalidade IN ('KIDS','REGULAR','VIP','REGULAR ONLINE','BOLSA'));

-- a coluna level já tinha uma CHECK constraint (definida fora deste
-- arquivo, no schema-base) que só aceitava os valores antigos
-- (Básico/Intermediário/Avançado). Atualiza para os novos valores do
-- cadastro de aluno. Usa NOT VALID para não exigir migração dos alunos
-- já cadastrados com os valores antigos — a validação passa a valer
-- só para inserções/edições novas a partir de agora.
ALTER TABLE students DROP CONSTRAINT IF EXISTS students_level_check;
ALTER TABLE students ADD CONSTRAINT students_level_check
  CHECK (level IS NULL OR level IN ('STARTER','LEVEL 1','LEVEL 2','LEVEL 3','LEVEL 4','LEVEL 5','KIDS 4-5','KIDS 6-7','KIDS 8-9'))
  NOT VALID;

-- força o PostgREST a recarregar o cache de schema imediatamente, sem
-- precisar esperar o recarregamento automático (evita o erro "Could not
-- find the 'modalidade' column ... in the schema cache" logo após rodar
-- este script)
NOTIFY pgrst, 'reload schema';


-- #####################################################################
-- 13. VALIDAÇÃO DE CPF NA ASSINATURA DE DOCUMENTOS
-- #####################################################################
-- O front-end já valida o CPF antes de enviar, mas assinar_documento é
-- SECURITY DEFINER e liberada para o papel anon (link público de
-- assinatura), então a validação também precisa existir aqui — do
-- contrário alguém poderia chamar o RPC diretamente e gravar um
-- documento como "assinado" com um CPF inválido/forjado.

CREATE OR REPLACE FUNCTION is_valid_cpf(p_cpf text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
  cpf text;
  d int[] := ARRAY[]::int[];
  i int;
  sum1 int := 0;
  sum2 int := 0;
  d1 int;
  d2 int;
BEGIN
  cpf := regexp_replace(coalesce(p_cpf,''), '\D', '', 'g');
  IF length(cpf) <> 11 THEN RETURN false; END IF;
  IF cpf ~ '^(\d)\1{10}$' THEN RETURN false; END IF;

  FOR i IN 1..11 LOOP
    d := d || substring(cpf from i for 1)::int;
  END LOOP;

  FOR i IN 1..9 LOOP
    sum1 := sum1 + d[i] * (11 - i);
  END LOOP;
  d1 := (sum1 * 10) % 11;
  IF d1 >= 10 THEN d1 := 0; END IF;
  IF d1 <> d[10] THEN RETURN false; END IF;

  FOR i IN 1..10 LOOP
    sum2 := sum2 + d[i] * (12 - i);
  END LOOP;
  d2 := (sum2 * 10) % 11;
  IF d2 >= 10 THEN d2 := 0; END IF;
  IF d2 <> d[11] THEN RETURN false; END IF;

  RETURN true;
END; $$;

-- PÚBLICA — assinar (exige leitura completa registrada no servidor e CPF válido)
CREATE OR REPLACE FUNCTION assinar_documento(
  p_token text, p_signer_name text, p_signer_cpf text,
  p_ip text DEFAULT NULL, p_user_agent text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row document_signatures%ROWTYPE; BEGIN
  SELECT * INTO v_row FROM document_signatures WHERE token = p_token;
  IF NOT FOUND THEN RAISE EXCEPTION 'Link inválido.'; END IF;
  IF v_row.status = 'assinado' THEN RAISE EXCEPTION 'Este documento já foi assinado.'; END IF;
  IF v_row.status = 'revogado' OR v_row.expires_at < now() THEN RAISE EXCEPTION 'Este link expirou ou foi revogado.'; END IF;
  IF v_row.reading_completed_at IS NULL THEN RAISE EXCEPTION 'É necessário ler o documento até o final antes de assinar.'; END IF;
  IF coalesce(trim(p_signer_name),'')='' OR coalesce(trim(p_signer_cpf),'')='' THEN RAISE EXCEPTION 'Nome completo e CPF são obrigatórios.'; END IF;
  IF NOT is_valid_cpf(p_signer_cpf) THEN RAISE EXCEPTION 'CPF inválido.'; END IF;
  UPDATE document_signatures SET
    status='assinado', signed_at=now(),
    signer_name=trim(p_signer_name), signer_cpf=trim(p_signer_cpf),
    ip_address=p_ip, user_agent=p_user_agent
  WHERE id=v_row.id;
END; $$;

GRANT EXECUTE ON FUNCTION assinar_documento(text, text, text, text, text) TO anon, authenticated;


-- #####################################################################
-- 14. PERMITIR SECRETARIA/DIREÇÃO EXCLUIR CONTRATOS GERADOS POR ENGANO
-- #####################################################################
-- Antes só is_admin() (super_admin/direção) podia excluir uma linha de
-- document_signatures. Libera também para secretaria, que é quem mais
-- gera esses links no dia a dia e precisa poder apagar um contrato
-- criado errado (aluno errado, tipo de contrato errado etc.).

DROP POLICY IF EXISTS "ds_delete" ON document_signatures;
CREATE POLICY "ds_delete" ON document_signatures FOR DELETE
  USING (has_role(ARRAY['super_admin','direcao','secretaria']));


-- #####################################################################
-- 15. CPF DE QUEM ASSINA TEM QUE SER O CPF DO RESPONSÁVEL CADASTRADO
-- #####################################################################
-- Antes só validava se o CPF digitado era um CPF válido (dígitos
-- verificadores corretos), mas não conferia se era o CPF do responsável
-- daquele aluno específico — alguém podia assinar com qualquer CPF
-- válido, mesmo não sendo o do responsável cadastrado.
--
-- Se o aluno já tem parent_cpf cadastrado, a assinatura só é aceita se
-- o CPF digitado (só os números) bater com o cadastrado. Se o aluno
-- ainda não tem parent_cpf cadastrado (cadastro antigo, campo não
-- preenchido), mantém o comportamento anterior — não bloqueia, para não
-- travar assinaturas de alunos já cadastrados antes deste campo existir.
--
-- Importante: essa checagem fica só no banco (não no front-end da
-- página pública de assinatura) para não expor o CPF do responsável
-- cadastrado a quem abrir o link antes de assinar.

CREATE OR REPLACE FUNCTION assinar_documento(
  p_token text, p_signer_name text, p_signer_cpf text,
  p_ip text DEFAULT NULL, p_user_agent text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row document_signatures%ROWTYPE; v_parent_cpf text; BEGIN
  SELECT * INTO v_row FROM document_signatures WHERE token = p_token;
  IF NOT FOUND THEN RAISE EXCEPTION 'Link inválido.'; END IF;
  IF v_row.status = 'assinado' THEN RAISE EXCEPTION 'Este documento já foi assinado.'; END IF;
  IF v_row.status = 'revogado' OR v_row.expires_at < now() THEN RAISE EXCEPTION 'Este link expirou ou foi revogado.'; END IF;
  IF v_row.reading_completed_at IS NULL THEN RAISE EXCEPTION 'É necessário ler o documento até o final antes de assinar.'; END IF;
  IF coalesce(trim(p_signer_name),'')='' OR coalesce(trim(p_signer_cpf),'')='' THEN RAISE EXCEPTION 'Nome completo e CPF são obrigatórios.'; END IF;
  IF NOT is_valid_cpf(p_signer_cpf) THEN RAISE EXCEPTION 'CPF inválido.'; END IF;

  SELECT parent_cpf INTO v_parent_cpf FROM students WHERE id = v_row.student_id;
  IF v_parent_cpf IS NOT NULL AND regexp_replace(v_parent_cpf,'\D','','g') <> '' THEN
    IF regexp_replace(v_parent_cpf,'\D','','g') <> regexp_replace(p_signer_cpf,'\D','','g') THEN
      RAISE EXCEPTION 'O CPF informado não confere com o CPF do responsável cadastrado para este aluno.';
    END IF;
  END IF;

  UPDATE document_signatures SET
    status='assinado', signed_at=now(),
    signer_name=trim(p_signer_name), signer_cpf=trim(p_signer_cpf),
    ip_address=p_ip, user_agent=p_user_agent
  WHERE id=v_row.id;
END; $$;

GRANT EXECUTE ON FUNCTION assinar_documento(text, text, text, text, text) TO anon, authenticated;


-- #####################################################################
-- 16. SINALIZAR NA AUDITORIA QUANDO O CPF ASSINADO DIVERGE DO CADASTRO
-- #####################################################################
-- A Seção 15 já bloqueia no servidor a assinatura com CPF diferente do
-- cadastrado, mas como camada extra de segurança, o histórico de
-- auditoria (tela Documentos) passa a mostrar um aviso visível sempre
-- que um documento assinado tiver CPF diferente do parent_cpf do aluno
-- — cobre também documentos assinados antes desta trava existir.

DROP FUNCTION IF EXISTS listar_documentos_assinatura(uuid);
CREATE FUNCTION listar_documentos_assinatura(p_student_id uuid DEFAULT NULL)
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  document_type text, status text, created_at timestamptz, expires_at timestamptz,
  opened_at timestamptz, reading_completed_at timestamptz, signed_at timestamptz,
  signer_name text, signer_cpf text, ip_address text, user_agent text,
  created_by_name text, cpf_confere boolean
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT d.id, d.student_id, s.first_name, s.last_name,
      d.document_type, d.status, d.created_at, d.expires_at,
      d.opened_at, d.reading_completed_at, d.signed_at,
      d.signer_name, d.signer_cpf, d.ip_address, d.user_agent,
      p.name,
      (
        d.status <> 'assinado'
        OR s.parent_cpf IS NULL
        OR regexp_replace(s.parent_cpf,'\D','','g') = ''
        OR regexp_replace(s.parent_cpf,'\D','','g') = regexp_replace(coalesce(d.signer_cpf,''),'\D','','g')
      ) AS cpf_confere
    FROM document_signatures d
    JOIN students s ON s.id = d.student_id
    LEFT JOIN profiles p ON p.id = d.created_by
    WHERE p_student_id IS NULL OR d.student_id = p_student_id
    ORDER BY d.created_at DESC;
END; $$;


-- #####################################################################
-- 17. EXIGIR CPF DO RESPONSÁVEL CADASTRADO (ENDURECE A SEÇÃO 15)
-- #####################################################################
-- A Seção 15 só bloqueava a assinatura quando o aluno JÁ tinha
-- parent_cpf cadastrado e o CPF digitado era diferente. Por decisão
-- explícita, agora a assinatura exige que o CPF do responsável já
-- esteja cadastrado no aluno — se não estiver, a assinatura é
-- recusada (em vez de aceitar qualquer CPF válido). Use parent_cpf
-- (coluna real da tabela students nesta base — não confundir com um
-- eventual "responsavel_cpf" sugerido por outra ferramenta, que não
-- existe neste schema).

CREATE OR REPLACE FUNCTION assinar_documento(
  p_token text, p_signer_name text, p_signer_cpf text,
  p_ip text DEFAULT NULL, p_user_agent text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row document_signatures%ROWTYPE; v_parent_cpf text; BEGIN
  SELECT * INTO v_row FROM document_signatures WHERE token = p_token;
  IF NOT FOUND THEN RAISE EXCEPTION 'Link inválido.'; END IF;
  IF v_row.status = 'assinado' THEN RAISE EXCEPTION 'Este documento já foi assinado.'; END IF;
  IF v_row.status = 'revogado' OR v_row.expires_at < now() THEN RAISE EXCEPTION 'Este link expirou ou foi revogado.'; END IF;
  IF v_row.reading_completed_at IS NULL THEN RAISE EXCEPTION 'É necessário ler o documento até o final antes de assinar.'; END IF;
  IF coalesce(trim(p_signer_name),'')='' OR coalesce(trim(p_signer_cpf),'')='' THEN RAISE EXCEPTION 'Nome completo e CPF são obrigatórios.'; END IF;
  IF NOT is_valid_cpf(p_signer_cpf) THEN RAISE EXCEPTION 'CPF inválido.'; END IF;

  SELECT parent_cpf INTO v_parent_cpf FROM students WHERE id = v_row.student_id;
  IF v_parent_cpf IS NULL OR regexp_replace(v_parent_cpf,'\D','','g') = '' THEN
    RAISE EXCEPTION 'CPF do responsável não está cadastrado para este aluno. Peça para a secretaria cadastrar o CPF antes de assinar.';
  END IF;
  IF regexp_replace(v_parent_cpf,'\D','','g') <> regexp_replace(p_signer_cpf,'\D','','g') THEN
    RAISE EXCEPTION 'O CPF informado não confere com o CPF do responsável cadastrado para este aluno.';
  END IF;

  UPDATE document_signatures SET
    status='assinado', signed_at=now(),
    signer_name=trim(p_signer_name), signer_cpf=trim(p_signer_cpf),
    ip_address=p_ip, user_agent=p_user_agent
  WHERE id=v_row.id;
END; $$;

GRANT EXECUTE ON FUNCTION assinar_documento(text, text, text, text, text) TO anon, authenticated;


-- #####################################################################
-- 18. NÍVEL DE TURMA — MESMOS VALORES DO NÍVEL DE ALUNO
-- #####################################################################
-- A tabela classes tinha uma CHECK constraint (classes_level_check,
-- definida fora deste arquivo, no schema-base) restrita aos valores
-- antigos (Básico/Intermediário/Avançado), igual ao que aconteceu com
-- students_level_check. Atualiza para os novos valores usados também
-- no cadastro de aluno. NOT VALID para não exigir migração das turmas
-- já cadastradas com os valores antigos.

ALTER TABLE classes DROP CONSTRAINT IF EXISTS classes_level_check;
ALTER TABLE classes ADD CONSTRAINT classes_level_check
  CHECK (level IS NULL OR level IN ('STARTER','LEVEL 1','LEVEL 2','LEVEL 3','LEVEL 4','LEVEL 5','KIDS 4-5','KIDS 6-7','KIDS 8-9'))
  NOT VALID;


-- #####################################################################
-- 19. REVISÃO DE SEGURANÇA — dados sensíveis de aluno/responsável
-- #####################################################################
-- Achado da auditoria: a policy "students_select" liberava a leitura de
-- TODA a linha de students (inclusive parent_cpf, parent_rg,
-- parent_email, parent_address, parent_comprovante_path) para
-- QUALQUER usuário autenticado — inclusive professor, que acessa as
-- telas Aluno, Turma e VIP Online sem nenhum bloqueio de papel. Como o
-- front-end usa select('*') nessas telas, os dados sensíveis do
-- responsável chegavam ao navegador do professor mesmo sem aparecer
-- na interface (visível via devtools/network).
--
-- Correção:
--  1. students_select passa a exigir papel de equipe (super_admin,
--     direção, financeiro, secretaria) — professor não lê mais a
--     tabela students diretamente.
--  2. Cria get_turma_alunos(): RPC segura para professor (e demais
--     papéis) conseguir a lista de alunos de uma turma só com os
--     campos necessários para chamada/frequência (nome, modalidade,
--     nível, celular, whatsapp) — sem CPF/RG/e-mail/endereço/
--     comprovante do responsável.
--  3. Cria count_active_students() e count_students_in_class() para
--     os cards/contadores do painel e da lista de turmas não
--     dependerem de leitura direta da tabela.
--  4. Restringe o bucket "comprovantes" (boletos e comprovante de
--     residência) a papéis de equipe — professor não tinha motivo
--     para ler esses arquivos.

DROP POLICY IF EXISTS "students_select" ON students;
CREATE POLICY "students_select" ON students FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

CREATE OR REPLACE FUNCTION get_turma_alunos(p_class_id uuid)
RETURNS TABLE(
  id uuid, first_name text, last_name text,
  modalidade text, level text, mobile_number text, whatsapp text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  RETURN QUERY
    SELECT s.id, s.first_name, s.last_name, s.modalidade, s.level, s.mobile_number, s.whatsapp
    FROM students s
    WHERE s.class_id = p_class_id AND s.status = true
    ORDER BY s.first_name;
END; $$;

CREATE OR REPLACE FUNCTION count_active_students()
RETURNS integer LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT count(*)::integer FROM students WHERE status = true; $$;

CREATE OR REPLACE FUNCTION count_students_in_class(p_class_id uuid)
RETURNS integer LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT count(*)::integer FROM students WHERE class_id = p_class_id AND status = true; $$;

DROP POLICY IF EXISTS "comprovantes_select" ON storage.objects;
CREATE POLICY "comprovantes_select" ON storage.objects FOR SELECT
  USING (bucket_id='comprovantes' AND has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));


-- #####################################################################
-- 20. ASSINATURA MANUAL (FOTO) ANEXADA AO CONTRATO
-- #####################################################################
-- Além da assinatura eletrônica pelo link, o documento pode ter uma
-- foto da assinatura feita a próprio punho anexada — os dois registros
-- podem coexistir no mesmo contrato. Reaproveita o bucket "comprovantes"
-- (já privado e restrito a papéis de equipe) em vez de criar um bucket
-- novo.

ALTER TABLE document_signatures ADD COLUMN IF NOT EXISTS manual_signature_path text;
ALTER TABLE document_signatures ADD COLUMN IF NOT EXISTS manual_signature_uploaded_at timestamptz;
ALTER TABLE document_signatures ADD COLUMN IF NOT EXISTS manual_signature_uploaded_by uuid REFERENCES profiles(id) ON DELETE SET NULL;

DROP FUNCTION IF EXISTS listar_documentos_assinatura(uuid);
CREATE FUNCTION listar_documentos_assinatura(p_student_id uuid DEFAULT NULL)
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  document_type text, status text, created_at timestamptz, expires_at timestamptz,
  opened_at timestamptz, reading_completed_at timestamptz, signed_at timestamptz,
  signer_name text, signer_cpf text, ip_address text, user_agent text,
  created_by_name text, cpf_confere boolean,
  manual_signature_path text, manual_signature_uploaded_at timestamptz
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT d.id, d.student_id, s.first_name, s.last_name,
      d.document_type, d.status, d.created_at, d.expires_at,
      d.opened_at, d.reading_completed_at, d.signed_at,
      d.signer_name, d.signer_cpf, d.ip_address, d.user_agent,
      p.name,
      (
        d.status <> 'assinado'
        OR s.parent_cpf IS NULL
        OR regexp_replace(s.parent_cpf,'\D','','g') = ''
        OR regexp_replace(s.parent_cpf,'\D','','g') = regexp_replace(coalesce(d.signer_cpf,''),'\D','','g')
      ) AS cpf_confere,
      d.manual_signature_path, d.manual_signature_uploaded_at
    FROM document_signatures d
    JOIN students s ON s.id = d.student_id
    LEFT JOIN profiles p ON p.id = d.created_by
    WHERE p_student_id IS NULL OR d.student_id = p_student_id
    ORDER BY d.created_at DESC;
END; $$;

-- Anexar/atualizar a foto da assinatura manual (staff)
CREATE OR REPLACE FUNCTION anexar_assinatura_manual(p_id uuid, p_path text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE document_signatures SET
    manual_signature_path = p_path,
    manual_signature_uploaded_at = now(),
    manual_signature_uploaded_by = auth.uid()
  WHERE id = p_id;
END; $$;


-- #####################################################################
-- 21. NOVO PAPEL "captacao" — MÓDULO DE CAPTAÇÃO DE CLIENTES
-- #####################################################################
-- Papel isolado: só enxerga o módulo de Captação (contatos e disparos).
-- Não deve conseguir ler aluno, responsável, financeiro, documentos,
-- turma, professor ou qualquer dado interno da escola — nem pela
-- interface, nem chamando a API/RPC diretamente.

ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_role_check;
ALTER TABLE profiles ADD CONSTRAINT profiles_role_check CHECK (
  role IN ('super_admin', 'direcao', 'financeiro', 'secretaria', 'professor', 'captacao')
);

-- --- Reforço: as policies abaixo liberavam leitura para "qualquer
-- autenticado" (auth.uid() IS NOT NULL). Sem esse reforço, o novo papel
-- captacao conseguiria ler escola/professor/turma/frequência mesmo sem
-- nenhum botão na interface, só chamando a API diretamente.

DROP POLICY IF EXISTS "schools_select" ON schools;
CREATE POLICY "schools_select" ON schools FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']));

DROP POLICY IF EXISTS "teachers_select" ON teachers;
CREATE POLICY "teachers_select" ON teachers FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']));

DROP POLICY IF EXISTS "classes_select" ON classes;
CREATE POLICY "classes_select" ON classes FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']));

DROP POLICY IF EXISTS "attendance_select" ON attendance;
CREATE POLICY "attendance_select" ON attendance FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']));

DROP POLICY IF EXISTS "cl_select" ON class_lessons;
CREATE POLICY "cl_select" ON class_lessons FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']));

-- --- Reforço: estas duas RPCs só checavam "está logado", não o papel.
CREATE OR REPLACE FUNCTION get_aulas_turma(p_class_id uuid)
RETURNS TABLE(
  id uuid, lesson_date date, teacher_id uuid, teacher_name text,
  status text, content text, notes text,
  total_presentes bigint, total_ausentes bigint, total_justificados bigint, total_alunos bigint
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT cl.id, cl.lesson_date, cl.teacher_id, (t.first_name||' '||t.last_name)::text,
      cl.status, cl.content, cl.notes,
      COUNT(a.id) FILTER (WHERE a.status='presente'),
      COUNT(a.id) FILTER (WHERE a.status='ausente'),
      COUNT(a.id) FILTER (WHERE a.status='justificado'),
      COUNT(a.id)
    FROM class_lessons cl
    LEFT JOIN teachers t ON t.id = cl.teacher_id
    LEFT JOIN attendance a ON a.lesson_id = cl.id
    WHERE cl.class_id = p_class_id
    GROUP BY cl.id, cl.lesson_date, cl.teacher_id, t.first_name, t.last_name, cl.status, cl.content, cl.notes
    ORDER BY cl.lesson_date DESC;
END; $$;

CREATE OR REPLACE FUNCTION get_frequencia_aluno(p_student_id uuid)
RETURNS TABLE(
  attendance_id uuid, lesson_date date, class_name text, teacher_name text,
  content text, status text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT a.id, a.date, c.name::text, (t.first_name||' '||t.last_name)::text,
      cl.content, a.status
    FROM attendance a
    JOIN classes c ON c.id = a.class_id
    LEFT JOIN class_lessons cl ON cl.id = a.lesson_id
    LEFT JOIN teachers t ON t.id = cl.teacher_id
    WHERE a.student_id = p_student_id AND a.status <> 'pendente'
    ORDER BY a.date DESC;
END; $$;

-- --- Tabelas do módulo de Captação ---

CREATE TABLE IF NOT EXISTS captacao_contatos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nome text NOT NULL,
  telefone text NOT NULL,
  observacoes text,
  origem text DEFAULT 'manual',
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  last_contacted_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_captacao_contatos_created_at ON captacao_contatos(created_at DESC);

CREATE TABLE IF NOT EXISTS captacao_disparos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  mensagem text NOT NULL,
  total_contatos int NOT NULL DEFAULT 0,
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  finalizado_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_captacao_disparos_created_at ON captacao_disparos(created_at DESC);

CREATE TABLE IF NOT EXISTS captacao_disparo_contatos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  disparo_id uuid REFERENCES captacao_disparos(id) ON DELETE CASCADE,
  contato_id uuid REFERENCES captacao_contatos(id) ON DELETE SET NULL,
  contato_nome text NOT NULL,
  contato_telefone text NOT NULL,
  status text NOT NULL DEFAULT 'pendente',
  enviado_at timestamptz
);
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='cdc_status_check') THEN
    ALTER TABLE captacao_disparo_contatos ADD CONSTRAINT cdc_status_check CHECK (status IN ('pendente','enviado','pulado'));
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_captacao_disparo_contatos_disparo ON captacao_disparo_contatos(disparo_id);

ALTER TABLE captacao_contatos ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "captacao_contatos_select" ON captacao_contatos;
DROP POLICY IF EXISTS "captacao_contatos_insert" ON captacao_contatos;
DROP POLICY IF EXISTS "captacao_contatos_update" ON captacao_contatos;
DROP POLICY IF EXISTS "captacao_contatos_delete" ON captacao_contatos;
CREATE POLICY "captacao_contatos_select" ON captacao_contatos FOR SELECT USING (has_role(ARRAY['super_admin','direcao','captacao']));
CREATE POLICY "captacao_contatos_insert" ON captacao_contatos FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','captacao']));
CREATE POLICY "captacao_contatos_update" ON captacao_contatos FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','captacao']));
CREATE POLICY "captacao_contatos_delete" ON captacao_contatos FOR DELETE USING (has_role(ARRAY['super_admin','direcao','captacao']));

ALTER TABLE captacao_disparos ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "captacao_disparos_select" ON captacao_disparos;
DROP POLICY IF EXISTS "captacao_disparos_insert" ON captacao_disparos;
DROP POLICY IF EXISTS "captacao_disparos_update" ON captacao_disparos;
DROP POLICY IF EXISTS "captacao_disparos_delete" ON captacao_disparos;
-- histórico de disparos: captação só vê os próprios; direção/admin vê tudo
CREATE POLICY "captacao_disparos_select" ON captacao_disparos FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND created_by = auth.uid()));
CREATE POLICY "captacao_disparos_insert" ON captacao_disparos FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','captacao']) AND created_by = auth.uid());
CREATE POLICY "captacao_disparos_update" ON captacao_disparos FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND created_by = auth.uid()));
CREATE POLICY "captacao_disparos_delete" ON captacao_disparos FOR DELETE USING (is_admin());

ALTER TABLE captacao_disparo_contatos ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "cdc_select" ON captacao_disparo_contatos;
DROP POLICY IF EXISTS "cdc_insert" ON captacao_disparo_contatos;
DROP POLICY IF EXISTS "cdc_update" ON captacao_disparo_contatos;
DROP POLICY IF EXISTS "cdc_delete" ON captacao_disparo_contatos;
CREATE POLICY "cdc_select" ON captacao_disparo_contatos FOR SELECT
  USING (EXISTS (SELECT 1 FROM captacao_disparos d WHERE d.id = disparo_id
    AND (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND d.created_by = auth.uid()))));
CREATE POLICY "cdc_insert" ON captacao_disparo_contatos FOR INSERT
  WITH CHECK (EXISTS (SELECT 1 FROM captacao_disparos d WHERE d.id = disparo_id
    AND (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND d.created_by = auth.uid()))));
CREATE POLICY "cdc_update" ON captacao_disparo_contatos FOR UPDATE
  USING (EXISTS (SELECT 1 FROM captacao_disparos d WHERE d.id = disparo_id
    AND (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND d.created_by = auth.uid()))));
CREATE POLICY "cdc_delete" ON captacao_disparo_contatos FOR DELETE USING (is_admin());


-- #####################################################################
-- 22. CORREÇÃO CRÍTICA — view resumo_financeiro_aluno vazando dados
-- financeiros de todos os alunos sem exigir login
-- #####################################################################
-- Achado ao conectar diretamente no banco (advisor de segurança do
-- Supabase): a view resumo_financeiro_aluno (não usada por nenhuma
-- tela do sistema — provavelmente sobra de um scaffold anterior)
-- estava com SELECT liberado para anon e authenticated, e como views
-- em Postgres/Supabase rodam com security_invoker=false por padrão,
-- ela ignorava completamente as regras de RLS de students/boletos.
-- Resultado: qualquer pessoa na internet, sem estar logada, conseguia
-- acessar essa view pela API pública e baixar nome + totais
-- financeiros (valor pago, em aberto, total) de todos os alunos.

REVOKE ALL ON public.resumo_financeiro_aluno FROM anon, authenticated;
ALTER VIEW public.resumo_financeiro_aluno SET (security_invoker = true);

-- Reforço: duas funções ficaram sem "SET search_path = public"
-- (achado do advisor — mutable search_path é uma classe conhecida de
-- vulnerabilidade em funções Postgres).
CREATE OR REPLACE FUNCTION public.is_valid_cpf(p_cpf text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path = public
AS $$
DECLARE
  cpf text;
  d int[] := ARRAY[]::int[];
  i int;
  sum1 int := 0;
  sum2 int := 0;
  d1 int;
  d2 int;
BEGIN
  cpf := regexp_replace(coalesce(p_cpf,''), '\D', '', 'g');
  IF length(cpf) <> 11 THEN RETURN false; END IF;
  IF cpf ~ '^(\d)\1{10}$' THEN RETURN false; END IF;

  FOR i IN 1..11 LOOP
    d := d || substring(cpf from i for 1)::int;
  END LOOP;

  FOR i IN 1..9 LOOP
    sum1 := sum1 + d[i] * (11 - i);
  END LOOP;
  d1 := (sum1 * 10) % 11;
  IF d1 >= 10 THEN d1 := 0; END IF;
  IF d1 <> d[10] THEN RETURN false; END IF;

  FOR i IN 1..10 LOOP
    sum2 := sum2 + d[i] * (12 - i);
  END LOOP;
  d2 := (sum2 * 10) % 11;
  IF d2 >= 10 THEN d2 := 0; END IF;
  IF d2 <> d[11] THEN RETURN false; END IF;

  RETURN true;
END; $$;

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger LANGUAGE plpgsql SET search_path = public
AS $function$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$function$;


-- #####################################################################
-- 23. LIMPEZA — remove tabela legada "users" (não usada pelo app)
-- #####################################################################
-- O app usa "profiles" (vinculada a auth.users). A tabela "users" era
-- sobra de um scaffold anterior, com RLS ativado mas sem nenhuma
-- policy (já bloqueava todo acesso). Confirmado com o usuário que não
-- há mais uso — removida. CASCADE limpa só as FKs em teachers.user_id
-- e schools.user_id (também não usadas pelo app), sem apagar dados de
-- teachers/schools.

DROP TABLE IF EXISTS public.users CASCADE;


-- #####################################################################
-- 24. CAPTAÇÃO — compartilha histórico de disparos entre operadores
-- #####################################################################
-- Achado da auditoria: a tela nova de Captação mostra, pra qualquer
-- contato, se já foi enviado por QUALQUER operador de captação
-- ("Já enviados"/badges/histórico), pra evitar que dois atendentes
-- mandem mensagem pro mesmo lead. Mas a policy de SELECT em
-- captacao_disparos/captacao_disparo_contatos só liberava "próprios
-- disparos" pra quem tem papel captacao — assim que existir mais de
-- um usuário com esse papel, cada um só enxergaria o que ELE MESMO
-- enviou, e o "já enviado" ficaria incompleto/errado silenciosamente
-- pros envios dos colegas. Corrige pra leitura compartilhada entre
-- todos os operadores de captação (exclusão continua só admin).
-- Aproveita pra otimizar auth.uid() -> (select auth.uid()) nas
-- policies (achado do advisor de performance).

DROP POLICY IF EXISTS "captacao_disparos_select" ON captacao_disparos;
CREATE POLICY "captacao_disparos_select" ON captacao_disparos FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','captacao']));

DROP POLICY IF EXISTS "cdc_select" ON captacao_disparo_contatos;
CREATE POLICY "cdc_select" ON captacao_disparo_contatos FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','captacao']));

DROP POLICY IF EXISTS "captacao_disparos_insert" ON captacao_disparos;
CREATE POLICY "captacao_disparos_insert" ON captacao_disparos FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','captacao']) AND created_by = (select auth.uid()));
DROP POLICY IF EXISTS "captacao_disparos_update" ON captacao_disparos;
CREATE POLICY "captacao_disparos_update" ON captacao_disparos FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND created_by = (select auth.uid())));

DROP POLICY IF EXISTS "cdc_insert" ON captacao_disparo_contatos;
CREATE POLICY "cdc_insert" ON captacao_disparo_contatos FOR INSERT
  WITH CHECK (EXISTS (SELECT 1 FROM captacao_disparos d WHERE d.id = disparo_id
    AND (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND d.created_by = (select auth.uid())))));
DROP POLICY IF EXISTS "cdc_update" ON captacao_disparo_contatos;
CREATE POLICY "cdc_update" ON captacao_disparo_contatos FOR UPDATE
  USING (EXISTS (SELECT 1 FROM captacao_disparos d WHERE d.id = disparo_id
    AND (has_role(ARRAY['super_admin','direcao']) OR (has_role(ARRAY['captacao']) AND d.created_by = (select auth.uid())))));

-- Performance (achado do advisor): auth.uid() reavaliado por linha.
DROP POLICY IF EXISTS "profiles_select_own" ON profiles;
CREATE POLICY "profiles_select_own" ON profiles FOR SELECT USING (id = (select auth.uid()));


-- #####################################################################
-- 25. MELHORIAS — lembrete de vencimento, aniversariantes, risco de evasão
-- #####################################################################

-- Boletos que vencem nos próximos N dias (padrão 7) — ainda em aberto.
-- Complementa get_boletos_vencem_hoje/get_boletos_vencidos, que só
-- cobrem "hoje" e "já venceu": aqui é o aviso PROATIVO, antes de vencer.
CREATE OR REPLACE FUNCTION get_boletos_vencem_em_breve(p_dias int DEFAULT 7)
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text, whatsapp text, mobile_number text,
  mes_referencia int, ano_referencia int, data_vencimento date, valor numeric,
  status text, url_boleto text, codigo_boleto text, observacao text,
  dias_restantes int, comprovante_path text, comprovante_url text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT b.id, b.student_id, s.first_name, s.last_name, s.whatsapp, s.mobile_number,
      b.mes_referencia, b.ano_referencia, b.data_vencimento, b.valor,
      b.status, b.url_boleto, b.codigo_boleto, b.observacao,
      (b.data_vencimento - CURRENT_DATE)::int,
      b.comprovante_path, b.comprovante_url
    FROM boletos b JOIN students s ON s.id=b.student_id
    WHERE b.data_vencimento > CURRENT_DATE
      AND b.data_vencimento <= CURRENT_DATE + p_dias
      AND b.status='aberto'
    ORDER BY b.data_vencimento;
END; $$;

-- Aniversariantes dos próximos N dias (padrão 7), independente do ano.
-- Usa "date + interval" em vez de make_date() para calcular o próximo
-- aniversário: make_date(ano,2,29) LANÇA EXCEÇÃO em anos não-bissextos,
-- o que derrubaria a função inteira (e o painel do dashboard pra todo
-- mundo) assim que o primeiro aluno nascido em 29/fev fosse cadastrado.
-- "date + interval" nunca lança erro, apenas ajusta o resultado.
CREATE OR REPLACE FUNCTION get_aniversariantes_semana(p_dias int DEFAULT 7)
RETURNS TABLE(
  id uuid, first_name text, last_name text, date_birth date,
  whatsapp text, mobile_number text, dias_para_aniversario int
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT s.id, s.first_name, s.last_name, s.date_birth, s.whatsapp, s.mobile_number,
      (prox.data_prox - CURRENT_DATE)::int
    FROM students s
    CROSS JOIN LATERAL (
      SELECT CASE
        WHEN c.cand >= CURRENT_DATE THEN c.cand
        ELSE (s.date_birth + make_interval(years =>
          (EXTRACT(year FROM CURRENT_DATE)::int - EXTRACT(year FROM s.date_birth)::int + 1)))::date
      END AS data_prox
      FROM (SELECT (s.date_birth + make_interval(years =>
        (EXTRACT(year FROM CURRENT_DATE)::int - EXTRACT(year FROM s.date_birth)::int)))::date AS cand) c
    ) prox
    WHERE s.status = true AND s.date_birth IS NOT NULL
      AND (prox.data_prox - CURRENT_DATE) BETWEEN 0 AND p_dias
    ORDER BY dias_para_aniversario;
END; $$;

-- Alunos ativos sem nenhuma atualização de matrícula há muito tempo
-- (risco de evasão) — usa date_joining como proxy de "última matrícula/
-- módulo contratado", já que o sistema não tem um campo de módulo
-- separado hoje. Sinaliza quem está há mais de p_meses sem
-- rematrícula registrada.
CREATE OR REPLACE FUNCTION get_alunos_risco_evasao(p_meses int DEFAULT 6)
RETURNS TABLE(
  id uuid, first_name text, last_name text, whatsapp text, mobile_number text,
  date_joining date, meses_sem_rematricula int, class_name text, modalidade text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT s.id, s.first_name, s.last_name, s.whatsapp, s.mobile_number, s.date_joining,
      (EXTRACT(year FROM age(CURRENT_DATE, s.date_joining))*12 + EXTRACT(month FROM age(CURRENT_DATE, s.date_joining)))::int,
      c.name, s.modalidade
    FROM students s
    LEFT JOIN classes c ON c.id = s.class_id
    WHERE s.status = true AND s.date_joining IS NOT NULL
      AND s.date_joining <= CURRENT_DATE - (p_meses || ' months')::interval
    ORDER BY s.date_joining;
END; $$;


-- #####################################################################
-- 26. PORTAL DO RESPONSÁVEL (link público por token, somente leitura)
-- #####################################################################

-- Ao contrário do link de assinatura (uso único), o link do portal é
-- reutilizável: o responsável pode acessar quantas vezes quiser para
-- ver frequência, boletos e próxima aula do aluno.
CREATE TABLE IF NOT EXISTS portal_acesso (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  token text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'ativo',
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  last_accessed_at timestamptz,
  revoked_at timestamptz,
  revoked_by uuid REFERENCES profiles(id) ON DELETE SET NULL
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='portal_acesso_status_check') THEN
    ALTER TABLE portal_acesso ADD CONSTRAINT portal_acesso_status_check CHECK (status IN ('ativo','revogado'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_portal_acesso_student ON portal_acesso(student_id);

ALTER TABLE portal_acesso ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "portal_acesso_select" ON portal_acesso;
DROP POLICY IF EXISTS "portal_acesso_insert" ON portal_acesso;
DROP POLICY IF EXISTS "portal_acesso_update" ON portal_acesso;
CREATE POLICY "portal_acesso_select" ON portal_acesso FOR SELECT USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "portal_acesso_insert" ON portal_acesso FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "portal_acesso_update" ON portal_acesso FOR UPDATE USING (has_role(ARRAY['super_admin','direcao','secretaria']));

-- Gera (ou reaproveita, se já houver um ativo) o link do portal do aluno.
CREATE OR REPLACE FUNCTION gerar_link_portal(p_student_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_token text; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  SELECT token INTO v_token FROM portal_acesso WHERE student_id = p_student_id AND status='ativo' LIMIT 1;
  IF v_token IS NOT NULL THEN RETURN v_token; END IF;
  v_token := replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','');
  INSERT INTO portal_acesso (student_id, token, created_by) VALUES (p_student_id, v_token, auth.uid());
  RETURN v_token;
END; $$;

-- Revoga o link do portal ativo de um aluno.
CREATE OR REPLACE FUNCTION revogar_link_portal(p_student_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE portal_acesso SET status='revogado', revoked_at=now(), revoked_by=auth.uid()
  WHERE student_id = p_student_id AND status='ativo';
END; $$;

-- PÚBLICA — dados somente-leitura do aluno pelo token do portal (sem login).
-- SECURITY DEFINER contorna a RLS de students/attendance/boletos/classes
-- de propósito, mas só devolve dados do aluno dono do token (v_row.student_id).
CREATE OR REPLACE FUNCTION obter_dados_portal(p_token text)
RETURNS TABLE(
  first_name text, last_name text, class_name text, level text, modalidade text,
  class_days text, start_time text, end_time text,
  frequencia jsonb, boletos jsonb
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row portal_acesso%ROWTYPE; BEGIN
  SELECT * INTO v_row FROM portal_acesso WHERE token = p_token AND status='ativo';
  IF v_row IS NULL THEN RAISE EXCEPTION 'Link inválido ou expirado'; END IF;
  UPDATE portal_acesso SET last_accessed_at = now() WHERE id = v_row.id;
  RETURN QUERY
    SELECT s.first_name, s.last_name, c.name::text, s.level, s.modalidade,
      c.class_days, c.start_time, c.end_time,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('date', x.date, 'status', x.status) ORDER BY x.date DESC)
        FROM (SELECT date, status FROM attendance WHERE student_id=s.id AND status<>'pendente' ORDER BY date DESC LIMIT 20) x), '[]'::jsonb),
      COALESCE((SELECT jsonb_agg(jsonb_build_object('mes_referencia',y.mes_referencia,'ano_referencia',y.ano_referencia,'data_vencimento',y.data_vencimento,'valor',y.valor,'status',y.status,'url_boleto',y.url_boleto) ORDER BY y.ano_referencia DESC, y.mes_referencia DESC)
        FROM (SELECT mes_referencia,ano_referencia,data_vencimento,valor,status,url_boleto FROM boletos WHERE student_id=s.id ORDER BY ano_referencia DESC, mes_referencia DESC LIMIT 12) y), '[]'::jsonb)
    FROM students s LEFT JOIN classes c ON c.id = s.class_id
    WHERE s.id = v_row.student_id;
END; $$;


-- #####################################################################
-- 27. PESQUISA DE SATISFAÇÃO — NPS (link público por token)
-- #####################################################################

CREATE TABLE IF NOT EXISTS nps_pesquisas (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  token text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pendente',
  nota int,
  comentario text,
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  respondido_at timestamptz
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='nps_pesquisas_status_check') THEN
    ALTER TABLE nps_pesquisas ADD CONSTRAINT nps_pesquisas_status_check CHECK (status IN ('pendente','respondida'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='nps_pesquisas_nota_check') THEN
    ALTER TABLE nps_pesquisas ADD CONSTRAINT nps_pesquisas_nota_check CHECK (nota IS NULL OR (nota BETWEEN 0 AND 10));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_nps_student ON nps_pesquisas(student_id);
CREATE INDEX IF NOT EXISTS idx_nps_created_at ON nps_pesquisas(created_at DESC);

ALTER TABLE nps_pesquisas ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "nps_select" ON nps_pesquisas;
DROP POLICY IF EXISTS "nps_insert" ON nps_pesquisas;
CREATE POLICY "nps_select" ON nps_pesquisas FOR SELECT USING (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));
CREATE POLICY "nps_insert" ON nps_pesquisas FOR INSERT WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro','secretaria']));

-- Gera um novo link de pesquisa NPS para o aluno (uso único).
CREATE OR REPLACE FUNCTION gerar_link_nps(p_student_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_token text; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  v_token := replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','');
  INSERT INTO nps_pesquisas (student_id, token, created_by) VALUES (p_student_id, v_token, auth.uid());
  RETURN v_token;
END; $$;

-- Lista pesquisas NPS com nome do aluno, para o painel interno.
CREATE OR REPLACE FUNCTION listar_nps()
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  status text, nota int, comentario text, created_at timestamptz, respondido_at timestamptz
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT n.id, n.student_id, s.first_name, s.last_name, n.status, n.nota, n.comentario, n.created_at, n.respondido_at
    FROM nps_pesquisas n JOIN students s ON s.id = n.student_id
    ORDER BY n.created_at DESC;
END; $$;

-- PÚBLICA — abre a pesquisa pelo token (sem login).
CREATE OR REPLACE FUNCTION abrir_nps(p_token text)
RETURNS TABLE(first_name text, last_name text, status text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row nps_pesquisas%ROWTYPE; BEGIN
  SELECT * INTO v_row FROM nps_pesquisas WHERE token = p_token;
  IF v_row IS NULL THEN RAISE EXCEPTION 'Link inválido'; END IF;
  RETURN QUERY
    SELECT s.first_name, s.last_name, v_row.status FROM students s WHERE s.id = v_row.student_id;
END; $$;

-- PÚBLICA — registra a resposta da pesquisa pelo token (sem login).
CREATE OR REPLACE FUNCTION responder_nps(p_token text, p_nota int, p_comentario text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_row nps_pesquisas%ROWTYPE; BEGIN
  SELECT * INTO v_row FROM nps_pesquisas WHERE token = p_token;
  IF v_row IS NULL THEN RAISE EXCEPTION 'Link inválido'; END IF;
  IF v_row.status = 'respondida' THEN RAISE EXCEPTION 'Esta pesquisa já foi respondida'; END IF;
  IF p_nota IS NULL OR p_nota < 0 OR p_nota > 10 THEN RAISE EXCEPTION 'Nota inválida'; END IF;
  UPDATE nps_pesquisas SET nota = p_nota, comentario = p_comentario, status = 'respondida', respondido_at = now()
  WHERE id = v_row.id;
END; $$;


-- #####################################################################
-- 28. CONTADOR DE ENCONTROS POR TURMA (regra flexível — nunca bloqueia)
-- #####################################################################
-- Base de 20 encontros por turma/módulo, usada só pra sinalização visual
-- no painel inicial e na tela de chamada (19 = reta final, >20 =
-- excedeu). Conta apenas aulas com status='realizada' em class_lessons —
-- nunca impede o lançamento de uma nova aula, mesmo passando de 20.

CREATE OR REPLACE FUNCTION get_contagem_encontros()
RETURNS TABLE(class_id uuid, total_encontros bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria','professor']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT cl.class_id, count(*)::bigint
    FROM class_lessons cl
    WHERE cl.status = 'realizada'
    GROUP BY cl.class_id;
END; $$;


-- #####################################################################
-- 29. CORREÇÃO: EDIÇÃO DE AULA (UPDATE em vez de duplicar) + EXCLUSÃO
-- #####################################################################
-- Antes, editar a data de uma aula existente sempre fazia
-- INSERT ... ON CONFLICT(class_id, lesson_date), então trocar a data
-- "perdia" a identidade do registro original e criava um novo em vez
-- de mover/atualizar o existente. Agora, quando p_lesson_id é
-- informado, o registro é atualizado (UPDATE) diretamente por id,
-- inclusive quando a data muda.

CREATE OR REPLACE FUNCTION registrar_aula_turma(
  p_class_id uuid, p_lesson_date date, p_teacher_id uuid DEFAULT NULL,
  p_status text DEFAULT 'realizada', p_content text DEFAULT NULL, p_notes text DEFAULT NULL,
  p_lesson_id uuid DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_id uuid; v_conflict uuid; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','secretaria','professor']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  IF p_status NOT IN ('realizada','cancelada','remarcada') THEN RAISE EXCEPTION 'Status de aula inválido'; END IF;

  IF p_lesson_id IS NOT NULL THEN
    SELECT id INTO v_conflict FROM class_lessons WHERE class_id=p_class_id AND lesson_date=p_lesson_date AND id<>p_lesson_id;
    IF v_conflict IS NOT NULL THEN
      RAISE EXCEPTION 'Já existe uma aula registrada nesta data para esta turma. Edite aquela aula ou escolha outra data.';
    END IF;
    UPDATE class_lessons SET
      lesson_date=p_lesson_date, teacher_id=p_teacher_id, status=p_status,
      content=p_content, notes=p_notes, updated_at=now()
    WHERE id=p_lesson_id
    RETURNING id INTO v_id;
    IF v_id IS NULL THEN RAISE EXCEPTION 'Aula não encontrada'; END IF;
    -- Se a data mudou, remove presenças órfãs lançadas na data antiga
    -- (salvar_frequencia_aula recria tudo na data nova logo em seguida).
    DELETE FROM attendance WHERE lesson_id=p_lesson_id AND date<>p_lesson_date;
  ELSE
    INSERT INTO class_lessons (class_id, lesson_date, teacher_id, status, content, notes, created_by)
    VALUES (p_class_id, p_lesson_date, p_teacher_id, p_status, p_content, p_notes, auth.uid())
    ON CONFLICT (class_id, lesson_date) DO UPDATE SET
      teacher_id=EXCLUDED.teacher_id, status=EXCLUDED.status, content=EXCLUDED.content,
      notes=EXCLUDED.notes, updated_at=now()
    RETURNING id INTO v_id;
  END IF;

  PERFORM sync_pagamento_aula(v_id);
  RETURN v_id;
END; $$;

-- Excluir um registro de aula lançado errado (não desfaz pagamentos já confirmados:
-- se já existir lançamento de pagamento pago vinculado, ele só é desvinculado,
-- não apagado; se ainda não foi pago, o lançamento automático some junto).
CREATE OR REPLACE FUNCTION deletar_aula_turma(p_lesson_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  DELETE FROM teacher_lessons WHERE class_lesson_id = p_lesson_id AND paid IS NOT TRUE;
  DELETE FROM class_lessons WHERE id = p_lesson_id;
END; $$;


-- #####################################################################
-- 30. PORTAL DO PROFESSOR (link público único + seleção de nome + PIN)
-- #####################################################################
-- Em vez de um login individual por professor (email/senha), todos usam
-- o MESMO link público (?professor=1). O professor escolhe o próprio
-- nome numa lista e confirma um PIN de 4 dígitos — criado na primeira
-- vez que ele usa o link, só pra evitar que alguém escolha o nome de
-- outro colega por engano/brincadeira. O token de sessão fica salvo no
-- localStorage do aparelho, então só pede o PIN de novo num aparelho
-- novo (ou depois de um reset de PIN pela secretaria/admin).
-- Não usa auth.users — por isso todas as RPCs aqui validam a sessão
-- manualmente (teacher_id + token) em vez de auth.uid()/has_role.

ALTER TABLE teachers ADD COLUMN IF NOT EXISTS access_pin_hash text;

CREATE TABLE IF NOT EXISTS professor_portal_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  teacher_id uuid NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
  token text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now(),
  last_used_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pps_teacher ON professor_portal_sessions(teacher_id);

ALTER TABLE professor_portal_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "pps_select" ON professor_portal_sessions;
CREATE POLICY "pps_select" ON professor_portal_sessions FOR SELECT USING (has_role(ARRAY['super_admin','direcao']));
-- Sem policies de insert/update/delete diretas: só é possível escrever
-- aqui através das RPCs SECURITY DEFINER abaixo.

-- Helper interno — confere se teacher_id+token corresponde a uma sessão válida.
CREATE OR REPLACE FUNCTION _professor_sessao_valida(p_teacher_id uuid, p_token text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT EXISTS(SELECT 1 FROM professor_portal_sessions WHERE teacher_id=p_teacher_id AND token=p_token); $$;

-- PÚBLICA — lista de professores ativos, pra tela de "quem é você?".
CREATE OR REPLACE FUNCTION listar_professores_portal()
RETURNS TABLE(id uuid, first_name text, last_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT id, first_name, last_name FROM teachers WHERE status = true ORDER BY first_name; $$;

-- PÚBLICA — diz se o professor já tem PIN cadastrado (pra UI decidir o texto certo).
CREATE OR REPLACE FUNCTION professor_tem_pin(p_teacher_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$ SELECT access_pin_hash IS NOT NULL FROM teachers WHERE id = p_teacher_id AND status = true; $$;

-- PÚBLICA — login por PIN. Se for a primeira vez (sem PIN cadastrado),
-- o PIN informado vira o PIN definitivo do professor.
CREATE OR REPLACE FUNCTION professor_portal_login(p_teacher_id uuid, p_pin text)
RETURNS TABLE(token text, first_name text, last_name text, pin_criado boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_teacher teachers%ROWTYPE; v_token text; v_criado boolean := false; BEGIN
  IF p_pin !~ '^[0-9]{4}$' THEN RAISE EXCEPTION 'O PIN deve ter exatamente 4 dígitos'; END IF;
  SELECT * INTO v_teacher FROM teachers WHERE id = p_teacher_id AND status = true;
  IF v_teacher IS NULL THEN RAISE EXCEPTION 'Professor não encontrado'; END IF;

  IF v_teacher.access_pin_hash IS NULL THEN
    UPDATE teachers SET access_pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf')) WHERE id = p_teacher_id;
    v_criado := true;
  ELSIF v_teacher.access_pin_hash <> extensions.crypt(p_pin, v_teacher.access_pin_hash) THEN
    RAISE EXCEPTION 'PIN incorreto';
  END IF;

  v_token := replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','');
  INSERT INTO professor_portal_sessions (teacher_id, token) VALUES (p_teacher_id, v_token);

  RETURN QUERY SELECT v_token, v_teacher.first_name, v_teacher.last_name, v_criado;
END; $$;

-- PÚBLICA — turmas visíveis ao professor logado: as suas primeiro
-- (is_own=true), depois as demais (pra permitir dar aula de substituição).
CREATE OR REPLACE FUNCTION professor_minhas_turmas(p_teacher_id uuid, p_token text)
RETURNS TABLE(id uuid, name text, level text, modalidade text, class_days text, start_time text, end_time text, is_own boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT _professor_sessao_valida(p_teacher_id, p_token) THEN RAISE EXCEPTION 'Sessão inválida. Volte e faça login novamente.'; END IF;
  RETURN QUERY
    SELECT c.id, c.name::text, c.level, c.modalidade, c.class_days, c.start_time, c.end_time,
      (c.teacher_id = p_teacher_id)
    FROM classes c
    WHERE c.status = true
    ORDER BY (c.teacher_id = p_teacher_id) DESC, c.name;
END; $$;

-- PÚBLICA — dados da aula de uma turma numa data (lançamento existente,
-- se houver) + lista de alunos matriculados com a presença atual.
CREATE OR REPLACE FUNCTION professor_turma_aula(p_teacher_id uuid, p_token text, p_class_id uuid, p_lesson_date date)
RETURNS TABLE(lesson_id uuid, teacher_id uuid, status text, content text, notes text, alunos jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_lesson class_lessons%ROWTYPE; BEGIN
  IF NOT _professor_sessao_valida(p_teacher_id, p_token) THEN RAISE EXCEPTION 'Sessão inválida. Volte e faça login novamente.'; END IF;
  SELECT * INTO v_lesson FROM class_lessons WHERE class_id=p_class_id AND lesson_date=p_lesson_date;
  RETURN QUERY
    SELECT v_lesson.id, v_lesson.teacher_id, COALESCE(v_lesson.status,'realizada'), v_lesson.content, v_lesson.notes,
      COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'id', s.id, 'first_name', s.first_name, 'last_name', s.last_name,
          'status', COALESCE(a.status, 'presente')
        ) ORDER BY s.first_name)
        FROM students s
        LEFT JOIN attendance a ON a.student_id = s.id AND a.class_id = p_class_id AND a.date = p_lesson_date
        WHERE s.class_id = p_class_id AND s.status = true), '[]'::jsonb);
END; $$;

-- PÚBLICA — o professor que registrou a aula repassa para outro professor
-- (ex: marcou a aula mas não vai conseguir dar). Conteúdo e presença já
-- preenchidos continuam intactos; o pagamento é recalculado na hora para
-- o novo professor via sync_pagamento_aula.
CREATE OR REPLACE FUNCTION professor_repassar_aula(p_teacher_id uuid, p_token text, p_lesson_id uuid, p_novo_teacher_id uuid)
RETURNS TABLE(first_name text, last_name text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_lesson class_lessons%ROWTYPE; v_novo teachers%ROWTYPE; BEGIN
  IF NOT _professor_sessao_valida(p_teacher_id, p_token) THEN RAISE EXCEPTION 'Sessão inválida. Volte e faça login novamente.'; END IF;

  SELECT * INTO v_lesson FROM class_lessons WHERE id = p_lesson_id;
  IF v_lesson IS NULL THEN RAISE EXCEPTION 'Aula não encontrada'; END IF;
  IF v_lesson.teacher_id IS DISTINCT FROM p_teacher_id THEN
    RAISE EXCEPTION 'Só quem registrou esta aula pode repassá-la para outro professor.';
  END IF;
  IF p_novo_teacher_id = p_teacher_id THEN RAISE EXCEPTION 'Escolha um professor diferente de você.'; END IF;

  SELECT * INTO v_novo FROM teachers WHERE id = p_novo_teacher_id AND status = true;
  IF v_novo IS NULL THEN RAISE EXCEPTION 'Professor não encontrado'; END IF;

  UPDATE class_lessons SET teacher_id = p_novo_teacher_id, updated_at = now() WHERE id = p_lesson_id;
  PERFORM sync_pagamento_aula(p_lesson_id);

  RETURN QUERY SELECT v_novo.first_name, v_novo.last_name;
END; $$;

-- PÚBLICA — registra/atualiza a aula e a frequência via portal do professor.
-- teacher_id sempre recebe quem está logado no portal (não o titular da
-- turma) — é o que faz a regra de substituição funcionar: o pagamento
-- (seção 31) sempre segue quem efetivamente deu a aula.
CREATE OR REPLACE FUNCTION professor_registrar_aula(
  p_teacher_id uuid, p_token text, p_class_id uuid, p_lesson_date date,
  p_status text DEFAULT 'realizada', p_content text DEFAULT NULL, p_notes text DEFAULT NULL,
  p_presencas jsonb DEFAULT '[]'::jsonb
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_id uuid; r jsonb; BEGIN
  IF NOT _professor_sessao_valida(p_teacher_id, p_token) THEN RAISE EXCEPTION 'Sessão inválida. Volte e faça login novamente.'; END IF;
  IF p_status NOT IN ('realizada','cancelada','remarcada') THEN RAISE EXCEPTION 'Status de aula inválido'; END IF;

  INSERT INTO class_lessons (class_id, lesson_date, teacher_id, status, content, notes)
  VALUES (p_class_id, p_lesson_date, p_teacher_id, p_status, p_content, p_notes)
  ON CONFLICT (class_id, lesson_date) DO UPDATE SET
    teacher_id = p_teacher_id, status = EXCLUDED.status, content = EXCLUDED.content,
    notes = EXCLUDED.notes, updated_at = now()
  RETURNING id INTO v_id;

  FOR r IN SELECT * FROM jsonb_array_elements(p_presencas) LOOP
    INSERT INTO attendance (class_id, student_id, date, status, lesson_id, confirmed)
    VALUES (p_class_id, (r->>'student_id')::uuid, p_lesson_date, r->>'status', v_id, true)
    ON CONFLICT (class_id, student_id, date) DO UPDATE SET
      status = EXCLUDED.status, lesson_id = EXCLUDED.lesson_id, confirmed = true;
  END LOOP;

  PERFORM sync_pagamento_aula(v_id);
  RETURN v_id;
END; $$;

-- Admin/secretaria — reseta o PIN de um professor (ex: esqueceu o PIN)
-- e derruba as sessões ativas dele em todos os aparelhos.
CREATE OR REPLACE FUNCTION resetar_pin_professor(p_teacher_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE teachers SET access_pin_hash = NULL WHERE id = p_teacher_id;
  DELETE FROM professor_portal_sessions WHERE teacher_id = p_teacher_id;
END; $$;


-- #####################################################################
-- 31. AUTOMAÇÃO DE PAGAMENTO — lançar horas ao registrar a aula
-- #####################################################################
-- Antes, a secretaria lançava a aula em class_lessons e DEPOIS lançava
-- o pagamento do professor separado em teacher_lessons — trabalho em
-- dobro e risco de esquecer. Agora, toda vez que uma aula é registrada
-- (pela equipe ou pelo próprio professor no portal), o sistema já joga
-- as horas automaticamente no extrato de pagamento do professor que
-- efetivamente ministrou (class_lessons.teacher_id) — mesmo que seja
-- diferente do titular da turma (classes.teacher_id), o que cobre a
-- regra de substituição: o pagamento sempre segue quem deu a aula.
--
-- class_lesson_id liga 1-para-1 um lançamento automático de
-- teacher_lessons ao class_lessons que o originou (índice único
-- parcial permite, ao mesmo tempo, muitos lançamentos manuais antigos
-- com class_lesson_id NULL). Reeditar/apagar a aula atualiza/remove
-- esse lançamento automaticamente — mas NUNCA mexe num lançamento que
-- já foi marcado como pago (paid=true), pra não bagunçar um pagamento
-- já confirmado.

ALTER TABLE teacher_lessons ADD COLUMN IF NOT EXISTS class_lesson_id uuid REFERENCES class_lessons(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tl_class_lesson_unique ON teacher_lessons(class_lesson_id) WHERE class_lesson_id IS NOT NULL;

CREATE OR REPLACE FUNCTION sync_pagamento_aula(p_lesson_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_lesson class_lessons%ROWTYPE;
  v_class classes%ROWTYPE;
  v_existing teacher_lessons%ROWTYPE;
  v_hours numeric(4,2);
  v_lesson_type text;
  v_tl_status text;
  v_counts boolean;
BEGIN
  SELECT * INTO v_lesson FROM class_lessons WHERE id = p_lesson_id;
  IF v_lesson IS NULL OR v_lesson.teacher_id IS NULL THEN RETURN; END IF;

  SELECT * INTO v_class FROM classes WHERE id = v_lesson.class_id;
  IF v_class IS NULL THEN RETURN; END IF;

  SELECT * INTO v_existing FROM teacher_lessons WHERE class_lesson_id = p_lesson_id;
  IF v_existing.paid IS TRUE THEN RETURN; END IF;

  BEGIN
    v_hours := GREATEST(0.5, ROUND(EXTRACT(EPOCH FROM (v_class.end_time::time - v_class.start_time::time)) / 3600.0, 2));
  EXCEPTION WHEN OTHERS THEN
    v_hours := NULL;
  END;
  IF v_hours IS NULL OR v_hours <= 0 THEN v_hours := 1; END IF;

  v_lesson_type := CASE WHEN v_lesson.teacher_id IS DISTINCT FROM v_class.teacher_id THEN 'substituicao' ELSE 'aula_normal' END;

  IF v_lesson.status = 'realizada' THEN
    v_tl_status := 'realizada'; v_counts := true;
  ELSE
    v_tl_status := 'cancelada'; v_counts := false;
  END IF;

  INSERT INTO teacher_lessons (class_id, teacher_id, actual_teacher_id, lesson_date, lesson_type, status, hours, counts_for_payment, class_lesson_id)
  VALUES (v_lesson.class_id, v_lesson.teacher_id, v_lesson.teacher_id, v_lesson.lesson_date, v_lesson_type, v_tl_status, v_hours, v_counts, p_lesson_id)
  ON CONFLICT (class_lesson_id) WHERE class_lesson_id IS NOT NULL DO UPDATE SET
    teacher_id = EXCLUDED.teacher_id, actual_teacher_id = EXCLUDED.actual_teacher_id,
    lesson_date = EXCLUDED.lesson_date, lesson_type = EXCLUDED.lesson_type,
    status = EXCLUDED.status, hours = EXCLUDED.hours, counts_for_payment = EXCLUDED.counts_for_payment
  WHERE teacher_lessons.paid IS NOT TRUE;
END; $$;
