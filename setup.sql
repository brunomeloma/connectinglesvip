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
AS $$ SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('super_admin','direcao','financeiro') AND status = true); $$;

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

-- Boletos de UM aluno — secretaria: SEM valor, SEM comprovante_url
-- Retorna apenas o necessário para operar cobrança
-- LIMITAÇÃO CONHECIDA: a secretaria vê status por boleto.
-- Se ela anotar "pago" de cada mês, pode inferir quanto o aluno paga.
-- Isso é inevitável se ela precisa cobrar. O que ela NÃO pode ver
-- é o valor da mensalidade nem totais agregados.
CREATE OR REPLACE FUNCTION get_boletos_aluno_secretaria(p_student_id uuid, p_ano int)
RETURNS TABLE(
  id uuid, mes_referencia int, ano_referencia int,
  data_vencimento date, status text, data_pagamento date,
  observacao text, url_boleto text, codigo_boleto text,
  tem_comprovante boolean
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT b.id, b.mes_referencia, b.ano_referencia,
      b.data_vencimento, b.status, b.data_pagamento,
      b.observacao, b.url_boleto, b.codigo_boleto,
      (b.comprovante_path IS NOT NULL OR b.comprovante_url IS NOT NULL)
    FROM boletos b WHERE b.student_id=p_student_id AND b.ano_referencia=p_ano
    ORDER BY b.mes_referencia;
END; $$;

-- Listagem com nome do aluno — SOMENTE direção/financeiro
-- Secretaria NÃO tem acesso a esta RPC
CREATE OR REPLACE FUNCTION get_boletos_com_aluno(p_ano int, p_status text DEFAULT NULL)
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  mes_referencia int, ano_referencia int, data_vencimento date,
  valor numeric, status text, data_pagamento date, observacao text,
  comprovante_url text, comprovante_path text, url_boleto text, codigo_boleto text
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro']) THEN
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
    WHERE schemaname='public' AND policyname LIKE 'anon_%' OR policyname LIKE 'temp_dev_%' OR policyname='Allow all for authenticated'
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
  paid boolean DEFAULT false,
  paid_at date,
  paid_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now()
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='tl_type_check') THEN
    ALTER TABLE teacher_lessons ADD CONSTRAINT tl_type_check CHECK (lesson_type IN ('aula_normal','substituicao','reuniao','evento','outro'));
  END IF;
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
  p_notes text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ DECLARE v_id uuid; BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  INSERT INTO teacher_lessons(class_id, teacher_id, actual_teacher_id, lesson_date, lesson_type, status, hours, notes, created_by)
  VALUES (p_class_id, p_teacher_id, COALESCE(p_actual_teacher_id, p_teacher_id), p_lesson_date, p_lesson_type, p_status, p_hours, p_notes, auth.uid())
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
  p_notes text DEFAULT NULL
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
    notes = COALESCE(p_notes, notes)
  WHERE id = p_id;
END; $$;

-- Deletar aula (só admin)
CREATE OR REPLACE FUNCTION deletar_aula_professor(p_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  DELETE FROM teacher_lessons WHERE id = p_id;
END; $$;

-- Listar aulas — admin/financeiro (com valor_hora)
CREATE OR REPLACE FUNCTION get_aulas_mes(p_mes int, p_ano int, p_teacher_id uuid DEFAULT NULL)
RETURNS TABLE(
  id uuid, class_id uuid, class_name text,
  teacher_id uuid, teacher_name text,
  actual_teacher_id uuid, actual_teacher_name text,
  lesson_date date, lesson_type text, status text,
  hours numeric, valor_hora numeric, notes text,
  paid boolean, paid_at date, created_at timestamptz
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
      tl.paid, tl.paid_at, tl.created_at
    FROM teacher_lessons tl
    LEFT JOIN classes c ON c.id = tl.class_id
    LEFT JOIN teachers tr ON tr.id = tl.teacher_id
    LEFT JOIN teachers at2 ON at2.id = tl.actual_teacher_id
    WHERE EXTRACT(MONTH FROM tl.lesson_date)::int = p_mes
      AND EXTRACT(YEAR FROM tl.lesson_date)::int = p_ano
      AND (p_teacher_id IS NULL OR tl.actual_teacher_id = p_teacher_id)
    ORDER BY tl.lesson_date DESC;
END; $$;

-- Listar aulas — secretaria (SEM valor_hora)
CREATE OR REPLACE FUNCTION get_aulas_mes_secretaria(p_mes int, p_ano int, p_teacher_id uuid DEFAULT NULL)
RETURNS TABLE(
  id uuid, class_id uuid, class_name text,
  teacher_id uuid, teacher_name text,
  actual_teacher_id uuid, actual_teacher_name text,
  lesson_date date, lesson_type text, status text,
  hours numeric, notes text, paid boolean, created_at timestamptz
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT tl.id,
      tl.class_id, c.name::text,
      tl.teacher_id, (tr.first_name||' '||tr.last_name)::text,
      tl.actual_teacher_id, (at2.first_name||' '||at2.last_name)::text,
      tl.lesson_date, tl.lesson_type, tl.status,
      tl.hours, tl.notes, tl.paid, tl.created_at
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
CREATE OR REPLACE FUNCTION get_relatorio_pagamento_professor(p_mes int, p_ano int)
RETURNS TABLE(
  teacher_id uuid, teacher_name text, valor_hora numeric,
  total_aulas bigint, total_horas numeric, total_substituicoes bigint,
  aulas_nao_realizadas bigint, total_a_pagar numeric, todos_pagos boolean
) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  RETURN QUERY
    SELECT
      t.id,
      (t.first_name||' '||t.last_name)::text,
      COALESCE(t.valor_hora, 0)::numeric,
      COUNT(tl.id) FILTER (WHERE tl.status='realizada'),
      COALESCE(SUM(tl.hours) FILTER (WHERE tl.status='realizada'), 0)::numeric,
      COUNT(tl.id) FILTER (WHERE tl.lesson_type='substituicao' AND tl.status='realizada'),
      COUNT(tl.id) FILTER (WHERE tl.status IN ('cancelada','nao_realizada','falta')),
      COALESCE(SUM(tl.hours) FILTER (WHERE tl.status='realizada'), 0) * COALESCE(t.valor_hora, 0),
      COALESCE(bool_and(tl.paid) FILTER (WHERE tl.status='realizada'), false)
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
    AND status='realizada';
END; $$;

-- Atualizar valor_hora do professor (admin/direção)
CREATE OR REPLACE FUNCTION atualizar_valor_hora(p_teacher_id uuid, p_valor_hora numeric)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Permissão negada'; END IF;
  UPDATE teachers SET valor_hora = p_valor_hora WHERE id = p_teacher_id;
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
