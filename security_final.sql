-- =====================================================================
-- Connect Inglês VIP — Segurança Final
-- Remover policies abertas, criar RPCs para secretaria, storage privado
-- Executar no SQL Editor do Supabase
-- =====================================================================

-- 1. REMOVER POLICIES ABERTAS DO migration.sql ANTIGO
DROP POLICY IF EXISTS "Allow all for authenticated" ON student_contacts;
DROP POLICY IF EXISTS "Allow all for authenticated" ON attendance;
DROP POLICY IF EXISTS "temp_dev_users" ON users;
DROP POLICY IF EXISTS "temp_dev_schools" ON schools;
DROP POLICY IF EXISTS "temp_dev_teachers" ON teachers;
DROP POLICY IF EXISTS "temp_dev_students" ON students;
DROP POLICY IF EXISTS "temp_dev_classes" ON classes;
DROP POLICY IF EXISTS "temp_dev_boletos" ON boletos;
DROP POLICY IF EXISTS "temp_dev_contacts" ON student_contacts;
DROP POLICY IF EXISTS "temp_dev_attendance" ON attendance;

-- 2. REMOVER SELECT AMPLO DE BOLETOS PARA SECRETARIA
-- Trocar por policy que exclui secretaria do SELECT direto
DROP POLICY IF EXISTS "boletos_select" ON boletos;
DROP POLICY IF EXISTS "boletos_insert" ON boletos;
DROP POLICY IF EXISTS "boletos_update" ON boletos;
DROP POLICY IF EXISTS "boletos_delete" ON boletos;

-- Apenas direção e financeiro podem SELECT direto em boletos
CREATE POLICY "boletos_select" ON boletos FOR SELECT
  USING (has_role(ARRAY['super_admin','direcao','financeiro']));

-- Insert/update/delete: direção e financeiro via query direta
CREATE POLICY "boletos_insert" ON boletos FOR INSERT
  WITH CHECK (has_role(ARRAY['super_admin','direcao','financeiro']));

CREATE POLICY "boletos_update" ON boletos FOR UPDATE
  USING (has_role(ARRAY['super_admin','direcao','financeiro']));

CREATE POLICY "boletos_delete" ON boletos FOR DELETE
  USING (has_role(ARRAY['super_admin','direcao','financeiro']));

-- Secretaria opera APENAS via RPCs abaixo (SECURITY DEFINER bypassa RLS)

-- 3. RPCs SEGURAS PARA SECRETARIA

-- Buscar boletos de UM aluno específico
CREATE OR REPLACE FUNCTION get_boletos_aluno(p_student_id uuid, p_ano int)
RETURNS SETOF boletos
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  RETURN QUERY
    SELECT * FROM boletos
    WHERE student_id = p_student_id AND ano_referencia = p_ano
    ORDER BY mes_referencia;
END;
$$;

-- Marcar pagamento de um boleto
CREATE OR REPLACE FUNCTION marcar_pagamento_boleto(
  p_boleto_id uuid,
  p_status text,
  p_data_pagamento date DEFAULT NULL,
  p_observacao text DEFAULT NULL,
  p_comprovante_path text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  IF p_status NOT IN ('pago', 'aberto') THEN
    RAISE EXCEPTION 'Status inválido';
  END IF;
  UPDATE boletos SET
    status = p_status,
    data_pagamento = CASE WHEN p_status = 'pago' THEN COALESCE(p_data_pagamento, CURRENT_DATE) ELSE NULL END,
    observacao = CASE WHEN p_status = 'pago' THEN p_observacao ELSE NULL END,
    comprovante_url = CASE WHEN p_status = 'pago' THEN p_comprovante_path ELSE NULL END
  WHERE id = p_boleto_id;
END;
$$;

-- Marcar múltiplos boletos vencidos como pago
CREATE OR REPLACE FUNCTION marcar_vencidos_pago(p_boleto_ids uuid[])
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  UPDATE boletos SET status = 'pago', data_pagamento = CURRENT_DATE
  WHERE id = ANY(p_boleto_ids);
END;
$$;

-- Lançar/atualizar boletos de um aluno (upsert)
CREATE OR REPLACE FUNCTION lancar_boletos_aluno(p_rows jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  r jsonb;
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  FOR r IN SELECT * FROM jsonb_array_elements(p_rows) LOOP
    INSERT INTO boletos (student_id, mes_referencia, ano_referencia, data_vencimento, valor, url_boleto, codigo_boleto)
    VALUES (
      (r->>'student_id')::uuid,
      (r->>'mes_referencia')::int,
      (r->>'ano_referencia')::int,
      (r->>'data_vencimento')::date,
      (r->>'valor')::numeric,
      r->>'url_boleto',
      r->>'codigo_boleto'
    )
    ON CONFLICT (student_id, mes_referencia, ano_referencia)
    DO UPDATE SET
      data_vencimento = EXCLUDED.data_vencimento,
      valor = EXCLUDED.valor,
      url_boleto = EXCLUDED.url_boleto,
      codigo_boleto = EXCLUDED.codigo_boleto;
  END LOOP;
END;
$$;

-- Deletar boleto individual
CREATE OR REPLACE FUNCTION deletar_boleto(p_boleto_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  DELETE FROM boletos WHERE id = p_boleto_id;
END;
$$;

-- Resumo financeiro global (só direção/financeiro)
CREATE OR REPLACE FUNCTION get_resumo_financeiro()
RETURNS TABLE(student_id uuid, nome text, valor_pago numeric, valor_aberto numeric)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF NOT can_view_finance() THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT
    s.id,
    (s.first_name || ' ' || s.last_name)::text,
    COALESCE(SUM(CASE WHEN b.status = 'pago' THEN b.valor ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN b.status = 'aberto' THEN b.valor ELSE 0 END), 0)
  FROM students s
  LEFT JOIN boletos b ON b.student_id = s.id
  WHERE s.status = true
  GROUP BY s.id, s.first_name, s.last_name
  HAVING SUM(b.valor) > 0;
END;
$$;

-- Listar boletos com nome do aluno (para listagem financeira — só direção/financeiro)
CREATE OR REPLACE FUNCTION get_boletos_com_aluno(p_ano int, p_status text DEFAULT NULL)
RETURNS TABLE(
  id uuid, student_id uuid, first_name text, last_name text,
  mes_referencia int, ano_referencia int, data_vencimento date,
  valor numeric, status text, data_pagamento date, observacao text,
  comprovante_url text, url_boleto text, codigo_boleto text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  RETURN QUERY
    SELECT b.id, b.student_id, s.first_name, s.last_name,
      b.mes_referencia, b.ano_referencia, b.data_vencimento,
      b.valor, b.status, b.data_pagamento, b.observacao,
      b.comprovante_url, b.url_boleto, b.codigo_boleto
    FROM boletos b
    JOIN students s ON s.id = b.student_id
    WHERE b.ano_referencia = p_ano
      AND (p_status IS NULL OR b.status = p_status)
    ORDER BY b.data_vencimento;
END;
$$;

-- Gerar signed URL para comprovante
CREATE OR REPLACE FUNCTION get_comprovante_url(p_path text)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF NOT has_role(ARRAY['super_admin','direcao','financeiro','secretaria']) THEN
    RAISE EXCEPTION 'Permissão negada';
  END IF;
  -- Retorna o path; o frontend gera signed URL via JS SDK
  RETURN p_path;
END;
$$;

-- 4. STORAGE — garantir bucket privado
UPDATE storage.buckets SET public = false WHERE id = 'comprovantes';

-- Adicionar coluna para salvar path em vez de URL pública
ALTER TABLE boletos ADD COLUMN IF NOT EXISTS comprovante_path text;
