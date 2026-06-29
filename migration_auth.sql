-- =====================================================================
-- Migration: Supabase Auth — Ajustes de FK e limpeza
-- Execute APÓS criar os usuários no Supabase Auth e rodar rls_security.sql
-- =====================================================================
--
-- PASSO A PASSO PARA MIGRAR:
--
-- 1. No Supabase Dashboard > Authentication > Users, crie cada usuário:
--    - Email: mesmo email que estava na tabela users
--    - Password: nova senha segura
--    - Em "User Metadata" (JSON), adicione:
--      {"name": "Nome do Usuário", "role": "super_admin"}
--    - O trigger handle_new_user() criará o profile automaticamente
--
-- 2. Verifique que os profiles foram criados:
--    SELECT * FROM profiles;
--
-- 3. Execute o rls_security.sql (Parte A + Parte C)
--
-- 4. Execute este arquivo (migration_auth.sql)
--
-- 5. Faça deploy do index.html atualizado
--
-- 6. Teste: login, sessão persistente, logout, permissões
--
-- =====================================================================

-- Atualizar FK de student_contacts para apontar para profiles
-- (só executar se a tabela student_contacts já tem dados com user_id
--  referenciando a tabela users legada)
-- Se student_contacts está vazia, pode dropar e recriar:

-- Opção segura: dropar a FK antiga e criar nova apontando para profiles
DO $$ BEGIN
  -- Remove FK antiga se existir
  IF EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'student_contacts_user_id_fkey'
    AND table_name = 'student_contacts'
  ) THEN
    ALTER TABLE student_contacts DROP CONSTRAINT student_contacts_user_id_fkey;
  END IF;
END $$;

-- Nova FK apontando para profiles
-- user_id agora contém auth.users.id (= profiles.id)
-- Registros antigos com user_id da tabela users ficarão órfãos
-- (SET NULL garante que não quebra)
ALTER TABLE student_contacts
  ADD CONSTRAINT student_contacts_user_id_fkey
  FOREIGN KEY (user_id) REFERENCES profiles(id) ON DELETE SET NULL;

-- Atualizar FK de attendance.marked_by
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'attendance_marked_by_fkey'
    AND table_name = 'attendance'
  ) THEN
    ALTER TABLE attendance DROP CONSTRAINT attendance_marked_by_fkey;
  END IF;
END $$;

ALTER TABLE attendance
  ADD CONSTRAINT attendance_marked_by_fkey
  FOREIGN KEY (marked_by) REFERENCES profiles(id) ON DELETE SET NULL;

-- =====================================================================
-- CRIAR PRIMEIRO USUÁRIO ADMIN (se ainda não existir)
-- =====================================================================
-- Se você criou o usuário via Dashboard e o trigger rodou,
-- o profile já existe. Verifique:
--
--   SELECT * FROM profiles WHERE role = 'super_admin';
--
-- Se o role ficou como 'secretaria' (padrão), corrija:
--
--   UPDATE profiles
--   SET role = 'super_admin', name = 'Direção Connect'
--   WHERE email = 'seu-email@exemplo.com';
--
-- Para criar via SQL (alternativa ao Dashboard):
-- Não é possível criar auth.users via SQL sem service_role.
-- Use o Dashboard ou a API admin.
-- =====================================================================
