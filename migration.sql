-- =============================================
-- Migration: Permissões, campos VIP e contatos
-- Connect Inglês VIP — Gestão Escolar
-- =============================================

-- 1. Adicionar campo 'role' na tabela users (se ainda não existir com os novos valores)
-- Roles possíveis: super_admin, admin, direcao, financeiro, secretaria, escola, escola_admin, professor
-- Já existe a coluna role, apenas garantir que aceita os novos valores.

-- 2. Novos campos na tabela students
ALTER TABLE students ADD COLUMN IF NOT EXISTS student_type text DEFAULT 'Regular';
ALTER TABLE students ADD COLUMN IF NOT EXISTS contact_preference text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS whatsapp text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_status text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_notes text;

-- 3. Tabela de histórico de contatos com alunos
CREATE TABLE IF NOT EXISTS student_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid REFERENCES students(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  contact_type text,
  message text,
  channel text DEFAULT 'whatsapp',
  notes text,
  created_at timestamptz DEFAULT now()
);

-- 4. Índices para performance
CREATE INDEX IF NOT EXISTS idx_student_contacts_student_id ON student_contacts(student_id);
CREATE INDEX IF NOT EXISTS idx_student_contacts_created_at ON student_contacts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_students_student_type ON students(student_type);

-- 5. RLS (Row Level Security) para student_contacts
ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all for authenticated" ON student_contacts
  FOR ALL USING (true) WITH CHECK (true);

-- 6. Permitir leitura da view resumo_financeiro_aluno (já existente)
-- Nenhuma alteração necessária, o controle de visibilidade é feito no frontend por role.
