-- =============================================
-- Migration: Campos VIP, contatos, horários, presença
-- Connect Inglês VIP — Gestão Escolar
-- (Sem policies abertas — segurança via rls_security.sql)
-- =============================================

-- 1. Novos campos na tabela students (VIP)
ALTER TABLE students ADD COLUMN IF NOT EXISTS student_type text DEFAULT 'Regular';
ALTER TABLE students ADD COLUMN IF NOT EXISTS contact_preference text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS whatsapp text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_status text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_notes text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_class_days text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_start_time text;
ALTER TABLE students ADD COLUMN IF NOT EXISTS vip_end_time text;

-- 2. Novos campos na tabela classes (horários estruturados)
ALTER TABLE classes ADD COLUMN IF NOT EXISTS class_days text;
ALTER TABLE classes ADD COLUMN IF NOT EXISTS start_time text;
ALTER TABLE classes ADD COLUMN IF NOT EXISTS end_time text;

-- 3. Tabela de histórico de contatos com alunos
CREATE TABLE IF NOT EXISTS student_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid REFERENCES students(id) ON DELETE CASCADE,
  user_id uuid REFERENCES profiles(id) ON DELETE SET NULL,
  contact_type text,
  message text,
  channel text DEFAULT 'whatsapp',
  notes text,
  created_at timestamptz DEFAULT now()
);

-- 4. Tabela de chamada / presença
CREATE TABLE IF NOT EXISTS attendance (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id uuid REFERENCES classes(id) ON DELETE CASCADE,
  student_id uuid REFERENCES students(id) ON DELETE CASCADE,
  date date NOT NULL,
  status text DEFAULT 'pendente',
  confirmed boolean DEFAULT false,
  marked_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  UNIQUE(class_id, student_id, date)
);

-- 5. Índices
CREATE INDEX IF NOT EXISTS idx_student_contacts_student_id ON student_contacts(student_id);
CREATE INDEX IF NOT EXISTS idx_student_contacts_created_at ON student_contacts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_students_student_type ON students(student_type);
CREATE INDEX IF NOT EXISTS idx_attendance_class_date ON attendance(class_id, date);
CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance(student_id);

-- 6. RLS habilitado (policies definidas em rls_security.sql)
ALTER TABLE student_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;

-- 7. Coluna para path de comprovante (storage privado)
ALTER TABLE boletos ADD COLUMN IF NOT EXISTS comprovante_path text;
