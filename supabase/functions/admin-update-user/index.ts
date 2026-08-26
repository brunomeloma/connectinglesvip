import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://connectinglesvip.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

async function getCallerProfile(supabaseUrl: string, supabaseAnonKey: string, authHeader: string) {
  const userClient = createClient(supabaseUrl, supabaseAnonKey, {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: { user: caller } } = await userClient.auth.getUser();
  if (!caller) return { caller: null, callerProfile: null, userClient };
  const { data: callerProfile } = await userClient
    .from("profiles").select("role,status").eq("id", caller.id).single();
  return { caller, callerProfile, userClient };
}

function err(msg: string, status = 400) {
  return new Response(JSON.stringify({ error: msg }), {
    status, headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function ok(data: Record<string, unknown> = { success: true }) {
  return new Response(JSON.stringify(data), {
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) return err("Token ausente", 401);

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

    const { caller, callerProfile } = await getCallerProfile(supabaseUrl, supabaseAnonKey, authHeader);
    if (!caller || !callerProfile) return err("Não autenticado", 401);
    if (!callerProfile.status || !["super_admin", "direcao"].includes(callerProfile.role)) {
      return err("Sem permissão.", 403);
    }

    const body = await req.json();
    const { action } = body;
    const adminClient = createClient(supabaseUrl, supabaseServiceKey);

    if (action === "update") {
      const { user_id, name, role, status } = body;
      if (!user_id) return err("user_id obrigatório");

      const { data: target } = await adminClient.from("profiles").select("role").eq("id", user_id).single();
      if (!target) return err("Usuário não encontrado.", 404);

      if (target.role === "super_admin" && callerProfile.role !== "super_admin") {
        return err("Apenas super_admin pode alterar outro super_admin.", 403);
      }
      if (role === "super_admin" && callerProfile.role !== "super_admin") {
        return err("Apenas super_admin pode promover a super_admin.", 403);
      }

      const allowedRoles = ["super_admin", "direcao", "financeiro", "secretaria", "professor", "captacao"];
      if (role && !allowedRoles.includes(role)) return err("Role inválido: " + role);

      const updates: Record<string, unknown> = {};
      if (name !== undefined) updates.name = name;
      if (role !== undefined) updates.role = role;
      if (status !== undefined) updates.status = status;

      const { error } = await adminClient.from("profiles").update(updates).eq("id", user_id);
      if (error) return err(error.message);
      return ok();
    }

    if (action === "reset_password") {
      const { user_id, new_password } = body;
      if (!user_id || !new_password) return err("user_id e new_password obrigatórios");
      if (new_password.length < 6) return err("Senha deve ter no mínimo 6 caracteres.");

      const { data: target } = await adminClient.from("profiles").select("role").eq("id", user_id).single();
      if (!target) return err("Usuário não encontrado.", 404);

      if (target.role === "super_admin" && callerProfile.role !== "super_admin") {
        return err("Apenas super_admin pode resetar senha de outro super_admin.", 403);
      }

      const { error } = await adminClient.auth.admin.updateUserById(user_id, { password: new_password });
      if (error) return err(error.message);
      return ok();
    }

    if (action === "deactivate") {
      const { user_id } = body;
      if (!user_id) return err("user_id obrigatório");

      if (user_id === caller.id) return err("Você não pode desativar a si mesmo.");

      const { data: target } = await adminClient.from("profiles").select("role").eq("id", user_id).single();
      if (!target) return err("Usuário não encontrado.", 404);
      if (target.role === "super_admin" && callerProfile.role !== "super_admin") {
        return err("Apenas super_admin pode desativar outro super_admin.", 403);
      }

      await adminClient.from("profiles").update({ status: false }).eq("id", user_id);
      return ok();
    }

    return err("action inválida");
  } catch (e) {
    return err(e.message, 500);
  }
});
