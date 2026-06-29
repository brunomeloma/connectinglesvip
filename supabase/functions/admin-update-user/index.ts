import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Token ausente" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const {
      data: { user: caller },
    } = await userClient.auth.getUser();

    if (!caller) {
      return new Response(JSON.stringify({ error: "Não autenticado" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: callerProfile } = await userClient
      .from("profiles")
      .select("role,status")
      .eq("id", caller.id)
      .single();

    if (
      !callerProfile ||
      !callerProfile.status ||
      !["super_admin", "direcao"].includes(callerProfile.role)
    ) {
      return new Response(
        JSON.stringify({ error: "Sem permissão." }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const body = await req.json();
    const { action } = body;

    const adminClient = createClient(supabaseUrl, supabaseServiceKey);

    if (action === "update") {
      const { user_id, name, role, status } = body;
      if (!user_id) {
        return new Response(JSON.stringify({ error: "user_id obrigatório" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      if (role === "super_admin" && callerProfile.role !== "super_admin") {
        return new Response(
          JSON.stringify({ error: "Apenas super_admin pode promover a super_admin." }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const { data: targetProfile } = await adminClient
        .from("profiles")
        .select("role")
        .eq("id", user_id)
        .single();

      if (targetProfile?.role === "super_admin" && callerProfile.role !== "super_admin") {
        return new Response(
          JSON.stringify({ error: "Apenas super_admin pode alterar outro super_admin." }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const updates: Record<string, unknown> = {};
      if (name !== undefined) updates.name = name;
      if (role !== undefined) updates.role = role;
      if (status !== undefined) updates.status = status;

      const { error } = await adminClient
        .from("profiles")
        .update(updates)
        .eq("id", user_id);

      if (error) {
        return new Response(JSON.stringify({ error: error.message }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (action === "reset_password") {
      const { user_id, new_password } = body;
      if (!user_id || !new_password) {
        return new Response(
          JSON.stringify({ error: "user_id e new_password obrigatórios" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      if (new_password.length < 6) {
        return new Response(
          JSON.stringify({ error: "Senha deve ter no mínimo 6 caracteres." }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const { error } = await adminClient.auth.admin.updateUserById(user_id, {
        password: new_password,
      });

      if (error) {
        return new Response(JSON.stringify({ error: error.message }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (action === "deactivate") {
      const { user_id } = body;
      if (!user_id) {
        return new Response(JSON.stringify({ error: "user_id obrigatório" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      if (user_id === caller.id) {
        return new Response(
          JSON.stringify({ error: "Você não pode desativar a si mesmo." }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const { data: targetProfile } = await adminClient
        .from("profiles")
        .select("role")
        .eq("id", user_id)
        .single();

      if (targetProfile?.role === "super_admin" && callerProfile.role !== "super_admin") {
        return new Response(
          JSON.stringify({ error: "Apenas super_admin pode desativar outro super_admin." }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      await adminClient.from("profiles").update({ status: false }).eq("id", user_id);

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "action inválida" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
