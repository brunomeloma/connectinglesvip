import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { Buffer } from "node:buffer";
import officeCrypto from "npm:officecrypto-tool@0.0.19";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://connectinglesvip.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(obj: unknown, status: number) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return json({ error: "Token ausente" }, 401);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const {
      data: { user: caller },
      error: authError,
    } = await userClient.auth.getUser();

    if (authError || !caller) {
      return json({ error: "Não autenticado" }, 401);
    }

    const { data: callerProfile } = await userClient
      .from("profiles")
      .select("role,status")
      .eq("id", caller.id)
      .single();

    const allowedRoles = ["super_admin", "direcao", "financeiro", "secretaria"];
    if (!callerProfile || !callerProfile.status || !allowedRoles.includes(callerProfile.role)) {
      return json({ error: "Sem permissão para importar caixa." }, 403);
    }

    const { file_base64, senha } = await req.json();
    if (!file_base64 || !senha) {
      return json({ error: "Campos obrigatórios: file_base64, senha" }, 400);
    }

    const inputBytes = Uint8Array.from(atob(file_base64), (c) => c.charCodeAt(0));

    let decrypted: Buffer;
    try {
      decrypted = await officeCrypto.decrypt(Buffer.from(inputBytes), { password: senha });
    } catch (_e) {
      return json({ error: "Senha incorreta ou arquivo inválido." }, 400);
    }

    return json({ file_base64: bytesToBase64(new Uint8Array(decrypted)) }, 200);
  } catch (e) {
    return json({ error: (e as Error).message || "Erro interno" }, 500);
  }
});
